"""Scanner execution with isolation, timeouts, and deterministic result states."""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secweaver.config import SAFE_ENVIRONMENT_KEYS
from secweaver.models import Finding, PolicyDecision, ScannerResult
from secweaver.redact import redact_text, sensitive_key
from secweaver.reports import (
    evaluate_policy,
    parse_scanner_report,
    sanitize_raw_report,
)
from secweaver.scanners import ScannerDefinition, scanner_controls_dir
from secweaver.util import atomic_write_text


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    results: tuple[ScannerResult, ...]
    findings: tuple[Finding, ...]
    decision: PolicyDecision
    exit_code: int


def _safe_environment(config: dict[str, Any], report_root: Path) -> dict[str, str]:
    allowed = {
        str(value)
        for value in config["environment"]["passthrough"]
        if str(value) in SAFE_ENVIRONMENT_KEYS
    }
    environment: dict[str, str] = {}
    for key in allowed:
        value = os.environ.get(key)
        if value is not None and not sensitive_key(key):
            environment[key] = value
    environment.setdefault("PATH", os.environ.get("PATH", ""))
    if os.name == "nt":
        for key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
            if key in os.environ:
                environment.setdefault(key, os.environ[key])
    isolated_home = (
        Path(str(config["offline"]["home_dir"])).resolve()
        if bool(config["scan"]["offline"])
        else report_root / ".runtime-home"
    )
    isolated_cache = isolated_home / ".cache"
    isolated_cache.mkdir(parents=True, exist_ok=True)
    environment["HOME"] = str(isolated_home)
    environment["USERPROFILE"] = str(isolated_home)
    environment["XDG_CACHE_HOME"] = str(isolated_cache)
    environment["SEMGREP_SEND_METRICS"] = "off"
    environment["NO_COLOR"] = "1"
    return environment


def _log_tail(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 64 * 1024))
            content = handle.read().decode("utf-8", errors="replace")
    except OSError:
        return ""
    return redact_text(content, limit=4_000)


def _tool_version(executable: str, env: dict[str, str]) -> str:
    try:
        completed = subprocess.run(
            [executable, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    output = (completed.stdout or completed.stderr).strip().splitlines()
    return redact_text(output[0], limit=300) if output else ""


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        elif os.name == "nt":
            taskkill = shutil.which("taskkill")
            if taskkill:
                subprocess.run(
                    [taskkill, "/PID", str(process.pid), "/T", "/F"],
                    check=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    shell=False,
                )
            else:
                process.kill()
        else:
            process.kill()
    except (OSError, subprocess.SubprocessError):
        process.kill()
    with suppress(OSError, subprocess.TimeoutExpired):
        process.wait(timeout=10)


def _run_process(
    command: list[str],
    *,
    cwd: Path,
    stdout: Any,
    timeout: int,
    env: dict[str, str],
) -> int:
    options: dict[str, Any] = {}
    if os.name == "posix":
        options["start_new_session"] = True
    elif os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=subprocess.STDOUT,
        env=env,
        shell=False,
        **options,
    )
    try:
        return_code = process.wait(timeout=timeout)
        if os.name == "posix":
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        return return_code
    except subprocess.TimeoutExpired:
        _terminate_process_tree(process)
        raise


def _version_matches(expected: str, actual: str) -> bool:
    if not expected or not actual:
        return False
    return bool(
        re.search(
            rf"(?<![0-9A-Za-z.+-])v?{re.escape(expected)}(?![0-9A-Za-z.+-])",
            actual,
        )
    )


def _immutable_image(image: str) -> bool:
    name, marker, digest = image.rpartition("@sha256:")
    valid_digest = len(digest) == 64 and all(
        character in "0123456789abcdef" for character in digest
    )
    return bool(marker and name and valid_digest)


def _discard_output(path: Path | None) -> None:
    if path is None:
        return
    try:
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path)
    except OSError:
        # The containing report directory is new and dedicated to this run.
        # A failed cleanup is represented by a scanner error; callers must not
        # publish an unreviewed partial directory.
        pass


def _finish_log(config: dict[str, Any], result: ScannerResult) -> None:
    path = result.log_path
    if path is None:
        return
    if not bool(config["reports"].get("retain_logs", False)):
        _discard_output(path)
        result.log_path = None
        return
    try:
        sanitized_tail = _log_tail(path)
        atomic_write_text(path, sanitized_tail + ("\n" if sanitized_tail else ""))
    except OSError:
        _discard_output(path)
        result.log_path = None


def _container_command(
    config: dict[str, Any],
    definition: ScannerDefinition,
    target: Path,
    report_root: Path,
) -> list[str]:
    engine = str(config["scan"]["container_engine"])
    if engine not in {"docker", "podman"}:
        raise ValueError("Unsupported container engine")
    command = [
        engine,
        "run",
        "--rm",
        "--init",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=536870912",
        "--tmpfs=/root/.cache:rw,noexec,nosuid,size=1073741824",
        "--mount",
        f"type=bind,src={report_root.resolve()},dst=/reports",
        "--mount",
        (
            "type=bind,"
            f"src={scanner_controls_dir().resolve()},"
            "dst=/secweaver-controls,readonly"
        ),
    ]
    if str(config["scan"]["target_kind"]) == "source":
        command.extend(
            [
                "--mount",
                f"type=bind,src={target.resolve()},dst=/workspace,readonly",
            ]
        )
    if bool(config["scan"]["offline"]):
        command.append("--network=none")
    command.extend(["--", definition.container_image])
    command.extend(definition.container_args)
    return command


def select_execution(
    config: dict[str, Any],
    definition: ScannerDefinition,
) -> tuple[str, list[str] | None, str]:
    requested = str(config["scan"]["execution"])
    native = shutil.which(definition.executable)
    engine = shutil.which(str(config["scan"]["container_engine"]))
    workspace = Path.cwd().resolve()
    native_unsafe = False
    engine_unsafe = False
    if native:
        try:
            Path(native).resolve().relative_to(workspace)
            native_unsafe = True
            native = None
        except ValueError:
            pass
    if engine:
        try:
            Path(engine).resolve().relative_to(workspace)
            engine_unsafe = True
            engine = None
        except ValueError:
            pass

    if requested == "native":
        if native:
            return "native", [native, *definition.native_args], ""
        if native_unsafe:
            return "missing", None, (
                f"Refusing {definition.executable} resolved inside the workspace"
            )
        return "missing", None, f"Executable not found: {definition.executable}"

    if requested == "container":
        if not definition.container_image or not definition.container_args:
            return "missing", None, f"No container adapter is available for {definition.name}"
        if not engine:
            if engine_unsafe:
                return "missing", None, (
                    f"Refusing {config['scan']['container_engine']} resolved "
                    "inside the workspace"
                )
            return (
                "missing",
                None,
                f"Container engine not found: {config['scan']['container_engine']}",
            )
        if bool(config["policy"].get("require_immutable_images", False)) and not _immutable_image(
            definition.container_image
        ):
            return "missing", None, f"Container image is not digest-pinned: {definition.name}"
        return "container", [], ""

    if native:
        return "native", [native, *definition.native_args], ""
    if definition.container_image and definition.container_args and engine:
        if bool(config["policy"].get("require_immutable_images", False)) and not _immutable_image(
            definition.container_image
        ):
            return "missing", None, f"Container image is not digest-pinned: {definition.name}"
        return "container", [], ""
    return "missing", None, f"No native executable or usable container adapter: {definition.name}"


def execute_scanner(
    config: dict[str, Any],
    definition: ScannerDefinition,
    *,
    target: Path,
    report_root: Path,
) -> ScannerResult:
    result = ScannerResult(
        scanner=definition.name,
        status="pending",
        report_path=definition.report_path,
        log_path=definition.log_path,
    )
    if str(config["scan"]["target_kind"]) not in definition.target_kinds:
        result.status = "skipped"
        result.error = "not applicable"
        result.report_path = None
        result.log_path = None
        return result

    mode, selected_command, error = select_execution(config, definition)
    result.execution = mode if mode != "missing" else ""
    if mode == "missing":
        result.status = "missing"
        result.error = error
        result.report_path = None
        result.log_path = None
        return result

    env = _safe_environment(config, report_root)
    tool_key = "trivy" if definition.name == "sbom" else definition.name
    if mode == "container":
        command = _container_command(config, definition, target, report_root)
        result.tool_version = str(config["tools"].get(tool_key, {}).get("version", ""))
    else:
        if selected_command is None:
            result.status = "error"
            result.error = "Native execution was selected without a command"
            result.report_path = None
            result.log_path = None
            return result
        command = selected_command
        result.tool_version = _tool_version(command[0], env)
        expected_version = str(config["tools"].get(tool_key, {}).get("version", ""))
        if not _version_matches(expected_version, result.tool_version):
            result.status = "error"
            result.error = (
                f"Expected {tool_key} {expected_version}, got "
                f"{result.tool_version or 'an unreadable version'}"
            )
            result.report_path = None
            result.log_path = None
            return result
    result.command_preview = tuple(
        "[REDACTED]" if sensitive_key(value) else value for value in command
    )
    definition.report_path.parent.mkdir(parents=True, exist_ok=True)
    definition.log_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        with definition.log_path.open("wb") as log:
            result.exit_code = _run_process(
                command,
                cwd=target if target.is_dir() else target.parent,
                stdout=log,
                timeout=int(config["scan"]["timeout_seconds"]),
                env=env,
            )
    except subprocess.TimeoutExpired:
        result.duration_seconds = time.monotonic() - started
        result.status = "timeout"
        result.error = f"Exceeded {config['scan']['timeout_seconds']} seconds"
        _discard_output(result.report_path)
        result.report_path = None
        _finish_log(config, result)
        return result
    except OSError as exc:
        result.duration_seconds = time.monotonic() - started
        result.status = "error"
        result.error = redact_text(str(exc), limit=1_000)
        _discard_output(result.report_path)
        result.report_path = None
        _finish_log(config, result)
        return result
    result.duration_seconds = time.monotonic() - started

    if result.scanner == "osv" and result.exit_code == 128:
        result.status = "skipped"
        result.error = "no supported packages found"
        _discard_output(result.report_path)
        result.report_path = None
        _finish_log(config, result)
        return result

    if result.exit_code not in {0, 1}:
        result.status = "error"
        result.error = f"Exited with code {result.exit_code}"
        _discard_output(result.report_path)
        result.report_path = None
        _finish_log(config, result)
        return result

    try:
        result.findings = parse_scanner_report(result, target)
        sanitize_raw_report(result, target)
    except Exception as exc:
        # Scanner reports are untrusted data. Any parser or sanitizer failure
        # must fail closed and remove both raw output and captured logs.
        result.status = "invalid-report"
        result.error = redact_text(str(exc), limit=1_000)
        _discard_output(result.report_path)
        result.report_path = None
        _finish_log(config, result)
        return result
    result.status = "findings" if result.findings else "clean"
    _finish_log(config, result)
    return result


def execute_all(
    config: dict[str, Any],
    definitions: list[ScannerDefinition],
    *,
    target: Path,
    report_root: Path,
) -> ScanOutcome:
    workers = min(int(config["scan"]["parallelism"]), max(1, len(definitions)))
    indexed: dict[str, int] = {
        definition.name: index for index, definition in enumerate(definitions)
    }
    results: list[ScannerResult] = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="secweaver") as pool:
        futures = {
            pool.submit(
                execute_scanner,
                config,
                definition,
                target=target,
                report_root=report_root,
            ): definition.name
            for definition in definitions
        }
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda item: indexed[item.scanner])
    findings = [
        finding
        for result in results
        for finding in result.findings
    ]
    findings.sort(
        key=lambda item: (
            item.scanner,
            item.severity,
            item.rule_id,
            item.location,
            item.fingerprint,
        )
    )
    decision = evaluate_policy(config, results, findings)

    required = set(config["scan"]["required_scanners"])
    infrastructure_failure = any(
        (
            result.status == "missing"
            and result.scanner in required
            and config["policy"]["missing_required_tool"] == "fail"
        )
        or (
            result.status in {"error", "timeout", "invalid-report"}
            and (result.scanner in required or result.scanner == "sbom")
            and config["policy"]["scanner_error"] == "fail"
        )
        for result in results
    )
    exit_code = 3 if infrastructure_failure else (0 if decision.passed else 1)
    return ScanOutcome(
        results=tuple(results),
        findings=tuple(findings),
        decision=decision,
        exit_code=exit_code,
    )
