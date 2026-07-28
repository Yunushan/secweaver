"""Command-line interface for the CI-neutral SecWeaver core."""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from secweaver import __version__
from secweaver.config import ConfigError, load_config
from secweaver.languages import coverage_row, detect_languages, load_catalog
from secweaver.models import ScannerResult
from secweaver.reports import (
    OUTPUT_MARKER_CONTENT,
    OUTPUT_MARKER_NAME,
    REPORT_ARTIFACT_PATHS,
    ReportError,
    now_utc,
    output_marker_is_valid,
    write_manifest,
    write_reports,
)
from secweaver.runner import _immutable_image, execute_all, select_execution
from secweaver.scanners import build_sbom_definition, build_scanner_definitions
from secweaver.util import is_safe_oci_reference

EXIT_PASS = 0
EXIT_POLICY = 1
EXIT_CONFIG = 2
EXIT_SCANNER = 3
EXIT_INCOMPLETE = 4


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secweaver",
        description="Portable, policy-driven security CI/CD orchestration.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    configuration = parser.add_mutually_exclusive_group()
    configuration.add_argument(
        "--config",
        action="append",
        default=[],
        metavar="FILE",
        help="TOML configuration or overlay; may be repeated.",
    )
    configuration.add_argument(
        "--no-project-config",
        action="store_true",
        help="Do not auto-load secweaver.toml from the scanned repository.",
    )
    parser.add_argument(
        "--profile",
        choices=("advisory", "balanced", "strict"),
        help="Lock the built-in policy profile after repository configuration.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run configured security scanners.")
    scan.add_argument("--target", default=None, help="Workspace-relative source directory.")
    scan.add_argument("--image", default=None, help="Scan this immutable OCI image reference.")
    scan.add_argument(
        "--report-dir",
        default=None,
        help="Workspace-relative dedicated output directory.",
    )
    scan.add_argument(
        "--execution",
        choices=("auto", "native", "container"),
        default=None,
    )
    scan.add_argument(
        "--scanner",
        action="append",
        choices=("gitleaks", "trivy", "opengrep", "osv"),
    )
    scan.add_argument("--offline", action="store_true", help="Disable online scanner behavior.")
    scan.add_argument("--no-history", action="store_true", help="Scan files, not full Git history.")
    scan.add_argument("--no-sbom", action="store_true", help="Do not generate CycloneDX SBOM.")
    scan.add_argument("--dry-run", action="store_true", help="Print a sanitized scan plan.")

    doctor = subparsers.add_parser("doctor", help="Check configuration and tool availability.")
    doctor.add_argument("--json", action="store_true", dest="as_json")

    validate = subparsers.add_parser("validate", help="Validate configuration and scan plan.")
    validate.add_argument("--target", default=None)

    languages = subparsers.add_parser("languages", help="Show or detect catalog languages.")
    languages.add_argument("--target", default=".")
    languages.add_argument("--all", action="store_true", help="Show all 50 catalog entries.")
    languages.add_argument("--json", action="store_true", dest="as_json")
    return parser


def _config_paths(
    values: list[str],
    root: Path,
    *,
    no_project_config: bool = False,
) -> list[Path]:
    if values:
        return [
            (Path(value) if Path(value).is_absolute() else root / value).resolve()
            for value in values
        ]
    if no_project_config:
        return []
    default = root / "secweaver.toml"
    return [default] if default.is_file() else []


def _overrides(args: argparse.Namespace) -> dict[str, Any]:
    scan: dict[str, Any] = {}
    for arg_name, key in (
        ("target", "target"),
        ("report_dir", "report_dir"),
        ("execution", "execution"),
    ):
        value = getattr(args, arg_name, None)
        if value is not None:
            scan[key] = value
    image = getattr(args, "image", None)
    if image is not None:
        scan["image"] = image
        scan["target_kind"] = "image"
    scanners = getattr(args, "scanner", None)
    if scanners:
        scan["enabled_scanners"] = scanners
        scan["required_scanners"] = scanners
    if getattr(args, "offline", False):
        scan["offline"] = True
    if getattr(args, "no_history", False):
        scan["history"] = False
    if getattr(args, "no_sbom", False):
        scan["generate_sbom"] = False
    return {"scan": scan} if scan else {}


def _load(args: argparse.Namespace, root: Path) -> dict[str, Any]:
    return load_config(
        _config_paths(
            args.config,
            root,
            no_project_config=args.no_project_config,
        ),
        overrides=_overrides(args),
        locked_profile=args.profile,
    )


def _within(root: Path, value: str, *, must_exist: bool) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ConfigError(f"Path must remain inside the workspace: {value}") from exc
    if must_exist and not resolved.is_dir():
        raise ConfigError(f"Source target is not a directory: {value}")
    return resolved


def _prepare_report_dir(root: Path, value: str) -> Path:
    report_root = _within(root, value, must_exist=False)
    if report_root == root.resolve():
        raise ConfigError("Report directory cannot be the workspace root")
    marker = report_root / OUTPUT_MARKER_NAME
    if report_root.exists():
        if report_root.is_symlink() or not report_root.is_dir():
            raise ConfigError("Report path must be a non-symlink directory")
        entries = list(report_root.iterdir())
        if entries:
            raise ConfigError(
                "Report directory must be empty; remove an earlier SecWeaver report "
                "explicitly or choose a new directory"
            )
    report_root.mkdir(parents=True, exist_ok=True)
    marker.write_bytes(OUTPUT_MARKER_CONTENT)
    return report_root


def _stage_relative(path: Path, stage_root: Path) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ConfigError(f"Staged scanner output is not a regular file: {path.name}")
    if path.lstat().st_nlink != 1:
        raise ConfigError(f"Staged scanner output must not be hard-linked: {path.name}")
    try:
        return path.resolve().relative_to(stage_root.resolve())
    except ValueError as exc:
        raise ConfigError("Scanner output escaped the private staging directory") from exc


def _validate_staged_outputs(
    stage_root: Path,
    results: list[ScannerResult],
) -> None:
    expected: set[str] = set()
    for result in results:
        for path in (result.report_path, result.log_path):
            if path is None:
                continue
            relative = _stage_relative(path, stage_root).as_posix()
            if relative not in REPORT_ARTIFACT_PATHS:
                raise ConfigError(f"Scanner selected an unsupported artifact path: {relative}")
            expected.add(relative)

    for path in stage_root.rglob("*"):
        relative = path.relative_to(stage_root)
        if relative.parts and relative.parts[0] == ".runtime-home":
            continue
        if path.is_symlink():
            raise ConfigError(
                f"Scanner created an unexpected staging symlink: {relative.as_posix()}"
            )
        if path.is_dir():
            continue
        if not path.is_file():
            raise ConfigError(
                f"Scanner created an unexpected special staging entry: "
                f"{relative.as_posix()}"
            )
        if relative.as_posix() not in expected:
            raise ConfigError(
                f"Scanner created an unexpected staging artifact: {relative.as_posix()}"
            )


def _publish_staged_outputs(
    stage_root: Path,
    report_root: Path,
    results: list[ScannerResult],
) -> None:
    for result in results:
        for attribute in ("report_path", "log_path"):
            source = getattr(result, attribute)
            if source is None:
                continue
            relative = _stage_relative(source, stage_root)
            destination = report_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            setattr(result, attribute, destination)


def _purge_unexpected_report_artifacts(
    report_root: Path,
    *,
    allowed_paths: frozenset[str] = REPORT_ARTIFACT_PATHS,
) -> list[str]:
    removed: list[str] = []
    marker_valid = output_marker_is_valid(report_root)
    allowed_directories = {
        parent.as_posix()
        for value in allowed_paths
        for parent in Path(value).parents
        if parent.as_posix() != "."
    }
    paths = sorted(
        report_root.rglob("*"),
        key=lambda item: len(item.relative_to(report_root).parts),
        reverse=True,
    )
    for path in paths:
        relative = path.relative_to(report_root).as_posix()
        marker_allowed = relative == OUTPUT_MARKER_NAME and marker_valid
        allowed = marker_allowed or relative in allowed_paths
        is_special = not path.is_dir() and not path.is_file()
        if path.is_symlink() or is_special or (path.is_file() and not allowed):
            removed.append(relative)
            path.unlink()
        elif path.is_dir():
            try:
                path.rmdir()
            except OSError:
                pass
            else:
                if relative not in allowed_directories:
                    removed.append(relative)
    if not marker_valid and OUTPUT_MARKER_NAME not in removed:
        removed.append(OUTPUT_MARKER_NAME)
    return removed


def _resolve_catalog(config: dict[str, Any], root: Path):
    configured = str(config["languages"].get("catalog", "")).strip()
    if not configured:
        return load_catalog()
    path = _within(root, configured, must_exist=False)
    if not path.is_file():
        raise ConfigError(f"Language catalog is not a file: {configured}")
    return load_catalog(path)


def _target(config: dict[str, Any], root: Path) -> Path:
    if str(config["scan"]["target_kind"]) == "image":
        image = str(config["scan"]["image"])
        if not is_safe_oci_reference(image):
            raise ConfigError("OCI image reference is empty, option-shaped, or malformed")
        if bool(config["policy"].get("require_immutable_images")) and not _immutable_image(
            image
        ):
            raise ConfigError("Strict policy requires the scan target image by sha256 digest")
        return root
    return _within(root, str(config["scan"]["target"]), must_exist=True)


def _definitions(config: dict[str, Any], root: Path, target: Path, report_root: Path):
    definitions = build_scanner_definitions(
        config,
        target=target,
        report_root=report_root,
        invocation_root=root,
    )
    if bool(config["scan"]["generate_sbom"]):
        definitions.append(
            build_sbom_definition(
                config,
                target=target,
                report_root=report_root,
                invocation_root=root,
            )
        )
    return definitions


def _validate_offline_layout(
    config: dict[str, Any],
    root: Path,
    report_root: Path,
) -> None:
    if not bool(config["scan"]["offline"]):
        return
    paths = {
        key: _within(root, str(config["offline"][key]), must_exist=True)
        for key in ("home_dir", "trivy_cache_dir", "osv_database_path")
    }
    for key, path in paths.items():
        if (
            path == report_root
            or path in report_root.parents
            or report_root in path.parents
        ):
            raise ConfigError(
                f"offline.{key} must not overlap the report directory"
            )
    trivy_cache = paths["trivy_cache_dir"]
    osv_database = paths["osv_database_path"]
    if (
        trivy_cache == osv_database
        or trivy_cache in osv_database.parents
        or osv_database in trivy_cache.parents
    ):
        raise ConfigError("Trivy and OSV offline database directories must be distinct")
    for key in ("trivy_cache_dir", "osv_database_path"):
        if not any(
            item.is_file() and not item.is_symlink()
            for item in paths[key].rglob("*")
        ):
            raise ConfigError(f"offline.{key} contains no regular database files")


def _command_scan(args: argparse.Namespace, root: Path) -> int:
    config = _load(args, root)
    target = _target(config, root)
    report_value = str(config["scan"]["report_dir"])
    configured_report_root = _within(root, report_value, must_exist=False)
    _validate_offline_layout(config, root, configured_report_root)
    if args.dry_run:
        definitions = _definitions(
            config,
            root,
            target,
            configured_report_root,
        )
        plan = {
            "profile": config["scan"]["profile"],
            "target_kind": config["scan"]["target_kind"],
            "execution": config["scan"]["execution"],
            "offline": config["scan"]["offline"],
            "scanners": [
                {
                    "name": definition.name,
                    "native_executable": definition.executable,
                    "container_available": bool(
                        definition.container_image and definition.container_args
                    ),
                    "report": definition.report_path.name,
                    "applicable": str(config["scan"]["target_kind"]) in definition.target_kinds,
                }
                for definition in definitions
            ],
        }
        print(json.dumps(plan, indent=2, sort_keys=True))
        return EXIT_PASS

    report_root = _prepare_report_dir(root, report_value)
    catalog = _resolve_catalog(config, root)
    languages = (
        detect_languages(
            target,
            catalog,
            excludes=tuple(str(value) for value in config["scan"]["excludes"]),
        )
        if str(config["scan"]["target_kind"]) == "source"
        else {}
    )
    started = now_utc()
    with tempfile.TemporaryDirectory(prefix="secweaver-scanner-") as directory:
        stage_root = Path(directory)
        definitions = _definitions(config, root, target, stage_root)
        outcome = execute_all(
            config,
            definitions,
            target=target,
            report_root=stage_root,
        )
        results = list(outcome.results)
        _validate_staged_outputs(stage_root, results)
        if not bool(config["reports"]["retain_raw"]):
            for result in results:
                if (
                    result.report_path is not None
                    and "raw" in result.report_path.parts
                ):
                    result.report_path = None
        unexpected = _purge_unexpected_report_artifacts(
            report_root,
            allowed_paths=frozenset(),
        )
        if unexpected:
            raise ConfigError(
                "Scanner wrote outside its private staging directory; "
                "unexpected output was removed"
            )
        _publish_staged_outputs(stage_root, report_root, results)
    finished = now_utc()

    write_reports(
        config,
        report_root=report_root,
        target=target,
        results=results,
        findings=list(outcome.findings),
        decision=outcome.decision,
        languages=languages,
        started_at=started,
        finished_at=finished,
    )
    try:
        write_manifest(report_root)
    except ReportError:
        _purge_unexpected_report_artifacts(report_root)
        raise
    verdict = "PASS" if outcome.decision.passed else "FAIL"
    counts = outcome.decision.counts
    print(
        f"SecWeaver {verdict}: {counts.get('TOTAL', 0)} finding(s); "
        f"critical={counts.get('CRITICAL', 0)}, high={counts.get('HIGH', 0)}, "
        f"medium={counts.get('MEDIUM', 0)}"
    )
    print(f"Reports: {report_root}")
    return outcome.exit_code


def _doctor_rows(
    config: dict[str, Any],
    *,
    root: Path,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = [
        {
            "component": "python",
            "available": sys.version_info >= (3, 11),
            "detail": platform.python_version(),
            "required": True,
        }
    ]
    engine_name = str(config["scan"]["container_engine"])
    engine_path = shutil.which(engine_name)
    rows.append(
        {
            "component": f"container:{engine_name}",
            "available": engine_path is not None,
            "detail": engine_path or "not found",
            "required": str(config["scan"]["execution"]) == "container",
        }
    )

    target = _target(config, root)
    report_root = _within(root, str(config["scan"]["report_dir"]), must_exist=False)
    _validate_offline_layout(config, root, report_root)
    required = set(config["scan"]["required_scanners"])
    for definition in _definitions(config, root, target, report_root):
        applicable = str(config["scan"]["target_kind"]) in definition.target_kinds
        mode, command, error = select_execution(config, definition)
        available = not applicable or mode != "missing"
        if not applicable:
            detail = f"not applicable to {config['scan']['target_kind']} targets"
        elif mode == "native" and command:
            detail = f"native: {command[0]}"
        elif mode == "container":
            detail = f"container: {definition.container_image}"
        else:
            detail = error
        rows.append(
            {
                "component": definition.name,
                "available": available,
                "detail": detail,
                "container": definition.container_image,
                "required": definition.name in required or definition.name == "sbom",
            }
        )
    return rows


def _command_doctor(args: argparse.Namespace, root: Path) -> int:
    config = _load(args, root)
    rows = _doctor_rows(config, root=root)
    if args.as_json:
        print(json.dumps({"host": platform.platform(), "checks": rows}, indent=2, sort_keys=True))
    else:
        print(f"SecWeaver {__version__} on {platform.platform()}")
        for row in rows:
            status = "ok" if row["available"] else "missing"
            print(f"[{status:7}] {row['component']}: {row['detail']}")
    missing = {
        row["component"]
        for row in rows
        if not row["available"] and row["required"]
    }
    return EXIT_INCOMPLETE if missing else EXIT_PASS


def _command_validate(args: argparse.Namespace, root: Path) -> int:
    config = _load(args, root)
    target = _target(config, root)
    report_root = _within(root, str(config["scan"]["report_dir"]), must_exist=False)
    _validate_offline_layout(config, root, report_root)
    _definitions(config, root, target, report_root)
    _resolve_catalog(config, root)
    print("Configuration and scan plan are valid.")
    return EXIT_PASS


def _command_languages(args: argparse.Namespace, root: Path) -> int:
    config = _load(args, root)
    catalog = _resolve_catalog(config, root)
    if args.all:
        value: Any = [coverage_row(language) for language in catalog]
    else:
        target = _within(root, args.target, must_exist=True)
        value = detect_languages(
            target,
            catalog,
            excludes=tuple(str(item) for item in config["scan"]["excludes"]),
        )
    if args.as_json:
        print(json.dumps(value, indent=2, sort_keys=True))
    elif isinstance(value, list):
        for item in value:
            print(f"T{item['tier']} {item['name']}: {', '.join(item['coverage'])}")
    elif value:
        for name, count in sorted(value.items(), key=lambda item: (-item[1], item[0])):
            print(f"{name}: {count}")
    else:
        print("No catalog languages detected.")
    return EXIT_PASS


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = Path.cwd().resolve()
    try:
        if args.command == "scan":
            return _command_scan(args, root)
        if args.command == "doctor":
            return _command_doctor(args, root)
        if args.command == "validate":
            return _command_validate(args, root)
        if args.command == "languages":
            return _command_languages(args, root)
    except (ConfigError, ValueError, OSError) as exc:
        print(f"SecWeaver configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    return EXIT_CONFIG
