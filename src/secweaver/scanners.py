"""Typed scanner adapters. No configuration value is evaluated as shell code."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class ScannerDefinition:
    name: str
    executable: str
    native_args: tuple[str, ...]
    report_path: Path
    log_path: Path
    container_image: str = ""
    container_args: tuple[str, ...] = ()
    target_kinds: tuple[str, ...] = ("source",)
    report_format: str = "json"


def _tool(config: dict[str, Any], name: str) -> dict[str, Any]:
    return dict(config["tools"][name])


def _offline_directory(
    config: dict[str, Any],
    key: str,
    invocation_root: Path,
) -> Path:
    path = Path(str(config["offline"][key]))
    if not path.is_absolute():
        path = invocation_root / path
    path = path.resolve()
    if not path.is_dir():
        raise ValueError(f"Offline directory is missing: {key}={path}")
    return path


def _builtin_rule() -> Path:
    candidate = resources.files("secweaver").joinpath("data/rules/secweaver-baseline.yml")
    packaged = Path(str(candidate))
    if packaged.is_file():
        return packaged
    # Keep source checkouts usable without first building or installing a wheel.
    source_checkout = Path(__file__).resolve().parents[2] / "rules" / "secweaver-baseline.yml"
    return source_checkout


def scanner_controls_dir() -> Path:
    candidate = resources.files("secweaver").joinpath("data/scanner-controls")
    packaged = Path(str(candidate))
    if packaged.is_dir():
        return packaged
    raise ValueError("Bundled scanner controls are unavailable")


def _scanner_control(name: str) -> Path:
    path = (scanner_controls_dir() / name).resolve()
    if not path.is_file():
        raise ValueError(f"Bundled scanner control is unavailable: {name}")
    return path


def resolve_rule_paths(values: list[str], invocation_root: Path) -> tuple[Path, ...]:
    paths: list[Path] = []
    for value in values:
        is_builtin = value == "builtin:baseline"
        if is_builtin:
            path = _builtin_rule()
        else:
            path = Path(value)
            if not path.is_absolute():
                path = invocation_root / path
        path = path.resolve()
        if not is_builtin:
            try:
                path.relative_to(invocation_root.resolve())
            except ValueError as exc:
                raise ValueError(
                    f"SAST rule path must remain inside the workspace: {value}"
                ) from exc
        if not path.is_file():
            raise ValueError(f"SAST rule path is not a regular file: {path}")
        paths.append(path)
    if not paths:
        raise ValueError("At least one SAST rule path is required")
    return tuple(paths)


def _gitleaks(
    config: dict[str, Any],
    target: Path,
    report_root: Path,
    target_kind: str,
) -> ScannerDefinition:
    tool = _tool(config, "gitleaks")
    report = report_root / "raw" / "gitleaks.json"
    history = bool(config["scan"]["history"])
    mode = "git" if history else "dir"
    config_path = _scanner_control("gitleaks.toml")
    empty_ignore = _scanner_control("empty.ignore")
    native = (
        mode,
        f"--config={config_path}",
        f"--gitleaks-ignore-path={empty_ignore}",
        "--ignore-gitleaks-allow",
        "--report-format=json",
        f"--report-path={report}",
        "--redact=100",
        "--exit-code=0",
        "--no-banner",
        str(target),
    )
    container = (
        mode,
        "--config=/secweaver-controls/gitleaks.toml",
        "--gitleaks-ignore-path=/secweaver-controls/empty.ignore",
        "--ignore-gitleaks-allow",
        "--report-format=json",
        "--report-path=/reports/raw/gitleaks.json",
        "--redact=100",
        "--exit-code=0",
        "--no-banner",
        "/workspace",
    )
    return ScannerDefinition(
        name="gitleaks",
        executable=str(tool["command"]),
        native_args=native,
        report_path=report,
        log_path=report_root / "logs" / "gitleaks.log",
        container_image=str(tool.get("image", "")),
        container_args=container,
        target_kinds=("source",),
    )


def _trivy(
    config: dict[str, Any],
    target: Path,
    report_root: Path,
    target_kind: str,
    invocation_root: Path,
) -> ScannerDefinition:
    tool = _tool(config, "trivy")
    report = report_root / "raw" / "trivy.json"
    config_path = _scanner_control("trivy.yaml")
    empty_ignore = _scanner_control("empty.ignore")
    common = [
        f"--config={config_path}",
        f"--ignorefile={empty_ignore}",
        f"--secret-config={config_path}",
        "--show-suppressed",
        "--format=json",
        f"--output={report}",
        "--exit-code=0",
        "--disable-telemetry",
        "--scanners=vuln,misconfig,secret,license",
        "--severity=UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
    ]
    container_common = [
        "--config=/secweaver-controls/trivy.yaml",
        "--ignorefile=/secweaver-controls/empty.ignore",
        "--secret-config=/secweaver-controls/trivy.yaml",
        "--show-suppressed",
        "--format=json",
        "--output=/reports/raw/trivy.json",
        "--exit-code=0",
        "--disable-telemetry",
        "--scanners=vuln,misconfig,secret,license",
        "--severity=UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
    ]
    if bool(config["scan"]["offline"]):
        cache = _offline_directory(config, "trivy_cache_dir", invocation_root)
        common.extend(
            [
                f"--cache-dir={cache}",
                "--offline-scan",
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
            ]
        )
    for excluded in config["scan"]["excludes"]:
        common.extend(["--skip-dirs", str(excluded)])
        container_common.extend(["--skip-dirs", str(excluded)])

    if target_kind == "image":
        native = ("image", *common, str(config["scan"]["image"]))
        container = ("image", *container_common, str(config["scan"]["image"]))
    else:
        native = ("filesystem", *common, str(target))
        container = ("filesystem", *container_common, "/workspace")
    return ScannerDefinition(
        name="trivy",
        executable=str(tool["command"]),
        native_args=tuple(native),
        report_path=report,
        log_path=report_root / "logs" / "trivy.log",
        container_image=str(tool.get("image", "")),
        container_args=tuple(container),
        target_kinds=("source", "image"),
    )


def _opengrep(
    config: dict[str, Any],
    target: Path,
    report_root: Path,
    target_kind: str,
    invocation_root: Path,
) -> ScannerDefinition:
    tool = _tool(config, "opengrep")
    report = report_root / "raw" / "opengrep.sarif"
    rule_paths = resolve_rule_paths(
        list(config["scan"]["sast_rule_paths"]),
        invocation_root,
    )
    empty_ignore = _scanner_control("empty.ignore")
    args: list[str] = [
        "scan",
        "--metrics=off",
        "--disable-nosem",
        "--no-git-ignore",
        f"--semgrepignore-filename={empty_ignore}",
        f"--sarif-output={report}",
    ]
    for rule_path in rule_paths:
        args.extend(["--config", str(rule_path)])
    for excluded in config["scan"]["excludes"]:
        args.extend(["--exclude", str(excluded)])
    args.append(str(target))
    return ScannerDefinition(
        name="opengrep",
        executable=str(tool["command"]),
        native_args=tuple(args),
        report_path=report,
        log_path=report_root / "logs" / "opengrep.log",
        container_image=str(tool.get("image", "")),
        container_args=(),
        target_kinds=("source",),
        report_format="sarif",
    )


def _osv(
    config: dict[str, Any],
    target: Path,
    report_root: Path,
    target_kind: str,
    invocation_root: Path,
) -> ScannerDefinition:
    tool = _tool(config, "osv")
    report = report_root / "raw" / "osv.json"
    config_path = _scanner_control("osv-scanner.toml")
    if target_kind == "image":
        native: tuple[str, ...] = (
            "scan",
            "image",
            f"--config={config_path}",
            "--format=json",
            f"--output-file={report}",
            str(config["scan"]["image"]),
        )
        container: tuple[str, ...] = ()
    else:
        native = (
            "scan",
            "source",
            "--recursive",
            "--no-ignore",
            f"--config={config_path}",
            "--format=json",
            f"--output-file={report}",
            str(target),
        )
        container = (
            "scan",
            "source",
            "--recursive",
            "--no-ignore",
            "--config=/secweaver-controls/osv-scanner.toml",
            "--format=json",
            "--output-file=/reports/raw/osv.json",
            "/workspace",
        )
    if bool(config["scan"]["offline"]):
        database = _offline_directory(config, "osv_database_path", invocation_root)
        native = (
            *native[:-1],
            "--offline-vulnerabilities",
            f"--local-db-path={database}",
            native[-1],
        )
    return ScannerDefinition(
        name="osv",
        executable=str(tool["command"]),
        native_args=native,
        report_path=report,
        log_path=report_root / "logs" / "osv.log",
        container_image=str(tool.get("image", "")),
        container_args=container,
        target_kinds=("source", "image"),
    )


def build_scanner_definitions(
    config: dict[str, Any],
    *,
    target: Path,
    report_root: Path,
    invocation_root: Path,
) -> list[ScannerDefinition]:
    target_kind = str(config["scan"]["target_kind"])
    builders = {
        "gitleaks": lambda: _gitleaks(config, target, report_root, target_kind),
        "trivy": lambda: _trivy(
            config,
            target,
            report_root,
            target_kind,
            invocation_root,
        ),
        "opengrep": lambda: _opengrep(
            config,
            target,
            report_root,
            target_kind,
            invocation_root,
        ),
        "osv": lambda: _osv(
            config,
            target,
            report_root,
            target_kind,
            invocation_root,
        ),
    }
    definitions: list[ScannerDefinition] = []
    for name in config["scan"]["enabled_scanners"]:
        definition = builders[name]()
        definitions.append(definition)
    return definitions


def build_sbom_definition(
    config: dict[str, Any],
    *,
    target: Path,
    report_root: Path,
    invocation_root: Path,
) -> ScannerDefinition:
    tool = _tool(config, "trivy")
    report = report_root / "sbom.cdx.json"
    target_kind = str(config["scan"]["target_kind"])
    config_path = _scanner_control("trivy.yaml")
    empty_ignore = _scanner_control("empty.ignore")
    if target_kind == "image":
        native = (
            "image",
            f"--config={config_path}",
            f"--ignorefile={empty_ignore}",
            "--format=cyclonedx",
            f"--output={report}",
            str(config["scan"]["image"]),
        )
        container = (
            "image",
            "--config=/secweaver-controls/trivy.yaml",
            "--ignorefile=/secweaver-controls/empty.ignore",
            "--format=cyclonedx",
            "--output=/reports/sbom.cdx.json",
            str(config["scan"]["image"]),
        )
    else:
        native = (
            "filesystem",
            f"--config={config_path}",
            f"--ignorefile={empty_ignore}",
            "--format=cyclonedx",
            f"--output={report}",
            str(target),
        )
        container = (
            "filesystem",
            "--config=/secweaver-controls/trivy.yaml",
            "--ignorefile=/secweaver-controls/empty.ignore",
            "--format=cyclonedx",
            "--output=/reports/sbom.cdx.json",
            "/workspace",
        )
    if bool(config["scan"]["offline"]):
        cache = _offline_directory(config, "trivy_cache_dir", invocation_root)
        native = (
            *native[:-1],
            f"--cache-dir={cache}",
            "--offline-scan",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            native[-1],
        )
    return ScannerDefinition(
        name="sbom",
        executable=str(tool["command"]),
        native_args=native,
        report_path=report,
        log_path=report_root / "logs" / "sbom.log",
        container_image=str(tool.get("image", "")),
        container_args=container,
        target_kinds=("source", "image"),
        report_format="cyclonedx",
    )
