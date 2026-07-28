"""Normalize scanner reports, evaluate policy, and emit portable artifacts."""

from __future__ import annotations

import json
import platform
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secweaver import __version__
from secweaver.models import (
    SEVERITY_ORDER,
    Finding,
    PolicyDecision,
    ScannerResult,
    normalize_severity,
)
from secweaver.redact import redact_structure, redact_text
from secweaver.util import (
    atomic_write_json,
    atomic_write_text,
    safe_relative,
    sha256_file,
    sha256_text,
)


class ReportError(ValueError):
    """Raised when a scanner report is absent, malformed, or unsafe."""


OUTPUT_MARKER_NAME = ".secweaver-output"
OUTPUT_MARKER_CONTENT = b"SecWeaver generated output\n"


REPORT_ARTIFACT_PATHS = frozenset(
    {
        "junit.xml",
        "logs/gitleaks.log",
        "logs/opengrep.log",
        "logs/osv.log",
        "logs/sbom.log",
        "logs/trivy.log",
        "raw/gitleaks.json",
        "raw/opengrep.sarif",
        "raw/osv.json",
        "raw/trivy.json",
        "report-manifest.json",
        "results.sarif",
        "sbom.cdx.json",
        "summary.json",
        "summary.md",
        "verdict.json",
    }
)


def output_marker_is_valid(report_root: Path) -> bool:
    marker = report_root / OUTPUT_MARKER_NAME
    try:
        stat = marker.lstat()
    except OSError:
        return False
    if marker.is_symlink() or not marker.is_file():
        return False
    if stat.st_nlink != 1 or stat.st_size != len(OUTPUT_MARKER_CONTENT):
        return False
    try:
        return marker.read_bytes() == OUTPUT_MARKER_CONTENT
    except OSError:
        return False


def _load_json(path: Path, *, max_bytes: int = 200 * 1024 * 1024) -> Any:
    try:
        stat = path.lstat()
    except FileNotFoundError as exc:
        raise ReportError(f"Scanner did not create {path.name}") from exc
    if path.is_symlink() or not path.is_file():
        raise ReportError(f"Scanner report is not a regular file: {path.name}")
    if stat.st_size > max_bytes:
        raise ReportError(f"Scanner report exceeds {max_bytes} bytes: {path.name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReportError(f"Scanner report is not valid JSON: {path.name}: {exc}") from exc


def _location(path: object, line: object, target: Path) -> str:
    value = str(path or "")
    if value:
        candidate = Path(value)
        if candidate.is_absolute():
            try:
                value = candidate.resolve().relative_to(target.resolve()).as_posix()
            except ValueError:
                value = candidate.name
        value = value.replace("\\", "/").lstrip("/")
    try:
        line_number = int(line)
    except (TypeError, ValueError):
        line_number = 0
    return f"{value}:{line_number}" if value and line_number > 0 else value


def _fingerprint(scanner: str, rule_id: str, location: str, message: str, value: object) -> str:
    if value:
        return str(value)
    return sha256_text("\x00".join((scanner, rule_id, location, message)))


def _parse_gitleaks(data: Any, target: Path) -> list[Finding]:
    if not isinstance(data, list):
        raise ReportError("Gitleaks report root must be an array")
    findings: list[Finding] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("RuleID") or "gitleaks.secret")
        location = _location(item.get("File"), item.get("StartLine"), target)
        message = redact_text(
            str(item.get("Description") or "Potential secret detected"),
            limit=500,
        )
        findings.append(
            Finding(
                scanner="gitleaks",
                rule_id=rule_id,
                severity="HIGH",
                category="secret",
                message=message,
                location=location,
                fingerprint=_fingerprint(
                    "gitleaks",
                    rule_id,
                    location,
                    message,
                    item.get("Fingerprint"),
                ),
            )
        )
    return findings


def _sarif_rule_levels(run: dict[str, Any]) -> dict[str, str]:
    levels: dict[str, str] = {}
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    if not isinstance(rules, list):
        return levels
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rule_id = str(rule.get("id") or "")
        level = rule.get("defaultConfiguration", {}).get("level", "warning")
        levels[rule_id] = normalize_severity(level)
    return levels


def _parse_sarif(data: Any, target: Path, scanner: str) -> list[Finding]:
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
        raise ReportError(f"{scanner} SARIF report is missing runs")
    findings: list[Finding] = []
    for run in data["runs"]:
        if not isinstance(run, dict):
            continue
        levels = _sarif_rule_levels(run)
        results = run.get("results", [])
        if not isinstance(results, list):
            continue
        for item in results:
            if not isinstance(item, dict):
                continue
            rule_id = str(item.get("ruleId") or "unknown-rule")
            message_value = item.get("message", {})
            message = (
                str(message_value.get("text") or "Static analysis finding")
                if isinstance(message_value, dict)
                else str(message_value)
            )
            locations = item.get("locations", [])
            physical: dict[str, Any] = {}
            if isinstance(locations, list) and locations and isinstance(locations[0], dict):
                physical = locations[0].get("physicalLocation", {}) or {}
            artifact = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
            region = physical.get("region", {}) if isinstance(physical, dict) else {}
            location = _location(
                artifact.get("uri") if isinstance(artifact, dict) else "",
                region.get("startLine") if isinstance(region, dict) else 0,
                target,
            )
            fingerprints = item.get("fingerprints", {})
            fingerprint = ""
            if isinstance(fingerprints, dict) and fingerprints:
                fingerprint = str(next(iter(fingerprints.values())))
            findings.append(
                Finding(
                    scanner=scanner,
                    rule_id=rule_id,
                    severity=normalize_severity(item.get("level") or levels.get(rule_id)),
                    category="sast",
                    message=redact_text(message, limit=1_000),
                    location=location,
                    fingerprint=_fingerprint(
                        scanner,
                        rule_id,
                        location,
                        message,
                        fingerprint,
                    ),
                )
            )
    return findings


def _parse_trivy(data: Any, target: Path) -> list[Finding]:
    if not isinstance(data, dict):
        raise ReportError("Trivy report root must contain a Results array")
    results = data.get("Results")
    if "Results" not in data:
        recognized_empty_envelope = (
            isinstance(data.get("SchemaVersion"), int)
            and data["SchemaVersion"] >= 1
            and isinstance(data.get("ArtifactName"), str)
            and isinstance(data.get("ArtifactType"), str)
            and ("Trivy" in data or "CreatedAt" in data)
        )
        if not recognized_empty_envelope:
            raise ReportError(
                "Trivy report without Results must contain a recognized report envelope"
            )
        results = []
    elif not isinstance(results, list):
        raise ReportError("Trivy report root must contain a Results array")
    findings: list[Finding] = []
    modified_count = 0
    groups = (
        ("Vulnerabilities", "vulnerability", "VulnerabilityID", "PkgName"),
        ("Misconfigurations", "misconfiguration", "ID", "Title"),
        ("Secrets", "secret", "RuleID", "Title"),
        ("Licenses", "license", "Name", "Category"),
    )
    for result in results:
        if not isinstance(result, dict):
            continue
        modified = result.get("ExperimentalModifiedFindings", [])
        if not isinstance(modified, list):
            raise ReportError("Trivy suppressed-finding data must be an array")
        modified_count += len(modified)
        result_target = result.get("Target", "")
        for key, category, rule_key, message_key in groups:
            items = result.get(key, [])
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                rule_id = str(item.get(rule_key) or f"trivy.{category}")
                message = str(
                    item.get("Title")
                    or item.get("Description")
                    or item.get(message_key)
                    or f"Trivy {category} finding"
                )
                line = item.get("StartLine") or item.get("Line") or 0
                severity = "HIGH" if category == "secret" else item.get("Severity")
                references: tuple[str, ...] = ()
                primary = item.get("PrimaryURL")
                if isinstance(primary, str) and primary.startswith(("https://", "http://")):
                    references = (primary,)
                location = _location(result_target, line, target)
                findings.append(
                    Finding(
                        scanner="trivy",
                        rule_id=rule_id,
                        severity=normalize_severity(severity),
                        category=category,
                        message=redact_text(message, limit=1_000),
                        location=location,
                        fingerprint=_fingerprint(
                            "trivy",
                            rule_id,
                            location,
                            message,
                            item.get("PkgIdentifier", {}).get("PURL")
                            if isinstance(item.get("PkgIdentifier"), dict)
                            else "",
                        ),
                        references=references,
                    )
                )
    root_modified = data.get("ExperimentalModifiedFindings", [])
    if not isinstance(root_modified, list):
        raise ReportError("Trivy suppressed-finding data must be an array")
    modified_count += len(root_modified)
    if modified_count:
        message = (
            f"Trivy reported {modified_count} suppressed or modified finding(s); "
            "repository-local suppression is not trusted"
        )
        findings.append(
            Finding(
                scanner="trivy",
                rule_id="trivy.suppressed-finding",
                severity="HIGH",
                category="misconfiguration",
                message=message,
                fingerprint=_fingerprint(
                    "trivy",
                    "trivy.suppressed-finding",
                    "",
                    message,
                    f"suppressed:{modified_count}",
                ),
            )
        )
    return findings


def _numeric_severity(value: object) -> str:
    try:
        numeric = float(str(value).strip())
    except (TypeError, ValueError):
        return "UNKNOWN"
    if numeric >= 9:
        return "CRITICAL"
    if numeric >= 7:
        return "HIGH"
    if numeric >= 4:
        return "MEDIUM"
    if numeric > 0:
        return "LOW"
    return "UNKNOWN"


def _osv_severity(
    vulnerabilities: list[dict[str, Any]],
    *,
    group_max: object = "",
) -> str:
    candidates: list[str] = []
    if str(group_max).strip():
        candidate = _numeric_severity(group_max)
        if candidate == "UNKNOWN":
            candidate = normalize_severity(group_max)
        if candidate != "UNKNOWN":
            candidates.append(candidate)
    for vulnerability in vulnerabilities:
        database = vulnerability.get("database_specific", {})
        if isinstance(database, dict) and database.get("severity"):
            candidates.append(normalize_severity(database["severity"]))
        for score in vulnerability.get("severity", []) or []:
            if not isinstance(score, dict):
                continue
            value = str(score.get("score", ""))
            candidate = _numeric_severity(value)
            if candidate != "UNKNOWN":
                candidates.append(candidate)
            elif value:
                # OSV commonly emits a CVSS vector while its group contains the
                # computed maximum. If a non-empty vector arrives without that
                # maximum, fail closed rather than silently treating it as
                # non-blocking UNKNOWN.
                candidates.append("HIGH")
    return max(candidates, key=lambda item: SEVERITY_ORDER[item], default="UNKNOWN")


def _parse_osv(data: Any, target: Path) -> list[Finding]:
    if (
        not isinstance(data, dict)
        or "results" not in data
        or not isinstance(data["results"], list)
    ):
        raise ReportError("OSV report root must contain a results array")
    findings: list[Finding] = []
    for result in data.get("results", []):
        if not isinstance(result, dict):
            continue
        source = result.get("source", {})
        source_path = source.get("path", "") if isinstance(source, dict) else ""
        for item in result.get("packages", []) or []:
            if not isinstance(item, dict):
                continue
            package = item.get("package", {})
            name = (
                str(package.get("name") or "unknown-package")
                if isinstance(package, dict)
                else ""
            )
            version = str(package.get("version") or "") if isinstance(package, dict) else ""
            vulnerabilities = [
                value
                for value in item.get("vulnerabilities", []) or []
                if isinstance(value, dict)
            ]
            groups = item.get("groups", []) or []
            identifiers: list[tuple[str, tuple[str, ...], object]] = []
            if isinstance(groups, list) and groups:
                for group in groups:
                    ids = group.get("ids", []) if isinstance(group, dict) else []
                    if ids:
                        identifiers.append(
                            (
                                str(ids[0]),
                                tuple(str(value) for value in ids),
                                group.get("max_severity", ""),
                            )
                        )
            else:
                for vulnerability in vulnerabilities:
                    vuln_id = str(vulnerability.get("id") or "osv.unknown")
                    identifiers.append((vuln_id, (vuln_id,), ""))

            by_id = {
                str(vulnerability.get("id")): vulnerability
                for vulnerability in vulnerabilities
                if vulnerability.get("id")
            }
            for rule_id, aliases, group_max in identifiers:
                relevant = [by_id[value] for value in aliases if value in by_id]
                message = redact_text(
                    f"{name}@{version} is affected by {', '.join(aliases)}",
                    limit=1_000,
                )
                location = _location(source_path, 0, target)
                findings.append(
                    Finding(
                        scanner="osv",
                        rule_id=rule_id,
                        severity=_osv_severity(relevant, group_max=group_max),
                        category="vulnerability",
                        message=message,
                        location=location,
                        fingerprint=_fingerprint(
                            "osv",
                            rule_id,
                            location,
                            message,
                            "",
                        ),
                        references=(f"https://osv.dev/{rule_id}",),
                    )
                )
    return findings


def _validate_cyclonedx(data: Any) -> None:
    if not isinstance(data, dict):
        raise ReportError("CycloneDX SBOM root must be an object")
    if data.get("bomFormat") != "CycloneDX":
        raise ReportError("SBOM does not declare bomFormat=CycloneDX")
    if not isinstance(data.get("specVersion"), str) or not data["specVersion"]:
        raise ReportError("CycloneDX SBOM is missing specVersion")
    if not isinstance(data.get("components"), list):
        raise ReportError("CycloneDX SBOM must contain a components array")


def parse_scanner_report(result: ScannerResult, target: Path) -> list[Finding]:
    if result.report_path is None:
        raise ReportError(f"{result.scanner} has no report path")
    data = _load_json(result.report_path)
    if result.scanner == "gitleaks":
        return _parse_gitleaks(data, target)
    if result.scanner == "trivy":
        return _parse_trivy(data, target)
    if result.scanner == "opengrep":
        return _parse_sarif(data, target, "opengrep")
    if result.scanner == "osv":
        return _parse_osv(data, target)
    if result.scanner == "sbom":
        _validate_cyclonedx(data)
        return []
    raise ReportError(f"No parser registered for {result.scanner}")


def _sanitize_paths(value: Any, target: Path) -> Any:
    if isinstance(value, dict):
        return {str(key): _sanitize_paths(item, target) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_paths(item, target) for item in value]
    if isinstance(value, str):
        target_values = {str(target), str(target.resolve()), str(target).replace("\\", "/")}
        sanitized = value
        for candidate in sorted(target_values, key=len, reverse=True):
            if candidate:
                sanitized = sanitized.replace(candidate, ".")
        return sanitized
    return value


def sanitize_raw_report(result: ScannerResult, target: Path) -> None:
    if result.report_path is None or result.scanner == "sbom":
        return
    data = _load_json(result.report_path)
    if result.scanner == "gitleaks" and isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                for key in ("Secret", "Match", "Line", "Author", "Email", "Message"):
                    if key in item:
                        item[key] = "[REDACTED]"
    if result.scanner == "trivy" and isinstance(data, dict):
        for scan_result in data.get("Results", []) or []:
            if not isinstance(scan_result, dict):
                continue
            for item in scan_result.get("Secrets", []) or []:
                if isinstance(item, dict):
                    for key in ("Match", "Code", "Line"):
                        if key in item:
                            item[key] = "[REDACTED]"
    if result.scanner == "opengrep":
        for run in data.get("runs", []) if isinstance(data, dict) else []:
            for item in run.get("results", []) if isinstance(run, dict) else []:
                for location in item.get("locations", []) if isinstance(item, dict) else []:
                    region = (
                        location.get("physicalLocation", {}).get("region", {})
                        if isinstance(location, dict)
                        else {}
                    )
                    if isinstance(region, dict):
                        region.pop("snippet", None)
    data = _sanitize_paths(redact_structure(data), target)
    atomic_write_json(result.report_path, data)


def evaluate_policy(
    config: dict[str, Any],
    results: list[ScannerResult],
    findings: list[Finding],
) -> PolicyDecision:
    policy = config["policy"]
    fail_severities = {
        str(value).upper() for value in policy.get("fail_on_severities", [])
    }
    fail_categories = {
        str(value).lower() for value in policy.get("fail_on_categories", [])
    }
    required = set(config["scan"].get("required_scanners", []))
    reasons: list[str] = []

    for result in results:
        if result.status == "skipped" and result.error == "not applicable":
            continue
        if result.status == "missing" and result.scanner in required:
            if policy["missing_required_tool"] == "fail":
                reasons.append(f"Required scanner unavailable: {result.scanner}")
        elif (
            result.status in {"error", "timeout", "invalid-report"}
            and policy["scanner_error"] == "fail"
        ):
            reasons.append(f"Scanner did not complete successfully: {result.scanner}")

    blocked = [
        finding
        for finding in findings
        if finding.severity in fail_severities
        or finding.category.lower() in fail_categories
    ]
    if blocked:
        reasons.append(f"{len(blocked)} finding(s) matched the blocking policy")

    max_findings = int(policy.get("max_findings", -1))
    if max_findings >= 0 and len(findings) > max_findings:
        reasons.append(
            f"Total findings {len(findings)} exceed policy maximum {max_findings}"
        )

    counts = Counter(finding.severity for finding in findings)
    counts["TOTAL"] = len(findings)
    return PolicyDecision(
        passed=not reasons,
        reasons=tuple(reasons),
        counts=dict(counts),
    )


def _create_sarif(findings: list[Finding]) -> dict[str, Any]:
    level_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
        "UNKNOWN": "warning",
    }
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        rule_key = f"{finding.scanner}/{finding.rule_id}"
        rules.setdefault(
            rule_key,
            {
                "id": rule_key,
                "shortDescription": {"text": finding.message[:200]},
                "properties": {
                    "category": finding.category,
                    "scanner": finding.scanner,
                },
            },
        )
        location: dict[str, Any] = {}
        if finding.location:
            path, separator, line = finding.location.rpartition(":")
            uri = path if separator and line.isdigit() else finding.location
            region = {"startLine": int(line)} if separator and line.isdigit() else {}
            physical: dict[str, Any] = {
                "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"}
            }
            if region:
                physical["region"] = region
            location = {"physicalLocation": physical}
        result: dict[str, Any] = {
            "ruleId": rule_key,
            "level": level_map[finding.severity],
            "message": {"text": finding.message},
            "fingerprints": {"secweaver/v1": finding.fingerprint},
            "properties": {
                "severity": finding.severity,
                "category": finding.category,
            },
        }
        if location:
            result["locations"] = [location]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecWeaver",
                        "semanticVersion": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _markdown(
    decision: PolicyDecision,
    results: list[ScannerResult],
    findings: list[Finding],
    languages: dict[str, int],
) -> str:
    verdict = "PASS" if decision.passed else "FAIL"
    lines = [
        "# SecWeaver security report",
        "",
        f"**Verdict:** {verdict}",
        "",
        "## Scanner status",
        "",
        "| Scanner | Status | Findings | Duration |",
        "| --- | --- | ---: | ---: |",
    ]
    for result in results:
        lines.append(
            f"| {result.scanner} | {result.status} | {len(result.findings)} | "
            f"{result.duration_seconds:.2f}s |"
        )
    lines.extend(["", "## Finding counts", ""])
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"):
        lines.append(f"- {severity}: {decision.counts.get(severity, 0)}")
    if decision.reasons:
        lines.extend(["", "## Blocking reasons", ""])
        lines.extend(f"- {reason}" for reason in decision.reasons)
    if languages:
        lines.extend(["", "## Detected languages", ""])
        lines.extend(
            f"- {name}: {count} file(s)"
            for name, count in sorted(languages.items(), key=lambda item: (-item[1], item[0]))
        )
    lines.extend(
        [
            "",
            "This summary is sanitized. Raw artifacts may contain private package "
            "and path metadata; "
            "apply access controls and short retention.",
            "",
        ]
    )
    return "\n".join(lines)


def _junit(decision: PolicyDecision, results: list[ScannerResult]) -> str:
    suite = ET.Element(
        "testsuite",
        {
            "name": "SecWeaver",
            "tests": str(len(results) + 1),
            "failures": str(0 if decision.passed else 1),
            "errors": str(
                sum(
                    result.status in {"error", "timeout", "invalid-report", "missing"}
                    for result in results
                )
            ),
        },
    )
    for result in results:
        case = ET.SubElement(
            suite,
            "testcase",
            {
                "name": result.scanner,
                "classname": "secweaver.scanners",
                "time": f"{result.duration_seconds:.3f}",
            },
        )
        if result.status in {"error", "timeout", "invalid-report", "missing"}:
            node = ET.SubElement(case, "error", {"message": result.status})
            node.text = redact_text(result.error, limit=2_000)
        elif result.status == "skipped":
            ET.SubElement(case, "skipped", {"message": result.error or "skipped"})
    policy_case = ET.SubElement(
        suite,
        "testcase",
        {"name": "policy", "classname": "secweaver.policy", "time": "0"},
    )
    if not decision.passed:
        failure = ET.SubElement(policy_case, "failure", {"message": "Security policy failed"})
        failure.text = "\n".join(decision.reasons)
    ET.indent(suite, space="  ")
    return ET.tostring(suite, encoding="unicode", xml_declaration=True) + "\n"


def write_reports(
    config: dict[str, Any],
    *,
    report_root: Path,
    target: Path,
    results: list[ScannerResult],
    findings: list[Finding],
    decision: PolicyDecision,
    languages: dict[str, int],
    started_at: datetime,
    finished_at: datetime,
) -> dict[str, Any]:
    summary = {
        "schema_version": "1.0",
        "secweaver_version": __version__,
        "project": {"name": str(config["project"]["name"])},
        "run": {
            "started_at": started_at.astimezone(UTC).isoformat(),
            "finished_at": finished_at.astimezone(UTC).isoformat(),
            "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
            "profile": str(config["scan"]["profile"]),
            "target_kind": str(config["scan"]["target_kind"]),
            "execution": str(config["scan"]["execution"]),
            "offline": bool(config["scan"]["offline"]),
            "host": {
                "os": platform.system(),
                "release": platform.release(),
                "architecture": platform.machine(),
                "python": platform.python_version(),
            },
        },
        "languages": dict(
            sorted(languages.items(), key=lambda item: (-item[1], item[0]))
        ),
        "scanners": [result.to_dict(report_root) for result in results],
        "findings": [finding.to_dict() for finding in findings],
        "policy": decision.to_dict(),
    }
    summary = redact_structure(summary)
    atomic_write_json(report_root / "summary.json", summary)
    atomic_write_json(
        report_root / "verdict.json",
        {
            "schema_version": "1.0",
            "passed": decision.passed,
            "exit_code": 0 if decision.passed else 1,
            "reasons": list(decision.reasons),
            "counts": decision.counts,
        },
    )
    atomic_write_text(
        report_root / "summary.md",
        _markdown(decision, results, findings, languages),
    )
    atomic_write_text(report_root / "junit.xml", _junit(decision, results))
    atomic_write_json(
        report_root / "results.sarif",
        redact_structure(_create_sarif(findings)),
    )
    return summary


def write_manifest(report_root: Path) -> dict[str, Any]:
    if not output_marker_is_valid(report_root):
        raise ReportError("Report output ownership marker is missing or invalid")
    files: list[dict[str, Any]] = []
    for path in sorted(report_root.rglob("*")):
        if path.is_symlink():
            raise ReportError(
                f"Report output contains an unexpected symlink: "
                f"{safe_relative(path, report_root)}"
            )
        if not path.is_file():
            continue
        relative = safe_relative(path, report_root)
        if relative == OUTPUT_MARKER_NAME:
            continue
        if relative not in REPORT_ARTIFACT_PATHS:
            raise ReportError(f"Unexpected report artifact: {relative}")
        if relative == "report-manifest.json":
            continue
        digest = sha256_file(path)
        files.append(
            {
                "path": relative,
                "sha256": digest,
                "size_bytes": path.stat().st_size,
            }
        )
    manifest = {
        "schema_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "files": files,
    }
    atomic_write_json(report_root / "report-manifest.json", manifest)
    return manifest


def now_utc() -> datetime:
    return datetime.now(UTC)
