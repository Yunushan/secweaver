"""Small, serializable domain models used by SecWeaver."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {
    "UNKNOWN": 0,
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


def normalize_severity(value: object) -> str:
    candidate = str(value or "UNKNOWN").strip().upper()
    aliases = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "WARN": "MEDIUM",
        "NOTE": "LOW",
        "MODERATE": "MEDIUM",
        "IMPORTANT": "HIGH",
    }
    candidate = aliases.get(candidate, candidate)
    return candidate if candidate in SEVERITY_ORDER else "UNKNOWN"


@dataclass(frozen=True, slots=True)
class Finding:
    scanner: str
    rule_id: str
    severity: str
    category: str
    message: str
    location: str = ""
    fingerprint: str = ""
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["references"] = list(self.references)
        return value


@dataclass(slots=True)
class ScannerResult:
    scanner: str
    status: str
    duration_seconds: float = 0.0
    exit_code: int | None = None
    report_path: Path | None = None
    log_path: Path | None = None
    error: str = ""
    execution: str = ""
    tool_version: str = ""
    command_preview: tuple[str, ...] = ()
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self, report_root: Path) -> dict[str, Any]:
        def relative(path: Path | None) -> str | None:
            if path is None:
                return None
            try:
                return path.resolve().relative_to(report_root.resolve()).as_posix()
            except ValueError:
                return path.name

        return {
            "scanner": self.scanner,
            "status": self.status,
            "duration_seconds": round(self.duration_seconds, 3),
            "exit_code": self.exit_code,
            "report_path": relative(self.report_path),
            "log_path": relative(self.log_path),
            "error": self.error,
            "execution": self.execution,
            "tool_version": self.tool_version,
            "findings_count": len(self.findings),
        }


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    passed: bool
    reasons: tuple[str, ...]
    counts: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "reasons": list(self.reasons),
            "counts": dict(sorted(self.counts.items())),
        }
