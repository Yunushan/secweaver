"""Shared inert fixtures and constructors for SecWeaver tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from secweaver.models import ScannerResult

FIXTURE_ROOT = Path(__file__).parent / "fixtures"
REPORT_FIXTURES = FIXTURE_ROOT / "reports"
CONFIG_FIXTURES = FIXTURE_ROOT / "config"

# Deliberately low-entropy and visibly synthetic. It is not shaped like a real
# credential and should never be used outside redaction tests.
SYNTHETIC_CANARY = "sw-fixture-canary-0007"


def load_json_fixture(name: str) -> Any:
    return json.loads((REPORT_FIXTURES / name).read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def scanner_result(
    scanner: str,
    *,
    status: str = "clean",
    report_path: Path | None = None,
    error: str = "",
) -> ScannerResult:
    return ScannerResult(
        scanner=scanner,
        status=status,
        report_path=report_path,
        error=error,
    )
