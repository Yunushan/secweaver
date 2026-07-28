"""Conservative redaction helpers for logs and normalized reports."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_SENSITIVE_KEY = re.compile(
    r"(?:secret|token|password|passwd|credential|authorization|private[_-]?key|api[_-]?key)",
    re.IGNORECASE,
)
_INLINE_ASSIGNMENT = re.compile(
    r"(?i)\b(secret|token|password|passwd|api[_-]?key|authorization)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_BEARER = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
_URL_CREDENTIAL = re.compile(r"(https?://[^:/\s]+:)([^@\s]+)(@)")


def sensitive_key(name: str) -> bool:
    return bool(_SENSITIVE_KEY.search(name))


def redact_text(value: str, *, limit: int = 12_000) -> str:
    """Redact common inline credentials and bound diagnostic output."""
    text = value[-limit:]
    text = _INLINE_ASSIGNMENT.sub(r"\1\2[REDACTED]", text)
    text = _BEARER.sub(r"\1[REDACTED]", text)
    text = _URL_CREDENTIAL.sub(r"\1[REDACTED]\3", text)
    return text


def redact_structure(value: Any, *, key: str = "") -> Any:
    """Remove secret-bearing fields recursively without mutating the input."""
    if sensitive_key(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(k): redact_structure(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_structure(item, key=key) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_structure(item, key=key) for item in value)
    if isinstance(value, str):
        return redact_text(value, limit=4_000)
    return value
