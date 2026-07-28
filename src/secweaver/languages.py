"""Language catalog loading and deterministic repository detection."""

from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class Language:
    name: str
    tier: int
    extensions: tuple[str, ...]
    filenames: tuple[str, ...]
    ecosystems: tuple[str, ...]
    semantic_sast: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Language:
        return cls(
            name=str(value["name"]),
            tier=int(value["tier"]),
            extensions=tuple(str(item).lower() for item in value.get("extensions", [])),
            filenames=tuple(str(item) for item in value.get("filenames", [])),
            ecosystems=tuple(str(item) for item in value.get("ecosystems", [])),
            semantic_sast=str(value.get("semantic_sast", "generic")),
        )


def load_catalog(path: Path | None = None) -> list[Language]:
    if path is None:
        catalog = resources.files("secweaver").joinpath("data/languages.toml")
        with catalog.open("rb") as handle:
            data = tomllib.load(handle)
    else:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    languages = [Language.from_dict(item) for item in data.get("languages", [])]
    names = [language.name.casefold() for language in languages]
    if len(names) != len(set(names)):
        raise ValueError("Language catalog contains duplicate names")
    return languages


def detect_languages(
    root: Path,
    catalog: list[Language],
    *,
    excludes: tuple[str, ...] = (),
) -> dict[str, int]:
    counts = {language.name: 0 for language in catalog}
    extension_map: dict[str, list[Language]] = {}
    filename_map: dict[str, list[Language]] = {}
    for language in catalog:
        for extension in language.extensions:
            extension_map.setdefault(extension, []).append(language)
        for filename in language.filenames:
            filename_map.setdefault(filename.casefold(), []).append(language)

    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        parts = set(path.relative_to(root).parts)
        if any(
            pattern in parts or fnmatch.fnmatch(relative, pattern)
            for pattern in excludes
        ):
            continue
        candidates = filename_map.get(path.name.casefold(), [])
        if not candidates:
            candidates = extension_map.get(path.suffix.lower(), [])
        if candidates:
            # Ambiguous extensions are catalog ordered; one file counts once.
            counts[candidates[0].name] += 1
    return {name: count for name, count in counts.items() if count}


def coverage_row(language: Language) -> dict[str, Any]:
    baseline = [
        "Gitleaks content/history baseline",
        "Trivy repository/filesystem baseline",
    ]
    if language.ecosystems:
        baseline.append(
            "Dependency metadata candidate; verify scanner/package-format support"
        )
    else:
        baseline.append("Dependency scanning not declared for this catalog entry")
    baseline.append(
        f"Opengrep parser catalog: {language.semantic_sast}; "
        "active bundled rules: generic baseline"
    )
    return {
        "name": language.name,
        "tier": language.tier,
        "ecosystems": list(language.ecosystems),
        "coverage": baseline,
    }
