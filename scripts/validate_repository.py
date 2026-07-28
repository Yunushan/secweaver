#!/usr/bin/env python3
"""Fast, dependency-free repository consistency checks."""

from __future__ import annotations

import json
import sys
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATHS = (
    "templates/argo-cd/presync-security-gate.yml",
    "templates/argo-workflows/security-workflowtemplate.yml",
    "templates/azure/azure-pipelines.yml",
    "templates/bitbucket/bitbucket-pipelines.yml",
    "templates/circleci/config.yml",
    "templates/drone/.drone.yml",
    "templates/forgejo/security.yml",
    "templates/gitea/security.yml",
    "templates/github/security.yml",
    "templates/gitlab/security.yml",
    "templates/jenkins/Jenkinsfile",
    "templates/tekton/security-pipeline.yml",
    "templates/woodpecker/security.yml",
)


def fail(message: str) -> None:
    raise ValueError(message)


def validate_toml() -> None:
    for path in sorted(ROOT.rglob("*.toml")):
        relative = path.relative_to(ROOT)
        if (
            any(part in {".venv", "secweaver-reports"} for part in path.parts)
            or relative.parts[:2] == ("tests", "fixtures")
        ):
            continue
        with path.open("rb") as handle:
            tomllib.load(handle)


def validate_json() -> None:
    for path in sorted(ROOT.rglob("*.json")):
        relative = path.relative_to(ROOT)
        if (
            any(part in {".venv", "secweaver-reports"} for part in path.parts)
            or relative.parts[:2] == ("tests", "fixtures")
        ):
            continue
        with path.open(encoding="utf-8") as handle:
            json.load(handle)


def _resolve_local_ref(schema: Mapping[str, Any], document: Mapping[str, Any]) -> Mapping[str, Any]:
    reference = schema.get("$ref")
    if not isinstance(reference, str):
        return schema
    if not reference.startswith("#/"):
        fail(f"config schema uses unsupported non-local reference: {reference}")
    resolved: Any = document
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(resolved, Mapping) or part not in resolved:
            fail(f"config schema reference does not resolve: {reference}")
        resolved = resolved[part]
    if not isinstance(resolved, Mapping):
        fail(f"config schema reference is not an object: {reference}")
    return resolved


def _validate_schema_keys(
    value: Any,
    schema: Mapping[str, Any],
    document: Mapping[str, Any],
    *,
    path: str,
) -> None:
    resolved = _resolve_local_ref(schema, document)
    for branch in resolved.get("allOf", []):
        if isinstance(branch, Mapping):
            _validate_schema_keys(value, branch, document, path=path)

    if isinstance(value, Mapping):
        properties = resolved.get("properties", {})
        if not isinstance(properties, Mapping):
            properties = {}
        additional = resolved.get("additionalProperties", True)
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            child_schema = properties.get(key)
            if isinstance(child_schema, Mapping):
                _validate_schema_keys(child, child_schema, document, path=child_path)
            elif additional is False:
                fail(f"config key is rejected by schema: {child_path}")
            elif isinstance(additional, Mapping):
                _validate_schema_keys(child, additional, document, path=child_path)
    elif isinstance(value, list):
        items = resolved.get("items")
        if isinstance(items, Mapping):
            for index, child in enumerate(value):
                _validate_schema_keys(child, items, document, path=f"{path}[{index}]")


def validate_config_schema_keys() -> None:
    schema_path = ROOT / "schemas" / "secweaver-config.schema.json"
    with schema_path.open(encoding="utf-8") as handle:
        schema = json.load(handle)
    if not isinstance(schema, Mapping):
        fail("config schema root must be an object")

    examples = sorted((ROOT / "examples").glob("*/secweaver*.toml"))
    if len(examples) != 4:
        fail(f"expected four example configurations, found {len(examples)}")
    for path in [ROOT / "secweaver.toml", *examples]:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
        _validate_schema_keys(value, schema, schema, path="")


def validate_language_catalog() -> None:
    catalog_path = ROOT / "src" / "secweaver" / "data" / "languages.toml"
    with catalog_path.open("rb") as handle:
        entries = tomllib.load(handle)["languages"]
    names = [entry["name"] for entry in entries]
    if len(entries) != 50:
        fail(f"expected 50 catalog languages, found {len(entries)}")
    if len({name.casefold() for name in names}) != 50:
        fail("language names must be unique")
    tier_1 = [entry["name"] for entry in entries if entry["tier"] == 1]
    if len(tier_1) != 20:
        fail(f"expected 20 tier-1 languages, found {len(tier_1)}")

    with (ROOT / "config" / "ranking-snapshot.toml").open("rb") as handle:
        ranking = tomllib.load(handle)
    if tier_1 != ranking["tier_1"]:
        fail("tier-1 catalog order differs from ranking snapshot")
    if names[20:] != ranking["tier_2"]:
        fail("tier-2 catalog order differs from ranking snapshot")

    with (ROOT / "support-matrix.json").open(encoding="utf-8") as handle:
        support = json.load(handle)
    if support["tier_1_languages"] != tier_1:
        fail("support matrix tier-1 list differs from language catalog")
    if support["tier_2_count"] != 30:
        fail("support matrix tier-2 count must be 30")


def validate_template_contracts() -> None:
    for relative in TEMPLATE_PATHS:
        path = ROOT / relative
        if not path.is_file():
            fail(f"missing CI/CD template: {relative}")
        content = path.read_text(encoding="utf-8")
        for fragment in (
            "YOUR_RUNNER_IMAGE@sha256:REPLACE_WITH_DIGEST",
            "--no-project-config",
            "--profile",
            "--execution",
            "native",
        ):
            if fragment not in content:
                fail(f"template contract {fragment!r} is missing from {relative}")
        if path.suffix in {".yaml", ".yml"} and "\t" in content:
            fail(f"YAML template contains a tab: {relative}")


def validate_public_safety() -> None:
    forbidden_fragments = (
        "/workspace/" + "scratch/",
        "\\workspace\\" + "scratch\\",
        "BEGIN OPENSSH " + "PRIVATE KEY",
        "BEGIN RSA " + "PRIVATE KEY",
        "BEGIN EC " + "PRIVATE KEY",
    )
    text_suffixes = {
        ".cfg",
        ".ini",
        ".json",
        ".md",
        ".ps1",
        ".py",
        ".sh",
        ".toml",
        ".txt",
        ".yaml",
        ".yml",
    }
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in text_suffixes:
            continue
        if any(part in {".git", ".venv", "secweaver-reports"} for part in path.parts):
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        for fragment in forbidden_fragments:
            if fragment in content:
                fail(f"public-safety check failed in {path.relative_to(ROOT)}")


def main() -> int:
    try:
        validate_toml()
        validate_json()
        validate_config_schema_keys()
        validate_language_catalog()
        validate_template_contracts()
        validate_public_safety()
    except (OSError, ValueError, KeyError, tomllib.TOMLDecodeError, json.JSONDecodeError) as exc:
        print(f"repository validation failed: {exc}", file=sys.stderr)
        return 1
    print("Repository metadata, catalogs, and public-safety invariants are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
