"""TOML configuration loading with bounded environment overrides."""

from __future__ import annotations

import copy
import os
import tomllib
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from secweaver.util import deep_merge, is_safe_oci_reference

SAFE_ENVIRONMENT_KEYS = frozenset(
    {
        "CI",
        "COMSPEC",
        "DOCKER_CONFIG",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "LANG",
        "LC_ALL",
        "NO_PROXY",
        "PATH",
        "PATHEXT",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
    }
)


PROFILE_DEFAULTS: dict[str, dict[str, Any]] = {
    "advisory": {
        "policy": {
            "fail_on_severities": [],
            "fail_on_categories": [],
            "missing_required_tool": "warn",
            "scanner_error": "warn",
            "max_findings": -1,
            "require_immutable_images": False,
        },
        "scan": {"required_scanners": []},
    },
    "balanced": {
        "policy": {
            "fail_on_severities": ["CRITICAL", "HIGH"],
            "fail_on_categories": ["secret"],
            "missing_required_tool": "fail",
            "scanner_error": "fail",
            "max_findings": -1,
            "require_immutable_images": False,
        },
        "scan": {"required_scanners": ["gitleaks", "trivy", "opengrep", "osv"]},
    },
    "strict": {
        "policy": {
            "fail_on_severities": ["CRITICAL", "HIGH", "MEDIUM"],
            "fail_on_categories": ["secret", "misconfiguration"],
            "missing_required_tool": "fail",
            "scanner_error": "fail",
            "max_findings": -1,
            "require_immutable_images": True,
        },
        "scan": {"required_scanners": ["gitleaks", "trivy", "opengrep", "osv"]},
    },
}

DEFAULT_CONFIG: dict[str, Any] = {
    "project": {
        "name": "unnamed-project",
    },
    "scan": {
        "profile": "balanced",
        "target": ".",
        "target_kind": "source",
        "image": "",
        "execution": "auto",
        "container_engine": "docker",
        "report_dir": "secweaver-reports",
        "enabled_scanners": ["gitleaks", "trivy", "opengrep", "osv"],
        "required_scanners": ["gitleaks", "trivy", "opengrep", "osv"],
        "history": True,
        "offline": False,
        "timeout_seconds": 900,
        "parallelism": 2,
        "excludes": [
            ".git",
            ".hg",
            ".svn",
            ".venv",
            ".secweaver-offline",
            "node_modules",
            "vendor",
            "secweaver-reports",
        ],
        "sast_rule_paths": ["builtin:baseline"],
        "generate_sbom": True,
    },
    "policy": {
        "fail_on_severities": ["CRITICAL", "HIGH"],
        "fail_on_categories": ["secret"],
        "missing_required_tool": "fail",
        "scanner_error": "fail",
        "max_findings": -1,
        "require_immutable_images": False,
    },
    "reports": {
        "formats": ["json", "markdown", "junit", "sarif"],
        "retain_raw": True,
        "retain_logs": False,
        "privacy": "standard",
        "include_absolute_paths": False,
    },
    "tools": {
        "gitleaks": {
            "command": "gitleaks",
            "version": "8.30.1",
            "image": "docker.io/zricethezav/gitleaks:v8.30.1",
        },
        "trivy": {
            "command": "trivy",
            "version": "0.72.0",
            "image": "docker.io/aquasec/trivy:0.72.0",
        },
        "opengrep": {
            "command": "opengrep",
            "version": "1.26.0",
            "image": "",
        },
        "osv": {
            "command": "osv-scanner",
            "version": "2.4.0",
            "image": "ghcr.io/google/osv-scanner:v2.4.0",
        },
    },
    "environment": {
        "passthrough": [
            "CI",
            "LANG",
            "LC_ALL",
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "TMPDIR",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "SSL_CERT_DIR",
            "SSL_CERT_FILE",
        ],
    },
    "offline": {
        "home_dir": "",
        "trivy_cache_dir": "",
        "osv_database_path": "",
    },
    "languages": {
        "catalog": "",
    },
}

_ENV_MAP: dict[str, tuple[str, str]] = {
    "SECWEAVER_PROFILE": ("scan", "profile"),
    "SECWEAVER_TARGET": ("scan", "target"),
    "SECWEAVER_TARGET_KIND": ("scan", "target_kind"),
    "SECWEAVER_IMAGE": ("scan", "image"),
    "SECWEAVER_EXECUTION": ("scan", "execution"),
    "SECWEAVER_CONTAINER_ENGINE": ("scan", "container_engine"),
    "SECWEAVER_REPORT_DIR": ("scan", "report_dir"),
}


class ConfigError(ValueError):
    """Raised for user-correctable configuration errors."""


def _find_unknown_keys(
    value: Mapping[str, Any],
    allowed: Mapping[str, Any],
    *,
    prefix: str = "",
) -> list[str]:
    unknown: list[str] = []
    for key, child in value.items():
        dotted = f"{prefix}.{key}" if prefix else str(key)
        if key not in allowed:
            unknown.append(dotted)
            continue
        allowed_child = allowed[key]
        if isinstance(child, Mapping) and isinstance(allowed_child, Mapping):
            unknown.extend(
                _find_unknown_keys(child, allowed_child, prefix=dotted)
            )
    return unknown


def _parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"Expected a boolean value, got {value!r}")


def _list_from_env(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError(f"Configuration file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ConfigError(f"Configuration root must be a table: {path}")
    return value


def apply_environment(config: dict[str, Any], env: Mapping[str, str]) -> dict[str, Any]:
    result = copy.deepcopy(config)
    for env_name, (section, key) in _ENV_MAP.items():
        if env_name in env:
            result[section][key] = env[env_name]

    list_overrides = {
        "SECWEAVER_SCANNERS": ("scan", "enabled_scanners"),
        "SECWEAVER_REQUIRED_SCANNERS": ("scan", "required_scanners"),
        "SECWEAVER_FAIL_ON": ("policy", "fail_on_severities"),
        "SECWEAVER_FAIL_CATEGORIES": ("policy", "fail_on_categories"),
        "SECWEAVER_SAST_RULE_PATHS": ("scan", "sast_rule_paths"),
    }
    for env_name, (section, key) in list_overrides.items():
        if env_name in env:
            result[section][key] = _list_from_env(env[env_name])

    bool_overrides = {
        "SECWEAVER_OFFLINE": ("scan", "offline"),
        "SECWEAVER_HISTORY": ("scan", "history"),
        "SECWEAVER_GENERATE_SBOM": ("scan", "generate_sbom"),
        "SECWEAVER_RETAIN_RAW": ("reports", "retain_raw"),
    }
    for env_name, (section, key) in bool_overrides.items():
        if env_name in env:
            result[section][key] = _parse_bool(env[env_name])
    return result


def validate_config(config: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    unknown = _find_unknown_keys(config, DEFAULT_CONFIG)
    if unknown:
        errors.append(f"Unknown configuration keys: {', '.join(sorted(unknown))}")
    scan = config.get("scan")
    policy = config.get("policy")
    tools = config.get("tools")
    if not isinstance(scan, Mapping):
        return ["Missing [scan] table"]
    if not isinstance(policy, Mapping):
        errors.append("Missing [policy] table")
    if not isinstance(tools, Mapping):
        errors.append("Missing [tools] table")

    profile = str(scan.get("profile", ""))
    if profile not in PROFILE_DEFAULTS:
        errors.append(f"scan.profile must be one of: {', '.join(PROFILE_DEFAULTS)}")
    if str(scan.get("execution", "")) not in {"auto", "native", "container"}:
        errors.append("scan.execution must be auto, native, or container")
    if str(scan.get("target_kind", "")) not in {"source", "image"}:
        errors.append("scan.target_kind must be source or image")
    if str(scan.get("target_kind")) == "image" and not str(scan.get("image", "")).strip():
        errors.append("scan.image is required when scan.target_kind is image")

    for key in ("enabled_scanners", "required_scanners", "excludes", "sast_rule_paths"):
        if not isinstance(scan.get(key), list) or not all(
            isinstance(value, str) for value in scan.get(key, [])
        ):
            errors.append(f"scan.{key} must be an array of strings")

    enabled = set(scan.get("enabled_scanners", []))
    required = set(scan.get("required_scanners", []))
    if len(enabled) != len(scan.get("enabled_scanners", [])):
        errors.append("scan.enabled_scanners must not contain duplicates")
    if len(required) != len(scan.get("required_scanners", [])):
        errors.append("scan.required_scanners must not contain duplicates")
    if not required.issubset(enabled):
        errors.append("Every required scanner must also be enabled")
    known = {"gitleaks", "trivy", "opengrep", "osv"}
    unknown = enabled - known
    if unknown:
        errors.append(f"Unknown scanners: {', '.join(sorted(unknown))}")

    try:
        timeout_value = scan.get("timeout_seconds", 0)
        parallelism_value = scan.get("parallelism", 0)
        if isinstance(timeout_value, bool) or isinstance(parallelism_value, bool):
            raise ValueError
        timeout = int(timeout_value)
        parallelism = int(parallelism_value)
        if not 1 <= timeout <= 86_400:
            errors.append("scan.timeout_seconds must be between 1 and 86400")
        if not 1 <= parallelism <= 16:
            errors.append("scan.parallelism must be between 1 and 16")
    except (TypeError, ValueError):
        errors.append("scan.timeout_seconds and scan.parallelism must be integers")

    for key in ("history", "offline", "generate_sbom"):
        if not isinstance(scan.get(key), bool):
            errors.append(f"scan.{key} must be a boolean")
    for key in ("target", "report_dir", "container_engine"):
        if not isinstance(scan.get(key), str) or not str(scan.get(key)).strip():
            errors.append(f"scan.{key} must be a non-empty string")
    if scan.get("container_engine") not in {"docker", "podman"}:
        errors.append("scan.container_engine must be docker or podman")

    if isinstance(policy, Mapping):
        severity_values = policy.get("fail_on_severities", [])
        category_values = policy.get("fail_on_categories", [])
        if not isinstance(severity_values, list) or not all(
            isinstance(item, str) for item in severity_values
        ):
            errors.append("policy.fail_on_severities must be an array of strings")
            severity_values = []
        if not isinstance(category_values, list) or not all(
            isinstance(item, str) for item in category_values
        ):
            errors.append("policy.fail_on_categories must be an array of strings")
        severities = {str(item).upper() for item in severity_values}
        allowed_severities = {"UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if severities - allowed_severities:
            errors.append("policy.fail_on_severities contains an unsupported severity")
        for key in ("missing_required_tool", "scanner_error"):
            if str(policy.get(key, "")) not in {"fail", "warn", "ignore"}:
                errors.append(f"policy.{key} must be fail, warn, or ignore")
        max_findings = policy.get("max_findings", -1)
        if (
            isinstance(max_findings, bool)
            or not isinstance(max_findings, int)
            or max_findings < -1
        ):
            errors.append("policy.max_findings must be an integer of -1 or greater")
        if not isinstance(policy.get("require_immutable_images"), bool):
            errors.append("policy.require_immutable_images must be a boolean")

    reports = config.get("reports")
    if not isinstance(reports, Mapping):
        errors.append("Missing [reports] table")
    else:
        formats = reports.get("formats", [])
        allowed_formats = {"json", "markdown", "junit", "sarif"}
        if (
            not isinstance(formats, list)
            or not all(isinstance(item, str) for item in formats)
            or set(formats) - allowed_formats
        ):
            errors.append("reports.formats contains an unsupported format")
        for key in ("retain_raw", "retain_logs", "include_absolute_paths"):
            if not isinstance(reports.get(key), bool):
                errors.append(f"reports.{key} must be a boolean")
        if reports.get("include_absolute_paths") is True:
            errors.append("reports.include_absolute_paths=true is not supported")
        if str(reports.get("privacy", "")) not in {"standard", "strict"}:
            errors.append("reports.privacy must be standard or strict")

    environment = config.get("environment")
    if not isinstance(environment, Mapping) or not isinstance(
        environment.get("passthrough"), list
    ) or not all(
        isinstance(item, str) and item
        for item in environment.get("passthrough", [])
    ):
        errors.append("environment.passthrough must be an array of non-empty strings")
    elif set(environment["passthrough"]) - SAFE_ENVIRONMENT_KEYS:
        errors.append(
            "environment.passthrough contains keys outside the fixed safe allowlist"
        )

    offline = config.get("offline")
    if not isinstance(offline, Mapping):
        errors.append("Missing [offline] table")
    else:
        for key in ("home_dir", "trivy_cache_dir", "osv_database_path"):
            if not isinstance(offline.get(key), str):
                errors.append(f"offline.{key} must be a string")
        if bool(scan.get("offline")):
            if scan.get("execution") != "native":
                errors.append("offline scans require scan.execution=native")
            for key in ("home_dir", "trivy_cache_dir", "osv_database_path"):
                if not str(offline.get(key, "")).strip():
                    errors.append(f"offline.{key} is required for an offline scan")

    languages = config.get("languages")
    if not isinstance(languages, Mapping) or not isinstance(
        languages.get("catalog"), str
    ):
        errors.append("languages.catalog must be a string")

    expected_commands = {
        "gitleaks": "gitleaks",
        "trivy": "trivy",
        "opengrep": "opengrep",
        "osv": "osv-scanner",
    }
    if isinstance(tools, Mapping):
        for name, expected_command in expected_commands.items():
            tool = tools.get(name)
            if not isinstance(tool, Mapping):
                errors.append(f"Missing [tools.{name}] table")
                continue
            if tool.get("command") != expected_command:
                errors.append(
                    f"tools.{name}.command is fixed by the typed scanner adapter"
                )
            if not isinstance(tool.get("version"), str) or not tool.get("version"):
                errors.append(f"tools.{name}.version must be a non-empty string")
            image = tool.get("image")
            if not isinstance(image, str) or (
                image and not is_safe_oci_reference(image)
            ):
                errors.append(f"tools.{name}.image contains unsafe characters")

    return errors


def load_config(
    paths: Iterable[Path] = (),
    *,
    env: Mapping[str, str] | None = None,
    overrides: Mapping[str, Any] | None = None,
    locked_profile: str | None = None,
) -> dict[str, Any]:
    supplied_env = os.environ if env is None else env
    discovery = copy.deepcopy(DEFAULT_CONFIG)
    for path in paths:
        discovery = deep_merge(discovery, load_toml(path))
    discovery = apply_environment(discovery, supplied_env)
    if overrides:
        discovery = deep_merge(discovery, overrides)
    selected_profile = (
        locked_profile
        if locked_profile is not None
        else str(discovery.get("scan", {}).get("profile", "balanced"))
    )
    if selected_profile not in PROFILE_DEFAULTS:
        raise ConfigError(
            f"Unknown profile {selected_profile!r}; expected one of {', '.join(PROFILE_DEFAULTS)}"
        )

    config = deep_merge(copy.deepcopy(DEFAULT_CONFIG), PROFILE_DEFAULTS[selected_profile])
    for path in paths:
        config = deep_merge(config, load_toml(path))
    config = apply_environment(config, supplied_env)
    if overrides:
        config = deep_merge(config, overrides)
    if locked_profile is not None:
        config = deep_merge(config, PROFILE_DEFAULTS[locked_profile])
        config["scan"]["profile"] = locked_profile
    if str(config.get("reports", {}).get("privacy", "")) == "strict":
        config["reports"]["retain_raw"] = False
        config["reports"]["retain_logs"] = False
        config["reports"]["include_absolute_paths"] = False

    errors = validate_config(config)
    if errors:
        raise ConfigError("; ".join(errors))
    return config
