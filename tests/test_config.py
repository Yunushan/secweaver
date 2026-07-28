from __future__ import annotations

import unittest

from secweaver.config import (
    PROFILE_DEFAULTS,
    ConfigError,
    apply_environment,
    load_config,
    load_toml,
    validate_config,
)
from tests._helpers import CONFIG_FIXTURES


class ConfigProfileTests(unittest.TestCase):
    def test_all_builtin_profiles_are_loadable_and_apply_their_policy(self) -> None:
        expected = {
            "advisory": ([], [], []),
            "balanced": (
                ["CRITICAL", "HIGH"],
                ["secret"],
                ["gitleaks", "trivy", "opengrep", "osv"],
            ),
            "strict": (
                ["CRITICAL", "HIGH", "MEDIUM"],
                ["secret", "misconfiguration"],
                ["gitleaks", "trivy", "opengrep", "osv"],
            ),
        }
        self.assertEqual(set(PROFILE_DEFAULTS), set(expected))
        for profile, (severities, categories, required) in expected.items():
            with self.subTest(profile=profile):
                config = load_config(env={}, overrides={"scan": {"profile": profile}})
                self.assertEqual(config["scan"]["profile"], profile)
                self.assertEqual(config["policy"]["fail_on_severities"], severities)
                self.assertEqual(config["policy"]["fail_on_categories"], categories)
                self.assertEqual(config["scan"]["required_scanners"], required)

    def test_file_environment_and_explicit_override_precedence(self) -> None:
        config = load_config(
            [CONFIG_FIXTURES / "strict-overlay.toml"],
            env={
                "SECWEAVER_PROFILE": "advisory",
                "SECWEAVER_TARGET": "environment-target",
                "SECWEAVER_HISTORY": "yes",
            },
            overrides={
                "scan": {
                    "profile": "balanced",
                    "target": "explicit-target",
                    "parallelism": 4,
                }
            },
        )
        self.assertEqual(config["scan"]["profile"], "balanced")
        self.assertEqual(config["scan"]["target"], "explicit-target")
        self.assertEqual(config["scan"]["parallelism"], 4)
        self.assertTrue(config["scan"]["history"])
        self.assertEqual(config["scan"]["required_scanners"], ["gitleaks"])
        self.assertEqual(config["policy"]["fail_on_severities"], ["CRITICAL", "HIGH"])
        self.assertEqual(config["project"]["name"], "synthetic-fixture-project")

    def test_environment_list_and_boolean_overrides_are_bounded(self) -> None:
        config = load_config(
            env={
                "SECWEAVER_SCANNERS": "trivy, gitleaks",
                "SECWEAVER_REQUIRED_SCANNERS": "gitleaks",
                "SECWEAVER_FAIL_ON": "critical, medium",
                "SECWEAVER_FAIL_CATEGORIES": "secret, vulnerability",
                "SECWEAVER_SAST_RULE_PATHS": "one.yml, two.yml",
                "SECWEAVER_OFFLINE": "on",
                "SECWEAVER_HISTORY": "0",
                "SECWEAVER_GENERATE_SBOM": "false",
                "SECWEAVER_RETAIN_RAW": "no",
                "UNRELATED_FIXTURE_VALUE": "ignored",
            },
            overrides={
                "scan": {"execution": "native"},
                "offline": {
                    "home_dir": "fixture-home",
                    "trivy_cache_dir": "fixture-trivy",
                    "osv_database_path": "fixture-osv",
                },
            },
        )
        self.assertEqual(config["scan"]["enabled_scanners"], ["trivy", "gitleaks"])
        self.assertEqual(config["scan"]["required_scanners"], ["gitleaks"])
        self.assertEqual(config["policy"]["fail_on_severities"], ["critical", "medium"])
        self.assertEqual(
            config["policy"]["fail_on_categories"],
            ["secret", "vulnerability"],
        )
        self.assertEqual(config["scan"]["sast_rule_paths"], ["one.yml", "two.yml"])
        self.assertTrue(config["scan"]["offline"])
        self.assertFalse(config["scan"]["history"])
        self.assertFalse(config["scan"]["generate_sbom"])
        self.assertFalse(config["reports"]["retain_raw"])
        self.assertNotIn("UNRELATED_FIXTURE_VALUE", repr(config))

    def test_loaded_config_is_not_shared_with_future_loads(self) -> None:
        first = load_config(env={})
        first["scan"]["enabled_scanners"].append("fixture-only")
        second = load_config(env={})
        self.assertNotIn("fixture-only", second["scan"]["enabled_scanners"])

    def test_file_policy_can_override_profile_defaults(self) -> None:
        config = load_config(
            env={},
            overrides={
                "scan": {"profile": "strict"},
                "policy": {
                    "fail_on_severities": ["CRITICAL"],
                    "fail_on_categories": [],
                },
            },
        )
        self.assertEqual(config["policy"]["fail_on_severities"], ["CRITICAL"])
        self.assertEqual(config["policy"]["fail_on_categories"], [])

    def test_locked_profile_cannot_be_weakened_by_repository_policy(self) -> None:
        config = load_config(
            env={},
            overrides={
                "scan": {
                    "required_scanners": [],
                    "enabled_scanners": ["gitleaks", "trivy", "opengrep", "osv"],
                },
                "policy": {
                    "fail_on_severities": [],
                    "fail_on_categories": [],
                    "missing_required_tool": "warn",
                    "scanner_error": "warn",
                },
            },
            locked_profile="balanced",
        )
        self.assertEqual(
            config["scan"]["required_scanners"],
            ["gitleaks", "trivy", "opengrep", "osv"],
        )
        self.assertEqual(config["policy"]["fail_on_severities"], ["CRITICAL", "HIGH"])
        self.assertEqual(config["policy"]["fail_on_categories"], ["secret"])
        self.assertEqual(config["policy"]["scanner_error"], "fail")

    def test_strict_privacy_disables_raw_reports_and_logs(self) -> None:
        config = load_config(
            env={},
            overrides={
                "reports": {
                    "privacy": "strict",
                    "retain_raw": True,
                    "retain_logs": True,
                }
            },
        )
        self.assertFalse(config["reports"]["retain_raw"])
        self.assertFalse(config["reports"]["retain_logs"])
        self.assertFalse(config["reports"]["include_absolute_paths"])


class ConfigValidationTests(unittest.TestCase):
    def test_invalid_boolean_environment_value_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "Expected a boolean"):
            apply_environment(load_config(env={}), {"SECWEAVER_OFFLINE": "perhaps"})

    def test_missing_scan_table_is_reported(self) -> None:
        self.assertEqual(validate_config({"policy": {}, "tools": {}}), ["Missing [scan] table"])

    def test_invalid_toml_is_wrapped_as_config_error(self) -> None:
        with self.assertRaisesRegex(ConfigError, "Invalid TOML"):
            load_toml(CONFIG_FIXTURES / "malformed.toml")

    def test_missing_toml_is_wrapped_as_config_error(self) -> None:
        with self.assertRaisesRegex(ConfigError, "Configuration file not found"):
            load_toml(CONFIG_FIXTURES / "does-not-exist.toml")

    def test_invalid_known_settings_are_rejected(self) -> None:
        cases = {
            "unknown profile": {"scan": {"profile": "unbounded"}},
            "unsafe execution mode": {"scan": {"execution": "shell-string"}},
            "unknown target kind": {"scan": {"target_kind": "device"}},
            "image without reference": {"scan": {"target_kind": "image", "image": ""}},
            "unknown scanner": {
                "scan": {
                    "enabled_scanners": ["gitleaks", "fixture-scanner"],
                    "required_scanners": ["gitleaks"],
                }
            },
            "required scanner disabled": {
                "scan": {
                    "enabled_scanners": ["trivy"],
                    "required_scanners": ["gitleaks"],
                }
            },
            "zero timeout": {"scan": {"timeout_seconds": 0}},
            "excessive timeout": {"scan": {"timeout_seconds": 86_401}},
            "zero parallelism": {"scan": {"parallelism": 0}},
            "excessive parallelism": {"scan": {"parallelism": 17}},
            "noninteger limits": {"scan": {"timeout_seconds": "later"}},
            "invalid scanner action": {"policy": {"scanner_error": "continue"}},
            "invalid missing action": {"policy": {"missing_required_tool": "continue"}},
            "invalid severity": {"policy": {"fail_on_severities": ["SEVERE"]}},
            "invalid list shape": {"scan": {"excludes": "vendor"}},
            "duplicate scanners": {
                "scan": {
                    "enabled_scanners": ["gitleaks", "gitleaks"],
                    "required_scanners": ["gitleaks"],
                }
            },
            "arbitrary executable": {
                "tools": {"gitleaks": {"command": "./repository-script"}}
            },
            "absolute paths requested": {
                "reports": {"include_absolute_paths": True}
            },
            "arbitrary container engine": {
                "scan": {"container_engine": "python"}
            },
            "option-shaped scanner image": {
                "tools": {"trivy": {"image": "--privileged"}}
            },
            "unsafe environment hook": {
                "environment": {"passthrough": ["PATH", "LD_PRELOAD"]}
            },
        }
        for label, overrides in cases.items():
            with self.subTest(label=label), self.assertRaises(ConfigError):
                load_config(env={}, overrides=overrides)

    def test_unknown_setting_is_rejected_instead_of_silently_ignored(self) -> None:
        with self.assertRaises(ConfigError):
            load_config(env={}, overrides={"scan": {"paralellism": 16}})

    def test_protected_jobs_can_allow_docker_config_path(self) -> None:
        config = load_config(
            env={},
            overrides={"environment": {"passthrough": ["DOCKER_CONFIG"]}},
        )
        self.assertEqual(config["environment"]["passthrough"], ["DOCKER_CONFIG"])


if __name__ == "__main__":
    unittest.main()
