from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from secweaver.cli import _prepare_report_dir, _target, _within
from secweaver.config import ConfigError, load_config
from secweaver.redact import redact_structure, redact_text, sensitive_key
from secweaver.runner import _immutable_image, _safe_environment
from secweaver.scanners import build_scanner_definitions, resolve_rule_paths
from tests._helpers import SYNTHETIC_CANARY


class RedactionTests(unittest.TestCase):
    def test_sensitive_key_recognizes_common_variants(self) -> None:
        for key in (
            "token",
            "API_KEY",
            "private-key",
            "dbPassword",
            "Authorization",
            "credentials_file",
        ):
            with self.subTest(key=key):
                self.assertTrue(sensitive_key(key))
        self.assertFalse(sensitive_key("fixture_description"))

    def test_text_redaction_covers_assignment_bearer_and_url_credentials(self) -> None:
        value = " ".join(
            (
                f"token={SYNTHETIC_CANARY}",
                f"Bearer {SYNTHETIC_CANARY}",
                f"https://fixture-user:{SYNTHETIC_CANARY}@example.invalid/path",
            )
        )
        redacted = redact_text(value)
        self.assertNotIn(SYNTHETIC_CANARY, redacted)
        self.assertGreaterEqual(redacted.count("[REDACTED]"), 3)

    def test_structure_redaction_is_recursive_and_does_not_mutate_input(self) -> None:
        original = {
            "metadata": {
                "apiKey": SYNTHETIC_CANARY,
                "nested": [{"password": SYNTHETIC_CANARY}],
                "description": f"authorization: {SYNTHETIC_CANARY}",
            }
        }
        redacted = redact_structure(original)
        self.assertEqual(original["metadata"]["apiKey"], SYNTHETIC_CANARY)
        self.assertNotIn(SYNTHETIC_CANARY, repr(redacted))
        self.assertEqual(redacted["metadata"]["apiKey"], "[REDACTED]")

    def test_text_limit_keeps_only_bounded_tail(self) -> None:
        redacted = redact_text("prefix-" * 20 + "tail", limit=12)
        self.assertLessEqual(len(redacted), 12)
        self.assertTrue(redacted.endswith("tail"))


class PathAndArgumentSafetyTests(unittest.TestCase):
    def test_within_rejects_parent_traversal_and_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "workspace"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            with self.assertRaisesRegex(ConfigError, "inside the workspace"):
                _within(root, "../outside", must_exist=False)

            link = root / "linked-outside"
            try:
                os.symlink(outside, link)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            with self.assertRaisesRegex(ConfigError, "inside the workspace"):
                _within(root, "linked-outside", must_exist=False)

    def test_report_directory_rejects_root_symlink_and_unowned_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "workspace"
            root.mkdir()
            with self.assertRaisesRegex(ConfigError, "cannot be the workspace root"):
                _prepare_report_dir(root, ".")

            occupied = root / "occupied"
            occupied.mkdir()
            (occupied / "keep.txt").write_text("inert fixture\n", encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "must be empty"):
                _prepare_report_dir(root, "occupied")

            outside = base / "outside"
            outside.mkdir()
            linked = root / "linked-report"
            try:
                os.symlink(outside, linked)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            with self.assertRaises(ConfigError):
                _prepare_report_dir(root, "linked-report")

    def test_existing_report_directory_is_never_deleted_implicitly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = _prepare_report_dir(root, "reports")
            (report / "old.txt").write_text("inert fixture\n", encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "must be empty"):
                _prepare_report_dir(root, "reports")
            self.assertEqual(
                (report / "old.txt").read_text(encoding="utf-8"),
                "inert fixture\n",
            )

    def test_image_target_rejects_whitespace_and_control_characters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = load_config(
                env={},
                overrides={
                    "scan": {
                        "target_kind": "image",
                        "image": "registry.example.invalid/fixture:tag\nnext",
                    }
                },
            )
            with self.assertRaisesRegex(ConfigError, "malformed"):
                _target(config, root)

            for value in (
                "--privileged",
                "registry.example.invalid/fixture:tag;second-command",
            ):
                config["scan"]["image"] = value
                with self.subTest(value=value), self.assertRaisesRegex(
                    ConfigError,
                    "malformed",
                ):
                    _target(config, root)

            config["scan"]["image"] = "registry.example.invalid/fixture:tag"
            self.assertEqual(_target(config, root), root)

    def test_immutable_image_requires_exact_lowercase_sha256_digest(self) -> None:
        digest = "a" * 64
        self.assertTrue(_immutable_image(f"registry.example.invalid/fixture@sha256:{digest}"))
        for value in (
            "registry.example.invalid/fixture:latest",
            f"registry.example.invalid/fixture@sha256:{'a' * 63}",
            f"registry.example.invalid/fixture@sha256:{'A' * 64}",
            f"@sha256:{digest}",
        ):
            with self.subTest(value=value):
                self.assertFalse(_immutable_image(value))

    def test_strict_policy_requires_immutable_scan_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = load_config(
                env={},
                overrides={
                    "scan": {
                        "target_kind": "image",
                        "image": "registry.example.invalid/fixture:latest",
                    }
                },
                locked_profile="strict",
            )
            with self.assertRaisesRegex(ConfigError, "sha256 digest"):
                _target(config, root)
            config["scan"]["image"] = (
                "registry.example.invalid/fixture@sha256:" + ("a" * 64)
            )
            self.assertEqual(_target(config, root), root)

    def test_scanner_arguments_keep_metacharacters_as_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "workspace ; inert"
            report_root = root / "reports"
            target.mkdir()
            rule = root / "rule ; inert.yml"
            rule.write_text("rules: []\n", encoding="utf-8")
            excluded = "vendor;still-data"
            config = load_config(
                env={},
                overrides={
                    "scan": {
                        "enabled_scanners": ["gitleaks", "trivy", "opengrep", "osv"],
                        "required_scanners": [],
                        "excludes": [excluded],
                        "sast_rule_paths": [str(rule)],
                    }
                },
            )
            definitions = build_scanner_definitions(
                config,
                target=target,
                report_root=report_root,
                invocation_root=root,
            )
            by_name = {definition.name: definition for definition in definitions}
            self.assertIn(str(target), by_name["gitleaks"].native_args)
            self.assertIn(str(target), by_name["trivy"].native_args)
            self.assertIn(str(target), by_name["opengrep"].native_args)
            self.assertIn(str(target), by_name["osv"].native_args)
            trivy_args = by_name["trivy"].native_args
            index = trivy_args.index("--skip-dirs")
            self.assertEqual(trivy_args[index + 1], excluded)
            opengrep_args = by_name["opengrep"].native_args
            self.assertIn(str(rule.resolve()), opengrep_args)
            self.assertIn("--disable-nosem", opengrep_args)
            self.assertIn("--no-git-ignore", opengrep_args)
            self.assertTrue(
                any(
                    value.startswith("--semgrepignore-filename=")
                    for value in opengrep_args
                )
            )
            self.assertIn("--ignore-gitleaks-allow", by_name["gitleaks"].native_args)
            self.assertTrue(
                any(
                    value.startswith("--gitleaks-ignore-path=")
                    for value in by_name["gitleaks"].native_args
                )
            )
            self.assertTrue(
                any(value.startswith("--ignorefile=") for value in trivy_args)
            )
            self.assertTrue(
                any(value.startswith("--secret-config=") for value in trivy_args)
            )
            self.assertIn("--show-suppressed", trivy_args)
            self.assertTrue(
                any(
                    value.startswith("--config=")
                    for value in by_name["osv"].native_args
                )
            )
            self.assertIn("--no-ignore", by_name["osv"].native_args)
            self.assertNotIn("sh", opengrep_args)
            self.assertNotIn("-c", opengrep_args)

    def test_safe_environment_drops_sensitive_passthrough_and_isolates_home(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_root = Path(directory) / "reports"
            config = load_config(env={})
            with patch.dict(
                os.environ,
                {
                    "FIXTURE_TOKEN": SYNTHETIC_CANARY,
                    "SAFE_FIXTURE_VALUE": "safe-fixture",
                    "HOME": "/outside/home",
                    "LD_PRELOAD": "/outside/hook.so",
                },
                clear=False,
            ):
                environment = _safe_environment(config, report_root)
            self.assertNotIn("FIXTURE_TOKEN", environment)
            self.assertNotIn("SAFE_FIXTURE_VALUE", environment)
            self.assertNotIn("LD_PRELOAD", environment)
            self.assertEqual(environment["HOME"], str(report_root / ".runtime-home"))
            self.assertEqual(environment["SEMGREP_SEND_METRICS"], "off")

    def test_builtin_rule_is_available_in_a_source_checkout(self) -> None:
        paths = resolve_rule_paths(["builtin:baseline"], Path.cwd())
        self.assertEqual(len(paths), 1)
        self.assertTrue(paths[0].is_file())

    def test_custom_rule_path_cannot_escape_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir()
            outside = root / "outside.yml"
            outside.write_text("rules: []\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "inside the workspace"):
                resolve_rule_paths([str(outside)], workspace)


if __name__ == "__main__":
    unittest.main()
