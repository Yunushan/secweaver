from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secweaver.config import load_config
from secweaver.runner import (
    _container_command,
    _version_matches,
    execute_scanner,
    select_execution,
)
from secweaver.scanners import ScannerDefinition


def definition(root: Path, scanner: str = "osv") -> ScannerDefinition:
    return ScannerDefinition(
        name=scanner,
        executable="osv-scanner" if scanner == "osv" else scanner,
        native_args=("scan",),
        report_path=root / "raw" / f"{scanner}.json",
        log_path=root / "logs" / f"{scanner}.log",
        container_image="registry.example.invalid/scanner@sha256:" + ("a" * 64),
        container_args=("scan", "/workspace"),
    )


class RunnerFailureSafetyTests(unittest.TestCase):
    def test_version_match_rejects_prerelease_and_dirty_suffixes(self) -> None:
        self.assertTrue(_version_matches("0.72.0", "trivy version 0.72.0"))
        self.assertTrue(_version_matches("2.4.0", "osv-scanner version v2.4.0"))
        self.assertFalse(_version_matches("0.72.0", "trivy 0.72.0-rc.1"))
        self.assertFalse(_version_matches("0.72.0", "trivy 0.72.0+dirty"))
        self.assertFalse(_version_matches("0.72.0", "trivy 10.72.0"))

    def test_workspace_native_executable_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "osv-scanner"
            executable.write_text("synthetic fixture\n", encoding="utf-8")
            item = definition(root)
            config = load_config(
                env={},
                overrides={"scan": {"execution": "native"}},
            )
            with (
                mock.patch("secweaver.runner.Path.cwd", return_value=root),
                mock.patch(
                    "secweaver.runner.shutil.which",
                    return_value=str(executable),
                ),
            ):
                mode, command, error = select_execution(config, item)
            self.assertEqual(mode, "missing")
            self.assertIsNone(command)
            self.assertIn("inside the workspace", error)

    def test_osv_exit_128_is_not_applicable_and_discards_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "workspace"
            reports = root / "reports"
            target.mkdir()
            item = definition(reports)
            config = load_config(
                env={},
                overrides={"scan": {"execution": "native"}},
            )

            def run(*args, **kwargs):
                item.report_path.parent.mkdir(parents=True, exist_ok=True)
                item.report_path.write_text(
                    json.dumps({"results": None}) + "\n",
                    encoding="utf-8",
                )
                kwargs["stdout"].write(b"no package sources found\n")
                return 128

            with (
                mock.patch(
                    "secweaver.runner.select_execution",
                    return_value=("native", ["/fixture/osv-scanner", "scan"], ""),
                ),
                mock.patch(
                    "secweaver.runner._tool_version",
                    return_value="osv-scanner 2.4.0",
                ),
                mock.patch("secweaver.runner._run_process", side_effect=run),
            ):
                result = execute_scanner(
                    config,
                    item,
                    target=target,
                    report_root=reports,
                )

            self.assertEqual(result.status, "skipped")
            self.assertIn("no supported packages", result.error)
            self.assertIsNone(result.report_path)
            self.assertIsNone(result.log_path)
            self.assertFalse(item.report_path.exists())
            self.assertFalse(item.log_path.exists())

    def test_failed_scanner_does_not_retain_unreviewed_raw_or_log_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "workspace"
            reports = root / "reports"
            target.mkdir()
            item = definition(reports, "trivy")
            config = load_config(
                env={},
                overrides={"scan": {"execution": "native"}},
            )

            def run(*args, **kwargs):
                item.report_path.parent.mkdir(parents=True, exist_ok=True)
                item.report_path.write_text(
                    '{"token":"fixture-sensitive-value"}\n',
                    encoding="utf-8",
                )
                kwargs["stdout"].write(b"fixture-sensitive-value\n")
                return 2

            with (
                mock.patch(
                    "secweaver.runner.select_execution",
                    return_value=("native", ["/fixture/trivy", "filesystem"], ""),
                ),
                mock.patch(
                    "secweaver.runner._tool_version",
                    return_value="trivy 0.72.0",
                ),
                mock.patch("secweaver.runner._run_process", side_effect=run),
            ):
                result = execute_scanner(
                    config,
                    item,
                    target=target,
                    report_root=reports,
                )

            self.assertEqual(result.status, "error")
            self.assertFalse(item.report_path.exists())
            self.assertFalse(item.log_path.exists())
            self.assertIsNone(result.report_path)
            self.assertIsNone(result.log_path)

    def test_malformed_report_discards_raw_output_and_log(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "workspace"
            reports = root / "reports"
            target.mkdir()
            item = definition(reports, "opengrep")
            config = load_config(
                env={},
                overrides={"scan": {"execution": "native"}},
            )

            def run(*args, **kwargs):
                item.report_path.parent.mkdir(parents=True, exist_ok=True)
                item.report_path.write_text(
                    '{"runs":[{"tool":null}]}\n',
                    encoding="utf-8",
                )
                kwargs["stdout"].write(b"synthetic private fixture\n")
                return 0

            with (
                mock.patch(
                    "secweaver.runner.select_execution",
                    return_value=("native", ["/fixture/opengrep", "scan"], ""),
                ),
                mock.patch(
                    "secweaver.runner._tool_version",
                    return_value="opengrep 1.26.0",
                ),
                mock.patch("secweaver.runner._run_process", side_effect=run),
            ):
                result = execute_scanner(
                    config,
                    item,
                    target=target,
                    report_root=reports,
                )

            self.assertEqual(result.status, "invalid-report")
            self.assertFalse(item.report_path.exists())
            self.assertFalse(item.log_path.exists())
            self.assertIsNone(result.report_path)
            self.assertIsNone(result.log_path)

    def test_container_command_uses_option_terminator_and_rejects_unknown_engine(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "workspace"
            reports = root / "reports"
            target.mkdir()
            reports.mkdir()
            item = definition(reports)
            config = load_config(env={})
            command = _container_command(config, item, target, reports)
            separator = command.index("--")
            self.assertEqual(command[separator + 1], item.container_image)
            self.assertTrue(
                any(
                    value.endswith("dst=/secweaver-controls,readonly")
                    for value in command
                )
            )

            config["scan"]["container_engine"] = "python"
            with self.assertRaisesRegex(ValueError, "Unsupported"):
                _container_command(config, item, target, reports)


if __name__ == "__main__":
    unittest.main()
