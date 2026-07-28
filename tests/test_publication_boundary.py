from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from secweaver.cli import (
    _prepare_report_dir,
    _publish_staged_outputs,
    _purge_unexpected_report_artifacts,
    _validate_offline_layout,
    _validate_staged_outputs,
)
from secweaver.config import ConfigError, load_config
from secweaver.models import ScannerResult


def _result(
    scanner: str,
    *,
    report_path: Path | None = None,
    log_path: Path | None = None,
) -> ScannerResult:
    return ScannerResult(
        scanner=scanner,
        status="clean",
        report_path=report_path,
        log_path=log_path,
    )


class PublicationBoundaryTests(unittest.TestCase):
    def test_extra_staged_file_blocks_all_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / "stage"
            stage.mkdir()
            raw = stage / "raw/gitleaks.json"
            raw.parent.mkdir()
            raw.write_text("[]\n", encoding="utf-8")
            (stage / "unexpected-private.txt").write_text(
                "synthetic private fixture\n",
                encoding="utf-8",
            )
            public = _prepare_report_dir(root, "public")

            with self.assertRaisesRegex(ConfigError, "unexpected staging artifact"):
                _validate_staged_outputs(
                    stage,
                    [_result("gitleaks", report_path=raw)],
                )

            self.assertEqual(
                {path.name for path in public.iterdir()},
                {".secweaver-output"},
            )

    def test_failed_cleanup_residue_blocks_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            residue = stage / "raw/trivy.json"
            residue.parent.mkdir()
            residue.write_text('{"private":"synthetic"}\n', encoding="utf-8")

            with self.assertRaisesRegex(ConfigError, "unexpected staging artifact"):
                _validate_staged_outputs(stage, [_result("trivy")])

    def test_only_validated_retained_files_are_copied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / "stage"
            raw = stage / "raw/trivy.json"
            log = stage / "logs/trivy.log"
            raw.parent.mkdir(parents=True)
            log.parent.mkdir(parents=True)
            raw.write_text('{"Results":[]}\n', encoding="utf-8")
            log.write_text("bounded sanitized log\n", encoding="utf-8")
            result = _result("trivy", report_path=raw, log_path=log)
            public = _prepare_report_dir(root, "public")

            _validate_staged_outputs(stage, [result])
            _publish_staged_outputs(stage, public, [result])

            self.assertEqual(result.report_path, public / "raw/trivy.json")
            self.assertEqual(result.log_path, public / "logs/trivy.log")
            self.assertEqual(
                (public / "raw/trivy.json").read_text(encoding="utf-8"),
                '{"Results":[]}\n',
            )
            self.assertEqual(
                (public / "logs/trivy.log").read_text(encoding="utf-8"),
                "bounded sanitized log\n",
            )

    def test_public_tree_tampering_is_removed_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = _prepare_report_dir(root, "public")
            (public / ".secweaver-output").write_text(
                "synthetic private fixture\n",
                encoding="utf-8",
            )
            (public / "unexpected-private.txt").write_text(
                "synthetic private fixture\n",
                encoding="utf-8",
            )
            (public / "empty-extra").mkdir()

            removed = _purge_unexpected_report_artifacts(
                public,
                allowed_paths=frozenset(),
            )

            self.assertEqual(
                set(removed),
                {
                    ".secweaver-output",
                    "empty-extra",
                    "unexpected-private.txt",
                },
            )
            self.assertEqual(list(public.iterdir()), [])

    def test_deleted_output_marker_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = _prepare_report_dir(root, "public")
            (public / ".secweaver-output").unlink()

            removed = _purge_unexpected_report_artifacts(
                public,
                allowed_paths=frozenset(),
            )

            self.assertEqual(removed, [".secweaver-output"])

    @unittest.skipIf(os.name == "nt", "FIFO creation is POSIX-only")
    def test_special_staging_entry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            fifo = stage / "scanner.fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ConfigError, "special staging entry"):
                _validate_staged_outputs(stage, [])


class OfflineLayoutTests(unittest.TestCase):
    def test_offline_databases_must_be_populated_distinct_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for value in ("offline/home", "offline/trivy", "offline/osv"):
                (root / value).mkdir(parents=True)
            config = load_config(
                env={},
                overrides={
                    "scan": {"execution": "native", "offline": True},
                    "offline": {
                        "home_dir": "offline/home",
                        "trivy_cache_dir": "offline/trivy",
                        "osv_database_path": "offline/osv",
                    },
                },
            )
            report = root / "reports"

            with self.assertRaisesRegex(ConfigError, "no regular database files"):
                _validate_offline_layout(config, root, report)

            (root / "offline/trivy/db").write_text("fixture\n", encoding="utf-8")
            (root / "offline/osv/db").write_text("fixture\n", encoding="utf-8")
            _validate_offline_layout(config, root, report)

            config["offline"]["osv_database_path"] = "offline/trivy"
            with self.assertRaisesRegex(ConfigError, "must be distinct"):
                _validate_offline_layout(config, root, report)

            config["offline"]["osv_database_path"] = "offline/osv"
            config["scan"]["report_dir"] = "offline/trivy/reports"
            with self.assertRaisesRegex(ConfigError, "must not overlap"):
                _validate_offline_layout(
                    config,
                    root,
                    root / "offline/trivy/reports",
                )


if __name__ == "__main__":
    unittest.main()
