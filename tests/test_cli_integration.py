from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from secweaver.cli import main
from secweaver.models import PolicyDecision
from secweaver.runner import ScanOutcome

_FAKE_SCANNER = """\
#!/usr/bin/env python3
import json
import sys
from pathlib import Path

name = Path(sys.argv[0]).name
args = sys.argv[1:]
if args == ["--version"]:
    versions = {
        "gitleaks": "8.30.1",
        "trivy": "0.72.0",
        "opengrep": "1.26.0",
        "osv-scanner": "2.4.0",
    }
    print(f"{name} {versions[name]}")
    raise SystemExit(0)

def option(prefix):
    for value in args:
        if value.startswith(prefix):
            return value.split("=", 1)[1]
    raise SystemExit(f"missing output option for {name}: {args!r}")

if name == "gitleaks":
    output = option("--report-path=")
    data = []
elif name == "trivy":
    output = option("--output=")
    if "--format=cyclonedx" in args:
        data = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
    else:
        data = {"Results": []}
elif name == "opengrep":
    output = option("--sarif-output=")
    data = {"version": "2.1.0", "runs": []}
elif name == "osv-scanner":
    output = option("--output-file=")
    data = {"results": []}
else:
    raise SystemExit(f"unexpected fake scanner name: {name}")

path = Path(output)
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(data) + "\\n", encoding="utf-8")
"""


@unittest.skipIf(os.name == "nt", "POSIX executable shims are tested on POSIX runners")
class PortableCliIntegrationTests(unittest.TestCase):
    def test_complete_clean_scan_writes_consistent_report_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            tools = root / "tools"
            workspace.mkdir()
            tools.mkdir()
            (workspace / "fixture.py").write_text("# inert fixture\n", encoding="utf-8")
            for name in ("gitleaks", "trivy", "opengrep", "osv-scanner"):
                executable = tools / name
                executable.write_text(
                    textwrap.dedent(_FAKE_SCANNER),
                    encoding="utf-8",
                )
                executable.chmod(0o755)

            original = Path.cwd()
            try:
                os.chdir(workspace)
                with mock.patch.dict(
                    os.environ,
                    {"PATH": f"{tools}{os.pathsep}{os.environ.get('PATH', '')}"},
                ):
                    exit_code = main(
                        [
                            "--profile",
                            "advisory",
                            "scan",
                            "--execution",
                            "native",
                        ]
                    )
            finally:
                os.chdir(original)

            self.assertEqual(exit_code, 0)
            report_root = workspace / "secweaver-reports"
            expected = {
                ".secweaver-output",
                "junit.xml",
                "report-manifest.json",
                "results.sarif",
                "sbom.cdx.json",
                "summary.json",
                "summary.md",
                "verdict.json",
            }
            self.assertTrue(expected.issubset({path.name for path in report_root.iterdir()}))

            summary = json.loads((report_root / "summary.json").read_text(encoding="utf-8"))
            self.assertTrue(summary["policy"]["passed"])
            self.assertEqual(summary["languages"], {"Python": 1})
            self.assertEqual(
                [row["status"] for row in summary["scanners"]],
                ["clean", "clean", "clean", "clean", "clean"],
            )

            manifest = json.loads(
                (report_root / "report-manifest.json").read_text(encoding="utf-8")
            )
            self.assertNotIn(
                ".secweaver-output",
                {entry["path"] for entry in manifest["files"]},
            )
            for entry in manifest["files"]:
                artifact = report_root / entry["path"]
                self.assertEqual(entry["size_bytes"], artifact.stat().st_size)
                self.assertEqual(
                    entry["sha256"],
                    hashlib.sha256(artifact.read_bytes()).hexdigest(),
                )

    def test_direct_public_report_write_is_purged_and_fails_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "fixture.py").write_text("# inert fixture\n", encoding="utf-8")

            def execute(*args, **kwargs):
                public = workspace / "secweaver-reports"
                (public / ".secweaver-output").write_text(
                    "synthetic private fixture\n",
                    encoding="utf-8",
                )
                (public / "unexpected-private.txt").write_text(
                    "synthetic private fixture\n",
                    encoding="utf-8",
                )
                return ScanOutcome(
                    results=(),
                    findings=(),
                    decision=PolicyDecision(
                        passed=True,
                        reasons=(),
                        counts={"TOTAL": 0},
                    ),
                    exit_code=0,
                )

            original = Path.cwd()
            try:
                os.chdir(workspace)
                with mock.patch("secweaver.cli.execute_all", side_effect=execute):
                    error = io.StringIO()
                    with redirect_stderr(error):
                        exit_code = main(
                            [
                                "--profile",
                                "advisory",
                                "scan",
                                "--execution",
                                "native",
                                "--no-sbom",
                            ]
                        )
            finally:
                os.chdir(original)

            self.assertEqual(exit_code, 2)
            self.assertIn("unexpected output was removed", error.getvalue())
            self.assertEqual(list((workspace / "secweaver-reports").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
