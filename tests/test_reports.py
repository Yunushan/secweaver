from __future__ import annotations

import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from secweaver.config import load_config
from secweaver.models import ScannerResult
from secweaver.reports import (
    OUTPUT_MARKER_CONTENT,
    OUTPUT_MARKER_NAME,
    ReportError,
    _load_json,
    evaluate_policy,
    parse_scanner_report,
    sanitize_raw_report,
    write_manifest,
    write_reports,
)
from tests._helpers import (
    REPORT_FIXTURES,
    SYNTHETIC_CANARY,
    load_json_fixture,
    scanner_result,
    write_json,
)


class ScannerParserTests(unittest.TestCase):
    def test_gitleaks_parser_normalizes_finding(self) -> None:
        result = scanner_result(
            "gitleaks",
            report_path=REPORT_FIXTURES / "gitleaks.json",
        )
        findings = parse_scanner_report(result, REPORT_FIXTURES)
        self.assertEqual(len(findings), 1)
        item = findings[0]
        self.assertEqual(item.scanner, "gitleaks")
        self.assertEqual(item.rule_id, "fixture.pattern")
        self.assertEqual(item.severity, "HIGH")
        self.assertEqual(item.category, "secret")
        self.assertEqual(item.location, "src/example.py:7")
        self.assertEqual(item.fingerprint, "fixture-fingerprint-gitleaks-1")

    def test_trivy_parser_handles_all_supported_finding_groups(self) -> None:
        result = scanner_result(
            "trivy",
            report_path=REPORT_FIXTURES / "trivy.json",
        )
        findings = parse_scanner_report(result, REPORT_FIXTURES)
        self.assertEqual(len(findings), 4)
        by_category = {item.category: item for item in findings}
        self.assertEqual(
            set(by_category),
            {"vulnerability", "misconfiguration", "secret", "license"},
        )
        self.assertEqual(by_category["vulnerability"].severity, "CRITICAL")
        self.assertEqual(by_category["misconfiguration"].severity, "MEDIUM")
        self.assertEqual(by_category["secret"].severity, "HIGH")
        self.assertEqual(by_category["license"].severity, "LOW")
        self.assertEqual(
            by_category["vulnerability"].references,
            ("https://example.invalid/advisories/SWV-0001",),
        )
        self.assertEqual(
            by_category["vulnerability"].fingerprint,
            "pkg:generic/fixture-lib@0.0.0-test",
        )

    def test_trivy_clean_report_envelope_may_omit_results(self) -> None:
        result = scanner_result(
            "trivy",
            report_path=REPORT_FIXTURES / "trivy-clean.json",
        )
        self.assertEqual(parse_scanner_report(result, REPORT_FIXTURES), [])

    def test_trivy_suppressed_findings_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trivy.json"
            write_json(
                path,
                {
                    "Results": [
                        {
                            "Target": "fixture.tf",
                            "ExperimentalModifiedFindings": [
                                {"Status": "suppressed", "Finding": None}
                            ],
                        }
                    ],
                },
            )
            findings = parse_scanner_report(
                scanner_result("trivy", report_path=path),
                Path(directory),
            )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "trivy.suppressed-finding")
        self.assertEqual(findings[0].severity, "HIGH")

    def test_opengrep_sarif_parser_uses_rule_default_and_result_level(self) -> None:
        result = scanner_result(
            "opengrep",
            report_path=REPORT_FIXTURES / "opengrep.sarif.json",
        )
        findings = parse_scanner_report(result, REPORT_FIXTURES)
        self.assertEqual(len(findings), 2)
        by_rule = {item.rule_id: item for item in findings}
        self.assertEqual(by_rule["fixture.warning"].severity, "MEDIUM")
        self.assertEqual(by_rule["fixture.warning"].location, "src/example.py:11")
        self.assertEqual(
            by_rule["fixture.warning"].fingerprint,
            "fixture-fingerprint-opengrep-1",
        )
        self.assertEqual(by_rule["fixture.error"].severity, "HIGH")
        self.assertEqual(by_rule["fixture.error"].location, "")

    def test_osv_parser_handles_grouped_aliases_and_ungrouped_vulnerability(self) -> None:
        result = scanner_result("osv", report_path=REPORT_FIXTURES / "osv.json")
        findings = parse_scanner_report(result, REPORT_FIXTURES)
        self.assertEqual(len(findings), 2)
        by_rule = {item.rule_id: item for item in findings}
        self.assertEqual(by_rule["SWV-1000"].severity, "CRITICAL")
        self.assertIn("SWV-1000-ALIAS", by_rule["SWV-1000"].message)
        self.assertEqual(by_rule["SWV-2000"].severity, "CRITICAL")
        self.assertEqual(by_rule["SWV-2000"].location, "requirements.lock")
        self.assertEqual(
            by_rule["SWV-2000"].references,
            ("https://osv.dev/SWV-2000",),
        )

    def test_osv_group_maximum_and_vectors_fail_closed_at_blocking_severity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "osv.json"
            data = {
                "results": [
                    {
                        "packages": [
                            {
                                "package": {"name": "fixture", "version": "1"},
                                "groups": [
                                    {
                                        "ids": ["SWV-MAX"],
                                        "max_severity": "9.8",
                                    }
                                ],
                                "vulnerabilities": [
                                    {
                                        "id": "SWV-MAX",
                                        "severity": [
                                            {
                                                "type": "CVSS_V3",
                                    "score": (
                                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                                        "S:U/C:H/I:H/A:N"
                                    ),
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                        "source": {"path": "fixture.lock"},
                    }
                ]
            }
            write_json(path, data)
            findings = parse_scanner_report(
                scanner_result("osv", report_path=path),
                Path(directory),
            )
            self.assertEqual(findings[0].severity, "CRITICAL")

    def test_missing_report_path_and_missing_file_are_errors(self) -> None:
        with self.assertRaisesRegex(ReportError, "has no report path"):
            parse_scanner_report(ScannerResult(scanner="trivy", status="clean"), REPORT_FIXTURES)
        with self.assertRaisesRegex(ReportError, "did not create"):
            parse_scanner_report(
                scanner_result(
                    "trivy",
                    report_path=REPORT_FIXTURES / "does-not-exist.json",
                ),
                REPORT_FIXTURES,
            )

    def test_malformed_json_and_wrong_roots_are_errors(self) -> None:
        with self.assertRaisesRegex(ReportError, "not valid JSON"):
            parse_scanner_report(
                scanner_result(
                    "trivy",
                    report_path=REPORT_FIXTURES / "malformed.json",
                ),
                REPORT_FIXTURES,
            )
        expectations = {
            "gitleaks": "root must be an array",
            "trivy": "Trivy report",
            "opengrep": "missing runs",
            "osv": "results array",
        }
        for scanner, message in expectations.items():
            with self.subTest(scanner=scanner), self.assertRaisesRegex(ReportError, message):
                parse_scanner_report(
                    scanner_result(
                        scanner,
                        report_path=REPORT_FIXTURES / "wrong-root.json",
                    ),
                    REPORT_FIXTURES,
                )

    def test_symlink_report_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "linked.json"
            try:
                os.symlink(REPORT_FIXTURES / "gitleaks.json", link)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            with self.assertRaisesRegex(ReportError, "not a regular file"):
                parse_scanner_report(
                    scanner_result("gitleaks", report_path=link),
                    REPORT_FIXTURES,
                )

    def test_report_size_limit_is_enforced_before_json_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.json"
            path.write_text('{"fixture": true}\n', encoding="utf-8")
            with self.assertRaisesRegex(ReportError, "exceeds"):
                _load_json(path, max_bytes=4)

    def test_unknown_scanner_is_rejected(self) -> None:
        with self.assertRaisesRegex(ReportError, "No parser registered"):
            parse_scanner_report(
                scanner_result(
                    "fixture-unknown",
                    report_path=REPORT_FIXTURES / "wrong-root.json",
                ),
                REPORT_FIXTURES,
            )

    def test_sbom_requires_minimal_cyclonedx_structure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = root / "invalid-sbom.json"
            valid = root / "valid-sbom.json"
            write_json(invalid, {"bomFormat": "CycloneDX"})
            write_json(
                valid,
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "components": [],
                },
            )
            with self.assertRaisesRegex(ReportError, "specVersion"):
                parse_scanner_report(
                    scanner_result("sbom", report_path=invalid),
                    root,
                )
            self.assertEqual(
                parse_scanner_report(
                    scanner_result("sbom", report_path=valid),
                    root,
                ),
                [],
            )


class ReportSanitizationTests(unittest.TestCase):
    def test_raw_reports_remove_canary_and_absolute_target_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "workspace"
            target.mkdir()
            raw = root / "raw"

            data_by_scanner = {
                "gitleaks": load_json_fixture("gitleaks.json"),
                "trivy": load_json_fixture("trivy.json"),
                "opengrep": load_json_fixture("opengrep.sarif.json"),
                "osv": load_json_fixture("osv.json"),
            }
            data_by_scanner["gitleaks"][0].update(
                {
                    "Secret": SYNTHETIC_CANARY,
                    "Match": SYNTHETIC_CANARY,
                    "Line": SYNTHETIC_CANARY,
                    "Author": "Synthetic Fixture",
                    "Email": "fixture@example.invalid",
                    "Message": SYNTHETIC_CANARY,
                    "File": str(target / "src/example.py"),
                }
            )
            trivy_secret = data_by_scanner["trivy"]["Results"][0]["Secrets"][0]
            trivy_secret.update(
                {
                    "Match": SYNTHETIC_CANARY,
                    "Code": {"fixture": SYNTHETIC_CANARY},
                    "Line": SYNTHETIC_CANARY,
                }
            )
            data_by_scanner["trivy"]["Results"][0]["Target"] = str(
                target / "requirements.lock"
            )
            region = data_by_scanner["opengrep"]["runs"][0]["results"][0]["locations"][0][
                "physicalLocation"
            ]["region"]
            region["snippet"] = {"text": SYNTHETIC_CANARY}
            data_by_scanner["osv"]["authorization"] = SYNTHETIC_CANARY

            for scanner, data in data_by_scanner.items():
                with self.subTest(scanner=scanner):
                    path = write_json(raw / f"{scanner}.json", data)
                    result = scanner_result(scanner, report_path=path)
                    sanitize_raw_report(result, target)
                    sanitized = path.read_text(encoding="utf-8")
                    self.assertNotIn(SYNTHETIC_CANARY, sanitized)
                    self.assertNotIn(str(target), sanitized)

    def test_normalized_outputs_and_sanitized_raw_reports_contain_no_canary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "workspace"
            target.mkdir()
            report_root = root / "reports"
            report_root.mkdir()
            (report_root / OUTPUT_MARKER_NAME).write_bytes(OUTPUT_MARKER_CONTENT)
            raw = report_root / "raw"

            data_by_scanner = {
                "gitleaks": load_json_fixture("gitleaks.json"),
                "trivy": load_json_fixture("trivy.json"),
                "opengrep": load_json_fixture("opengrep.sarif.json"),
                "osv": load_json_fixture("osv.json"),
            }
            data_by_scanner["gitleaks"][0]["Secret"] = SYNTHETIC_CANARY
            data_by_scanner["gitleaks"][0]["Description"] = (
                f"token={SYNTHETIC_CANARY}"
            )
            trivy_secret = data_by_scanner["trivy"]["Results"][0]["Secrets"][0]
            trivy_secret["Match"] = SYNTHETIC_CANARY
            trivy_secret["Title"] = f"authorization: {SYNTHETIC_CANARY}"
            opengrep_result = data_by_scanner["opengrep"]["runs"][0]["results"][0]
            opengrep_result["message"]["text"] = f"Bearer {SYNTHETIC_CANARY}"
            opengrep_result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": SYNTHETIC_CANARY
            }
            data_by_scanner["osv"]["authorization"] = SYNTHETIC_CANARY

            results: list[ScannerResult] = []
            findings = []
            for scanner, data in data_by_scanner.items():
                suffix = "sarif" if scanner == "opengrep" else "json"
                path = write_json(raw / f"{scanner}.{suffix}", data)
                result = scanner_result(scanner, report_path=path)
                result.findings = parse_scanner_report(result, target)
                result.status = "findings" if result.findings else "clean"
                findings.extend(result.findings)
                sanitize_raw_report(result, target)
                results.append(result)

            config = load_config(env={})
            decision = evaluate_policy(config, results, findings)
            started = datetime(2026, 1, 1, tzinfo=UTC)
            write_reports(
                config,
                report_root=report_root,
                target=target,
                results=results,
                findings=findings,
                decision=decision,
                languages={"Python": 1},
                started_at=started,
                finished_at=started,
            )
            write_manifest(report_root)

            for path in report_root.rglob("*"):
                if path.is_file() and not path.is_symlink():
                    with self.subTest(path=path.name):
                        self.assertNotIn(
                            SYNTHETIC_CANARY,
                            path.read_text(encoding="utf-8", errors="replace"),
                        )

    def test_attacker_controlled_osv_package_name_is_redacted_from_normalized_outputs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "workspace"
            target.mkdir()
            report_root = root / "reports"
            data = load_json_fixture("osv.json")
            data["results"][0]["packages"][0]["package"]["name"] = (
                f"token={SYNTHETIC_CANARY}"
            )
            path = write_json(report_root / "raw/osv.json", data)
            result = scanner_result("osv", report_path=path)
            result.findings = parse_scanner_report(result, target)
            result.status = "findings"
            config = load_config(env={})
            decision = evaluate_policy(config, [result], result.findings)
            started = datetime(2026, 1, 1, tzinfo=UTC)
            write_reports(
                config,
                report_root=report_root,
                target=target,
                results=[result],
                findings=result.findings,
                decision=decision,
                languages={},
                started_at=started,
                finished_at=started,
            )
            normalized = (
                "summary.json",
                "verdict.json",
                "summary.md",
                "junit.xml",
                "results.sarif",
            )
            for name in normalized:
                with self.subTest(name=name):
                    self.assertNotIn(
                        SYNTHETIC_CANARY,
                        (report_root / name).read_text(encoding="utf-8"),
                    )


if __name__ == "__main__":
    unittest.main()
