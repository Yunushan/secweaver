from __future__ import annotations

import unittest

from secweaver.config import load_config
from secweaver.models import Finding, ScannerResult
from secweaver.reports import evaluate_policy


def finding(
    *,
    severity: str = "LOW",
    category: str = "vulnerability",
    suffix: str = "1",
) -> Finding:
    return Finding(
        scanner="fixture",
        rule_id=f"fixture.rule.{suffix}",
        severity=severity,
        category=category,
        message="Synthetic policy fixture",
        fingerprint=f"fixture-fingerprint-{suffix}",
    )


class PolicyEvaluationTests(unittest.TestCase):
    def test_balanced_profile_fails_for_missing_required_scanner(self) -> None:
        config = load_config(env={})
        result = ScannerResult(scanner="gitleaks", status="missing")
        decision = evaluate_policy(config, [result], [])
        self.assertFalse(decision.passed)
        self.assertIn("Required scanner unavailable: gitleaks", decision.reasons)

    def test_missing_optional_scanner_does_not_fail(self) -> None:
        config = load_config(
            env={},
            overrides={"scan": {"required_scanners": ["gitleaks"]}},
        )
        decision = evaluate_policy(
            config,
            [ScannerResult(scanner="trivy", status="missing")],
            [],
        )
        self.assertTrue(decision.passed)

    def test_scanner_error_states_fail_when_policy_requires_it(self) -> None:
        config = load_config(env={})
        for status in ("error", "timeout", "invalid-report"):
            with self.subTest(status=status):
                decision = evaluate_policy(
                    config,
                    [ScannerResult(scanner="trivy", status=status)],
                    [],
                )
                self.assertFalse(decision.passed)
                self.assertIn(
                    "Scanner did not complete successfully: trivy",
                    decision.reasons,
                )

    def test_not_applicable_skip_is_ignored(self) -> None:
        config = load_config(env={})
        result = ScannerResult(
            scanner="gitleaks",
            status="skipped",
            error="not applicable",
        )
        self.assertTrue(evaluate_policy(config, [result], []).passed)

    def test_blocking_severity_and_category_are_both_enforced(self) -> None:
        config = load_config(env={})
        cases = (
            finding(severity="HIGH", category="vulnerability", suffix="severity"),
            finding(severity="LOW", category="secret", suffix="category"),
        )
        for item in cases:
            with self.subTest(item=item.rule_id):
                decision = evaluate_policy(config, [], [item])
                self.assertFalse(decision.passed)
                self.assertIn("1 finding(s) matched the blocking policy", decision.reasons)

    def test_nonblocking_finding_passes_and_counts_are_preserved(self) -> None:
        config = load_config(env={})
        decision = evaluate_policy(
            config,
            [],
            [finding(severity="LOW", category="vulnerability")],
        )
        self.assertTrue(decision.passed)
        self.assertEqual(decision.counts, {"LOW": 1, "TOTAL": 1})

    def test_max_findings_is_an_independent_policy_gate(self) -> None:
        config = load_config(
            env={},
            overrides={
                "policy": {
                    "fail_on_severities": [],
                    "fail_on_categories": [],
                    "max_findings": 1,
                }
            },
        )
        decision = evaluate_policy(
            config,
            [],
            [finding(suffix="one"), finding(suffix="two")],
        )
        self.assertFalse(decision.passed)
        self.assertIn("Total findings 2 exceed policy maximum 1", decision.reasons)

    def test_advisory_profile_warns_without_failing(self) -> None:
        config = load_config(env={}, overrides={"scan": {"profile": "advisory"}})
        results = [
            ScannerResult(scanner="gitleaks", status="missing"),
            ScannerResult(scanner="trivy", status="error"),
        ]
        decision = evaluate_policy(
            config,
            results,
            [finding(severity="CRITICAL", category="secret")],
        )
        self.assertTrue(decision.passed)
        self.assertEqual(decision.reasons, ())
        self.assertEqual(decision.counts["CRITICAL"], 1)


if __name__ == "__main__":
    unittest.main()
