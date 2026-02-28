import json
import tempfile
import unittest
from pathlib import Path

from bugbounty_tool import (
    ChatGPTTriage,
    Finding,
    LightweightScanner,
    ScanResult,
    SuppressionRule,
    compute_diff,
    load_baseline_fingerprints,
    load_targets,
    normalize_target,
)


class TestNormalizeTarget(unittest.TestCase):
    def test_adds_https_scheme(self):
        self.assertEqual(normalize_target("example.com"), "https://example.com")

    def test_preserves_http_scheme(self):
        self.assertEqual(normalize_target("http://example.com/path"), "http://example.com")

    def test_rejects_invalid_target(self):
        with self.assertRaises(ValueError):
            normalize_target("http://")


class TestLoadTargets(unittest.TestCase):
    def test_deduplicates_targets(self):
        class Args:
            target = ["a.com", "a.com", "b.com"]
            targets_file = None

        self.assertEqual(load_targets(Args), ["a.com", "b.com"])

    def test_loads_targets_file_and_ignores_comments(self):
        with tempfile.TemporaryDirectory() as tmp:
            targets_file = Path(tmp) / "targets.txt"
            targets_file.write_text("# comment\na.com\n\nb.com\n", encoding="utf-8")

            args = type("Args", (), {"target": ["a.com"], "targets_file": str(targets_file)})
            self.assertEqual(load_targets(args), ["a.com", "b.com"])


class TestLocalSummary(unittest.TestCase):
    def _f(self, title: str, severity: str) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            description="",
            evidence="e",
            target="https://example.com",
            recommendation="r",
            plugin_id="t.plugin",
            plugin_version="1.0.0",
            confidence=0.9,
            evidence_quality="high",
            fingerprint=f"fp-{title}",
        )

    def test_sorts_by_severity(self):
        triage = ChatGPTTriage()
        result = ScanResult(
            target="https://example.com",
            timestamp_utc="2020-01-01T00:00:00Z",
            metadata={},
            findings=[self._f("low item", "low"), self._f("high item", "high")],
        )
        summary = triage._local_summary([result])
        self.assertLess(summary.find("high item"), summary.find("low item"))

    def test_has_severity_summary_section(self):
        triage = ChatGPTTriage()
        result = ScanResult(
            target="https://example.com",
            timestamp_utc="2020-01-01T00:00:00Z",
            metadata={},
            findings=[self._f("one", "medium")],
        )
        summary = triage._local_summary([result])
        self.assertIn("## Severity Summary", summary)
        self.assertIn("- MEDIUM: 1", summary)


class TestSuppressionAndDiff(unittest.TestCase):
    def test_suppression_rule_match(self):
        scanner = LightweightScanner(suppression_rules=[SuppressionRule(plugin_id="web.jwt_misconfig", min_confidence=0.5)])
        finding = Finding(
            title="JWT token exposure in response",
            severity="medium",
            description="",
            evidence="e",
            target="https://x",
            recommendation="r",
            plugin_id="web.jwt_misconfig",
            plugin_version="1.0.0",
            confidence=0.8,
            evidence_quality="medium",
            fingerprint="abc",
        )
        self.assertTrue(scanner._is_suppressed(finding))

    def test_load_baseline_and_compute_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline = Path(tmp) / "baseline.json"
            baseline.write_text(
                json.dumps({"results": [{"findings": [{"fingerprint": "old"}]}]}),
                encoding="utf-8",
            )
            fps = load_baseline_fingerprints(str(baseline))
            self.assertEqual(fps, {"old"})

            result = ScanResult(
                target="https://example.com",
                timestamp_utc="2020-01-01T00:00:00Z",
                metadata={},
                findings=[
                    Finding("new", "low", "", "e", "https://example.com", "r", "p", "1", 0.4, "low", "new"),
                    Finding("old", "low", "", "e", "https://example.com", "r", "p", "1", 0.4, "low", "old"),
                ],
            )
            diff = compute_diff([result], fps)
            self.assertIsNotNone(diff)
            self.assertEqual(len(diff.new_findings), 1)
            self.assertEqual(diff.new_findings[0].fingerprint, "new")


if __name__ == "__main__":
    unittest.main()
