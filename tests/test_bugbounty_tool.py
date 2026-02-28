import tempfile
import unittest
from pathlib import Path

from bugbounty_tool import ChatGPTTriage, Finding, ScanResult, load_targets, normalize_target


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
    def test_sorts_by_severity(self):
        triage = ChatGPTTriage()
        result = ScanResult(
            target="https://example.com",
            timestamp_utc="2020-01-01T00:00:00Z",
            metadata={},
            findings=[
                Finding("low item", "low", "", "e1", "https://example.com", "r1"),
                Finding("high item", "high", "", "e2", "https://example.com", "r2"),
            ],
        )
        summary = triage._local_summary([result])
        self.assertLess(summary.find("high item"), summary.find("low item"))

    def test_has_severity_summary_section(self):
        triage = ChatGPTTriage()
        result = ScanResult(
            target="https://example.com",
            timestamp_utc="2020-01-01T00:00:00Z",
            metadata={},
            findings=[Finding("one", "medium", "", "e", "https://example.com", "r")],
        )
        summary = triage._local_summary([result])
        self.assertIn("## Severity Summary", summary)
        self.assertIn("- MEDIUM: 1", summary)


if __name__ == "__main__":
    unittest.main()
