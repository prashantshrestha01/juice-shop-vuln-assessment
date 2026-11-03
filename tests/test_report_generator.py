"""Tests for report_generator.py -- stdlib unittest only."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from report_generator import (  # noqa: E402
    count_severities,
    generate_markdown,
    load_findings,
    parse_yaml_lite,
    validate_findings,
)


def finding(**overrides):
    base = {
        "id": "JS-001",
        "title": "Example finding",
        "category": "A03:2021-Injection",
        "severity": "High",
        "description": "Observed locally.",
        "evidence": "Local steps.",
    }
    base.update(overrides)
    return base


class TestSeverityCounting(unittest.TestCase):
    def test_counts_include_zeroes(self):
        counts = count_severities([finding(severity="High"), finding(severity="Low")])
        self.assertEqual(counts["High"], 1)
        self.assertEqual(counts["Low"], 1)
        self.assertEqual(counts["Critical"], 0)
        self.assertEqual(counts["Info"], 0)

    def test_counts_sum_to_total(self):
        findings = [finding(severity=s) for s in ("Critical", "High", "Medium", "Low", "Info", "High")]
        counts = count_severities(findings)
        self.assertEqual(sum(counts.values()), len(findings))

    def test_empty_findings_all_zero(self):
        counts = count_severities([])
        self.assertTrue(all(v == 0 for v in counts.values()))


class TestReportGeneration(unittest.TestCase):
    def test_report_contains_counts_and_titles(self):
        findings = validate_findings(
            [finding(severity="Critical"), finding(title="Second", severity="Low")]
        )
        report = generate_markdown(findings, target="Local lab", date="2026-10-30")
        self.assertIn("| Critical | 1 |", report)
        self.assertIn("| Low | 1 |", report)
        self.assertIn("Example finding", report)
        self.assertIn("Second", report)
        self.assertIn("LOCAL LAB ONLY", report)

    def test_report_sorts_critical_first(self):
        findings = validate_findings(
            [finding(title="Low one", severity="Low"), finding(title="Crit one", severity="Critical")]
        )
        report = generate_markdown(findings)
        self.assertLess(report.index("Crit one"), report.index("Low one"))

    def test_report_includes_remediation(self):
        report = generate_markdown(validate_findings([finding()]))
        self.assertIn("Remediation:", report)
        self.assertIn("parameterised", report)

    def test_empty_report_is_explicit(self):
        report = generate_markdown([])
        self.assertIn("Total findings:** 0", report)
        self.assertIn("No findings recorded", report)

    def test_severity_case_is_normalised(self):
        findings = validate_findings([finding(severity="HIGH")])
        self.assertEqual(findings[0]["severity"], "High")

    def test_checklist_file_covers_all_ten(self):
        checklist = json.loads((Path(__file__).resolve().parent.parent / "checklist.json").read_text())
        self.assertEqual(len(checklist), 10)
        ids = [entry["id"] for entry in checklist]
        self.assertEqual(ids, [f"A{i:02d}" for i in range(1, 11)])
        for entry in checklist:
            self.assertTrue(entry["test_ideas"])
            self.assertTrue(entry["evidence_fields"])


class TestValidationRejectsMalformed(unittest.TestCase):
    def test_missing_title_rejected(self):
        bad = finding()
        del bad["title"]
        with self.assertRaises(ValueError):
            validate_findings([bad])

    def test_missing_severity_rejected(self):
        bad = finding()
        del bad["severity"]
        with self.assertRaises(ValueError):
            validate_findings([bad])

    def test_invalid_severity_rejected(self):
        with self.assertRaises(ValueError):
            validate_findings([finding(severity="Severe")])

    def test_non_object_finding_rejected(self):
        with self.assertRaises(ValueError):
            validate_findings(["not-a-dict"])

    def test_non_list_top_level_rejected(self):
        with self.assertRaises((ValueError, TypeError)):
            validate_findings("not-a-list")

    def test_object_without_findings_key_rejected(self):
        with self.assertRaises(ValueError):
            validate_findings({"target": "local"})

    def test_malformed_json_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("{not json")
            with self.assertRaises(ValueError):
                load_findings(path)

    def test_yaml_lite_parses(self):
        parsed = parse_yaml_lite("- id: JS-001\n  title: Hello\n  category: A03:2021-Injection\n  severity: High\n")
        self.assertEqual(parsed[0]["title"], "Hello")
        findings = validate_findings(parsed)
        self.assertEqual(findings[0]["severity"], "High")


if __name__ == "__main__":
    unittest.main()
