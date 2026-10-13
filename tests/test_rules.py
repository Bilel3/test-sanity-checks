import unittest
from pathlib import Path

from analyzer import analyze, load_config
from parser.sections import parse_sections
from rules.detect import detect_findings


ROOT = Path(__file__).resolve().parents[1]


class RuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_config(ROOT / "config.yaml")

    def test_healthy_sample_has_no_findings(self) -> None:
        report = analyze([ROOT / "sample_logs/PROD_healthy.log"], self.config)

        self.assertEqual(report.environments[0].environment, "PROD")
        self.assertEqual(report.environments[0].findings, [])
        self.assertTrue(all(status == "OK" for status in report.environments[0].section_status.values()))

    def test_failing_sample_covers_all_anomaly_sections(self) -> None:
        path = ROOT / "sample_logs/UAT_failing.log"
        report = analyze([path], self.config).environments[0]
        sections = {finding.section for finding in report.findings}

        self.assertTrue({"COB STATUS", "NPK COB", "FRA", "DB OUZELUM", "CFT", "MQ", "APPLICATION", "FS"}.issubset(sections))
        self.assertTrue(any(finding.severity == "CRITICAL" for finding in report.findings))

    def test_missing_section_is_critical_and_marked_missing(self) -> None:
        path = ROOT / "sample_logs/DEV_missing_section.log"
        report = analyze([path], self.config).environments[0]

        self.assertEqual(report.section_status["MQ"], "MISSING")
        self.assertTrue(any(finding.section == "MQ" and finding.severity == "CRITICAL" for finding in report.findings))

    def test_unseen_database_name_is_dynamic(self) -> None:
        text = (ROOT / "sample_logs/PREPROD_new_db.log").read_text()
        parsed = parse_sections(text)
        findings = detect_findings("PREPROD", parsed, text, self.config, "new-db.log")

        self.assertIn("DB XXX", [section.name for section in parsed.sections])
        self.assertFalse(any(finding.section == "DB XXX" and finding.severity == "CRITICAL" for finding in findings))


if __name__ == "__main__":
    unittest.main()