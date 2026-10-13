import unittest
from unittest.mock import patch

from ai.client import _merge_findings, enrich_environment
from ai.privacy import redact_secrets
from models import AnalysisReport, EnvironmentReport, Finding
from report.generate import render_html


class ReportAndAiTests(unittest.TestCase):
    def test_report_is_self_contained_and_renders_findings(self) -> None:
        finding = Finding("PROD", "FS", "CRITICAL", "/var", "Full disk", "/var 99%", "Free space")
        report = AnalysisReport("2026-10-13T06:15:00+00:00", "2026-10-13", [
            EnvironmentReport("PROD", "Disk is full.", [finding], {"FS": "CRITICAL"}),
        ])

        html = render_html(report)

        self.assertIn("Full disk", html)
        self.assertIn("Points requiring attention", html)
        self.assertIn("Findings by environment", html)
        self.assertIn('id="environment-chart"', html)
        self.assertNotIn('<script src=', html)
        self.assertIn('id="critical-count"', html)

    def test_redaction_masks_credentials_urls_connection_strings_and_ips(self) -> None:
        redacted = redact_secrets("password=secret http://user:pass@host user/pass@db 10.2.3.4")

        self.assertNotIn("secret", redacted)
        self.assertNotIn("user:pass", redacted)
        self.assertNotIn("user/pass", redacted)
        self.assertNotIn("10.2.3.4", redacted)

    def test_rule_critical_severity_cannot_be_downgraded(self) -> None:
        critical = Finding("PROD", "FS", "CRITICAL", "/var", "Usage critical", "99%", "Investigate")
        merged = _merge_findings([critical], [{
            "environment": "PROD", "section": "FS", "severity": "INFO", "item": "/var",
            "message": "Usage normal", "evidence": "99%", "recommended_action": "Check mount",
        }], "PROD")

        self.assertEqual(merged[0].severity, "CRITICAL")

    @patch("ai.client._request", return_value='not json')
    def test_invalid_ai_output_retries_once_then_falls_back(self, request) -> None:
        report = EnvironmentReport("PROD", "", [], {"FS": "OK"})
        config = {"ai": {"enabled": True, "api_key_env": "LOGAGENT_TEST_KEY", "endpoint": "https://invalid", "model": "test"}}

        with patch.dict("os.environ", {"LOGAGENT_TEST_KEY": "test-key"}):
            enriched = enrich_environment(report, [], "", config)

        self.assertEqual(request.call_count, 2)
        self.assertIn("No rule-based anomalies", enriched.summary)


if __name__ == "__main__":
    unittest.main()