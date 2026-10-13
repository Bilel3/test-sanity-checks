"""Optional OpenAI-compatible LLM enrichment with strict JSON validation."""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

from jsonschema import ValidationError, validate

from ai.privacy import redact_secrets
from models import EnvironmentReport, Finding

LOGGER = logging.getLogger(__name__)
SEVERITY_RANK = {"INFO": 0, "WARNING": 1, "CRITICAL": 2}
RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["summary", "findings"],
    "additionalProperties": False,
    "properties": {
        "summary": {"type": "string", "minLength": 1},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["environment", "section", "severity", "item", "message", "evidence", "recommended_action"],
                "additionalProperties": False,
                "properties": {
                    "environment": {"type": "string"},
                    "section": {"type": "string"},
                    "severity": {"enum": ["CRITICAL", "WARNING", "INFO"]},
                    "item": {"type": "string"},
                    "message": {"type": "string"},
                    "evidence": {"type": "string"},
                    "recommended_action": {"type": "string"},
                },
            },
        },
    },
}


def _request(config: dict[str, Any], api_key: str, messages: list[dict[str, str]]) -> str:
    body = json.dumps({
        "model": config.get("model", "gpt-4o-mini"),
        "messages": messages,
        "response_format": {"type": "json_object"},
        "temperature": 0.1,
    }).encode("utf-8")
    request = urllib.request.Request(
        str(config["endpoint"]),
        data=body,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=float(config.get("timeout_seconds", 30))) as response:
        response_payload = json.loads(response.read().decode("utf-8"))
    return str(response_payload["choices"][0]["message"]["content"])


def _merge_findings(rule_findings: list[Finding], ai_findings: list[dict[str, str]], environment: str) -> list[Finding]:
    merged = list(rule_findings)
    positions = {(finding.section, finding.item.casefold()): index for index, finding in enumerate(merged)}
    for data in ai_findings:
        if data["environment"].casefold() != environment.casefold():
            continue
        key = (data["section"], data["item"].casefold())
        if key in positions:
            existing = merged[positions[key]]
            if existing.source == "rules":
                existing.severity = max(
                    (existing.severity, data["severity"]), key=lambda value: SEVERITY_RANK[value]
                )
                if data["recommended_action"]:
                    existing.recommended_action = data["recommended_action"]
                continue
        finding = Finding(**data, source="ai")
        positions[key] = len(merged)
        merged.append(finding)
    deduplicated: dict[tuple[str, str, str], Finding] = {}
    for finding in merged:
        key = (finding.section, finding.item.casefold(), finding.message.casefold())
        existing = deduplicated.get(key)
        if existing is None or SEVERITY_RANK[finding.severity] > SEVERITY_RANK[existing.severity]:
            deduplicated[key] = finding
    return list(deduplicated.values())


def enrich_environment(
    report: EnvironmentReport,
    section_payload: list[dict[str, str]],
    unparsed_content: str,
    config: dict[str, Any],
) -> EnvironmentReport:
    ai_config = config.get("ai", {})
    if not ai_config.get("enabled", False):
        report.summary = _fallback_summary(report.findings)
        return report
    if ai_config.get("provider", "openai_compatible") != "openai_compatible":
        LOGGER.warning("Unsupported AI provider; configure an OpenAI-compatible endpoint")
        report.summary = _fallback_summary(report.findings)
        return report
    api_key = os.getenv(str(ai_config.get("api_key_env", "LOGAGENT_API_KEY")))
    if not api_key:
        LOGGER.warning("AI enabled but API key environment variable is unset; using rule findings")
        report.summary = _fallback_summary(report.findings)
        return report

    payload = {
        "environment": report.environment,
        "sections": section_payload,
        "unparsed_content": unparsed_content,
        "rule_findings": [finding.to_dict() for finding in report.findings],
    }
    safe_payload = redact_secrets(json.dumps(payload, ensure_ascii=True))
    messages = [
        {
            "role": "system",
            "content": (
                "Analyze sanity-check logs. Interpret unparsed content, correlate and deduplicate findings, "
                "write a concise 2-4 line environment summary, and recommend remediation. Return only a JSON "
                "object matching the requested fields. Preserve every rule finding and never downgrade its "
                "severity. Do not infer secrets or expose masked values. Evidence must be at most five lines."
            ),
        },
        {"role": "user", "content": f"Return JSON matching this schema: {json.dumps(RESPONSE_SCHEMA)}\nInput: {safe_payload}"},
    ]
    raw = ""
    result: dict[str, Any] | None = None
    for attempt in range(2):
        try:
            raw = _request(ai_config, api_key, messages)
            result = json.loads(raw)
            validate(instance=result, schema=RESPONSE_SCHEMA)
            break
        except (json.JSONDecodeError, ValidationError, KeyError, TypeError) as error:
            LOGGER.warning("AI returned invalid structured output (attempt %d): %s", attempt + 1, error)
            if attempt == 0:
                messages.append({"role": "assistant", "content": raw})
                messages.append({"role": "user", "content": "Your previous response was invalid. Return only a corrected JSON object matching the schema exactly."})
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            LOGGER.warning("AI request failed; using deterministic findings: %s", error)
            break

    if result is None:
        report.summary = _fallback_summary(report.findings)
        return report
    for data in result["findings"]:
        data["evidence"] = "\n".join(data["evidence"].splitlines()[:5])
    report.findings = _merge_findings(report.findings, result["findings"], report.environment)
    report.summary = result["summary"].strip()
    return report


def _fallback_summary(findings: list[Finding]) -> str:
    critical = sum(finding.severity == "CRITICAL" for finding in findings)
    warning = sum(finding.severity == "WARNING" for finding in findings)
    if critical == 0 and warning == 0:
        return "All checks OK. No rule-based anomalies were detected in the analyzed logs."
    return f"Detected {critical} critical and {warning} warning finding(s). Review the attention items and recommended actions below."