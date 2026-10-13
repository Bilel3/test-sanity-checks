"""Coordinate input parsing, deterministic rules, optional AI, and reporting data."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from ai.client import enrich_environment
from models import AnalysisReport, EnvironmentReport, Finding
from parser.inputs import InputLog, discover_logs, load_input_logs
from parser.sections import ParsedLog, Section, parse_sections
from rules.detect import detect_findings

LOGGER = logging.getLogger(__name__)


def load_config(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as stream:
        config = yaml.safe_load(stream) or {}
    if not isinstance(config, dict):
        raise ValueError("Configuration root must be a YAML mapping")
    return config


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    unique: dict[tuple[str, str, str], Finding] = {}
    rank = {"INFO": 0, "WARNING": 1, "CRITICAL": 2}
    for finding in findings:
        key = (finding.section, finding.item.casefold(), finding.message.casefold())
        old = unique.get(key)
        if old is None or rank[finding.severity] > rank[old.severity]:
            unique[key] = finding
    return list(unique.values())


def _section_status(expected: list[str], sections: list[Section], findings: list[Finding]) -> dict[str, str]:
    status: dict[str, str] = {name: "OK" for name in expected}
    for section in sections:
        status.setdefault(section.name, "OK")
    for finding in findings:
        if finding.section not in status:
            status[finding.section] = "OK"
        if (
            finding.severity == "CRITICAL"
            and (finding.message.startswith("Expected section ") or finding.message.startswith("No input log was found"))
        ):
            status[finding.section] = "MISSING"
        elif finding.severity == "CRITICAL":
            status[finding.section] = "CRITICAL"
        elif finding.severity == "WARNING" and status[finding.section] not in {"CRITICAL", "MISSING"}:
            status[finding.section] = "WARNING"
    return status


def _build_environment(
    environment: str,
    records: list[InputLog],
    config: dict[str, Any],
) -> EnvironmentReport:
    all_findings: list[Finding] = []
    all_sections: list[Section] = []
    section_payload: list[dict[str, str]] = []
    unparsed: list[str] = []
    for record in records:
        parsed = parse_sections(record.text)
        LOGGER.info("Parsed input", extra={"source": str(record.path), "environment": environment, "sections": len(parsed.sections)})
        all_sections.extend(parsed.sections)
        section_payload.extend(
            {"section": section.name, "title": section.title, "content": section.content}
            for section in parsed.sections
        )
        if parsed.unparsed_content:
            unparsed.append(f"Source: {record.path.name}\n{parsed.unparsed_content}")
        all_findings.extend(detect_findings(environment, parsed, record.text, config, record.path.name))

    findings = _deduplicate(all_findings)
    result = EnvironmentReport(
        environment=environment,
        summary="",
        findings=findings,
        section_status=_section_status(list(config.get("expected_sections", [])), all_sections, findings),
    )
    return enrich_environment(result, section_payload, "\n\n".join(unparsed), config)


def analyze(inputs: list[str | Path], config: dict[str, Any]) -> AnalysisReport:
    paths = discover_logs(inputs)
    if not paths:
        raise ValueError("No .log files found in the supplied input")
    records = load_input_logs(paths, config)
    by_environment: dict[str, list[InputLog]] = defaultdict(list)
    for record in records:
        by_environment[record.environment].append(record)

    required = set(str(value) for value in config.get("required_environments", []))
    for environment in sorted(required - set(by_environment)):
        LOGGER.warning("Required environment has no matching input logs", extra={"environment": environment})
        by_environment[environment] = []

    reports: list[EnvironmentReport] = []
    for environment, env_records in by_environment.items():
        if not env_records and environment in required:
            findings = [Finding(
                environment, section, "CRITICAL", section,
                f"No input log was found for required environment {environment}.",
                "No source log was provided.",
                "Include the environment's daily sanity-check log or remove it from required_environments.",
            ) for section in config.get("expected_sections", [])]
            result = EnvironmentReport(environment, "", findings, {section: "MISSING" for section in config.get("expected_sections", [])})
            reports.append(enrich_environment(result, [], "", config))
        elif env_records:
            reports.append(_build_environment(environment, env_records, config))

    declared = [str(value) for value in config.get("environments", [])]
    order = {environment: index for index, environment in enumerate(declared)}
    reports.sort(key=lambda item: (order.get(item.environment, len(order)), item.environment))
    now = datetime.now().astimezone()
    return AnalysisReport(now.isoformat(timespec="seconds"), now.date().isoformat(), reports)