"""Shared typed data models for analysis and reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal


Severity = Literal["CRITICAL", "WARNING", "INFO"]


@dataclass
class Finding:
    environment: str
    section: str
    severity: Severity
    item: str
    message: str
    evidence: str
    recommended_action: str
    source: str = "rules"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class EnvironmentReport:
    environment: str
    summary: str
    findings: list[Finding]
    section_status: dict[str, str]


@dataclass
class AnalysisReport:
    generated_at: str
    report_date: str
    environments: list[EnvironmentReport]