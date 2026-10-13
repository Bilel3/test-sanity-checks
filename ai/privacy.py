"""Redact credentials and network identifiers before any LLM request."""

from __future__ import annotations

import re


REDACTIONS = (
    (re.compile(r"(?i)\b(password|passwd|pwd|token|secret)\s*([=:])\s*([^\s,;]+)"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)(://)[^/@\s:]+:[^/@\s]+@"), r"\1[REDACTED]@"),
    (re.compile(r"\b[^\s/:@]+/[^\s@]+@[^\s,;]+"), "[REDACTED_CONNECTION_STRING]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP_REDACTED]"),
)


def redact_secrets(value: str) -> str:
    for pattern, replacement in REDACTIONS:
        value = pattern.sub(replacement, value)
    return value