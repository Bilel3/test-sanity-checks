"""Rule-based anomaly detection for parsed sanity-check sections."""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any

from models import Finding
from parser.sections import ParsedLog, Section


GLOBAL_ERROR_RE = re.compile(
    r"\b(ERROR|FAILED|FAILURE|KO|ORA-\d+|EXCEPTION|TIMEOUT)\b|"
    r"No such file|Permission denied",
    re.IGNORECASE,
)
DATE_RE = re.compile(r"\b\d{1,2}-[A-Z]{3}-\d{2,4}\b|\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}/\d{1,2}/\d{4}\b", re.I)
NUMBER_RE = re.compile(r"\d+(?:\.\d+)?")


def _evidence(lines: list[str], index: int, radius: int = 2) -> str:
    start = max(0, index - radius)
    return "\n".join(lines[start : start + 5])[:2000]


def _finding(
    environment: str,
    section: str,
    severity: str,
    item: str,
    message: str,
    evidence: str,
    action: str,
) -> Finding:
    return Finding(environment, section, severity, item, message, evidence, action)  # type: ignore[arg-type]


def _tokens(config: dict[str, Any], key: str) -> set[str]:
    return {str(token).upper() for token in config.get(key, [])}


def _branch_rows(section: Section) -> tuple[list[tuple[str, str, int]], dict[str, int]]:
    lines = section.content.splitlines()
    header: dict[str, int] = {}
    rows: list[tuple[str, str, int]] = []
    for index, line in enumerate(lines):
        columns = re.split(r"\s+", line.strip())
        upper = [column.upper().strip("|:") for column in columns]
        if "BRANCH" in upper and "STATUS" in upper:
            header = {value: position for position, value in enumerate(upper)}
            continue
        if header and len(columns) >= 2 and not set(upper).issubset({"-", "="}):
            if re.fullmatch(r"[|=+-]+", line.strip()):
                continue
            branch_index = header.get("BRANCH", 0)
            status_index = header.get("STATUS", 1)
            if len(columns) > max(branch_index, status_index):
                branch = columns[branch_index].strip("|")
                status = columns[status_index].strip("|:").upper()
                if re.fullmatch(r"[A-Z0-9_-]+", branch.upper()):
                    rows.append((branch, status, index))
    return rows, header


def _expected_branches(config: dict[str, Any], environment: str) -> list[str]:
    branches = config.get("expected_branches", {})
    return list(branches.get("by_environment", {}).get(environment, branches.get("default", [])))


def _business_date(config: dict[str, Any]) -> date | None:
    value = config.get("business_date", {}).get("expected")
    if not value:
        return None
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        return None


def _normalize_date(value: str, formats: list[str]) -> date | None:
    for date_format in formats:
        try:
            return datetime.strptime(value.upper(), date_format).date()
        except ValueError:
            continue
    return None


def _detect_cob(section: Section, environment: str, config: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    success = _tokens(config, "success_tokens")
    expected = _expected_branches(config, environment)
    rows, header = _branch_rows(section)
    lines = section.content.splitlines()
    if rows:
        found: set[str] = set()
        for branch, status, index in rows:
            found.add(branch.upper())
            if status not in success:
                findings.append(_finding(
                    environment, section.name, "CRITICAL", branch,
                    f"Branch status is {status or 'unknown'}.", _evidence(lines, index),
                    "Review the branch COB job and its upstream dependencies, then rerun the check.",
                ))
            expected_date = _business_date(config)
            if expected_date and header:
                date_columns = [name for name in ("LBD", "COB_DATE", "BUSINESS_DATE") if name in header]
                for column in date_columns:
                    row_columns = re.split(r"\s+", lines[index].strip())
                    position = header[column]
                    if position < len(row_columns):
                        logged_date = _normalize_date(
                            row_columns[position], config.get("business_date", {}).get("log_formats", [])
                        )
                        if logged_date and logged_date != expected_date:
                            findings.append(_finding(
                                environment, section.name, "CRITICAL", branch,
                                f"COB date {logged_date.isoformat()} differs from expected {expected_date.isoformat()}.",
                                _evidence(lines, index), "Confirm the business date and rerun COB for the expected date.",
                            ))
        for branch in expected:
            if branch.upper() not in found:
                findings.append(_finding(
                    environment, section.name, "CRITICAL", branch,
                    "Expected branch is missing from the COB results.", "\n".join(lines[:5]),
                    "Confirm the branch is enabled in the sanity check and rerun the COB status query.",
                ))
    elif section.name == "NPK COB":
        text = section.content.upper()
        failures = _tokens(config, "failure_tokens")
        if any(token in text for token in failures):
            findings.append(_finding(
                environment, section.name, "CRITICAL", "NPK COB",
                "NPK COB output contains a failure status.", "\n".join(lines[:5]),
                "Inspect the NPK COB job output and rerun failed branch processing.",
            ))
        elif not any(token in text for token in success):
            findings.append(_finding(
                environment, section.name, "WARNING", "NPK COB",
                "NPK COB output does not contain a recognized success status.", "\n".join(lines[:5]),
                "Confirm the NPK COB run completed and update success tokens if the wording is valid.",
            ))
    return findings


def _detect_fra(section: Section, environment: str, config: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    lines = section.content.splitlines()
    thresholds = config.get("thresholds", {}).get("fra", {})
    warning = float(thresholds.get("warning_percent", 80))
    critical = float(thresholds.get("critical_percent", 90))
    header: list[str] = []
    for index, line in enumerate(lines):
        columns = re.split(r"\s+", line.strip().replace("|", " "))
        upper = [column.upper().strip(":") for column in columns]
        if any("SPACE" in value or "USED(%)" in value or "PERCENT_SPACE_USED" in value for value in upper):
            header = upper
            continue
        if not header:
            continue
        percent_index = next((i for i, value in enumerate(header) if "PERCENT_SPACE_USED" in value or "USED(%)" in value or value == "USED%"), None)
        if percent_index is None or percent_index >= len(columns):
            continue
        match = NUMBER_RE.search(columns[percent_index])
        if not match:
            continue
        used = float(match.group())
        item = columns[1] if len(columns) > 1 else "FRA"
        severity = "CRITICAL" if used >= critical else "WARNING" if used >= warning else None
        if severity:
            reclaimable_index = next((i for i, value in enumerate(header) if "RECLAIMABLE" in value), None)
            reclaimable = None
            if reclaimable_index is not None and reclaimable_index < len(columns):
                number = NUMBER_RE.search(columns[reclaimable_index])
                reclaimable = float(number.group()) if number else None
            reclaim_note = f" Reclaimable space is {reclaimable:g} GB." if reclaimable is not None and reclaimable > 0 else ""
            findings.append(_finding(
                environment, section.name, severity, item,
                f"FRA usage is {used:g}%, crossing the {severity.lower()} threshold.{reclaim_note}",
                _evidence(lines, index), "Review FRA retention and backup cleanup; reclaim eligible space before increasing capacity.",
            ))
        reclaimable_limit = thresholds.get("reclaimable_warning_gb")
        if reclaimable_limit is not None:
            reclaimable_index = next((i for i, value in enumerate(header) if "RECLAIMABLE" in value), None)
            if reclaimable_index is not None and reclaimable_index < len(columns):
                number = NUMBER_RE.search(columns[reclaimable_index])
                if number and float(number.group()) >= float(reclaimable_limit):
                    findings.append(_finding(
                        environment, section.name, "WARNING", item,
                        f"Reclaimable FRA space is {number.group()} GB.", _evidence(lines, index),
                        "Review obsolete recovery files and reclaim eligible FRA space.",
                    ))
    return findings


def _detect_db(section: Section, environment: str, config: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    lines = section.content.splitlines()
    max_ms = float(config.get("thresholds", {}).get("database", {}).get("max_response_time_ms", 5000))
    for index, line in enumerate(lines):
        if GLOBAL_ERROR_RE.search(line):
            findings.append(_finding(
                environment, section.name, "CRITICAL", section.name.removeprefix("DB "),
                "Database connection output contains an error.", _evidence(lines, index),
                "Verify database availability, credentials, listener health, and network connectivity.",
            ))
            break
        response = re.search(r"(?:response|elapsed|duration|time)\s*[:=]\s*(\d+(?:\.\d+)?)\s*(ms|s|sec)?", line, re.I)
        if response:
            value = float(response.group(1)) * (1000 if response.group(2) and response.group(2).lower() in {"s", "sec"} else 1)
            if value > max_ms:
                findings.append(_finding(
                    environment, section.name, "WARNING", section.name.removeprefix("DB "),
                    f"Database response time {value:g} ms exceeds {max_ms:g} ms.", _evidence(lines, index),
                    "Check database load, listener latency, and network response time.",
                ))
    if lines and not any(token in " ".join(lines).upper() for token in _tokens(config, "success_tokens")) and not findings:
        findings.append(_finding(
            environment, section.name, "WARNING", section.name.removeprefix("DB "),
            "Database section has no recognized success status.", "\n".join(lines[:5]),
            "Confirm the connection test completed and configure its success wording if needed.",
        ))
    return findings


def _detect_cft(section: Section, environment: str, config: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    lines = section.content.splitlines()
    max_age = float(config.get("thresholds", {}).get("cft", {}).get("max_age_minutes", 30))
    for index, line in enumerate(lines):
        if re.search(r"\bno\s+(?:stuck\s+)?files?\b", line, re.I):
            continue
        age = re.search(r"(\d+(?:\.\d+)?)\s*(?:minutes?|mins?|min)\b", line, re.I)
        status = re.search(r"\bstatus\s*[:=]\s*([A-Z_-]+)", line, re.I)
        status_failed = status and status.group(1).upper() not in _tokens(config, "success_tokens")
        failed = (
            GLOBAL_ERROR_RE.search(line)
            or status_failed
            or re.search(r"\b(?:STUCK|PENDING|IN_PROGRESS|IN PROGRESS)\b|not found|has not been found", line, re.I)
        )
        if age and float(age.group(1)) > max_age:
            failed = True
        if failed:
            findings.append(_finding(
                environment, section.name, "CRITICAL", "CFT file",
                f"CFT output reports a failed or potentially stuck file{f' older than {max_age:g} minutes' if age else ''}.",
                _evidence(lines, index), "Inspect the transfer status, age, destination permissions, and retry or clear the stuck file.",
            ))
    return findings


def _detect_mq(section: Section, environment: str, config: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    lines = section.content.splitlines()
    max_depth = float(config.get("thresholds", {}).get("mq", {}).get("max_depth", 1000))
    for index, line in enumerate(lines):
        depth = re.search(r"(?:depth|messages?|msg(?:s)?)\s*[:=]\s*(\d+)", line, re.I)
        consumers = re.search(r"consumers?\s*[:=]\s*(\d+)", line, re.I)
        if re.search(r"\b(?:INCREASING|GROWING)\b", line, re.I) and re.search(r"\b(?:NO CONSUMPTION|NOT CONSUMED|ZERO CONSUMERS)\b", line, re.I):
            findings.append(_finding(environment, section.name, "CRITICAL", "MQ queue", "Queue depth is increasing without consumption.", _evidence(lines, index), "Restore consumers and inspect queue processing errors."))
        elif depth and float(depth.group(1)) > max_depth:
            findings.append(_finding(environment, section.name, "WARNING", "MQ queue", f"Queue depth {depth.group(1)} exceeds {max_depth:g}.", _evidence(lines, index), "Check consumer throughput, backlogs, and downstream service health."))
        if depth and consumers and int(depth.group(1)) > 0 and int(consumers.group(1)) == 0:
            findings.append(_finding(environment, section.name, "CRITICAL", "MQ queue", "Queue has messages but no consumers.", _evidence(lines, index), "Restore consumers and verify the queue listener configuration."))
        elif GLOBAL_ERROR_RE.search(line):
            findings.append(_finding(environment, section.name, "CRITICAL", "MQ", "MQ check contains an error.", _evidence(lines, index), "Inspect queue manager health and the MQ check output."))
    return findings


def _detect_application(section: Section, environment: str, config: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    lines = section.content.splitlines()
    pattern = re.compile(r"ghost\s*flow|process(?:es)?\s+(?:is\s+)?down|missing\s+heartbeat|heartbeat\s+missing|exception|error|failed|timeout|ORA-\d+|no such file|permission denied", re.I)
    for index, line in enumerate(lines):
        if pattern.search(line):
            findings.append(_finding(environment, section.name, "CRITICAL", "Application health", "Application check reports a flow, process, heartbeat, or runtime error.", _evidence(lines, index), "Check application process and heartbeat health, then inspect the associated COB and database dependencies."))
    return findings


def _detect_fs(section: Section, environment: str, config: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    lines = section.content.splitlines()
    thresholds = config.get("thresholds", {}).get("filesystem", {})
    mounts = thresholds.get("mounts", {})
    for index, line in enumerate(lines):
        match = re.search(r"(\d+(?:\.\d+)?)\s*%", line)
        if not match:
            continue
        used = float(match.group(1))
        mount_match = re.search(r"(/[^\s|]+)", line)
        mount = mount_match.group(1).rstrip(",") if mount_match else "unknown mount"
        override = mounts.get(mount, {})
        warning = float(override.get("warning_percent", thresholds.get("warning_percent", 80)))
        critical = float(override.get("critical_percent", thresholds.get("critical_percent", 90)))
        severity = "CRITICAL" if used >= critical else "WARNING" if used >= warning else None
        if severity:
            findings.append(_finding(environment, section.name, severity, mount, f"Filesystem usage is {used:g}% (threshold: {critical:g}% critical, {warning:g}% warning).", _evidence(lines, index), "Find large files and safely expand or clean the filesystem before it reaches capacity."))
    if not findings:
        for index, line in enumerate(lines):
            if re.search(r"\b(?:FAILED|FAILURE|KO)\b", line, re.I):
                findings.append(_finding(environment, section.name, "CRITICAL", "Filesystem", "Filesystem check reports failure.", _evidence(lines, index), "Review filesystem check output, mount availability, and permissions."))
                break
    return findings


def detect_findings(
    environment: str,
    parsed: ParsedLog,
    raw_text: str,
    config: dict[str, Any],
    source: str,
) -> list[Finding]:
    findings: list[Finding] = []
    expected_sections = set(config.get("expected_sections", []))
    present = {section.name for section in parsed.sections}
    for missing in sorted(expected_sections - present):
        findings.append(_finding(
            environment, missing, "CRITICAL", missing,
            f"Expected section {missing} is missing; the check did not run or did not emit output.",
            f"Source: {source}", "Verify the sanity-check script reached this section and emitted its marker.",
        ))

    for section in parsed.sections:
        if section.name in {"COB STATUS", "NPK COB"}:
            findings.extend(_detect_cob(section, environment, config))
        elif section.name == "FRA":
            findings.extend(_detect_fra(section, environment, config))
        elif section.name.startswith("DB "):
            findings.extend(_detect_db(section, environment, config))
        elif section.name == "CFT":
            findings.extend(_detect_cft(section, environment, config))
        elif section.name == "MQ":
            findings.extend(_detect_mq(section, environment, config))
        elif section.name == "APPLICATION":
            findings.extend(_detect_application(section, environment, config))
        elif section.name == "FS":
            findings.extend(_detect_fs(section, environment, config))

    active = "GLOBAL"
    for index, line in enumerate(raw_text.splitlines()):
        marker = re.match(r"^\s*\[([^\]]+)\]", line)
        if marker:
            from parser.sections import canonical_section

            active = canonical_section(marker.group(1)) or "UNPARSED"
        if GLOBAL_ERROR_RE.search(line):
            findings.append(_finding(
                environment, active, "CRITICAL", source,
                "Global error token detected in the log.", _evidence(raw_text.splitlines(), index),
                "Inspect the raw log line and resolve the reported error before considering the check healthy.",
            ))

    return findings