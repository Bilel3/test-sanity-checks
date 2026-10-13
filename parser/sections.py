"""Split sanity-check logs into known sections without discarding text."""

from __future__ import annotations

import re
from dataclasses import dataclass


MARKER_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")
FRA_SIGNATURE_RE = re.compile(
    r"SPACE_LIMIT|SPACE_USED|PERCENT_SPACE_USED|V\$RECOVERY_FILE_DEST|"
    r"V\$FLASH_RECOVERY_AREA_USAGE|ALLOCATED_SPACE|USED_SPACE",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Section:
    name: str
    title: str
    content: str


@dataclass(frozen=True)
class ParsedLog:
    sections: list[Section]
    unparsed_content: str


def canonical_section(title: str) -> str | None:
    normalized = " ".join(title.upper().split())
    if normalized == "COB STATUS":
        return "COB STATUS"
    if normalized == "NPK COB CHECKS":
        return "NPK COB"
    if normalized == "DBLIVE":
        return "DB LIVE"
    if normalized.startswith("FRA ") or normalized == "FRA":
        return "FRA"
    if normalized.startswith("DB "):
        return normalized
    if normalized == "CFT CHECKS":
        return "CFT"
    if normalized == "MQ CHECKS":
        return "MQ"
    if normalized == "APPLICATION CHECKS":
        return "APPLICATION"
    if normalized == "FS CHECKS":
        return "FS"
    return None


def parse_sections(text: str) -> ParsedLog:
    sections: list[Section] = []
    unparsed_lines: list[str] = []
    active_title: str | None = None
    active_name: str | None = None
    active_lines: list[str] = []
    pending_lines: list[str] = []

    def finish_active() -> None:
        nonlocal active_title, active_name, active_lines
        if active_title is not None and active_name is not None:
            sections.append(Section(active_name, active_title, "\n".join(active_lines).strip()))
        elif active_title is not None:
            pending_lines.append(f"[{active_title}]")
            pending_lines.extend(active_lines)
        active_title = None
        active_name = None
        active_lines = []

    for line in text.splitlines():
        if active_name == "COB STATUS" and re.fullmatch(r"[\s|=+-]+", line):
            active_lines.append(line)
            continue
        marker = MARKER_RE.match(line)
        if marker:
            finish_active()
            active_title = marker.group(1).strip()
            active_name = canonical_section(active_title)
            continue

        if active_title is None:
            if FRA_SIGNATURE_RE.search(line):
                active_title = "FRA (detected from SQL output)"
                active_name = "FRA"
            else:
                pending_lines.append(line)
                continue

        if active_name is None and FRA_SIGNATURE_RE.search(line):
            active_name = "FRA"
            active_title = "FRA (detected from SQL output)"
        active_lines.append(line)

    finish_active()
    unparsed_lines.extend(line for line in pending_lines if line.strip())
    return ParsedLog(sections=sections, unparsed_content="\n".join(unparsed_lines).strip())