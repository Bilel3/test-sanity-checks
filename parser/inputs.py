"""Input discovery and configurable environment resolution."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class InputLog:
    path: Path
    text: str
    environment: str


def discover_logs(inputs: Iterable[str | Path]) -> list[Path]:
    paths: list[Path] = []
    for value in inputs:
        path = Path(value)
        if path.is_dir():
            paths.extend(sorted(item for item in path.rglob("*") if item.is_file() and item.suffix.lower() == ".log"))
        elif path.is_file():
            paths.append(path)
        else:
            raise FileNotFoundError(f"Input path does not exist: {path}")
    return list(dict.fromkeys(paths))


def resolve_environment(path: Path, text: str, config: dict[str, Any]) -> str:
    basename = path.name
    exact = config.get("environment_file_map", {})
    for configured_name, environment in exact.items():
        if basename.lower() == str(configured_name).lower():
            return str(environment)

    for environment, patterns in config.get("environment_filename_patterns", {}).items():
        if any(re.search(str(pattern), basename) for pattern in patterns):
            return str(environment)

    known = sorted((str(value) for value in config.get("environments", [])), key=len, reverse=True)
    for environment in known:
        if re.search(rf"(?<![A-Z0-9]){re.escape(environment)}(?![A-Z0-9])", basename, re.IGNORECASE):
            return environment

    header = text.split("[", 1)[0]
    for environment, patterns in config.get("environment_title_patterns", {}).items():
        if any(re.search(str(pattern), header, re.IGNORECASE) for pattern in patterns):
            return str(environment)

    title_match = re.search(r"\b(?:ENVIRONMENT|ENV)\s*[:= -]\s*([A-Z0-9_-]+)", header, re.IGNORECASE)
    return title_match.group(1).upper() if title_match else "UNKNOWN"


def load_input_logs(paths: Iterable[Path], config: dict[str, Any]) -> list[InputLog]:
    records: list[InputLog] = []
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        records.append(InputLog(path, text, resolve_environment(path, text, config)))
    return records