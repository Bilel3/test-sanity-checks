"""Command-line interface for daily sanity-check log analysis."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from analyzer import analyze, load_config
from mailer import send_report
from report.generate import render_html


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        for key in ("environment", "source", "sections"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        return json.dumps(payload, ensure_ascii=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="logagent", description="Analyze daily sanity-check logs")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze_parser = subparsers.add_parser("analyze", help="Analyze logs and generate an offline HTML report")
    analyze_parser.add_argument("--input", nargs="+", required=True, help="Log directory or one or more .log files")
    analyze_parser.add_argument("--config", default="config.yaml", help="YAML configuration file")
    analyze_parser.add_argument("--out", default="report.html", help="Output HTML report path")
    analyze_parser.add_argument("--send-mail", action="store_true", help="Send the report using configured SMTP")
    analyze_parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    logging.basicConfig(level=logging.DEBUG if arguments.verbose else logging.INFO, handlers=[handler], force=True)
    try:
        config = load_config(arguments.config)
        report = analyze(arguments.input, config)
        output = Path(arguments.out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_html(report), encoding="utf-8")
        logging.getLogger(__name__).info("Report generated", extra={"source": str(output)})
        if arguments.send_mail:
            send_report(report, output, config)
            logging.getLogger(__name__).info("Report email sent", extra={"source": str(output)})
        print(f"Report written to {output}")
        return 0
    except Exception as error:
        logging.getLogger(__name__).exception("Analysis failed", extra={"source": str(getattr(arguments, "input", ""))})
        print(f"logagent: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())