"""Optional SMTP delivery for generated HTML reports."""

from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from models import AnalysisReport


def send_report(report: AnalysisReport, report_path: str | Path, config: dict[str, Any]) -> None:
    mail = config.get("mail", {})
    recipients = [str(address) for address in mail.get("to", [])]
    if not recipients:
        raise ValueError("mail.to must contain at least one recipient when --send-mail is used")
    findings = [finding for environment in report.environments for finding in environment.findings]
    status = "CRITICAL" if any(item.severity == "CRITICAL" for item in findings) else "WARNING" if any(item.severity == "WARNING" for item in findings) else "OK"
    affected = sum(any(f.severity in {"CRITICAL", "WARNING"} for f in environment.findings) for environment in report.environments)
    message = EmailMessage()
    message["Subject"] = f"[{status}] Daily sanity check - {report.report_date} - {affected} envs need attention"
    message["From"] = str(mail.get("from", "logagent@example.invalid"))
    message["To"] = ", ".join(recipients)
    html = Path(report_path).read_text(encoding="utf-8")
    if mail.get("attach_report", True):
        message.set_content(f"Daily sanity check status: {status}. See the attached HTML report.")
        message.add_attachment(html, subtype="html", filename=Path(report_path).name)
    else:
        message.set_content("Daily sanity check report is attached as an HTML email body.")
        message.add_alternative(html, subtype="html")

    host = str(mail.get("host", "localhost"))
    port = int(mail.get("port", 587))
    username = os.getenv(str(mail.get("username_env", "SMTP_USERNAME")))
    password = os.getenv(str(mail.get("password_env", "SMTP_PASSWORD")))
    if mail.get("ssl", False):
        with smtplib.SMTP_SSL(host, port, timeout=30) as smtp:
            if username:
                smtp.login(username, password or "")
            smtp.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            if mail.get("starttls", True):
                smtp.starttls()
            if username:
                smtp.login(username, password or "")
            smtp.send_message(message)