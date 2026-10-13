# Daily LogAgent

LogAgent analyzes sanity-check logs from multiple environments, applies deterministic rules first, optionally asks an LLM to interpret ambiguous content, and emits one self-contained HTML report.

## Setup and run

Python 3.11 or newer is required.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
logagent analyze --input ./logs --config config.yaml --out ./report.html
```

`--input` accepts a directory (searched recursively for `*.log`) or one or more log files. Logs with the same resolved environment are merged. Environment resolution checks exact filename mappings and filename patterns first, then environment tokens in the filename, configured title patterns, and finally an `ENV`/`ENVIRONMENT` header. Unresolved names are grouped as `UNKNOWN`.

To analyze selected files:

```sh
logagent analyze --input ./logs/PROD_20261013.log ./logs/UAT_20261013.log --config config.yaml --out ./report.html
```

The CLI uses JSON structured logs. `--verbose` enables debug logging. Exit code `0` means report generation succeeded; `2` indicates an input, configuration, or delivery error.

## Start and stop

The startup script runs one analysis immediately, then repeats once per day. It backgrounds the runner and writes its PID and log to `.logagent.pid` and `.logagent.log`.

```sh
chmod +x start.sh stop.sh
LOGAGENT_INPUT=/var/log/sanitychecks ./start.sh
./stop.sh
```

Configure `LOGAGENT_INPUT`, `LOGAGENT_CONFIG`, `LOGAGENT_OUTPUT`, `LOGAGENT_INTERVAL_SECONDS`, `LOGAGENT_SEND_MAIL=1`, `LOGAGENT_PID_FILE`, or `LOGAGENT_LOG_FILE` as needed. `stop.sh` sends a graceful signal and waits up to 30 seconds.

## Configuration

All rules and thresholds are in `config.yaml`:

| Setting | Purpose |
| --- | --- |
| `environments` | Environment labels recognized in filenames and report ordering. |
| `environment_filename_patterns` | Regex patterns applied to filenames, keyed by environment. |
| `environment_file_map` | Exact basename-to-environment overrides. |
| `environment_title_patterns` | Regex patterns checked against the pre-section title/header. |
| `expected_branches.default` | Required COB branches; use `by_environment` for overrides. Empty lists disable branch completeness checks. |
| `expected_sections` | Required sections checked independently in every log. DB names are dynamic but expected DB sections belong here. |
| `business_date.expected` | Expected ISO business date; `null` disables date comparison. `log_formats` lists date formats accepted from COB rows. |
| `success_tokens` / `failure_tokens` | Case-insensitive status tokens for COB, NPK COB, and connection checks. Defaults include `OK`, `SUCCESS`, `COMPLETED` and `KO`, `FAILED`, `FAILURE`. |
| `thresholds.fra` | FRA warning/critical percentages and optional reclaimable-space warning in GB. |
| `thresholds.filesystem` | Filesystem warning/critical percentages and per-mount overrides. |
| `thresholds.cft.max_age_minutes` | Maximum age for a stuck transfer. |
| `thresholds.mq.max_depth` | Queue depth warning threshold. A queue with messages and zero consumers is critical. |
| `thresholds.database.max_response_time_ms` | Database response-time warning threshold. |
| `required_environments` | Optional extra list of environments that must have at least one input log. |
| `ai` | OpenAI-compatible endpoint/model, enable flag, timeout, and API-key environment variable name. |
| `mail` | SMTP host/port, recipients, STARTTLS or SSL, and whether HTML is attached or used as the message body. Credentials are read from environment variables. |

The sample branch list is transcribed from the supplied PF2 screenshot; replace it with the real environment-specific list. Sample logs and the generated report are fixtures, not production data.

## AI behavior and privacy

AI is disabled by default. To enable, set `ai.enabled: true` and provide the configured key variable (default `LOGAGENT_API_KEY`). The request contains parsed sections, unparsed text, and rule findings after masking password-like values, credential-bearing URLs/connection strings, and IPv4 addresses. The response must validate against a strict JSON schema; invalid JSON/schema output is retried once, then deterministic findings and a generated summary are used. Rule findings are retained, and AI severity cannot lower a rule-based severity.

## Email

Set SMTP options and recipients under `mail`, export any configured credential variables, then add `--send-mail`:

```sh
export SMTP_USERNAME='logagent'
export SMTP_PASSWORD='...'
logagent analyze --input ./logs --config config.yaml --out ./report.html --send-mail
```

The subject includes the global status, report date, and number of environments requiring attention. Without `--send-mail`, no SMTP connection is attempted.

## Container and cron

The container reads logs from `/logs` and writes `/reports/report.html` by default:

```sh
docker build -t daily-logagent .
docker run --rm -v "$PWD/logs:/logs:ro" -v "$PWD/reports:/reports" daily-logagent
```

For cron, invoke the installed CLI with absolute paths and redirect process logs, for example:

```cron
15 6 * * * /opt/logagent/.venv/bin/logagent analyze --input /var/log/sanitychecks --config /opt/logagent/config.yaml --out /var/reports/daily.html >> /var/log/logagent.log 2>&1
```

## Adding a section parser

1. Add a marker-to-canonical-name mapping in `parser/sections.py` (`canonical_section`). Dynamic `[DB NAME]` markers are already supported and should remain generic.
2. Add deterministic section rules in `rules/detect.py` and dispatch them in `detect_findings`.
3. Add the canonical name to `expected_sections` in YAML if it must be present in every log.
4. Add healthy and failing fixture coverage in `sample_logs/` and `tests/`; unrecognized content is preserved and sent to the AI layer when enabled.

Run tests with `python -m unittest discover -s tests -v`. A sample offline report generated from the fixtures is included at `sample-report.html`.