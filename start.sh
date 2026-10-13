#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INPUT=${LOGAGENT_INPUT:-"$SCRIPT_DIR/logs"}
CONFIG=${LOGAGENT_CONFIG:-"$SCRIPT_DIR/config.yaml"}
OUTPUT=${LOGAGENT_OUTPUT:-"$SCRIPT_DIR/reports/daily.html"}
INTERVAL=${LOGAGENT_INTERVAL_SECONDS:-86400}
SEND_MAIL=${LOGAGENT_SEND_MAIL:-0}
PID_FILE=${LOGAGENT_PID_FILE:-"$SCRIPT_DIR/.logagent.pid"}
LOG_FILE=${LOGAGENT_LOG_FILE:-"$SCRIPT_DIR/.logagent.log"}

case "$INTERVAL" in
    ''|*[!0-9]*)
        printf '%s\n' "LOGAGENT_INTERVAL_SECONDS must be a positive integer." >&2
        exit 2
        ;;
esac
if [ "$INTERVAL" -lt 1 ]; then
    printf '%s\n' "LOGAGENT_INTERVAL_SECONDS must be greater than zero." >&2
    exit 2
fi

if [ ! -e "$INPUT" ]; then
    printf 'Input path does not exist: %s\n' "$INPUT" >&2
    exit 2
fi
if [ ! -f "$CONFIG" ]; then
    printf 'Config file does not exist: %s\n' "$CONFIG" >&2
    exit 2
fi

if [ -x "$SCRIPT_DIR/.venv/bin/logagent" ]; then
    LOGAGENT="$SCRIPT_DIR/.venv/bin/logagent"
elif command -v logagent >/dev/null 2>&1; then
    LOGAGENT=$(command -v logagent)
else
    printf '%s\n' "logagent not found. Install the project or create its .venv first." >&2
    exit 2
fi

if [ -f "$PID_FILE" ]; then
    EXISTING_PID=$(sed -n '1p' "$PID_FILE")
    case "$EXISTING_PID" in
        ''|*[!0-9]*) ;;
        *)
            if kill -0 "$EXISTING_PID" 2>/dev/null; then
                printf 'LogAgent is already running (PID %s).\n' "$EXISTING_PID"
                exit 1
            fi
            ;;
    esac
    rm -f "$PID_FILE"
fi

mkdir -p "$(dirname -- "$PID_FILE")" "$(dirname -- "$LOG_FILE")" "$(dirname -- "$OUTPUT")"

nohup /bin/sh -c '
pid_file=$1
agent=$2
input=$3
config=$4
output=$5
interval=$6
send_mail=$7
active_pid=

stop_runner() {
    trap - INT TERM HUP
    if [ -n "$active_pid" ]; then
        kill -TERM "$active_pid" 2>/dev/null || true
        wait "$active_pid" 2>/dev/null || true
    fi
    rm -f "$pid_file"
    exit 0
}

trap stop_runner INT TERM HUP
while :; do
    printf "Starting analysis at %s\n" "$(date "+%Y-%m-%d %H:%M:%S")"
    if [ "$send_mail" = "1" ]; then
        "$agent" analyze --input "$input" --config "$config" --out "$output" --send-mail
    else
        "$agent" analyze --input "$input" --config "$config" --out "$output"
    fi
    active_pid=
    sleep "$interval" &
    active_pid=$!
    wait "$active_pid" || true
    active_pid=
done
' logagent-runner "$PID_FILE" "$LOGAGENT" "$INPUT" "$CONFIG" "$OUTPUT" "$INTERVAL" "$SEND_MAIL" >>"$LOG_FILE" 2>&1 </dev/null &

RUNNER_PID=$!
printf '%s\n' "$RUNNER_PID" >"$PID_FILE"
printf 'LogAgent started (PID %s). Log: %s\n' "$RUNNER_PID" "$LOG_FILE"