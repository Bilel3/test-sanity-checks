#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PID_FILE=${LOGAGENT_PID_FILE:-"$SCRIPT_DIR/.logagent.pid"}

if [ ! -f "$PID_FILE" ]; then
    printf '%s\n' "LogAgent is not running (PID file not found)."
    exit 0
fi

RUNNER_PID=$(sed -n '1p' "$PID_FILE")
case "$RUNNER_PID" in
    ''|*[!0-9]*)
        printf 'Invalid PID file: %s\n' "$PID_FILE" >&2
        exit 2
        ;;
esac

if ! kill -0 "$RUNNER_PID" 2>/dev/null; then
    rm -f "$PID_FILE"
    printf '%s\n' "Removed stale LogAgent PID file."
    exit 0
fi

kill -TERM "$RUNNER_PID" 2>/dev/null || {
    printf 'Could not stop LogAgent (PID %s).\n' "$RUNNER_PID" >&2
    exit 1
}

ATTEMPTS=0
while kill -0 "$RUNNER_PID" 2>/dev/null; do
    if [ "$ATTEMPTS" -ge 30 ]; then
        printf 'LogAgent (PID %s) did not stop within 30 seconds.\n' "$RUNNER_PID" >&2
        exit 1
    fi
    sleep 1
    ATTEMPTS=$((ATTEMPTS + 1))
done

rm -f "$PID_FILE"
printf 'LogAgent stopped (PID %s).\n' "$RUNNER_PID"