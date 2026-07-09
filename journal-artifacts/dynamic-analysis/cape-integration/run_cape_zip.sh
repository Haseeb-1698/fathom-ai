#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$ROOT/venv"
PY="$VENV/bin/python3"
ROOTER_SOCKET="/tmp/cuckoo-rooter"
ROOTER_GROUP="${USER:-m47}"
LOG_DIR="$ROOT/log"
ROOTER_LOG="$LOG_DIR/rooter-launcher.log"
CUCKOO_LOG="$LOG_DIR/cuckoo-launcher.log"
PROCESS_LOG="$LOG_DIR/process-launcher.log"
ARCHIVE_PASSWORD="infected"

cd "$ROOT"
mkdir -p "$LOG_DIR"

if [[ ! -x "$PY" ]]; then
    echo "Could not find venv Python at: $PY" >&2
    exit 1
fi

echo "CAPE launcher"
echo "Project: $ROOT"
echo
read -r -p "Enter the full path to the sample ZIP/file: " SAMPLE

# Friendly handling for paths pasted with quotes.
SAMPLE="${SAMPLE%\"}"
SAMPLE="${SAMPLE#\"}"
SAMPLE="${SAMPLE%\'}"
SAMPLE="${SAMPLE#\'}"
if [[ "$SAMPLE" == "~/"* ]]; then
    SAMPLE="$HOME/${SAMPLE#~/}"
fi

if [[ ! -f "$SAMPLE" ]]; then
    echo "File not found: $SAMPLE" >&2
    exit 1
fi

source "$VENV/bin/activate"

start_rooter() {
    if [[ -S "$ROOTER_SOCKET" ]] && pgrep -f "utils/rooter.py" >/dev/null; then
        echo "Rooter is already running at $ROOTER_SOCKET"
        return
    fi

    echo "Starting CAPE rooter..."
    if ! sudo -n "$PY" "$ROOT/utils/rooter.py" -h >/dev/null 2>&1; then
        echo "Rooter needs sudo. Enter your sudo password when prompted."
        sudo -v
    fi

    nohup sudo -n "$PY" "$ROOT/utils/rooter.py" -g "$ROOTER_GROUP" >"$ROOTER_LOG" 2>&1 &

    for _ in {1..30}; do
        if [[ -S "$ROOTER_SOCKET" ]]; then
            echo "Rooter ready: $ROOTER_SOCKET"
            return
        fi
        sleep 1
    done

    echo "Rooter did not create $ROOTER_SOCKET. See: $ROOTER_LOG" >&2
    exit 1
}

start_cuckoo() {
    if pgrep -f "$ROOT/cuckoo.py" >/dev/null || pgrep -f "python3 cuckoo.py" >/dev/null; then
        echo "CAPE scheduler is already running"
        return
    fi

    echo "Starting CAPE scheduler..."
    nohup "$PY" "$ROOT/cuckoo.py" >"$CUCKOO_LOG" 2>&1 &

    for _ in {1..90}; do
        if grep -q "Waiting for analysis tasks" "$CUCKOO_LOG" 2>/dev/null; then
            echo "CAPE scheduler ready"
            return
        fi
        if ! pgrep -f "$ROOT/cuckoo.py" >/dev/null && ! pgrep -f "python3 cuckoo.py" >/dev/null; then
            echo "CAPE scheduler exited early. See: $CUCKOO_LOG" >&2
            tail -40 "$CUCKOO_LOG" >&2 || true
            exit 1
        fi
        sleep 1
    done

    echo "CAPE scheduler did not become ready in time. See: $CUCKOO_LOG" >&2
    exit 1
}

start_processor() {
    if pgrep -f "$ROOT/utils/process.py auto" >/dev/null || pgrep -f "utils/process.py auto" >/dev/null; then
        echo "CAPE processor is already running"
        return
    fi

    echo "Starting CAPE processor..."
    nohup "$PY" "$ROOT/utils/process.py" auto >"$PROCESS_LOG" 2>&1 &
}

submit_sample() {
    local lower
    lower="$(printf '%s' "$SAMPLE" | tr '[:upper:]' '[:lower:]')"

    echo "Submitting: $SAMPLE"
    if [[ "$lower" == *.zip ]]; then
        "$PY" "$ROOT/utils/submit.py" --package archive --options "password=$ARCHIVE_PASSWORD" "$SAMPLE"
    else
        "$PY" "$ROOT/utils/submit.py" "$SAMPLE"
    fi
}

start_rooter
start_cuckoo
start_processor
submit_sample

echo
echo "Done. Logs:"
echo "  Rooter:    $ROOTER_LOG"
echo "  Scheduler: $CUCKOO_LOG"
echo "  Processor: $PROCESS_LOG"
