#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${RUN_DIR:-$ROOT_DIR/.local-run}"
PID_FILE="$RUN_DIR/ds.pid"
LOG_FILE="$RUN_DIR/logs/ds.log"
CLEAN="${CLEAN:-0}"

if [[ ! -f "$PID_FILE" ]]; then
  echo "No PID file found at $PID_FILE. Nothing to stop."
  exit 0
fi

pid="$(cat "$PID_FILE" || true)"
if [[ -z "${pid:-}" ]]; then
  echo "PID file is empty. Removing it."
  rm -f "$PID_FILE"
  exit 0
fi

if kill -0 "$pid" >/dev/null 2>&1; then
  kill "$pid"
  for _ in $(seq 1 50); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
  if kill -0 "$pid" >/dev/null 2>&1; then
    echo "Process $pid did not stop gracefully; sending SIGKILL."
    kill -9 "$pid" >/dev/null 2>&1 || true
  fi
  echo "Stopped DS process $pid."
else
  echo "Process $pid is not running."
fi

rm -f "$PID_FILE"

if [[ "$CLEAN" == "1" ]]; then
  rm -rf "$RUN_DIR"
  echo "Removed run directory: $RUN_DIR"
else
  echo "Run data kept at: $RUN_DIR"
  if [[ -f "$LOG_FILE" ]]; then
    echo "DS log: $LOG_FILE"
  fi
fi
