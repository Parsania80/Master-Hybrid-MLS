#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${RUN_DIR:-$ROOT_DIR/.local-run}"
PID_FILE="$RUN_DIR/ds.pid"
CLIENT_DIR="$RUN_DIR/clients"
DS_BIND="${DS_BIND:-127.0.0.1:3000}"
BASE_URL="${BASE_URL:-http://$DS_BIND}"

echo "Run directory: $RUN_DIR"
echo "DS URL: $BASE_URL"

if [[ -f "$PID_FILE" ]]; then
  pid="$(cat "$PID_FILE" || true)"
  if [[ -n "${pid:-}" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    echo "DS process: running (PID $pid)"
  else
    echo "DS process: not running (stale PID file)"
  fi
else
  echo "DS process: PID file missing"
fi

if command -v curl >/dev/null 2>&1 && curl -sf "$BASE_URL/healthz" >/dev/null 2>&1; then
  echo "Health endpoint: OK"
else
  echo "Health endpoint: unavailable"
fi

if [[ -d "$CLIENT_DIR" ]]; then
  count="$(find "$CLIENT_DIR" -maxdepth 1 -type f -name '*.json' | wc -l | tr -d ' ')"
  echo "Client states: $count"
  find "$CLIENT_DIR" -maxdepth 1 -type f -name '*.json' -printf ' - %f\n' | sort
else
  echo "Client states: none"
fi
