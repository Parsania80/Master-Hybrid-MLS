#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${RUN_DIR:-$ROOT_DIR/.local-run}"
LOG_DIR="$RUN_DIR/logs"
CLIENT_DIR="$RUN_DIR/clients"
DS_DATA_DIR="$RUN_DIR/ds-data"
PID_FILE="$RUN_DIR/ds.pid"

DS_BIND="${DS_BIND:-127.0.0.1:3000}"
BASE_URL="${BASE_URL:-http://$DS_BIND}"
CLIENT_PASSWORD="${CLIENT_PASSWORD:-devpass123}"
CLIENT_NAMES="${CLIENT_NAMES:-alice bob carol dave}"
WAIT_SECONDS="${WAIT_SECONDS:-15}"
RESET="${RESET:-1}"
SKIP_BUILD="${SKIP_BUILD:-0}"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required but not installed." >&2
  exit 1
fi

if [[ "$RESET" == "1" ]]; then
  rm -rf "$RUN_DIR"
fi

mkdir -p "$LOG_DIR" "$CLIENT_DIR" "$DS_DATA_DIR"

if [[ "$SKIP_BUILD" != "1" ]]; then
  (cd "$ROOT_DIR" && cargo build --bin ds_server --bin ds_client)
fi

if [[ -f "$PID_FILE" ]]; then
  old_pid="$(cat "$PID_FILE" || true)"
  if [[ -n "${old_pid:-}" ]] && kill -0 "$old_pid" >/dev/null 2>&1; then
    echo "DS already running with PID $old_pid. Run scripts/local-1ds-4clients-down.sh first." >&2
    exit 1
  fi
fi

(
  cd "$ROOT_DIR"
  DS_BIND="$DS_BIND" \
  DS_DATA_DIR="$DS_DATA_DIR" \
  DS_DB_PATH="$DS_DATA_DIR/ds.sqlite" \
  target/debug/ds_server
) >"$LOG_DIR/ds.log" 2>&1 &

ds_pid=$!
echo "$ds_pid" >"$PID_FILE"

ready=0
for _ in $(seq 1 $((WAIT_SECONDS * 10))); do
  if curl -sf "$BASE_URL/healthz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.1
done

if [[ "$ready" != "1" ]]; then
  echo "DS health check failed at $BASE_URL/healthz" >&2
  tail -n 40 "$LOG_DIR/ds.log" || true
  exit 1
fi

for user in $CLIENT_NAMES; do
  state_file="$CLIENT_DIR/${user}.json"
  log_file="$LOG_DIR/client-${user}.log"
  (
    cd "$ROOT_DIR"
    target/debug/ds_client \
      --base-url "$BASE_URL" \
      --state "$state_file" \
      register \
      --username "$user" \
      --password "$CLIENT_PASSWORD" \
      --force
    target/debug/ds_client \
      --base-url "$BASE_URL" \
      --state "$state_file" \
      login \
      --username "$user" \
      --password "$CLIENT_PASSWORD"
  ) >>"$log_file" 2>&1
done

cat <<EOF
Local stack is up.
- DS URL: $BASE_URL
- DS PID: $ds_pid
- Run dir: $RUN_DIR
- Users: $CLIENT_NAMES
- Password: $CLIENT_PASSWORD

Useful commands:
- Check status: scripts/local-1ds-4clients-status.sh
- Stop stack: scripts/local-1ds-4clients-down.sh
- DS log: tail -f "$LOG_DIR/ds.log"
- Example client call:
  target/debug/ds_client --base-url "$BASE_URL" --state "$CLIENT_DIR/alice.json" list-messages --group-id group1 --limit 20 --kind any
EOF
