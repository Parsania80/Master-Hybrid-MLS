#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${RUN_DIR:-$ROOT_DIR/local-1ds-4clients-demo-run}"
LOG_DIR="$RUN_DIR/logs"
CLIENT_DIR="$RUN_DIR/clients"
KEY_DIR="$RUN_DIR/key-material"
GROUP_DIR="$RUN_DIR/group"
DEMO_LOG="$LOG_DIR/demo.log"

DS_BIND="${DS_BIND:-127.0.0.1:3000}"
BASE_URL="${BASE_URL:-http://$DS_BIND}"
GROUP_ID="${GROUP_ID:-demo-group}"
CLIENT_NAMES="${CLIENT_NAMES:-alice bob carol dave}"
CLIENT_PASSWORD="${CLIENT_PASSWORD:-devpass123}"
SKIP_BUILD="${SKIP_BUILD:-0}"
WAIT_SECONDS="${WAIT_SECONDS:-15}"

UP_SCRIPT="$ROOT_DIR/scripts/local-1ds-4clients-up.sh"
DOWN_SCRIPT="$ROOT_DIR/scripts/local-1ds-4clients-down.sh"
DS_CLIENT_BIN="$ROOT_DIR/target/debug/ds_client"

log() {
  local now
  now="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "[$now] $*" | tee -a "$DEMO_LOG"
}

run_client() {
  local user="$1"
  shift
  local state_file="$CLIENT_DIR/${user}.json"
  local user_log="$LOG_DIR/demo-${user}.log"

  if [[ ! -f "$state_file" ]]; then
    log "ERROR missing client state file: $state_file"
    exit 1
  fi

  log "CMD [$user] ds_client $*"
  "$DS_CLIENT_BIN" \
    --base-url "$BASE_URL" \
    --state "$state_file" \
    "$@" 2>&1 | tee -a "$DEMO_LOG" "$user_log"
}

RUN_DIR="$RUN_DIR" CLEAN=1 "$DOWN_SCRIPT" >/dev/null 2>&1 || true
rm -rf "$RUN_DIR"
mkdir -p "$LOG_DIR" "$KEY_DIR" "$GROUP_DIR"
touch "$DEMO_LOG"
log "Preparing fresh local environment in $RUN_DIR"

log "Starting DS + clients via local-1ds-4clients-up.sh (DS_MIN_PROPOSALS_PER_COMMIT=1)"
RUN_DIR="$RUN_DIR" \
DS_BIND="$DS_BIND" \
BASE_URL="$BASE_URL" \
CLIENT_NAMES="$CLIENT_NAMES" \
CLIENT_PASSWORD="$CLIENT_PASSWORD" \
WAIT_SECONDS="$WAIT_SECONDS" \
SKIP_BUILD="$SKIP_BUILD" \
RESET=0 \
DS_MIN_PROPOSALS_PER_COMMIT=1 \
"$UP_SCRIPT" 2>&1 | tee -a "$DEMO_LOG"

# up script owns client/ds-data setup; ensure demo artifact dirs exist.
mkdir -p "$KEY_DIR" "$GROUP_DIR"

if [[ ! -x "$DS_CLIENT_BIN" ]]; then
  log "ERROR ds_client binary not found: $DS_CLIENT_BIN"
  exit 1
fi

log "Step 0: Generate KEM keys, export signed key packages, publish key packages to DS"
for user in $CLIENT_NAMES; do
  run_client "$user" keygen --out "$KEY_DIR/${user}-kem.json" --force
  run_client "$user" keypackage-export \
    --kem-file "$KEY_DIR/${user}-kem.json" \
    --keypackage-out "$KEY_DIR/${user}.kp" \
    --receiver-private-out "$KEY_DIR/${user}.recv.json" \
    --force
  run_client "$user" publish-key-package --keypackage-file "$KEY_DIR/${user}.kp"
done

log "Bootstrap initial group state for Alice (group=$GROUP_ID, only Alice as member)"
ALICE_STATE="$GROUP_DIR/alice-group-state.bin"
run_client alice bootstrap-group-state \
  --group-id "$GROUP_ID" \
  --member-keypackage "$KEY_DIR/alice.kp" \
  --own-leaf 0 \
  --out "$ALICE_STATE" \
  --force

ALICE_RECV_CURRENT="$KEY_DIR/alice.recv.json"
BOB_STATE="$GROUP_DIR/bob-group-state.bin"
CAROL_STATE="$GROUP_DIR/carol-group-state.bin"

log "Step 1: A adds B (proposal -> commit -> join) and then A performs key update"
run_client alice fetch-key-package --target bob --out "$GROUP_DIR/bob-from-ds.kp"
run_client alice create-add-proposal \
  --group-state "$ALICE_STATE" \
  --keypackage-file "$GROUP_DIR/bob-from-ds.kp" \
  --out "$GROUP_DIR/epoch0-add-bob.proposal.bin" \
  --sender-leaf 0
run_client alice submit-proposal \
  --group-id "$GROUP_ID" \
  --proposal-file "$GROUP_DIR/epoch0-add-bob.proposal.bin"
run_client alice create-commit \
  --group-state "$ALICE_STATE" \
  --commit-out "$GROUP_DIR/epoch0-add-bob.commit.bin" \
  --path-update-out "$GROUP_DIR/epoch0-add-bob.path.bin" \
  --sender-leaf 0
run_client alice submit-commit \
  --group-id "$GROUP_ID" \
  --commit-file "$GROUP_DIR/epoch0-add-bob.commit.bin" \
  --path-update-file "$GROUP_DIR/epoch0-add-bob.path.bin"

run_client bob join-from-commit \
  --base-member-keypackage "$KEY_DIR/alice.kp" \
  --commit-file "$GROUP_DIR/epoch0-add-bob.commit.bin" \
  --path-update-file "$GROUP_DIR/epoch0-add-bob.path.bin" \
  --receiver-private-file "$KEY_DIR/bob.recv.json" \
  --out "$BOB_STATE" \
  --force

run_client alice keygen --out "$KEY_DIR/alice-v2-kem.json" --force
run_client alice keypackage-export \
  --kem-file "$KEY_DIR/alice-v2-kem.json" \
  --keypackage-out "$KEY_DIR/alice-v2.kp" \
  --receiver-private-out "$KEY_DIR/alice-v2.recv.json" \
  --force
run_client alice publish-key-package --keypackage-file "$KEY_DIR/alice-v2.kp"
run_client alice create-update-proposal \
  --group-state "$ALICE_STATE" \
  --keypackage-file "$KEY_DIR/alice-v2.kp" \
  --out "$GROUP_DIR/epoch1-update-alice.proposal.bin" \
  --sender-leaf 0 \
  --target-leaf 0
run_client alice submit-proposal \
  --group-id "$GROUP_ID" \
  --proposal-file "$GROUP_DIR/epoch1-update-alice.proposal.bin"
run_client alice create-commit \
  --group-state "$ALICE_STATE" \
  --commit-out "$GROUP_DIR/epoch1-update-alice.commit.bin" \
  --path-update-out "$GROUP_DIR/epoch1-update-alice.path.bin" \
  --sender-leaf 0
run_client alice submit-commit \
  --group-id "$GROUP_ID" \
  --commit-file "$GROUP_DIR/epoch1-update-alice.commit.bin" \
  --path-update-file "$GROUP_DIR/epoch1-update-alice.path.bin"
run_client bob apply-received-commit \
  --group-state "$BOB_STATE" \
  --commit-file "$GROUP_DIR/epoch1-update-alice.commit.bin" \
  --path-update-file "$GROUP_DIR/epoch1-update-alice.path.bin" \
  --receiver-private-file "$KEY_DIR/bob.recv.json"
ALICE_RECV_CURRENT="$KEY_DIR/alice-v2.recv.json"

log "Step 2: B adds C (proposal -> commit -> apply for A -> join C)"
run_client bob fetch-key-package --target carol --out "$GROUP_DIR/carol-from-ds.kp"
run_client bob create-add-proposal \
  --group-state "$BOB_STATE" \
  --keypackage-file "$GROUP_DIR/carol-from-ds.kp" \
  --out "$GROUP_DIR/epoch2-add-carol.proposal.bin" \
  --sender-leaf 1
run_client bob submit-proposal \
  --group-id "$GROUP_ID" \
  --proposal-file "$GROUP_DIR/epoch2-add-carol.proposal.bin"
run_client bob create-commit \
  --group-state "$BOB_STATE" \
  --commit-out "$GROUP_DIR/epoch2-add-carol.commit.bin" \
  --path-update-out "$GROUP_DIR/epoch2-add-carol.path.bin" \
  --sender-leaf 1
run_client bob submit-commit \
  --group-id "$GROUP_ID" \
  --commit-file "$GROUP_DIR/epoch2-add-carol.commit.bin" \
  --path-update-file "$GROUP_DIR/epoch2-add-carol.path.bin"
run_client alice apply-received-commit \
  --group-state "$ALICE_STATE" \
  --commit-file "$GROUP_DIR/epoch2-add-carol.commit.bin" \
  --path-update-file "$GROUP_DIR/epoch2-add-carol.path.bin" \
  --receiver-private-file "$ALICE_RECV_CURRENT"
run_client carol join-from-commit \
  --base-member-keypackage "$KEY_DIR/alice-v2.kp" \
  --base-member-keypackage "$KEY_DIR/bob.kp" \
  --commit-file "$GROUP_DIR/epoch2-add-carol.commit.bin" \
  --path-update-file "$GROUP_DIR/epoch2-add-carol.path.bin" \
  --receiver-private-file "$KEY_DIR/carol.recv.json" \
  --out "$CAROL_STATE" \
  --force

log "Step 3: A removes C (proposal -> commit -> apply for B)"
run_client alice create-remove-proposal \
  --group-state "$ALICE_STATE" \
  --remove-leaf 2 \
  --out "$GROUP_DIR/epoch3-remove-carol.proposal.bin" \
  --sender-leaf 0
run_client alice submit-proposal \
  --group-id "$GROUP_ID" \
  --proposal-file "$GROUP_DIR/epoch3-remove-carol.proposal.bin"
run_client alice create-commit \
  --group-state "$ALICE_STATE" \
  --commit-out "$GROUP_DIR/epoch3-remove-carol.commit.bin" \
  --path-update-out "$GROUP_DIR/epoch3-remove-carol.path.bin" \
  --sender-leaf 0
run_client alice submit-commit \
  --group-id "$GROUP_ID" \
  --commit-file "$GROUP_DIR/epoch3-remove-carol.commit.bin" \
  --path-update-file "$GROUP_DIR/epoch3-remove-carol.path.bin"
run_client bob apply-received-commit \
  --group-state "$BOB_STATE" \
  --commit-file "$GROUP_DIR/epoch3-remove-carol.commit.bin" \
  --path-update-file "$GROUP_DIR/epoch3-remove-carol.path.bin" \
  --receiver-private-file "$KEY_DIR/bob.recv.json"

log "Final DS message snapshot"
run_client alice list-messages --group-id "$GROUP_ID" --kind any --limit 200

log "Demo complete."
log "Run directory: $RUN_DIR"
log "Demo log: $DEMO_LOG"
log "DS log: $LOG_DIR/ds.log"
log "Client logs: $LOG_DIR/demo-*.log"
log "Use scripts/local-1ds-4clients-down.sh with RUN_DIR=$RUN_DIR to stop DS."
