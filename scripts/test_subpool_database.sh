#!/usr/bin/env bash
set -euo pipefail

# End-to-end smoke test for doxa-subpool-database.
#
# Steps:
#   1. Start a throwaway PostgreSQL container.
#   2. Build the binary.
#   3. Run the server (auto-migrates on startup).
#   4. Wait for the server to accept connections.
#   5. Run API assertions: happy path, duplicate rejection, bad input.
#   6. Tear everything down (server + container).
#
# Prerequisites: docker (or sudo docker), cargo, curl, python3.
#
# Usage:
#   bash scripts/test_subpool_database.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_DIR="$ROOT_DIR/doxa-subpool-database"

# ── Config ────────────────────────────────────────────────────────────────────
PG_CONTAINER="doxa-subpool-test-pg"
PG_PORT="15432"   # use non-default port to avoid conflicts
PG_USER="doxa"
PG_PASS="doxa"
PG_DB="doxa_subpool"
DATABASE_URL="postgres://${PG_USER}:${PG_PASS}@localhost:${PG_PORT}/${PG_DB}"
API_ADDR="127.0.0.1:18080"
API_URL="http://${API_ADDR}"
SERVER_PID=""

# ── Docker detection ──────────────────────────────────────────────────────────
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
  DOCKER="docker"
elif command -v sudo &>/dev/null && sudo docker info &>/dev/null 2>&1; then
  DOCKER="sudo docker"
else
  echo "ERROR: docker is not available. Install Docker and ensure your user can run it." >&2
  exit 1
fi

# ── Cleanup on exit ───────────────────────────────────────────────────────────
cleanup() {
  echo ""
  echo "── Cleaning up ──────────────────────────────────────────────────────────────"
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "  Stopping server (PID $SERVER_PID) ..."
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if $DOCKER ps --format '{{.Names}}' | grep -q "^${PG_CONTAINER}$" 2>/dev/null; then
    echo "  Removing postgres container ..."
    $DOCKER rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# ── Helpers ───────────────────────────────────────────────────────────────────
ok()   { echo "  ✓ $*"; }
fail() { echo "  ✗ FAIL: $*" >&2; exit 1; }

assert_status() {
  local label="$1" expected="$2" actual="$3" body="$4"
  if [[ "$actual" == "$expected" ]]; then
    ok "$label → HTTP $actual"
  else
    fail "$label: expected HTTP $expected, got $actual. Body: $body"
  fi
}

assert_field() {
  local label="$1" field="$2" body="$3"
  if echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); assert '$field' in d, '$field missing'" 2>/dev/null; then
    ok "$label → field '$field' present"
  else
    fail "$label: field '$field' missing in: $body"
  fi
}

# ── Build sample hex payloads ─────────────────────────────────────────────────
# private_identifier: 16 bytes (2 × u64 LE) — values 1 and 2
PRIV_ID_HEX=$(python3 -c "
import struct
b = struct.pack('<QQ', 1, 2)
print(b.hex())
")

# spend_auth_pk: 40 bytes (5 × u64 LE) — values 1..5
SPEND_PK_HEX=$(python3 -c "
import struct
b = struct.pack('<QQQQQ', 1, 2, 3, 4, 5)
print(b.hex())
")

# A second distinct private_identifier (values 3, 4)
PRIV_ID_HEX2=$(python3 -c "
import struct
b = struct.pack('<QQ', 3, 4)
print(b.hex())
")

REGISTER_BODY=$(cat <<EOF
{
  "private_identifier": "$PRIV_ID_HEX",
  "spend_auth_pk":      "$SPEND_PK_HEX",
  "eth_address":        "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
  "name":               "Alice",
  "physical_address":   "123 Main St",
  "dob":                "1990-01-15"
}
EOF
)

REGISTER_BODY2=$(cat <<EOF
{
  "private_identifier": "$PRIV_ID_HEX2",
  "spend_auth_pk":      "$SPEND_PK_HEX",
  "eth_address":        "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
  "name":               "Bob",
  "physical_address":   "456 Other St",
  "dob":                "1985-06-20"
}
EOF
)

# ── 1. Start postgres ─────────────────────────────────────────────────────────
echo "── Step 1: Starting PostgreSQL container ────────────────────────────────────"
$DOCKER rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
$DOCKER run -d \
  --name "$PG_CONTAINER" \
  -e POSTGRES_USER="$PG_USER" \
  -e POSTGRES_PASSWORD="$PG_PASS" \
  -e POSTGRES_DB="$PG_DB" \
  -p "${PG_PORT}:5432" \
  postgres:16 >/dev/null

echo -n "  Waiting for postgres to accept connections"
for i in $(seq 1 30); do
  if $DOCKER exec "$PG_CONTAINER" pg_isready -U "$PG_USER" -d "$PG_DB" -q 2>/dev/null; then
    echo " ready."
    break
  fi
  echo -n "."
  sleep 1
  if [[ $i -eq 30 ]]; then
    echo ""
    fail "postgres did not become ready in 30s"
  fi
done

# ── 2. Build ──────────────────────────────────────────────────────────────────
echo ""
echo "── Step 2: Building doxa-subpool-database ────────────────────────────────"
cargo build -p doxa-subpool-database --quiet 2>&1
ok "build succeeded"

# ── 3. Start server ───────────────────────────────────────────────────────────
echo ""
echo "── Step 3: Starting server ──────────────────────────────────────────────────"
LOG_FILE="$(mktemp /tmp/doxa-subpool-server.XXXXXX.log)"

DATABASE_URL="$DATABASE_URL" \
DOXA_SUBPOOL_API_ADDR="$API_ADDR" \
  cargo run -p doxa-subpool-database --quiet 2>&1 >"$LOG_FILE" &
SERVER_PID=$!

echo -n "  Waiting for server to start"
for i in $(seq 1 30); do
  if curl -sf "$API_URL/register" -o /dev/null -w "" 2>/dev/null || \
     curl -s "$API_URL/register" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -qE "^(405|422|400|200|201)$"; then
    echo " ready."
    break
  fi
  # Also accept if process is running and port is open
  if ss -tlnp 2>/dev/null | grep -q ":18080"; then
    echo " ready."
    break
  fi
  sleep 1
  echo -n "."
  if [[ $i -eq 30 ]]; then
    echo ""
    echo "Server log:" >&2
    cat "$LOG_FILE" >&2
    fail "server did not start in 30s"
  fi
done

# Give the server one more second to finish binding
sleep 1

# ── 4. API tests ──────────────────────────────────────────────────────────────
echo ""
echo "── Step 4: API assertions ───────────────────────────────────────────────────"

# 4a. Happy path — register Alice
echo ""
echo "  [4a] POST /register — Alice (happy path)"
resp=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/register" \
  -H 'Content-Type: application/json' \
  -d "$REGISTER_BODY")
body=$(echo "$resp" | head -n -1)
code=$(echo "$resp" | tail -n 1)
assert_status "register Alice" "201" "$code" "$body"
assert_field "register Alice response" "private_acc_address" "$body"
ALICE_ADDR=$(echo "$body" | python3 -c "import sys,json; print(json.load(sys.stdin)['private_acc_address'])")
ok "Alice's private_acc_address = $ALICE_ADDR"

# 4b. Duplicate — same private_identifier → 409
echo ""
echo "  [4b] POST /register — duplicate (expect 409)"
resp=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/register" \
  -H 'Content-Type: application/json' \
  -d "$REGISTER_BODY")
body=$(echo "$resp" | head -n -1)
code=$(echo "$resp" | tail -n 1)
assert_status "duplicate register" "409" "$code" "$body"

# 4c. Happy path — register Bob (different private_identifier)
echo ""
echo "  [4c] POST /register — Bob (different account)"
resp=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/register" \
  -H 'Content-Type: application/json' \
  -d "$REGISTER_BODY2")
body=$(echo "$resp" | head -n -1)
code=$(echo "$resp" | tail -n 1)
assert_status "register Bob" "201" "$code" "$body"
assert_field "register Bob response" "private_acc_address" "$body"
BOB_ADDR=$(echo "$body" | python3 -c "import sys,json; print(json.load(sys.stdin)['private_acc_address'])")
ok "Bob's private_acc_address = $BOB_ADDR"

# Sanity: Alice and Bob have different addresses
if [[ "$ALICE_ADDR" != "$BOB_ADDR" ]]; then
  ok "Alice and Bob have distinct addresses"
else
  fail "Alice and Bob produced the same address!"
fi

# 4d. Bad input — private_identifier wrong length → 400
echo ""
echo "  [4d] POST /register — bad private_identifier length (expect 400)"
BAD_BODY=$(echo "$REGISTER_BODY" | python3 -c "
import sys, json
d = json.load(sys.stdin)
d['private_identifier'] = 'deadbeef'  # only 4 bytes
print(json.dumps(d))
")
resp=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/register" \
  -H 'Content-Type: application/json' \
  -d "$BAD_BODY")
body=$(echo "$resp" | head -n -1)
code=$(echo "$resp" | tail -n 1)
assert_status "bad private_identifier" "400" "$code" "$body"

# 4e. Bad input — invalid eth_address → 400
echo ""
echo "  [4e] POST /register — bad eth_address (expect 400)"
BAD_ETH_BODY=$(echo "$REGISTER_BODY2" | python3 -c "
import sys, json
d = json.load(sys.stdin)
d['private_identifier'] = '$(python3 -c "import struct; print(struct.pack('<QQ',99,100).hex())")'
d['eth_address'] = 'not-an-address'
print(json.dumps(d))
")
resp=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/register" \
  -H 'Content-Type: application/json' \
  -d "$BAD_ETH_BODY")
body=$(echo "$resp" | head -n -1)
code=$(echo "$resp" | tail -n 1)
assert_status "bad eth_address" "400" "$code" "$body"

# 4f. Bad input — invalid dob format → 400
echo ""
echo "  [4f] POST /register — bad dob format (expect 400)"
BAD_DOB_BODY=$(echo "$REGISTER_BODY2" | python3 -c "
import sys, json
d = json.load(sys.stdin)
d['private_identifier'] = '$(python3 -c "import struct; print(struct.pack('<QQ',77,88).hex())")'
d['dob'] = '15-01-1990'
print(json.dumps(d))
")
resp=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/register" \
  -H 'Content-Type: application/json' \
  -d "$BAD_DOB_BODY")
body=$(echo "$resp" | head -n -1)
code=$(echo "$resp" | tail -n 1)
assert_status "bad dob" "400" "$code" "$body"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "  ALL TESTS PASSED"
echo "  Server log: $LOG_FILE"
echo "═══════════════════════════════════════════════════════════════════════"
