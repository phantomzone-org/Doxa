# Local E2E (ToyUSDT + ToyTrustedSource + Bridge + Sequencer)

This is the exact local flow:
1. deploy `ToyUSDT`
2. deploy `Verifier` + `DepositsRollupBridge`
3. deploy `ToyTrustedSource`
4. set bridge `trustedSource = ToyTrustedSource`
5. run sequencer
6. call `depositAndRecord(note, amount)` many times (e.g. 256)
7. post a random subset of notes (e.g. 128) to sequencer API
8. verify `consumedRoot` advanced and posted notes became `Consumed`

There is no on-chain `requestConsume` queue in the current model.

## Prerequisites

- `anvil`, `forge`, `cast`, `curl`
- Rust toolchain

```bash
cd tessera-server
cargo run --bin pending_deposit_artifacts --release
```
- generated pending-deposit artifacts under:
  - `tessera-server/artifacts/commitment-tree/plonky2-proof`
  - `tessera-server/artifacts/commitment-tree/groth-artifacts`

Use 4 terminals.

## Terminal A: Start chain

```bash
anvil
```

## Terminal B: Deploy contracts

```bash
cd tessera-solidity

export RPC=http://localhost:8545
export OPERATOR_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# Temporary trusted source for bridge deployment (updated later).
export TEMP_TRUSTED_SOURCE=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
export TESSERA_CONSUMED_GENERIS_ROOT=0x5d85139746d173c92bf3543b4c6ce3daf11bdff30e5b44879d216bc5f06256b6
export TESSERA_CONSUME_BATCH_SIZE=128
```

### 1) Deploy ToyUSDT

```bash
TOKEN=$(forge create src/pending-deposit/ToyUSDT.sol:ToyUSDT \
  --rpc-url "$RPC" \
  --private-key "$OPERATOR_KEY" \
  --broadcast | sed -n 's/Deployed to: //p' | tail -n1)

echo "TOKEN=$TOKEN"
```

### 2) Deploy Verifier + Bridge

```bash
export TESSERA_TRUSTED_SOURCE="$TEMP_TRUSTED_SOURCE"
export TESSERA_MONITORED_TOKEN="$TOKEN"

DEPLOY_OUT=$(forge script script/pending-deposit/Deploy.s.sol \
  --rpc-url "$RPC" \
  --private-key "$OPERATOR_KEY" \
  --broadcast)

echo "$DEPLOY_OUT"

BRIDGE=$(echo "$DEPLOY_OUT" | sed -n 's/.*Bridge deployed at:[[:space:]]*//p' | tail -n1 | tr -d '\r')
echo "BRIDGE=$BRIDGE"
```

### 3) Deploy ToyTrustedSource (cast fallback, robust)

```bash
# Build creation bytecode + constructor args.
BYTECODE=$(forge inspect src/pending-deposit/ToyTrustedSource.sol:ToyTrustedSource bytecode)

# Deploy using cast (works even when `forge create` signer resolution is flaky).
DEPLOY_TS_OUT=$(cast send \
  --rpc-url "$RPC" \
  --private-key "$OPERATOR_KEY" \
  --create "$BYTECODE" \
  "constructor(address,address)" "$BRIDGE" "$TOKEN")

echo "$DEPLOY_TS_OUT"
TRUSTED_SOURCE=$(echo "$DEPLOY_TS_OUT" | sed -n 's/^contractAddress[[:space:]]*//p' | head -n1)

echo "TRUSTED_SOURCE=$TRUSTED_SOURCE"
```

### 4) Point bridge to ToyTrustedSource

```bash
cast send "$BRIDGE" "setTrustedSource(address)" "$TRUSTED_SOURCE" \
  --rpc-url "$RPC" \
  --private-key "$OPERATOR_KEY"

cast call "$BRIDGE" "trustedSource()(address)" --rpc-url "$RPC"
```

## Terminal C: Run sequencer

```bash
cd tessera-server

export TESSERA_RPC_URL=http://localhost:8545
export TESSERA_OPERATOR_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
export TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=<PASTE_BRIDGE_FROM_TERMINAL_B>
export TESSERA_CHAIN_ID=31337
export TESSERA_PENDING_DEPOSITS_ARTIFACTS_PATH=./artifacts/commitment-tree
export TESSERA_SEQUENCER_API_ADDR=127.0.0.1:8081

cargo run --bin sequencer --release
```

## Terminal D: Deposit 256 notes and request consume for 128 random notes

```bash
export RPC=http://localhost:8545
export BRIDGE=<PASTE_BRIDGE_FROM_TERMINAL_B>
export TOKEN=<PASTE_TOKEN_FROM_TERMINAL_B>
export TRUSTED_SOURCE=<PASTE_TRUSTED_SOURCE_FROM_TERMINAL_B>

# User account (anvil account #2)
export USER_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
export USER_ADDR=$(cast wallet address --private-key "$USER_KEY")

echo "USER_ADDR=$USER_ADDR"
```

### 1) Fund user in ToyUSDT and approve ToyTrustedSource

```bash
# Mint 1,000,000,000 units (ToyUSDT uses 6 decimals)
cast send "$TOKEN" "mint(address,uint256)" "$USER_ADDR" 1000000000 \
  --rpc-url "$RPC" \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

cast send "$TOKEN" "approve(address,uint256)" "$TRUSTED_SOURCE" 1000000000 \
  --rpc-url "$RPC" \
  --private-key "$USER_KEY"
```

### 2) Create 256 deposits with unique notes via `depositAndRecord`

```bash
NOTES_FILE=/tmp/tessera_notes_256.txt
: > "$NOTES_FILE"

for i in $(seq 1 256); do
  NOTE=$(printf "0x%064x" "$i")
  AMOUNT=$((1000 + i))

  cast send "$TRUSTED_SOURCE" "depositAndRecord(bytes32,uint256)" "$NOTE" "$AMOUNT" \
    --rpc-url "$RPC" \
    --private-key "$USER_KEY" >/dev/null

  echo "$NOTE" >> "$NOTES_FILE"
done

echo "Recorded 256 deposits. Notes in $NOTES_FILE"
```

### 3) Submit 128 random consume requests to sequencer API

```bash
REQ_FILE=/tmp/tessera_consume_128.txt
shuf "$NOTES_FILE" | head -n 128 > "$REQ_FILE"

while read -r NOTE; do
  curl -sS -X POST http://127.0.0.1:8081/consume-request \
    -H 'content-type: application/json' \
    -d "{\"note_commitment\":\"$NOTE\"}" >/dev/null
done < "$REQ_FILE"

echo "Submitted 128 consume requests to sequencer API"
```

## Verify results (Terminal D)

### 1) `consumedRoot` changed

```bash
cast call "$BRIDGE" "consumedRoot()(bytes32)" --rpc-url "$RPC"
```

### 2) Count consumed notes among requested subset

```bash
consumed=0
while read -r NOTE; do
  STATUS=$(cast call "$BRIDGE" "getDepositStatus(bytes32)(uint8)" "$NOTE" --rpc-url "$RPC" | tr -d '[:space:]')
  if [[ "$STATUS" == "1" ]]; then
    consumed=$((consumed + 1))
  fi
done < "$REQ_FILE"

echo "Consumed in requested subset: $consumed/128"
```

Expected after sequencer finalizes one batch:
- `Consumed in requested subset: 128/128`
- non-requested notes remain `Available` (`status = 0`)

## Status codes

- `0 = Available`
- `1 = Consumed`

## One command alternative

From repo root, you can run the full Toy E2E automatically:

```bash
scripts/local_e2e_toy.sh 256 128
```

This performs deployment, sequencer launch, `depositAndRecord` loop, random consume-request submission, and final assertions.

## Troubleshooting: why `forge create` failed

If you saw:

`Error accessing local wallet...`

while `cast wallet address --private-key ...` worked, your local Foundry setup likely had a signer-resolution issue specific to `forge create`.

Using `cast send --create ...` avoids that path and is compatible with older `cast` versions too.
