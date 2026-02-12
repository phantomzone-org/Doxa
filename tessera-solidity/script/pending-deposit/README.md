# Local End-to-End Test (New Consume-Batch Flow)

This guide tests the updated bridge + sequencer flow locally:

1. trusted source records deposits (`recordDeposit`)
2. consume requests are submitted by commitment (`requestConsume`)
3. sequencer batches requests (size = `consumeBatchSize`)
4. sequencer generates proof and calls `finalizeConsumeBatch`

Use **4 terminals**.

## Fast Path (Recommended)

From repo root:

```bash
source scripts/local_env.sh
```

Then:

- Terminal A: `anvil`
- Terminal B: `scripts/local_deploy.sh` (exports/updates bridge address)
- Terminal C: `scripts/local_run_sequencer.sh`
- Terminal D: `scripts/local_seed.sh 256 128`

This replaces most manual export/copy-paste steps.

## Prerequisites

- `anvil`, `forge`, `cast`
- Rust toolchain
- used-deposit artifacts already generated:
  - `tessera-server/artifacts/used-deposit/plonky2-proof`
  - `tessera-server/artifacts/used-deposit/groth-artifacts`

---

## Terminal A: Start Chain

```bash
anvil
```

Default anvil keys used below:

- operator (account 0):
  - address: `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`
  - key: `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`
- trusted source (account 1):
  - address: `0x70997970C51812dc3A010C7d01b50e0d17dc79C8`
  - key: `0x59c6995e998f97a5a0044966f0945384c6d9e86dae88f6a6a8e10f5c1a4f7a5d`

---

## Terminal B: Deploy Bridge + Verifier

From repo root:

```bash
export TESSERA_TRUSTED_SOURCE=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
export TESSERA_CONSUMED_GENERIS_ROOT=0x1ef897f4a5c3f5c07cddaf7dec41197f2259296bb1bb56264ca73c3e1b998bf9
export TESSERA_CONSUME_BATCH_SIZE=128

cd tessera-solidity
forge script script/pending-deposit/Deploy.s.sol \
  --rpc-url http://localhost:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast
```

Copy the printed bridge address and set it as:

```bash
export BRIDGE=<DEPLOYED_BRIDGE_ADDRESS>
```

---

## Terminal C: Run Sequencer

From `tessera-server` directory:

```bash
cd tessera-server
export TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=<DEPLOYED_BRIDGE_ADDRESS>
cargo run --bin sequencer --release
```

Notes:

- `src/bin/sequencer.rs` loads `tessera-server/.env` automatically.
- Ensure `.env` points to used-deposit artifacts:
  - `TESSERA_PENDING_DEPOSITS_ARTIFACTS_PATH=./artifacts/used-deposit`

---

## Terminal D: Create Deposits + Requests

Set helpers:

```bash
export RPC=http://localhost:8545
export BRIDGE=<DEPLOYED_BRIDGE_ADDRESS>
export TRUSTED_KEY=0x59c6995e998f97a5a0044966f0945384c6d9e86dae88f6a6a8e10f5c1a4f7a5d
export DEPOSITOR=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
export RECIPIENT=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
```

Submit 128 deposits and request consume for each:

```bash
for i in $(seq 1 128); do
  NOTE=$(printf "0x%064x" "$i")
  VALUE=$i

  # 1) recordDeposit from trusted source
  cast send "$BRIDGE" \
    "recordDeposit(bytes32,uint256,address,address)" \
    "$NOTE" "$VALUE" "$DEPOSITOR" "$RECIPIENT" \
    --rpc-url "$RPC" --private-key "$TRUSTED_KEY" >/dev/null

  # 2) compute commitment (must match contract hashing)
  COMMITMENT=$(cast call "$BRIDGE" \
    "computeCommitment(bytes32,uint256,address)(bytes32)" \
    "$NOTE" "$VALUE" "$RECIPIENT" \
    --rpc-url "$RPC")

  # 3) request consume by leaf value
  cast send "$BRIDGE" \
    "requestConsume(bytes32)" \
    "$COMMITMENT" \
    --rpc-url "$RPC" --private-key "$TRUSTED_KEY" >/dev/null
done
```

Alternative:

```bash
scripts/local_seed.sh 256 128
```

## Stress Tests

From repo root:

```bash
source scripts/local_env.sh
```

### Recovery on sequencer restart

This scenario simulates:

1. deposits + partial consume requests
2. sequencer shutdown before batch can finalize
3. more requests while sequencer is down
4. sequencer restart and recovery/finalization

Run:

```bash
scripts/local_stress_recovery.sh
```

If successful, it prints `Recovery test passed.` and shows the sequencer log path.

### Inspect deposit statuses

Example: inspect first 20 deposits:

```bash
scripts/local_status.sh 0 20
```

### Submit extra consume requests against existing deposits

Example: request consume for note indices `129..256` in random order:

```bash
scripts/local_request.sh 129 128 random
```

Expected result:

- Sequencer logs should show a batch proving/finalization cycle.
- Contract root should advance:

```bash
cast call "$BRIDGE" "consumedRoot()(bytes32)" --rpc-url "$RPC"
```

Optional status check:

```bash
cast call "$BRIDGE" "getDeposit(uint256)((bytes32,uint256,address,address,uint8))" 0 --rpc-url "$RPC"
```

`status` enum values:

- `0 = Available`
- `1 = Withdrawn`
- `2 = Consumed`

---

## If Something Fails

- `InvalidProof()`:
  - Verifier/artifacts mismatch. Confirm `src/pending-deposit/Verifier.sol` matches:
    - `tessera-server/artifacts/used-deposit/groth-artifacts/Verifier.sol`
- No sequencer batching:
  - check contract `consumeBatchSize` and number of submitted requests.
- Root mismatch on startup:
  - sequencer local replay did not match chain history; redeploy/reset local chain for clean test.
