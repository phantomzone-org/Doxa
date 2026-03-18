# Local Scripts Guide

These scripts are aligned with the current API-driven consume flow.

Flow:
1. deposits are registered on-chain via `bridge.depositAndRegister()` called directly from the operator key (using the `client deposit` binary)
2. consume requests are pushed to sequencer API (`POST /consume-request` or `POST /notes/commitment`)
   - each request must include `input_proof` — a hex-encoded Plonky2 **4-PI** leaf proof; validated cryptographically when `TESSERA_CONSUME_ARTIFACTS_PATH` is set; falls back to accepting any non-empty bytes otherwise
   - the `client consume` binary generates real 4-PI proofs on-the-fly from the consume artifacts
3. other tree leaves can be pushed via:
- `POST /notes/nullifier` with body `{"leaf":"0x..."}`
4. private-tx payloads can be pushed via:
- `POST /private-tx` (or `/private-tx/notes`) with body:
  - `input_notes[]` (max 8)
  - `output_notes[]` (max 8)
  - `input_account_commitment`
  - `output_account_commitment`
  - `tx_proof` (hex-encoded Plonky2 **72-PI** `ProofWithPublicInputs` bytes)
- the `client private-tx` binary generates random TX data (nullifiers, commitments, account mutations) and proves real 73-PI proofs on-the-fly from the aggregator artifacts
5. sequencer batches, proves (single SuperAggregator Groth16 proof), then records on-chain:
   - Phase A: `registerTransactionBatchUpdate(newNCRoot, ncLeaves, newNNRoot, nnLeaves, newACRoot, acLeaves, newANRoot, anLeaves)` — all 4 optimistic roots advance immediately
   - Phase B: `confirmBatch(batchId, superAggregatorProof)` — all 4 confirmed roots advance atomically

## Scripts

- `local_env.sh`
  - Loads local defaults (`RPC`, keys, `TESSERA_NOTE_BATCH_SIZE` (1024), `TESSERA_ACCOUNT_BATCH_SIZE` (128), artifact paths, sequencer API address).
  - Sets `TESSERA_SUPER_AGGREGATOR_ARTIFACTS_PATH` (required by prover), `TESSERA_AGGREGATOR_ARTIFACTS_PATH` (optional, for 72-PI TX leaf proof validation), and `TESSERA_CONSUME_ARTIFACTS_PATH` (optional, for 4-PI consume proof validation).
  - Artifact paths are **guarded**: only exported when the corresponding `leaf_common.bin` file exists on disk.

- `local_deploy.sh`
  - Deploys verifier + bridge.
  - Auto-deploys `ToyUSDT` if `TESSERA_MONITORED_TOKEN` is not pre-set.
  - Writes `TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS` into `tessera-server/.env`.

- `local_run_prover.sh`
  - Starts standalone prover service (`cargo run --bin prover --release`).
  - Uses `TESSERA_PROVER_API_ADDR` (default `127.0.0.1:8091`).

- `local_run_sequencer.sh`
  - Starts sequencer with env expected by `SequencerConfig::from_env()`.
  - Connects to prover service via `TESSERA_PROVER_API_URL`.
  - Exposes consume API at `TESSERA_SEQUENCER_API_ADDR` (default `127.0.0.1:8081`).

- `local_request.sh [start_note] [count] [order] [max_note]`
  - Pushes consume requests to sequencer API with `input_proof`.
  - **Fast-path** (ordered mode): when `TESSERA_CONSUME_ARTIFACTS_PATH` is set and `order=ordered`, delegates to `client consume` which generates real 4-PI proofs on-the-fly.
  - **Fallback** (random/random-unconsumed or no artifacts): uses `cast call` to enumerate pending notes and posts with dummy `0x01` sentinel (accepted when server has no consume verifier).

- `local_status.sh [start_note] [count]`
  - Prints consumed root + note statuses over a range.

- `local_request_reconsume.sh [count] [max_note]`
  - Re-submits consumed notes to API (negative check).

- `local_request_leaf.sh <endpoint> <0x-leaf>`
  - Posts a single leaf to a non-deposit tree endpoint (`/notes/nullifier`).

- `sync_verifiers_from_artifacts.sh`
  - Copies the freshly generated Groth16 verifier Solidity contract from the SuperAggregator artifact directory into `tessera-solidity/src/`:
    - `VerifierSuperAggregator.sol` ← `artifacts/super-aggregator/groth-artifacts/Verifier.sol`
  - Must be run after regenerating artifacts to keep on-chain verifying keys in sync.

## Artifact Binaries

The `tessera-server` crate provides artifact generator binaries that must be run in dependency order.
All require `--release`. Default batch sizes: `TESSERA_NOTE_BATCH_SIZE=1024`, `TESSERA_ACCOUNT_BATCH_SIZE=128`.

```bash
# Step 1 — commitment tree artifacts (NC + AC; no dependencies)
#   → tessera-server/artifacts/commitment-tree/
TESSERA_NOTE_BATCH_SIZE=1024 \
cargo run --bin commitment_tree_artifacts --release --manifest-path tessera-server/Cargo.toml

# Step 2 — TX leaf aggregator artifacts (77-PI; no dependencies)
#   → tessera-server/artifacts/associated-input-aggregator/
cargo run --bin aggregator_artifacts --release --manifest-path tessera-server/Cargo.toml

# Step 3 — consume circuit artifacts (4-PI; no dependencies)
#   → tessera-server/artifacts/consume/
cargo run --bin consume_artifacts --release --manifest-path tessera-server/Cargo.toml

# Step 4 — SuperAggregator artifacts (Groth16; requires steps 1–3)
#   → tessera-server/artifacts/super-aggregator/
TESSERA_NOTE_BATCH_SIZE=1024 TESSERA_ACCOUNT_BATCH_SIZE=128 \
cargo run --bin super_aggregator_artifacts --release --manifest-path tessera-server/Cargo.toml

# Step 5 — copy Groth16 Verifier.sol into tessera-solidity/src/
scripts/sync_verifiers_from_artifacts.sh
```

After running these, `local_env.sh` will auto-detect and export `TESSERA_CONSUME_ARTIFACTS_PATH`,
`TESSERA_AGGREGATOR_ARTIFACTS_PATH`, and `TESSERA_SUPER_AGGREGATOR_ARTIFACTS_PATH`.

## E2E Client Binary

The `client` binary provides subcommands for registering on-chain deposits and submitting proofs:

```bash
source scripts/local_env.sh
```

```bash
# Register N deposits on-chain (requires TESSERA_RPC_URL, TESSERA_CLIENT_KEY,
# TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS, TESSERA_MONITORED_TOKEN)
cargo run --bin client --release --manifest-path tessera-server/Cargo.toml -- \
  deposit --count 256 --start-index 1 --amount 1

# Submit N ordered consume-request proofs (requires TESSERA_CONSUME_ARTIFACTS_PATH,
# TESSERA_SEQUENCER_API_URL)
cargo run --bin client --release --manifest-path tessera-server/Cargo.toml -- \
  consume --count 16 --start-index 1

# Submit N private transactions with random data (requires
# TESSERA_AGGREGATOR_ARTIFACTS_PATH, TESSERA_SEQUENCER_API_URL)
cargo run --bin client --release --manifest-path tessera-server/Cargo.toml -- \
  private-tx --count 128
```

## Full E2E Walkthrough

256 deposits → validate all → private transactions each consuming 8 deposits.

### Prerequisites

Artifacts must be built once (see [Artifact Binaries](#artifact-binaries)).

### 1 — Start infrastructure

**Terminal A — Anvil:**
```bash
scripts/local_e2e_toy_a_anvil.sh
```

**Terminal B — Deploy contracts:**
```bash
scripts/local_e2e_toy_b_deploy.sh
# Writes: scripts/logs/tessera_e2e_latest.env  (BRIDGE, TOKEN)
```

**Terminal C — Prover:**
```bash
scripts/local_run_prover.sh
```

**Terminal D — Sequencer:**
```bash
scripts/local_e2e_toy_c_sequencer.sh scripts/logs/tessera_e2e_latest.env
```

### 2 — Register 256 deposits on-chain

The client auto-loads `tessera-server/.env` (`TESSERA_RPC_URL`, `TESSERA_CLIENT_KEY`,
`TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS`). Source the remaining env before each terminal session:

```bash
source scripts/local_env.sh                        # artifact paths, TESSERA_SEQUENCER_API_URL
source scripts/logs/tessera_e2e_latest.env          # TESSERA_MONITORED_TOKEN
```

Then register the deposits:

```bash
cargo run --bin client --release --manifest-path tessera-server/Cargo.toml -- \
  deposit --count 256 --start-index 1 --amount 1
```

Each call mints, approves, and calls `bridge.depositAndRegister(note, amount)` for one note
commitment (`0x000…01` through `0x000…100`).

### 3 — Validate all 256 deposits (consume requests)

```bash
cargo run --bin client --release --manifest-path tessera-server/Cargo.toml -- \
  consume --count 256 --start-index 1
```

With `TESSERA_NOTE_BATCH_SIZE=1024` and only 256 deposits, this produces **one batch** of 1024 leaves (256 real + 768 padding).
The sequencer runs Phase A then Phase B for the batch (`ValidatedBatchFinalized` event).
Wait for the Phase B confirmation in the sequencer log before continuing.

Optional: verify note statuses after each batch:
```bash
scripts/local_status.sh 1 256
```

### 4 — Submit private transactions

Each call generates random TX data and a valid 73-PI proof.

```bash
# Submit 32 private transactions with random data
cargo run --bin client --release --manifest-path tessera-server/Cargo.toml -- \
  private-tx --count 32
```

The calls accumulate leaves across all 4 trees (NC, NN, AC, AN).
Wait for the resulting `TransactionBatchConfirmed` in the sequencer log.

## Console-Split E2E (Toy)

### Console A

```bash
scripts/local_e2e_toy_a_anvil.sh
```

### Console B (deployment)

```bash
scripts/local_e2e_toy_b_deploy.sh
```

This generates:
- `scripts/logs/tessera_e2e_latest.env` with `BRIDGE`, `TOKEN`.

### Console C (prover)

```bash
scripts/local_run_prover.sh
```

### Console D (sequencer)

```bash
scripts/local_e2e_toy_c_sequencer.sh
```

Optional:
```bash
scripts/local_e2e_toy_c_sequencer.sh scripts/logs/tessera_e2e_latest.env
```

### Console E (traffic + verification)

```bash
scripts/local_e2e_toy_d_flow.sh 256 128
```

Optional:
```bash
scripts/local_e2e_toy_d_flow.sh 256 128 scripts/logs/tessera_e2e_latest.env
```

## One-shot wrapper

```bash
scripts/local_e2e_toy.sh 256 128
```

This runs deploy + flow only.
It requires prover and sequencer to already be running in separate terminals.

Required terminals before calling:
1. `scripts/local_run_prover.sh`
2. `scripts/local_e2e_toy_c_sequencer.sh`

## Recovery Test

```bash
scripts/local_stress_recovery.sh
```

Purpose:
- Validates restart resilience with a single local tree store.
- Ensures the sequencer still works after stop/start and continues finalizing batches.

What must be running before you call it:
1. Anvil RPC on `http://localhost:8545`
2. A deployed bridge for that same Anvil instance (run `scripts/local_e2e_toy_b_deploy.sh` after Anvil starts)

What the script runs itself:
- Starts/stops the sequencer process internally
- Seeds deposits and submits consume requests

What it does not run:
- It does not start Anvil
- It does not deploy contracts

How to run:
1. Terminal A: `scripts/local_e2e_toy_a_anvil.sh`
2. Terminal B: `scripts/local_e2e_toy_b_deploy.sh`
3. Terminal C: `scripts/local_stress_recovery.sh`

Pass criteria:
- First batch finalizes
- Sequencer is restarted
- Second batch finalizes after restart

Log path:
- `scripts/logs/tessera_sequencer_stress.log`

## Chain Catch-up Recovery Test

```bash
scripts/local_recover_from_chain.sh
```

What it validates:
- Sequencer A writes local store `A`, finalizes batch 1, then stops.
- Sequencer B runs with independent local store `B`, finalizes batch 2 while A is down.
- Sequencer A restarts from stale store `A`, catches up from on-chain transactions, and can finalize batch 3.
- Catch-up depends on chain replay of `ValidatedBatchFinalized` + tx calldata decoding, not only local WAL.

What must be running before you call it:
1. Anvil RPC on `http://localhost:8545`
2. A deployed bridge for that same Anvil instance (run `scripts/local_e2e_toy_b_deploy.sh` after Anvil starts)

What the script runs itself:
- Starts/stops prover + sequencer A/B internally (it kills stale prover/sequencer first)
- Seeds deposits and submits requests

What it does not run:
- It does not start Anvil
- It does not deploy contracts

How to run:
1. Terminal A: `scripts/local_e2e_toy_a_anvil.sh`
2. Terminal B: `scripts/local_e2e_toy_b_deploy.sh`
3. Terminal C: `scripts/local_recover_from_chain.sh`

Pass criteria:
- Batch 1 finalizes with sequencer A
- Batch 2 finalizes with sequencer B while A is offline
- Batch 3 finalizes after A restarts from stale store (proves catch-up from chain)

Log paths:
- `scripts/logs/tessera_recovery_a_first.log`
- `scripts/logs/tessera_recovery_b.log`
- `scripts/logs/tessera_recovery_a_second.log`

## Notes

- `local_e2e_toy_b_deploy.sh` and `local_deploy.sh` include `cast --create` fallback to avoid `forge create` signer-resolution issues.
- Pending API requests are in-memory; if sequencer is down, requests are not persisted by server state.
