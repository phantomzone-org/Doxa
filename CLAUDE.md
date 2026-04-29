# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Check compilation without building
cargo check -p <crate-name>

# Build a specific crate
cargo build -p <crate-name> --release

# Run tests for a specific crate
cargo test -p <crate-name> --release

# Run a single test
cargo test -p <crate-name> --release <test_name> -- --nocapture

# Solidity contracts
cd tessera-solidity
forge build
forge test
forge test --match-test <test_name>
forge test -vvv  # verbose
```

## System Prerequisites

Building `tessera-utils` (required by most crates) needs:
- **Go ≥ 1.24** — compiles `ffi/main.go` into `libgo.a` (gnark Groth16 via CGo)
- **libclang** — `sudo apt-get install libclang-dev` (bindgen at build time)
- **Foundry** (`forge`, `anvil`, `cast`) — artifact generation and E2E tests

## Workspace Structure

| Crate | Role |
|---|---|
| `tessera-client` | Client-side ZK primitives: account/note types, Plonky2 circuits (deposit, priv-tx, withdraw), Schnorr/GFp5 EC, Merkle trees, pool config |
| `tessera-trees` | Generic Merkle tree, commitment-tree, and verification logic |
| `tessera-utils` | Shared primitives: Plonky2/STARK gadgets, Keccak-256 in-circuit, Groth16/BN128 via Go FFI |
| `tessera-server` | Sequencer + prover services (see below) |
| `tessera-e2e` | Artifact generation binaries, `InProcessProver`, `TesseraClientState`, E2E tests |
| `tessera-demo` | Minimal demo sequencer using `AcceptAllVerifier` (no real ZK proofs) |
| `tessera-subpool-operator` | Off-chain operator service: approves FreshAcc/deposits/spend-txs, posts to sequencer |
| `tessera-subpool-database` | HTTP API + PostgreSQL persistence layer for a subpool |
| `tessera-client-wasm` | WASM build of the client library |
| `tessera-solidity` | Solidity contracts (`TesseraContract`, IMTLib, verifiers) |

## Architecture Overview

Tessera is a ZK privacy rollup. The full stack:

```
Client (tessera-client)
  └─ generates Plonky2 proofs for private txs / deposits / withdrawals
       ↓
Subpool Operator (tessera-subpool-operator)
  └─ validates txs, manages account state in PostgreSQL (via tessera-subpool-database)
  └─ forwards note commitments / tx proofs to Sequencer
       ↓
Sequencer (tessera-server / sequencer binary)
  └─ batches incoming requests, validates against on-chain state
  └─ sends ProveRequest to Prover
       ↓
Prover (tessera-server / prover binary)
  └─ TX pipeline: PrivTx leaf → TX Aggregator → SubtreeRoot → SuperAggregator → BN128 → Groth16
  └─ Deposit pipeline: Deposit leaf → Deposit Aggregator → DepositSuperAggregatorV2 → BN128 → Groth16
       ↓
TesseraContract (tessera-solidity)
  └─ two-phase batch lifecycle: submitTransactionBatch → proveTransactionBatch
  └─ on-chain Poseidon IMT, deposit escrow, mainPoolConfigRoot management
```

### Key constants (tessera-client/src/lib.rs)

- `PRIV_TX_BATCH_SIZE = 64` — TX slots per batch; compiled into all artifacts and the on-chain tree depth. **Cannot be changed at runtime; all artifacts must be rebuilt after any circuit change.**
- `BRIDGE_TX_BATCH_SIZE = 512` — deposit/withdraw slots per batch
- `NOTE_BATCH = 7` — input/output notes per private tx slot
- `MAIN_POOL_CONFIG_DEPTH = 20` — subpool config Merkle tree depth

### On-chain batch lifecycle (two-phase)

1. **Submit** (operator only): `submitTransactionBatch(batchPreimage)` — stores `keccak256(batchPreimage)` as `piCommitment`; preimage NOT stored on-chain.
2. **Prove** (permissionless): `proveTransactionBatch(batchPreimage, proof)` — re-derives commitment, verifies Groth16, inserts `batchPoseidonRoot` into IMT.

### Goldilocks field encoding

ZK circuits operate over the Goldilocks field (p = 2⁶⁴ − 2³² + 1). `HashOut` values are 4 field elements packed LE into `uint256`. On-chain Keccak preimages use GL-preimage encoding: each element as `[lo_u32_BE(4B)][hi_u32_BE(4B)]`.

### mainPoolConfigRoot / subpool config tree

- Binary Poseidon tree of depth `configTreeDepth`
- Leaf at position `subpool_id`: `poseidon.compress(subpool_id, subpoolRoot)` — but uninitialized subpools have effective leaf `0` (not `poseidon(id, 0)`)
- Only subpool owners (assigned by operator) can update their leaf via `updateSubpoolRoot(subpoolId, newSubpoolRoot, siblings[])`
- Genesis root = `zeros[configTreeDepth]` computed transiently (not stored)

### Sequencer recovery

On boot, the sequencer loads local tree snapshots + WAL, reads on-chain roots, replays any missing `ValidatedBatchFinalized` log calldata, re-derives dummies, and verifies all local roots match chain before accepting API traffic.

## Running the Server

```bash
# Prover (start first)
cd tessera-server
cargo run --bin prover --release

# Sequencer (separate terminal)
cargo run --bin sequencer --release

# Optional distributed aggregation prover worker
cargo run --bin aggregation_prover --release
```

All binaries load `.env` automatically.

### Required env vars (sequencer)

`TESSERA_RPC_URL`, `TESSERA_OPERATOR_KEY`, `TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS`, `TESSERA_CHAIN_ID`, `TESSERA_NOTES_COMMITMENT_ARTIFACTS_PATH`, `TESSERA_ACCOUNTS_COMMITMENT_ARTIFACTS_PATH`, `TESSERA_NOTES_NULLIFIER_ARTIFACTS_PATH`, `TESSERA_ACCOUNTS_NULLIFIER_ARTIFACTS_PATH`

## Generating Artifacts

Artifacts are required before running E2E tests or the real prover. BN128/Groth16 steps are idempotent (skipped if output dirs exist).

```bash
export TESSERA_ARTIFACTS_DIR=$(pwd)/tessera-e2e/artifacts

# TX pipeline (PrivTx circuit → aggregators → BN128 → Groth16 → copies Verifier.sol → forge build)
cargo run -p tessera-e2e --bin tx_artifacts --release

# Deposit pipeline
cargo run -p tessera-e2e --bin deposit_artifacts --release

# Force rebuild BN128/Groth16 steps
rm -rf $TESSERA_ARTIFACTS_DIR/super-aggregator-v2/plonky2-proof
rm -rf $TESSERA_ARTIFACTS_DIR/super-aggregator-v2/groth-artifacts
```

After circuit changes, rebuild everything from scratch:
```bash
rm -rf $TESSERA_ARTIFACTS_DIR
cargo run -p tessera-e2e --bin tx_artifacts --release && \
cargo run -p tessera-e2e --bin deposit_artifacts --release
```

## Running E2E Tests

```bash
export TESSERA_ARTIFACTS_DIR=$(pwd)/tessera-e2e/artifacts

# All (skip gracefully when artifacts absent)
cargo test -p tessera-e2e --release -- --nocapture

# Single test
TESSERA_ARTIFACTS_DIR=$(pwd)/tessera-e2e/artifacts \
cargo test -p tessera-e2e --release test_e2e_freshacc_groth16 -- --nocapture
```

### tessera-server integration tests (opt-in, requires anvil + forge)

```bash
TESSERA_RUN_INTEGRATION_SCRIPTS=1 \
cargo test --release -p tessera-server --features integration-tests scripted_full_flow_e2e -- --nocapture --test-threads=1
```

Set `TESSERA_REBUILD_ARTIFACTS=1` to force artifact regeneration (otherwise cached under `tessera-server/artifacts`).

## Local Demo (no real ZK proofs)

Uses `AcceptAllVerifier` — any Groth16 proof accepted.

```bash
# Terminal A
scripts/local_e2e_toy_a_anvil.sh   # or scripts/demo_a_anvil.sh

# Terminal B
scripts/local_e2e_toy_b_deploy.sh  # deploys + writes .env

# Terminal C
scripts/local_run_sequencer.sh     # TESSERA_TESTING=1 mode

# Terminal D
scripts/local_test_flow.sh [N]     # drives full flow via HTTP
```

`TESSERA_TESTING=1` enables test HTTP endpoints (`/test/deposits`, `/test/deposits/validate`, `/test/transactions`, `/test/transactions/validate`) that bypass proof requirements.

## tessera-server Agent Notes

- Keep `src/aggregator_service/**` and setup binaries inside `tessera-server` unless repo owners say otherwise.
- All prover/aggregator tests (including `#[ignore]`) are important for correctness — do not delete.
- Go FFI scaffolding was removed from `tessera-server`; Groth16/BN128 bindings live in `tessera-utils`. Do not reintroduce Go shims here.

## tessera-solidity Agent Notes

- `batchPreimage` is NEVER stored on-chain — must be re-supplied identically in the prove phase.
- `subpoolId = 0` cannot be assigned an owner.
- The operator cannot directly set `mainPoolConfigRoot`; only subpool owners can via `updateSubpoolRoot`.
- `TesseraBatchTransactionVerifier.sol` and `VerifierDepositSuperAggregatorV2.sol` are auto-generated by artifact binaries — do not edit manually.
