# Tessera Demo

End-to-end demo of the Tessera privacy-preserving rollup bridge running against
a local Anvil chain. No real ZK prover is required — the demo sequencer confirms
batches on-chain with zero Groth16 proofs accepted by `AcceptAllVerifier`.

## Overview

The demo exercises the full two-phase batch lifecycle:

1. **Deposit** — a user calls `depositAndRegister` on-chain directly,
   which escrows ToyUSDT and records a note commitment as `Pending`.
2. **Deposit validation** — the user requests validation from the sequencer,
   which verifies the deposit is `Pending` on-chain and queues it.
3. **Deposit batch** — the sequencer collects pending validation requests,
   submits a `DepositBatch` on-chain, then after a short delay sends a zero
   proof to confirm the batch and advance the Merkle root.
4. **Private transaction** — a user submits account/note leaf data to the
   sequencer, which accumulates it in a `BatchBuilder`.
5. **TX batch** — once the batch times out (or fills 64 slots), the sequencer
   submits a `TransactionBatch` on-chain, then confirms it with a zero proof.

Each confirmation emits the correct `piCommitment` (keccak hash of the batch
public inputs) and advances the on-chain `currentRoot`.

## Prerequisites

- [Rust toolchain](https://rustup.rs/) (stable)
- [Foundry](https://book.getfoundry.sh/getting-started/installation) (`anvil`, `forge`, `cast`)
- `jq` (for JSON parsing in scripts)
- `curl`

## Quick start

Open **three terminals** from the repository root.

### Terminal A — Local chain

```bash
scripts/demo_a_anvil.sh
```

Starts Anvil on `http://localhost:8545` with pre-funded test accounts.

### Terminal B — Deploy contracts

```bash
scripts/demo_b_deploy.sh
```

Deploys:
- `AcceptAllVerifier` (stub that accepts any Groth16 proof)
- `PoseidonGoldilocks` (on-chain Poseidon hash)
- `ToyUSDT` (mintable ERC-20 for testing)
- `TesseraContract` (the rollup bridge, configured with AcceptAllVerifier for
  both TX and deposit verification)
- `ToyUser` (convenience helper)

Writes deployed addresses to `scripts/logs/demo_latest.env`, which is
automatically loaded by all subsequent scripts.

### Terminal B — Start the sequencer

```bash
scripts/demo_c_sequencer.sh
```

Builds and runs the `demo-sequencer` binary. The sequencer connects to the
deployed contracts, fetches the genesis root, and starts an HTTP API on
`127.0.0.1:3000`.

### Terminal C — Run the demo flow

Each step is a separate script. Run them in order:

#### Step 1: Submit deposits

```bash
scripts/demo_d_deposit.sh [N]
```

Submits `N` deposits (default 2). For each deposit the script:
1. Mints ToyUSDT and approves the bridge (on-chain via `cast`)
2. Calls `depositAndRegister` on-chain (creates a `Pending` deposit)
3. Sends a validation request to the sequencer's `POST /deposit`

After `DEMO_BATCH_TIMEOUT_SECS` (default 10s) the sequencer auto-flushes the
deposit batch and proves it `DEMO_PROVE_DELAY_SECS` later (default 10s).
Watch the sequencer logs (Terminal B) for `=== Deposit batch CONFIRMED ===`.

#### Step 2: Submit a private transaction

```bash
scripts/demo_f_transaction.sh
```

Sends one transaction with synthetic leaf data to `POST /transaction`. The
sequencer queues it in the `BatchBuilder`. No real Plonky2 proof is needed for
the demo — a dummy proof byte is accepted.

Watch the sequencer logs (Terminal B) for `=== TX batch CONFIRMED ===`.

### Expected sequencer output

After both batches are confirmed, the sequencer logs will show three confirmed
roots (genesis, post-deposit, post-transaction) and the local tree leaf count
growing with each batch.

## Sequencer HTTP API

| Method | Path           | Body | Description |
|--------|----------------|------|-------------|
| `POST` | `/deposit`     | `{"note_commitment":"0x..."}` | Request validation for an on-chain `Pending` deposit |
| `POST` | `/transaction` | `{"tx_id":"...","input_account_leaf":"0x...","output_account_leaf":"0x...","input_notes":["0x..."×7],"output_notes":["0x..."×7],"tx_proof":"0x00"}` | Queue a private transaction |
| `GET`  | `/status`      | — | Returns confirmed root, batch slot count, pending deposits |
| `GET`  | `/config`      | — | Returns contract, token, and operator addresses |

## Configuration

All timing and address configuration is set via environment variables.
`scripts/demo_env.sh` provides defaults for local Anvil testing.

| Variable | Default | Description |
|----------|---------|-------------|
| `DEMO_RPC_URL` | `http://localhost:8545` | Ethereum JSON-RPC endpoint |
| `DEMO_OPERATOR_KEY` | Anvil key #0 | Operator private key (hex) |
| `DEMO_CHAIN_ID` | `31337` | EVM chain ID |
| `DEMO_BRIDGE_ADDRESS` | — | Deployed TesseraContract address |
| `DEMO_TOKEN_ADDRESS` | — | Deployed ToyUSDT address |
| `DEMO_BIND_ADDR` | `127.0.0.1:3000` | Sequencer HTTP listen address |
| `DEMO_BATCH_TIMEOUT_SECS` | `10` | Seconds before flushing a partial batch |
| `DEMO_PROVE_DELAY_SECS` | `10` | Seconds between batch submission and zero-proof confirmation |

## Scripts reference

| Script | Description |
|--------|-------------|
| `scripts/demo_env.sh` | Shared environment defaults (sourced by all other scripts) |
| `scripts/demo_a_anvil.sh` | Start a local Anvil chain |
| `scripts/demo_b_deploy.sh` | Deploy AcceptAllVerifier + full contract stack |
| `scripts/demo_c_sequencer.sh` | Build and start the demo sequencer |
| `scripts/demo_d_deposit.sh` | Deposit on-chain and request validation from sequencer |
| `scripts/demo_f_transaction.sh` | Submit a private transaction |

## Deposit pipeline

1. **Client deposits on-chain** — calls `depositAndRegister(noteCommitment, maxAmount)`
   on the TesseraContract directly. The contract escrows ToyUSDT and records the
   deposit as `Pending`.
2. **Client requests validation** — sends `POST /deposit { note_commitment }` to the
   sequencer. The handler verifies the deposit is `Pending` on-chain via `getDeposit`,
   rejects otherwise, and pushes the note commitment into the deposit queue.
3. **Batch flush** — after `DEMO_BATCH_TIMEOUT_SECS`, the background loop drains the
   deposit queue, pads to 512 leaves (matching on-chain `DEPOSIT_BATCH_SIZE`), computes
   the Poseidon subtree root, and calls `submitDepositBatch` (optimistic submission).
   The `piCommitment` is extracted from the `DepositBatchSubmitted` event.
4. **Batch prove** — after `DEMO_PROVE_DELAY_SECS`, calls `proveDepositBatch` with a
   zero Groth16 proof (accepted by `AcceptAllVerifier`). On success:
   - Updates `confirmed_root` from the `DepositBatchProven` event
   - Inserts all 512 leaves into the local depth-32 Merkle tree
   - The contract marks matching pending deposits as `Validated`

## Transaction pipeline

1. **Client submits a transaction** — sends `POST /transaction` with account leaves
   (input/output), 7 input notes (nullifiers), 7 output notes (commitments), and a
   proof. The handler checks for duplicate nullifiers and adds the slot to the
   `BatchBuilder`.
2. **Batch flush** — after `DEMO_BATCH_TIMEOUT_SECS` (or when 64 slots are full), the
   background loop finalizes the batch. `finalize()` pads to 64 slots and interleaves
   account commitments/nullifiers into the note arrays (stride 8: 7 notes + 1 account
   per slot = 512 total leaves). It computes the Poseidon subtree root over all 512
   `nc_leaves`, then calls `submitTransactionBatch` with 448 note commitments, 448 note
   nullifiers, 64 account commitments, 64 account nullifiers, and the Poseidon root.
   The `piCommitment` is extracted from the `TransactionBatchSubmitted` event.
3. **Batch prove** — after `DEMO_PROVE_DELAY_SECS`, calls `proveTransactionBatch` with
   a zero Groth16 proof. On success:
   - Updates `confirmed_root` from the `TransactionBatchProven` event
   - Inserts all 512 `nc_leaves` into the local depth-32 Merkle tree

## Architecture

```
                         ┌──────────────┐
                         │    Anvil     │
                         │  (local EVM) │
                         └──────┬───────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                  │
    ┌─────────┴──────┐  ┌──────┴───────┐  ┌───────┴────────┐
    │ TesseraContract │  │   ToyUSDT    │  │AcceptAllVerifier│
    │  (rollup bridge)│  │  (test ERC20)│  │  (stub verifier)│
    └─────────┬──────┘  └──────────────┘  └────────────────┘
              │
     ┌────────┴────────┐
     │ Demo Sequencer   │  HTTP :3000
     │  - /deposit      │  ← deposit validation requests
     │  - /transaction  │  ← private TX requests
     │  - /status       │  ← monitoring
     │                  │
     │  Background loop:│
     │   batch → submit │
     │   delay → prove  │
     └─────────────────┘
```

The sequencer is the only off-chain component. It:
1. Receives deposit validation requests and private transactions over HTTP.
2. Accumulates them in memory (deposit queue / BatchBuilder).
3. After `batch_timeout`, submits the batch on-chain (`submitDepositBatch` /
   `submitTransactionBatch`).
4. After `prove_delay`, sends a zero Groth16 proof on-chain (`proveDepositBatch` /
   `proveTransactionBatch`) which AcceptAllVerifier accepts unconditionally.
5. Updates its internal confirmed root and local Merkle tree (depth 32) from
   the emitted event, inserting all 512 batch leaves.
