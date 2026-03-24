# Tessera Demo

End-to-end demo of the Tessera privacy-preserving rollup bridge running against
a local Anvil chain. No real ZK prover is required — the demo sequencer confirms
batches on-chain with zero Groth16 proofs accepted by `AcceptAllVerifier`.

## Overview

The demo exercises the full two-phase batch lifecycle:

1. **Deposit** — a user calls `depositAndRegister` on-chain (via the sequencer),
   which escrows ToyUSDT and records a note commitment.
2. **Deposit batch** — the sequencer collects pending deposits, submits a
   `DepositBatch` on-chain, then after a short delay sends a zero proof to
   confirm the batch and advance the Merkle root.
3. **Private transaction** — a user submits account/note leaf data to the
   sequencer, which accumulates it in a `BatchBuilder`.
4. **TX batch** — once the batch times out (or fills 64 slots), the sequencer
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

Submits `N` deposits (default 2) to `POST /deposit`. For each deposit the
sequencer mints ToyUSDT, approves the bridge, and calls `depositAndRegister`
on-chain. The script prints the on-chain deposit status after each one.

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
| `POST` | `/deposit`     | `{"note_commitment":"0x...","amount":1000}` | Register a deposit (mints ToyUSDT, calls depositAndRegister) |
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
| `scripts/demo_d_deposit.sh` | Submit deposits and print on-chain state |
| `scripts/demo_f_transaction.sh` | Submit a private transaction |

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
     │  - /deposit      │  ← deposit requests
     │  - /transaction  │  ← private TX requests
     │  - /status       │  ← monitoring
     │                  │
     │  Background loop:│
     │   batch → submit │
     │   delay → prove  │
     └─────────────────┘
```

The sequencer is the only off-chain component. It:
1. Receives requests over HTTP.
2. Accumulates them in memory (deposit queue / BatchBuilder).
3. After `batch_timeout`, submits the batch on-chain (`submitDepositBatch` /
   `submitTransactionBatch`).
4. After `prove_delay`, sends a zero Groth16 proof on-chain (`proveDepositBatch` /
   `proveTransactionBatch`) which AcceptAllVerifier accepts unconditionally.
5. Updates its internal confirmed root from the emitted event.
