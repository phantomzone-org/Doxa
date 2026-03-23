# Local E2E Scripts

Four scripts drive the full V2 test pipeline against a local Anvil chain.
No real ZK prover is required — the sequencer runs in `TESSERA_TESTING=1` mode,
which confirms batches on-chain with zero proofs.

## Scripts

| Script | Purpose |
|---|---|
| `local_env.sh` | Shared env defaults — **source this before anything else** |
| `local_e2e_toy_a_anvil.sh` | Start a local Anvil chain |
| `local_e2e_toy_b_deploy.sh` | Deploy the V2 contract stack (PoseidonGoldilocks, Verifier, TesseraRollupV2, ToyUSDT, ToyUser) |
| `local_run_sequencer.sh` | Build and start the sequencer in test mode |
| `local_test_flow.sh` | Drive the full test pipeline via HTTP |

## Full E2E walkthrough

Open four terminals from the repo root.

**Terminal A — Anvil:**
```bash
scripts/local_e2e_toy_a_anvil.sh
```

**Terminal B — Deploy contracts:**
```bash
scripts/local_e2e_toy_b_deploy.sh
```
Writes deployed addresses to:
- `tessera-server/.env` (read automatically by the sequencer)
- `scripts/logs/tessera_e2e_latest.env`

**Terminal C — Sequencer:**
```bash
scripts/local_run_sequencer.sh
```
Wipes local tree state and starts fresh.
No prover needed: `TESSERA_TESTING=1` (set in `local_env.sh`) makes the sequencer
confirm batches on-chain with zero proofs, bypassing the prover entirely.
The sequencer also starts a test HTTP server at `TESSERA_TEST_API_ADDR` (default `127.0.0.1:8081`).

**Terminal D — Test flow:**
```bash
scripts/local_test_flow.sh [N_deposits]
```
Default: 3 deposits. Waits for the sequencer API, then:
1. Submits N deposits → `POST /test/deposits`
2. Flushes + confirms deposit batch → `POST /test/deposits/validate`
3. Submits one TX slot → `POST /test/transactions`
4. Flushes + confirms TX batch → `POST /test/transactions/validate`
5. Prints `currentRoot` before and after.

## Test API endpoints (TESSERA_TESTING=1)

| Method | Path | Body | Action |
|---|---|---|---|
| `GET` | `/health` | — | Liveness probe |
| `POST` | `/test/deposits` | `{"note_commitment":"0x..."}` | Submit deposit (no on-chain Pending check) |
| `POST` | `/test/deposits/validate` | — | Flush + confirm deposit batch with zero proof |
| `POST` | `/test/transactions` | `{"an":"0x...","ac":"0x...","nn":[8×"0x..."],"nc":[8×"0x..."]}` | Submit TX slot (no Plonky2 proof required) |
| `POST` | `/test/transactions/validate` | — | Flush + confirm TX batch with zero proof |

All endpoints return `{"accepted":true}` on success or `{"accepted":false,"error":"..."}` on failure.

## Key environment variables (`local_env.sh`)

| Variable | Default | Purpose |
|---|---|---|
| `RPC` | `http://localhost:8545` | Anvil RPC URL |
| `OPERATOR_KEY` | Anvil key #0 | Private key for deployer / sequencer |
| `TESSERA_CHAIN_ID` | `31337` | EVM chain ID |
| `TESSERA_TREE_DEPTH` | `20` | Depth of on-chain Poseidon tree |
| `TESSERA_POOL_CONFIG_ROOT` | `0x000...0` | Initial pool config root (zero for tests) |
| `TESSERA_TESTING` | `1` | Enable test HTTP endpoints |
| `TESSERA_TEST_API_ADDR` | `127.0.0.1:8081` | Test API bind address |
| `TESSERA_POLL_INTERVAL_SECS` | `2` | On-chain polling interval |
| `TESSERA_BATCH_TIMEOUT_SECS` | `5` | Max wait before flushing a partial batch |

`TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS` and `TESSERA_MONITORED_TOKEN` are loaded
automatically from `tessera-server/.env` (written by the deploy script).
