# Local Scripts Guide

These scripts are aligned with the current API-driven consume flow.

Flow:
1. deposits are recorded on-chain (`depositAndRegister*` via `depositAndRecord` in `ToyUser`)
2. consume requests are pushed to sequencer API (`POST /consume-request` or `POST /notes/commitment`)
   - each request must include `input_proof` (dummy value in Phase A: `0x01`)
3. other tree leaves can be pushed via:
- `POST /notes/nullifier` with body `{"leaf":"0x..."}`
- `POST /accounts/commitment` with body `{"leaf":"0x..."}`
- `POST /accounts/nullifier` with body `{"leaf":"0x..."}`
4. private-tx payloads can be pushed via:
- `POST /private-tx` (or `/private-tx/notes`) with body:
  - `input_notes[]`
  - `output_notes[]`
  - `input_account_commitment`
  - `output_account_commitment`
  - `tx_proof`
3. sequencer batches, proves, then records notes commitment update on-chain
   - `recordNotesCommitmentTreeUpdate(newNotesCommitmentRoot, notes, treeProof, aggregatedInputProof)` (operator-only)

## Scripts

- `local_env.sh`
  - Loads local defaults (`RPC`, keys, batch size, artifacts path, sequencer API address).
  - Defaults sequencer artifacts path to `tessera-server/artifacts/commitment-tree`.

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
  - Pushes consume requests to sequencer API with mandatory `input_proof` (dummy `0x01`).

- `local_status.sh [start_note] [count]`
  - Prints consumed root + note statuses over a range.

- `local_request_reconsume.sh [count] [max_note]`
  - Re-submits consumed notes to API (negative check), with mandatory `input_proof` (dummy `0x01`).

- `local_request_private_tx.sh [in_start] [in_count] [out_start] [out_count] [in_account] [out_account] [proof_hex]`
  - Submits one private-tx style intake payload to `/private-tx`.
  - Default proof is `0x01` (Phase A dummy placeholder verifier).

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
- `scripts/logs/tessera_e2e_latest.env` with `BRIDGE`, `TOKEN`, `TOY_USER`.

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
