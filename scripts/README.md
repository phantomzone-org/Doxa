# Local Scripts Guide

These scripts are aligned with the current API-driven consume flow.

Flow:
1. deposits are recorded on-chain (`recordDeposit(bytes32)` via `depositAndRecord`)
2. consume requests are pushed to sequencer API (`POST /consume-request`)
3. sequencer batches and finalizes (`finalizeConsumeBatch`)

## Scripts

- `local_env.sh`
  - Loads local defaults (`RPC`, keys, batch size, artifacts path, sequencer API address).
  - Defaults sequencer artifacts path to `tessera-server/artifacts/pending-deposit`.

- `local_deploy.sh`
  - Deploys verifier + bridge.
  - Auto-deploys `ToyUSDT` if `TESSERA_MONITORED_TOKEN` is not pre-set.
  - Writes `TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS` into `tessera-server/.env`.

- `local_run_sequencer.sh`
  - Starts sequencer with env expected by `SequencerConfig::from_env()`.
  - Exposes consume API at `TESSERA_SEQUENCER_API_ADDR` (default `127.0.0.1:8081`).

- `local_request.sh [start_note] [count] [order] [max_note]`
  - Pushes consume requests to sequencer API.

- `local_status.sh [start_note] [count]`
  - Prints consumed root + note statuses over a range.

- `local_request_reconsume.sh [count] [max_note]`
  - Re-submits consumed notes to API (negative check).

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
- `scripts/logs/tessera_e2e_latest.env` with `BRIDGE`, `TOKEN`, `TRUSTED_SOURCE`.

### Console C (sequencer)

```bash
scripts/local_e2e_toy_c_sequencer.sh
```

Optional:
```bash
scripts/local_e2e_toy_c_sequencer.sh scripts/logs/tessera_e2e_latest.env
```

### Console D (traffic + verification)

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

This runs console-B deploy, starts console-C sequencer in background, then runs console-D flow.

## Recovery Test

```bash
scripts/local_stress_recovery.sh
```

Log path:
- `scripts/logs/tessera_sequencer_stress.log`

## Notes

- `local_e2e_toy_b_deploy.sh` and `local_deploy.sh` include `cast --create` fallback to avoid `forge create` signer-resolution issues.
- Pending API requests are in-memory; if sequencer is down, requests are not persisted by server state.
