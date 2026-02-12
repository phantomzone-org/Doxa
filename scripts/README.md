# Local Scripts Guide

This folder contains helper scripts to run the local end-to-end flow with less manual setup.

## Scripts

- `local_env.sh`
  - Loads default local env vars (RPC, keys, trusted source, batch size, genesis root, paths).
  - Intended to be sourced:
    - `source scripts/local_env.sh`

- `local_deploy.sh`
  - Deploys `Verifier` + `DepositsRollupBridge`.
  - Parses deployed bridge address from forge output.
  - Writes `TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS` into `tessera-server/.env`.

- `local_run_sequencer.sh`
  - Starts `tessera-server` sequencer with the loaded env.
  - Reads bridge address from `BRIDGE` env var, else from `tessera-server/.env`.

- `local_seed.sh [total_deposits] [request_count]`
  - Records deposits (`recordDeposit`) then submits consume requests (`requestConsume`) in random order.
  - Request targets are selected as a random subset across all newly seeded deposits.
  - Defaults: `256` deposits, `128` requests.

- `local_request.sh [start_index] [count] [order]`
  - Submits consume requests for existing deposits.
  - `order`: `random` (default), `ordered`, or `random-unconsumed`.
  - `random-unconsumed` ignores `start_index` and samples `count` random deposits from currently `Available` deposits that are not already `consumeRequested`.
  - Useful for additional batches after initial seed.

- `local_request_reconsume.sh [count]`
  - Negative test helper.
  - Picks random already `Consumed` deposits and simulates `requestConsume` again via `eth_call`.
  - Expected behavior: all simulations revert (script exits non-zero if any unexpectedly succeeds).

- `local_status.sh [start_index] [count]`
  - Prints `consumedRoot` and deposit tuples for a range.
  - Shows summary counts by status (`Available`, `Withdrawn`, `Consumed`).

- `local_stress_recovery.sh`
  - Recovery stress scenario:
    1. start sequencer
    2. submit partial consume requests (not enough for a full batch)
    3. stop sequencer
    4. submit remaining requests while sequencer is down (`random-unconsumed`)
    5. restart sequencer and verify one full batch finalizes after recovery

## Recommended Run Order

Open terminals as needed.

1. Start anvil:
```bash
anvil
```

2. Load defaults (repo root):
```bash
source scripts/local_env.sh
```

3. Deploy contracts:
```bash
scripts/local_deploy.sh
```

4. Start sequencer:
```bash
scripts/local_run_sequencer.sh
```

5. Seed activity (from another terminal):
```bash
scripts/local_seed.sh 256 128
```

6. Check statuses:
```bash
scripts/local_status.sh 0 20
```

7. Negative test: try re-consuming already consumed deposits:
```bash
scripts/local_request_reconsume.sh 10
```

Expected:
- each request should fail
- summary should report `unexpected_successes=0`

## Recovery Test

Before running this test, stop any sequencer you started manually (for example via `scripts/local_run_sequencer.sh`).
`local_stress_recovery.sh` manages its own sequencer lifecycle and assumes exclusive ownership.
The script also performs best-effort cleanup of stale local sequencer processes before each start.

Run:
```bash
scripts/local_stress_recovery.sh
```

Sequencer log path:
- `scripts/logs/tessera_sequencer_stress.log`

Expected:
- script prints progress through phases
- waits for the phase-3 requests to be fully reflected on-chain before restart
- if needed, auto-submits top-up requests until the window reaches 128 pending consume requests
- prints consumed progress for the specific 256-deposit window created by that run
- eventually prints `Recovery test passed.`

## Notes

- If `BRIDGE` is empty in a terminal, reload env and/or pull from `.env`:
  - `source scripts/local_env.sh`
  - `export BRIDGE=$(sed -n 's/^TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=//p' tessera-server/.env | tail -n1)`
- Ensure used-deposit artifacts exist before deployment/sequencing.
