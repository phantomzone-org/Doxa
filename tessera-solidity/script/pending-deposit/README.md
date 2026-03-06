# Local E2E (ToyUSDT + Bridge + ToyUser + Sequencer)

This folder contains the Foundry deploy script used by the repo-level local scripts.

The current local model is:
1. Deploy `ToyUSDT`
2. Deploy Groth16 verifiers + `DepositsRollupBridge`
3. Deploy `ToyUser` adapter
4. Run the Rust sequencer (`tessera-server`)
5. Create many deposits via `ToyUser.depositAndRecord(note, amount)`
6. Submit a random subset of notes to the sequencer API (`POST /consume-request`)
7. Sequencer batches, proves, then finalizes notes commitment update on-chain via:
   - `recordNotesCommitmentTreeUpdate` (single-phase, operator-only)
8. Verify `notesCommitmentRoot` advanced and requested notes became `Validated`

There is no on-chain "request queue"; the queue is the sequencer API.

## Prerequisites

- `anvil`, `forge`, `cast`, `curl`
- Rust toolchain

Generate local prover artifacts:

```bash
cd tessera-server
TESSERA_NOTE_BATCH_SIZE=128 TESSERA_ACCOUNT_BATCH_SIZE=16 cargo run --bin commitment_tree_artifacts --release
TESSERA_NOTE_BATCH_SIZE=128 TESSERA_ACCOUNT_BATCH_SIZE=16 cargo run --bin nullifier_tree_artifacts --release
```

Artifacts are written to four directories:
- `tessera-server/artifacts/note-commitment-tree/`
- `tessera-server/artifacts/account-commitment-tree/`
- `tessera-server/artifacts/note-nullifier-tree/`
- `tessera-server/artifacts/account-nullifier-tree/`

## Recommended: Use Repo-Level Scripts

From repo root, run the console-split flow described in `scripts/README.md`:

```bash
scripts/local_e2e_toy_a_anvil.sh
scripts/local_e2e_toy_b_deploy.sh
scripts/local_run_prover.sh
scripts/local_e2e_toy_c_sequencer.sh
scripts/local_e2e_toy_d_flow.sh 256 128
```

Or use the one-shot wrapper:

```bash
scripts/local_e2e_toy.sh 256 128
```

Note:
- `local_e2e_toy.sh` now expects prover + sequencer to already be running in separate terminals.

## Manual Deploy (Advanced)

If you want to run the deploy script directly:

```bash
cd tessera-solidity
export RPC=http://localhost:8545
export OPERATOR_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

TOKEN=$(forge create src/ToyUSDT.sol:ToyUSDT --rpc-url "$RPC" --private-key "$OPERATOR_KEY" --broadcast | sed -n 's/Deployed to: //p' | tail -n1)

export TESSERA_MONITORED_TOKEN="$TOKEN"
export TESSERA_NOTES_NULLIFIER_ROOT=0x0000000000000000000000000000000000000000000000000000000000000000
export TESSERA_NOTES_COMMITMENT_ROOT=0x0000000000000000000000000000000000000000000000000000000000000000
export TESSERA_ACCOUNTS_NULLIFIER_ROOT=0x0000000000000000000000000000000000000000000000000000000000000000
export TESSERA_ACCOUNTS_COMMITMENT_ROOT=0x0000000000000000000000000000000000000000000000000000000000000000
export TESSERA_NOTE_BATCH_SIZE=128
export TESSERA_ACCOUNT_BATCH_SIZE=16

forge script script/pending-deposit/Deploy.s.sol --rpc-url "$RPC" --private-key "$OPERATOR_KEY" --broadcast
```

After deploy, optionally deploy `ToyUser` as a UX adapter:

```bash
TOY_USER=$(forge create src/ToyUser.sol:ToyUser --rpc-url "$RPC" --private-key "$OPERATOR_KEY" --broadcast --constructor-args "$BRIDGE" "$TOKEN" | sed -n 's/Deployed to: //p' | tail -n1)
```
