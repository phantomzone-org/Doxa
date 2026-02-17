# tessera-server

Sequencer plus standalone prover service for Tessera deposit-validation batching.

The sequencer is API-driven for intake:
- clients push note commitments to `POST /consume-request`
- private transactions can push full input/output payloads to `POST /private-tx`
- sequencer checks note status on-chain:
  - if note exists on bridge: required status depends on endpoint/tree flow
  - if note is not tracked by bridge (`NoteNotFound`): accepted as external/network-native leaf
- when `batchSize` notes are queued, sequencer proves append insertion and finalizes on-chain via:
  - `recordNotesCommitmentTreeUpdate` (single-phase)

## High-Level Flow

1. Trusted source records deposits on-chain via `depositAndRegister*`
2. External caller sends note commitments to sequencer API
3. Sequencer validates each note is `Pending` using `getDepositStatus(note)`
4. Sequencer batches notes (`batchSize` from contract)
5. Sequencer sends `ProveRequest` to dedicated prover API
6. Prover returns `ProveOutcome` with Solidity proof
7. Sequencer submits `recordNotesCommitmentTreeUpdate(newRoot, notes, proof)`
8. Contract marks tracked notes `Validated` and updates `notesCommitmentRoot`

## Components

- `src/sequencer/`
  - Main async loop, API intake, recovery, and on-chain finalization
- `src/prover.rs`
  - Prover runtime and proof generation pipeline (plonky2 -> BN128 -> Groth16)
- `src/prover_client.rs`
  - HTTP client used by sequencer to request proofs from dedicated prover service
- `src/states/`
  - In-memory pending request queues + local tree mirrors
- `src/contract.rs`
  - Alloy bindings for `DepositsRollupBridge`

## API

### `POST /consume-request`

Request body:

```json
{"note_commitment":"0x<32-byte-hex>","input_proof":"0x01"}
```

Response:

```json
{"accepted":true}
```

HTTP errors:
- `400` invalid commitment format
- `503` sequencer intake channel unavailable

Note: `accepted=true` means the request entered the sequencer queue; the note is still checked against on-chain status before batching.

### `POST /private-tx`

Request body:

```json
{
  "input_notes":["0x<32-byte-hex>","0x<32-byte-hex>"],
  "output_notes":["0x<32-byte-hex>","0x<32-byte-hex>"],
  "input_account_commitment":"0x<32-byte-hex>",
  "output_account_commitment":"0x<32-byte-hex>",
  "tx_proof":"0x01",
  "tx_id":"optional-client-tx-id"
}
```

Semantics:
- `tx_proof` is validated as non-empty hex (Phase A placeholder gate).
- if proof verification fails, the payload is dropped and response is:
  - `{"accepted":false,"invalid_proof_tx":{"tx_id":"...","reason":"..."}}`
- routing is deterministic:
  - `input_notes` -> notes nullifier queue
  - `output_notes` -> notes commitment queue
  - `input_account_commitment` -> accounts nullifier queue
  - `output_account_commitment` -> accounts commitment queue

## Configuration

Loaded via `SequencerConfig::from_env()`.

Required:
- `TESSERA_RPC_URL`
- `TESSERA_OPERATOR_KEY`
- `TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS`
- `TESSERA_CHAIN_ID`
- `TESSERA_PENDING_DEPOSITS_ARTIFACTS_PATH`

Optional:
- `TESSERA_POLL_INTERVAL_SECS` (default `12`)
- `TESSERA_SEQUENCER_API_ADDR` (default `127.0.0.1:8081`)
- `TESSERA_PROVER_API_URL` (default `http://127.0.0.1:8091`)
- `TESSERA_PROVER_API_TIMEOUT_SECS` (default `1800`)
- `RUST_LOG` (default `info`)

Artifacts path must contain:
- `plonky2-proof/`
- `groth-artifacts/`

## Running

```bash
cd tessera-server
cargo run --bin prover --release
```

In another terminal:

```bash
cd tessera-server
cargo run --bin sequencer --release
```

The binary loads `.env` automatically if present.

## Recovery Behavior

Sequencer recovery is now cache-first and chain-authoritative for all four trees:

- `notesCommitment`
- `notesNullifier`
- `accountsCommitment`
- `accountsNullifier`

Boot sequence:
1. Load each tree from local snapshot + WAL.
2. Read on-chain roots from bridge.
3. If any local root is behind, replay missing updates from chain:
   - query `ValidatedBatchFinalized` logs
   - fetch tx calldata for each log
   - decode function and leaf payload
   - apply leaves locally in canonical chain order
4. Verify all local roots equal on-chain roots before serving API traffic.

Persistence details:
- Each tree store now tracks a chain cursor:
  - `last_block`
  - `last_tx_index`
  - `last_log_index`
- Cursor is advanced after every successfully applied/recovered batch.
- Leaves are kept in WAL; snapshots are periodic checkpoints.

Notes:
- Pending API requests are still in-memory only.
- Requests sent while sequencer is down are not retained by server memory; only finalized on-chain state is recoverable.

## Build and Test

```bash
cargo check -p tessera-server
cargo test -p tessera-server --release
```
