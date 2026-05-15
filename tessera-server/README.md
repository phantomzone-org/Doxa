# tessera-server

Sequencer plus standalone prover service for Tessera deposit-validation batching.

The sequencer is API-driven for intake:
- clients push note commitments to `POST /consume-request`
- private transactions can push full input/output payloads to `POST /private-tx`
- sequencer checks note status on-chain:
  - if note exists on bridge: required status depends on endpoint/tree flow
  - if note is not tracked by bridge (`NoteNotFound`): accepted as external/network-native leaf
- when enough notes are queued **or** batch timeout elapses, sequencer proves a full `noteBatchSize` / `accountBatchSize` insertion (padding with deterministic dummies when needed) and finalizes on-chain via:
  - `recordNotesCommitmentTreeUpdate` (single-phase)

## High-Level Flow

1. Trusted source records deposits on-chain via `depositAndRegister*`
2. External caller sends note commitments to sequencer API
3. Sequencer validates each note is `Pending` using `getDepositStatus(note)`
4. Sequencer batches notes (`noteBatchSize` / `accountBatchSize` from contract), with timeout-based flush for partial pools
5. Sequencer sends `ProveRequest` to dedicated prover API
6. Prover returns `ProveOutcome` with:
   - tree-update Solidity proof
   - aggregated-input Solidity proof
7. Sequencer submits `recordNotesCommitmentTreeUpdate(newRoot, notes, treeProof, aggregatedInputProof)`
8. Contract marks tracked notes `Validated` and updates `notesCommitmentRoot`

## Components

- `src/sequencer/`
  - Main async loop, API intake, recovery, and on-chain finalization
- `src/prover.rs`
  - Prover runtime and proof generation pipeline (plonky2 -> BN128 -> Groth16)
- `src/prover_client.rs`
  - HTTP client used by sequencer to request proofs from dedicated prover service
- `src/aggregation_pipeline/`
  - Streaming aggregation actor (`session.rs`), worker pool with local and remote provers (`pool.rs`), and HTTP protocol types (`types.rs`)
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

`input_proof` rules:
- required for each request; empty bytes are rejected
- when `TESSERA_AGGREGATOR_ARTIFACTS_PATH` is configured on the sequencer, bytes are cryptographically verified against the leaf circuit (`LeafProofVerifier` loaded from `leaf_common.bin` / `leaf_verifier.bin`)
- when the aggregator path is not configured, any non-empty bytes are accepted and cryptographic validation is deferred to the prover

### `POST /private-tx`

Request body:

```json
{
  "input_notes":["0x<32-byte-hex>","0x<32-byte-hex>"],
  "output_notes":["0x<32-byte-hex>","0x<32-byte-hex>"],
  "input_account_commitment":"0x<32-byte-hex>",
  "output_account_commitment":"0x<32-byte-hex>",
  "tx_proof":"0x<plonky2-proof-bytes-hex>",
  "tx_id":"optional-client-tx-id"
}
```

Semantics:
- `tx_proof` is the hex-encoded serialization of a Plonky2 `ProofWithPublicInputs` for the transaction validity leaf circuit. Validated cryptographically at the API layer when `TESSERA_AGGREGATOR_ARTIFACTS_PATH` is set.
- if proof verification fails, the payload is dropped and response is:
  - `{"accepted":false,"invalid_proof_tx":{"tx_id":"...","reason":"..."}}`
- routing is deterministic:
  - `input_notes` -> notes nullifier queue
  - `output_notes` -> notes commitment queue
  - `input_account_commitment` -> accounts nullifier queue
  - `output_account_commitment` -> accounts commitment queue

Batch proving semantics:
- Sequencer sends one associated-input proof per leaf in batch order to prover.
- Prover aggregates all batch-size proofs (real + canonical padding) via a streaming `AggregationSession` backed by the `NodeProverPool`.
- Prover returns both proofs (tree update + aggregated input) to sequencer.

## Configuration

### Sequencer (`SequencerConfig::from_env()`)

Required:
- `TESSERA_RPC_URL`
- `TESSERA_OPERATOR_KEY`
- `TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS`
- `TESSERA_CHAIN_ID`
- `TESSERA_NOTES_COMMITMENT_ARTIFACTS_PATH`
- `TESSERA_ACCOUNTS_COMMITMENT_ARTIFACTS_PATH`
- `TESSERA_NOTES_NULLIFIER_ARTIFACTS_PATH`
- `TESSERA_ACCOUNTS_NULLIFIER_ARTIFACTS_PATH`

Optional:
- `TESSERA_POLL_INTERVAL_SECS` (default `12`)
- `TESSERA_BATCH_TIMEOUT_SECS` (default `12`)
- `TESSERA_SEQUENCER_API_ADDR` (default `127.0.0.1:8081`)
- `TESSERA_PROVER_API_URL` (default `http://127.0.0.1:8091`)
- `TESSERA_PROVER_API_TIMEOUT_SECS` (default `1800`)
- `TESSERA_AGGREGATOR_ARTIFACTS_PATH` (unset = disabled): when set, the API layer cryptographically validates `tx_proof` bytes against the leaf circuit before forwarding to the sequencer loop
- `RUST_LOG` (default `info`)

### Prover (`ProverConfig::from_env()`)

Required:
- `TESSERA_NOTES_COMMITMENT_ARTIFACTS_PATH`
- `TESSERA_ACCOUNTS_COMMITMENT_ARTIFACTS_PATH`
- `TESSERA_NOTES_NULLIFIER_ARTIFACTS_PATH`
- `TESSERA_ACCOUNTS_NULLIFIER_ARTIFACTS_PATH`

Optional:
- `TESSERA_NOTE_BATCH_SIZE` (default `128`)
- `TESSERA_ACCOUNT_BATCH_SIZE` (default `16`; must equal `NOTE_BATCH_SIZE / 8`)
- `TESSERA_PROVER_API_ADDR` (default `127.0.0.1:8091`)
- `TESSERA_AGGREGATOR_ARTIFACTS_PATH` (unset = disabled): path to `GenericAggregator` artifacts; required for real proof aggregation on the private-tx path
- `TESSERA_AGGREGATION_PROVER_URLS` (default empty): comma-separated list of remote `aggregation_prover` base URLs (e.g. `http://worker1:8092,http://worker2:8092`); when empty, aggregation uses a single local prover thread
- `TESSERA_AGGREGATION_PROVER_TIMEOUT_SECS` (default `300`): per-request HTTP timeout for remote aggregation provers

### Aggregation Prover (`AggregatorProverConfig::from_env()`)

The `aggregation_prover` binary is a stateless HTTP worker for distributed node proving.

Required:
- `TESSERA_AGGREGATOR_ARTIFACTS_PATH`: path to pre-built `GenericAggregator` artifacts

Optional:
- `TESSERA_AGGREGATION_PROVER_ADDR` (default `0.0.0.0:8092`): HTTP listen address

Artifacts path must contain:
- `plonky2-proof/`
- `groth-artifacts/`

## Running

### Prover

```bash
cd tessera-server
cargo run --bin prover --release
```

### Sequencer (separate terminal)

```bash
cd tessera-server
cargo run --bin sequencer --release
```

### Aggregation Prover (optional, for distributed proving)

```bash
cd tessera-server
cargo run --bin aggregation_prover --release
```

All binaries load `.env` automatically if present.

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
   - decode function and real leaf payload
   - re-derive any omitted dummy leaves
   - apply full (padded) leaves locally in canonical chain order
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

Feature-gated scripted integration test (runs local devnet + deploy + recovery flow):

```bash
TESSERA_RUN_INTEGRATION_SCRIPTS=1 \
cargo test --release -p tessera-server --features integration-tests scripted_chain_recovery_e2e -- --nocapture --test-threads=1
```

```bash
TESSERA_RUN_INTEGRATION_SCRIPTS=1 cargo test --release -p tessera-server \
  --features integration-tests scripted_full_flow_e2e -- --nocapture --test-threads=1
```

Notes:
- This is intentionally opt-in and heavy.
- It requires `anvil`, `cast`, `forge`, and local Rust/Foundry toolchain availability.
- Artifacts are auto-generated only when missing, then reused (cached by presence under `tessera-server/artifacts`).
- Set `TESSERA_REBUILD_ARTIFACTS=1` to force regeneration.
