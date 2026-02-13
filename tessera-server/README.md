# tessera-server

Sequencer and prover service for Tessera consumed-deposit batching.

The sequencer is API-driven for intake:
- clients push note commitments to `POST /consume-request`
- sequencer checks note status on-chain (`Available` required)
- when `consumeBatchSize` notes are queued, sequencer proves append insertion and calls `finalizeConsumeBatch`

## High-Level Flow

1. Trusted source records deposits on-chain via `recordDeposit(noteCommitment)`
2. External caller sends note commitments to sequencer API
3. Sequencer validates each note is `Available` using `getDepositStatus(note)`
4. Sequencer batches notes (`consumeBatchSize` from contract)
5. Prover generates Groth16 proof for batch append
6. Sequencer submits `finalizeConsumeBatch(newRoot, notes, proof)`
7. Contract marks notes `Consumed` and updates `consumedRoot`

## Components

- `src/sequencer.rs`
  - Main async loop
  - API server (`axum`) for consume requests
  - On-chain preflight checks and batch finalization
- `src/prover.rs`
  - Blocking prover worker (plonky2 -> BN128 wrap -> Groth16)
- `src/state.rs`
  - In-memory pending request queue + local used tree mirror
- `src/contract.rs`
  - Alloy bindings for `DepositsRollupBridge`

## API

### `POST /consume-request`

Request body:

```json
{"note_commitment":"0x<32-byte-hex>"}
```

Response:

```json
{"accepted":true}
```

HTTP errors:
- `400` invalid commitment format
- `503` sequencer intake channel unavailable

Note: `accepted=true` means the request entered the sequencer queue; the note is still checked against on-chain status before batching.

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
- `RUST_LOG` (default `info`)

Artifacts path must contain:
- `plonky2-proof/`
- `groth-artifacts/`

## Running

```bash
cd tessera-server
cargo run --bin sequencer --release
```

The binary loads `.env` automatically if present.

## Recovery Behavior

- Local used tree is rebuilt from on-chain `DepositConsumed` logs at startup.
- Pending consume requests are API-fed and in-memory only.
- Requests sent while sequencer is down are not persisted by the server itself.

## Build and Test

```bash
cargo check -p tessera-server
cargo test -p tessera-server --release
```
