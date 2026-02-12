# tessera-server

Sequencer and prover service for the Tessera zk-rollup deposit bridge. This crate provides both a library for deposit batch processing and a binary (`sequencer`) that orchestrates the full batch lifecycle: on-chain deposit event polling, Groth16 proof generation, and single-step batch finalization.

## Architecture

```
                          tokio::mpsc
  ┌───────────────┐   ProveRequest   ┌─────────────────┐
  │  Sequencer    │ ───────────────> │  Prover         │
  │  (async loop) │                  │ (spawn_blocking)│
  │               │ <─────────────── │                 │
  └──────┬────────┘   ProveResult    └─────────────────┘
         │
         │  alloy Provider (event polling + tx submission)
         v
  ┌───────────────┐
  │  Ethereum RPC │
  └───────────────┘
```

The system has two concurrent components:

- **Sequencer** (async, tokio): Polls `DepositPending` events from the `DepositsRollupBridge` contract, accumulates commitments into batches of 128, and calls `finalizeBatch` after receiving a proof from the prover.
- **Prover** (blocking, `tokio::task::spawn_blocking`): Runs the full proof pipeline (plonky2 -> BN128 wrap -> Groth16) on a dedicated OS thread. Initialized once at startup; proves each batch on demand. The Go FFI layer (gnark) is not thread-safe, so all Groth16 operations must happen on a single thread.

## Modules

|       Module       |                                                        Description                                                                   |
|--------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| `pending_deposits` | Core data types: `PendingDeposit`, `PendingDepositsBatch`, `PendingDepositsBatchReady`, `PendingDepositTree`                         |
| `config`           | `SequencerConfig` -- loads all configuration from `TESSERA_*` environment variables                                                  |
| `contract`         | Alloy `sol!` bindings for `DepositsRollupBridge` + encoding helpers (`hash_to_bytes32`, `bytes32_to_hash`)                           |
| `types`            | Channel message types: `ProveRequest`, `ProveResult`, `SolidityProof`                                                                |
| `state`            | `SequencerState` -- wraps the Merkle tree and commitment accumulator with `add_commitment` / `seal_batch`                            |
| `prover`           | `ProverService` (init once, prove per-batch) and `prover_thread` (blocking event loop)                                               |
| `sequencer`        | `Sequencer` struct with the main `tokio::select!` loop                                                                               |

## Data Flow

```
On-chain: user calls deposit(noteCommitment, value, recipient)
    -> emits DepositPending(depositId, commitment, value, recipient)
    |
    | event polling (alloy Provider)
    v
Sequencer: state.add_commitment(commitment) -- batch full (128)?
    |
    v
state.seal_batch()
    -> (start_index, BatchCommitmentProof { root_old, root_new, leaves, siblings })
    |
    | mpsc (ProveRequest)
    v
Prover: plonky2 prove -> BN128 wrap -> Groth16 prove -> SolidityProof
    |
    | mpsc (ProveResult)
    v
Sequencer: bridge.finalizeBatch(newRoot, depositStartIndex, proof)
    -> deposit statuses: Pending -> Validated
    -> merkleRoot updated on-chain
```

## Proof Pipeline

The prover executes the following steps for each batch (see `ProverService::prove`):

1. **Set witnesses** on the pre-built plonky2 circuit using the `BatchCommitmentProof`
2. **Prove** the plonky2 circuit (native Goldilocks field)
3. **Wrap to BN128** via `BN128Wrapper::wrap_proof_to_bn128` (recursive verification circuit using PoseidonBN128)
4. **Groth16 prove** via `Groth16Wrapper::prove` (Go FFI to gnark)
5. **Verify locally** via `Groth16Wrapper::verify`
6. **Format for Solidity** via `Groth16Wrapper::proof_to_solidity_json`, parsed into `SolidityProof { proof[8], commitments[2], commitment_pok[2] }`

The circuit shape is fixed: depth=32, batch_size=128, SHA-256 commitment with 8-bit LUT chunk width. The circuit is built once during `ProverService::init` and reused for every batch -- only the witnesses change.

## Configuration

All configuration is loaded from environment variables via `SequencerConfig::from_env()`. A `.env` file is supported via `dotenvy`.

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `TESSERA_RPC_URL` | Ethereum JSON-RPC endpoint | `http://localhost:8545` |
| `TESSERA_OPERATOR_KEY` | Operator private key (hex) | `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80` |
| `TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS` | `DepositsRollupBridge` contract address | `0x5FbDB2315678afecb367f032d93F642f64180aa3` |
| `TESSERA_CHAIN_ID` | Chain ID | `31337` |
| `TESSERA_PENDING_DEPOSITS_ARTIFACTS_PATH` | Base directory for proof artifacts | `./artifacts/pending-deposit` |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `TESSERA_POLL_INTERVAL_SECS` | `12` | Seconds between event polling cycles (one Ethereum block) |
| `RUST_LOG` | `info` | Tracing log level filter |

## On-Chain Contract Interface

The sequencer interacts with `DepositsRollupBridge.sol` via type-safe alloy bindings:

- **`merkleRoot()`** -- Current committed Merkle root.
- **`nextDepositId()`** -- Monotonic deposit counter.
- **`finalizeBatch(newRoot, depositStartIndex, proof)`** -- Finalize a batch of 128 pending deposits by verifying a Groth16 proof. Reads commitments from storage, computes the SHA-256 circuit commitment, verifies the proof, marks deposits as `Validated`, and advances `merkleRoot`.
- **`DepositPending` event** -- Emitted when a user calls `deposit()`. The sequencer polls these events to accumulate commitments.

### Encoding Conventions

- **Roots and commitments**: Each Goldilocks field element is encoded as an 8-byte big-endian uint64. A `Hash` (4 elements) becomes a `bytes32` (32 bytes).
- **Deposit commitment**: `sha256(DOMAIN_SEP || noteCommitment || value || recipient)` with the MSB of each 64-bit chunk cleared for Goldilocks field compatibility.
- **SHA-256 circuit commitment**: `sha256(merkleRoot_old || merkleRoot_new || commitment_0 || ... || commitment_127)` -- matches the circuit's public inputs.

## Building

```bash
# Build the library + binary
cargo build -p tessera-server

# Build in release mode (recommended for prover performance)
cargo build -p tessera-server --release
```

## Running

### Prerequisites

1. **Groth16 artifacts**: Run the trusted setup once to generate proving/verifying keys:
   ```bash
   cargo run --example groth16_wrapper --release
   ```
   This creates `examples/tmp/plonky2-proof/` and `examples/tmp/groth-artifacts/`.

2. **Ethereum node**: A local node (e.g., `anvil`) or remote RPC endpoint with the `DepositsRollupBridge` and `Verifier` contracts deployed.

### Start the sequencer

```bash
# Using environment variables directly
TESSERA_RPC_URL=http://localhost:8545 \
TESSERA_OPERATOR_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=0x5FbDB2315678afecb367f032d93F642f64180aa3 \
TESSERA_CHAIN_ID=31337 \
TESSERA_PENDING_DEPOSITS_ARTIFACTS_PATH=./artifacts/pending-deposit \
cargo run --bin sequencer --release

# Or using a .env file
cargo run --bin sequencer --release
```

The sequencer will:
1. Sync the genesis root and deposit counter from the contract
2. Poll for `DepositPending` events every `TESSERA_POLL_INTERVAL_SECS` seconds
3. When 128 commitments accumulate, seal the batch and send to the prover
4. Call `finalizeBatch` once the Groth16 proof is ready

## Testing

```bash
# Run unit tests
cargo test -p tessera-server --release

# Run full workspace tests (includes tessera-trees circuit tests)
cargo test --workspace --release
```

## Examples

### `groth16_wrapper`

End-to-end Groth16 proof generation for Foundry integration tests:

```bash
cargo run --example groth16_wrapper --release
```

### `genesis_root`

Compute the genesis root (empty tree) for contract deployment:

```bash
cargo run -p tessera-server --example genesis_root --release
```

## Project Structure

```
tessera-server/
  Cargo.toml
  src/
    lib.rs                      # Re-exports + sample_batch_tree_proof
    pending_deposits/
      mod.rs                    # Module declarations
      deposit.rs                # PendingDeposit (hash, serialize)
      batch.rs                  # PendingDepositsBatch (128 deposits)
      batch_ready.rs            # PendingDepositsBatchReady (batch + root)
      tree.rs                   # PendingDepositTree<H> (depth-32 Merkle)
    config.rs                   # SequencerConfig (env vars)
    contract.rs                 # Alloy sol! bindings + encoding helpers
    types.rs                    # ProveRequest, ProveResult, SolidityProof
    state.rs                    # SequencerState (tree + commitment accumulator)
    prover.rs                   # ProverService + prover_thread
    sequencer.rs                # Sequencer (main async loop)
    bin/
      sequencer.rs              # Binary entry point
  examples/
    groth16_wrapper.rs          # End-to-end proof generation
    genesis_root.rs             # Genesis root computation
    tmp/                        # Generated artifacts (gitignored)
```
