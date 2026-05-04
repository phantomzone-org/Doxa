# Tessera State Sync — Implementation Notes for Agents

## Overview

The `tessera-state-sync` crate is a standalone Rust binary + library that syncs on-chain state from `TesseraContract` and exposes it via an HTTP API (using Axum). It runs as a long-lived service that performs an initial genesis sync on startup, then continuously polls the chain for new events in a background loop.

**Location in codebase**: `/tessera-state-sync/`

**Targets**:
- Binary: `tessera-state-sync` (main HTTP server)
- Library: `tessera_state_sync` (public API for embedders)

## Architecture

### Entry Point (`main.rs`)

1. Loads environment configuration (RPC URL, contract address, poll interval, bind address)
2. Creates an Alloy provider for blockchain interaction
3. Calls `StateSyncService::sync_from_genesis()` — blocks until genesis sync completes
4. Sets up Axum HTTP routes with CORS enabled
5. Spawns a background tokio task that calls `poll_sync()` on the given interval
6. Runs the HTTP server in the main task

**Key insight**: The HTTP server only starts accepting traffic AFTER genesis sync completes. This guarantees all API responses return correct state from the beginning.

### State Model (`state.rs`)

The `StateSyncState` struct maintains six interconnected indexes:

#### 1. StateTree Mirror
- **`state_tree`**: A `MerkleTree<HashOutput>` that mirrors the on-chain IMT. Each leaf is a `batchPoseidonRoot` (one per proven batch).
- **`batch_root_to_leaf_index`**: Maps `batchPoseidonRoot` (as `[u8; 32]`) to its leaf index in the IMT.
- **`confirmed_roots`**: A `BTreeSet` of all valid IMT roots seen (seeded with genesis root). Used to validate root changes.

#### 2. Batch Subtree Storage
- **`pending_batch_leaves`**: Maps `piCommitment` to a vec of 512 commitments (account + note) extracted from the batch preimage during submission.
- **`confirmed_batch_subtrees`**: Maps `piCommitment` to a built `MerkleTree<HashOutput>` (depth 9) containing the 512 leaves from the batch.
- **`pi_to_batch_root`**: Maps `piCommitment` to the `batchPoseidonRoot` for that batch.

**Leaf layout in batch subtree** (for TX batches):
- Slot `s` (0 to 63) occupies leaves `s * 8` through `s * 8 + 7`:
  - Leaf `s*8 + 0`: account out-commitment
  - Leaf `s*8 + 1..8`: 7 note out-commitments

#### 3. Commitment Tracking
- **`commitment_to_batch`**: Maps each account/note commitment (as `HashOutput`) to a `CommitmentLocation` struct containing:
  - `pi_commitment`: the batch identifier (keccak256 of preimage)
  - `subtree_leaf_index`: 0-based position within the 512-leaf batch subtree
  - `confirmed`: whether the batch has been proven on-chain

#### 4. Batch Status Tracking
- **`pending_tx_batches`**: Maps `piCommitment` to the full `batchPreimage` bytes for unproven TX batches.
- **`confirmed_tx_batches`**: Set of `piCommitment` values for proven TX batches.
- **`pending_bridge_tx_batches`** / **`confirmed_bridge_tx_batches`**: Same for bridge-TX batches.

#### 5. Nullifier Index
- **`confirmed_nullifiers`**: Set of `HashOutput` nullifiers that have been confirmed on-chain (moved from pending when batch is proven).
- **`pending_nullifiers`**: Maps `HashOutput` nullifier to the `piCommitment` of its pending batch.

#### 6. MainPoolConfigTree Mirror
- **`config_tree`**: A `MainPoolConfigTree<HashOutput>` (from `tessera-client`) that mirrors the on-chain config tree.
- **`subpool_roots`**: Maps `subpool_id` (u64) to its current `HashOutput` root. Includes zero-root entries for assigned but not-yet-updated subpools.
- **`pending_subpool_assignments`**: A `BTreeMap` (sorted by `subpool_id`) that buffers out-of-order `SubpoolOwnerAssigned` events. These are processed once predecessors arrive.
- **`next_expected_subpool_id`**: The next sequential subpool ID expected in `SubpoolOwnerAssigned` events (starts at 1, incremented as events are processed in order).

#### 7. Deposit Index
- **`deposits`**: Maps note commitment (as `[u8; 32]`) to a `DepositRecord` containing value, recipient, asset ID, block number, and status.

#### 8. Sync State
- **`last_synced_block`**: The highest block number for which events have been processed. Used by poll sync to fetch only new events.

### Thread Safety

`StateSyncState` is wrapped in `StateSyncService`, which uses `Arc<RwLock<StateSyncState>>` for safe concurrent access. Two accessor methods:
- **`with_state(f)`**: Read-only access via closure
- **`with_state_mut(f)`**: Mutable access via closure

The HTTP server uses `with_state`; the polling loop uses both.

### Sync Logic (`sync.rs`)

Two main functions:

#### 1. Genesis Sync: `sync_from_genesis()`

Replays all events from block 1 to the current `eth_blockNumber()` in order:

1. **Event types monitored** (in order):
   - `TransactionBatchSubmitted(piCommitment, batchPreimage, batchPoseidonRoot, newTreeRoot)`
   - `BridgeTxBatchSubmitted(piCommitment, batchPreimage, batchPoseidonRoot, newTreeRoot)`
   - `TransactionBatchProven(piCommitment, leafIndex, newTreeRoot)`
   - `BridgeTxBatchProven(piCommitment, leafIndex, newTreeRoot)`
   - `SubpoolOwnerAssigned(subpoolId, owner)`
   - `SubpoolRootUpdated(subpoolId, newSubpoolRoot, newConfigRoot)`
   - `DepositAvailable(noteCommitment, value, recipient, assetId)` *(need to fetch block number and asset ID from receipt/calldata)*
   - `DepositValidated(noteCommitment)`
   - `DepositWithdrawn(noteCommitment, value, recipient)`

2. **Batch submissions**: Decode the `batchPreimage` from the transaction calldata (not the event). Extract all account and note commitments, storing them in `pending_batch_leaves` with `confirmed = false`.

3. **Batch proofs**: When a `*BatchProven` event is seen, call `StateSyncState::confirm_batch()` which:
   - Inserts the `batchPoseidonRoot` as a new leaf in `state_tree`
   - Builds a subtree from the pending leaves and caches it in `confirmed_batch_subtrees`
   - Marks all commitments in that batch as `confirmed = true`
   - Moves the batch from pending to confirmed
   - Moves all pending nullifiers for that batch to confirmed

4. **Config tree initialization**: For genesis sync only, after processing all `SubpoolOwnerAssigned` events, fetch the current `subpoolRoots[id]` from the contract for each assigned subpool (via `subpoolRoots(subpool_id)` view call), then rebuild the entire `config_tree` from scratch using all collected roots.

5. **Log fetching**: Uses paginated `eth_getLogs` with a chunk size of 1,000 blocks per request to avoid timeouts.

**Important**: Proven-batch events are sorted by `leafIndex` (ascending) before being applied to ensure the local tree leaf order matches the on-chain IMT order.

#### 2. Poll Sync: `poll_sync()`

Runs periodically (default every 12 seconds) to catch new events:

1. **Event window**: Fetches events in `(last_synced_block, current_block_number]`

2. **Same event types as genesis**, processed in the same way

3. **For batch proofs**: If a `*BatchProven` event is seen whose corresponding submission event falls outside the current poll window (e.g., it was submitted in a previous interval), perform a targeted `eth_getLogs` lookup to find the submission by `piCommitment` as a topic.

4. **For SubpoolOwnerAssigned in poll mode**: 
   - Apply events in order (using the same buffer logic as genesis)
   - Initialize newly assigned subpools in `subpool_roots` with `HashOutput::ZERO` (using `entry(...).or_insert(...)` to avoid clobbering on-chain roots that genesis may have fetched)
   - After all assigned events are processed, if any new subpools were assigned, rebuild the entire `config_tree` from the updated `subpool_roots` map

5. **For SubpoolRootUpdated**: Update the entry in `subpool_roots` and trigger an `update_subpool_root()` rebuild of the config tree.

6. **Error handling**: Any error in `poll_sync()` is logged; the loop continues on the next interval.

### HTTP API (`api.rs`)

All endpoints are GET with hex-encoded (0x-prefixed) hash parameters and JSON responses. Uses Axum with permissive CORS.

#### `GET /commitment/merkle-path?commitment=0x...`

**Response (confirmed)**:
```json
{
  "status": "confirmed",
  "batch_subtree_path": {
    "leaf_index": 3,
    "siblings": ["0x...", "0x...", ...],
    "directions": [0, 1, 0, ...]
  },
  "state_tree_path": {
    "leaf_index": 7,
    "siblings": ["0x...", ...],
    "directions": [...]
  }
}
```

**Response (pending)**:
```json
{
  "status": "pending",
  "pi_commitment": "0x..."
}
```

**Response (unknown)**: `{ "status": "not_found" }`

#### `GET /nullifier/status?nullifier=0x...`

Returns `{ "status": "confirmed" }`, `{ "status": "pending", "pi_commitment": "0x..." }`, or `{ "status": "not_found" }`.

#### `GET /subpool/full-proof?subpool_id=<u64>`

**Response**:
```json
{
  "subpool_id": 3,
  "subpool_root": "0x...",
  "leaf_value": "0x...",
  "config_tree_root": "0x...",
  "siblings": ["0x...", ...],
  "directions": [0, 1, ...]
}
```

Returns `404` if `subpool_id == 0` or the subpool was never assigned an owner.

#### `GET /batch/status?pi_commitment=0x...&kind=tx|bridge`

Returns `{ "status": "pending" }`, `{ "status": "confirmed" }`, or `{ "status": "not_found" }`.

The `kind` parameter must be either `"tx"` or `"bridge"` to disambiguate between TX and bridge-TX batches (they share the same key space).

#### `GET /deposits?from_block=<u64>`

**Response**:
```json
[
  {
    "note_commitment": "0x...",
    "value": "1000000",
    "recipient": "0x...",
    "asset_id": "1",
    "status": "Pending",
    "deposit_block": 12345
  }
]
```

If `from_block` is omitted, defaults to 0 (all deposits). Status is one of `"Pending"`, `"Validated"`, or `"Withdrawn"`.

### Contract Bindings (`contract.rs`)

Contains Alloy `sol!` macro bindings for `TesseraContract` ABI. Two utility functions for Goldilocks field encoding:

- **`hash_to_bytes32(hash: &HashOutput) -> &[u8; 32]`**: Converts a `HashOutput` to its byte representation, handling the GL-preimage encoding swap (each field element's two halves are byte-swapped).

- **`bytes32_to_hash(bytes: &B256) -> anyhow::Result<HashOutput>`**: Reverse conversion with validation.

These are necessary because ZK circuits operate over the Goldilocks field (p = 2⁶⁴ − 2³² + 1), and `HashOutput` is 4 Goldilocks elements LE-packed into a `uint256` (per CLAUDE.md).

### Constants (`constants.rs`)

Compile-time constants matching `TesseraContract.sol`:
- **Batch structure**: `PRIV_TX_BATCH_SIZE = 64`, `NOTE_BATCH = 7`, `BRIDGE_TX_HALF_SIZE = 256`, `BATCH_SUBTREE_DEPTH = 9`
- **TX batch preimage offsets**: Header (96B), then 64 slots of 520B each
- **Bridge-TX preimage offsets**: Header (96B), 256 withdraw slots (616B each), 256 deposit slots (216B each)
- **Total preimage lengths**: `TX_PREIMAGE_LEN`, `BRIDGE_TX_PREIMAGE_LEN` (compile-time asserts verify these)

These are hard-coded and must match the contract. They are NOT read from the contract at runtime.

**Dynamic values** that ARE read from the contract at startup:
- `configTreeDepth` — via `TesseraContract::configTreeDepth()` view call
- `treeDepth` — via `TesseraContract::treeDepth()` view call

## Known Limitations & Deferred Improvements

The codebase has been reviewed and approved. The following suggestions (non-blocking) were noted by the reviewer:

1. **Poll-sync rebuild optimization** (`sync.rs:367–381`):
   - The unconditional `else` block that rebuilds the config tree runs even when no new subpools were assigned in the current poll interval, wasting a full tree rebuild on steady-state ticks.
   - **Fix**: Add a guard `if !assigned_logs.is_empty()` before the rebuild.
   - **Priority**: Low (tree is small; cost is minimal).

2. **Partial mutation window in confirm_batch** (`state.rs:144–158`):
   - If any `subtree.insert()` call fails after `insert_state_tree_leaf()` succeeds, the state tree has a new leaf but the batch metadata (subtree, pi_to_batch_root, commitment confirmations, nullifier moves) is incomplete.
   - **Mitigation**: In practice this cannot happen (exactly 512 inserts into a depth-9 tree with 512-leaf capacity), but a defensive guard (clone leaves vec and build subtree before calling `remove`) would remove the dependency on that invariant.
   - **Priority**: Low (invariant is rock-solid).

3. **Root divergence visibility** (`state.rs:196`):
   - When `local_root != new_tree_root` after confirming a batch, the service logs a warning but still inserts the diverged root into `confirmed_roots`.
   - **Suggestion**: Consider surfacing divergences more visibly (health-check flag, metric, or refusing new traffic).
   - **Priority**: Low (unlikely in practice; would require contract or sync bug).

4. **Extract batch root from preimage** (`sync.rs:651–658`):
   - Both submission events emit `batchPoseidonRoot` as a field, but the code re-parses it from the preimage header.
   - **Suggestion**: Store `batchPoseidonRoot` from the event in the submission map to make the code more robust against future header layout changes.
   - **Priority**: Low (header layout is stable).

## Testing & Validation

- **Compilation**: `cargo check -p tessera-state-sync` — verified clean (no errors/warnings)
- **Unit tests**: None in this crate (state operations are integration-tested via E2E tests and demo flows)
- **Integration**: Tested via local demo script (`scripts/local_test_flow.sh`) and full E2E test suite

## Common Tasks

### Running the Service

```bash
export TESSERA_RPC_URL="http://localhost:8545"
export TESSERA_CONTRACT_ADDRESS="0x..."  # deployed contract address
export TESSERA_STATE_SYNC_POLL_INTERVAL="12"  # optional; default 12s
export TESSERA_STATE_SYNC_BIND_ADDR="0.0.0.0:3001"  # optional; default 0.0.0.0:3001

cargo run -p tessera-state-sync --release
```

### Querying the API

```bash
# Commitment Merkle path
curl "http://localhost:3001/commitment/merkle-path?commitment=0x..."

# Nullifier status
curl "http://localhost:3001/nullifier/status?nullifier=0x..."

# Subpool proof
curl "http://localhost:3001/subpool/full-proof?subpool_id=1"

# Batch status
curl "http://localhost:3001/batch/status?pi_commitment=0x...&kind=tx"

# Deposits from block 1000
curl "http://localhost:3001/deposits?from_block=1000"
```

### Debugging

Logging is controlled via the `RUST_LOG` environment variable (passed to `tracing_subscriber`):

```bash
RUST_LOG=tessera_state_sync=debug cargo run -p tessera-state-sync --release
RUST_LOG=tessera_state_sync=trace cargo run -p tessera-state-sync --release  # very verbose
```

Key log points:
- Genesis sync start/completion
- Poll sync errors (event processing)
- Root divergence warnings
- State tree insertions and batch confirmations

## Dependencies

- **tessera-client**: Pool config tree, SubpoolId types, leaf commitment logic
- **tessera-trees**: Generic Merkle tree implementation
- **tessera-utils**: Goldilocks field hashing, HashOutput type
- **alloy**: Blockchain RPC provider, ABI bindings (sol! macro), types (Address, B256, U256, Bytes)
- **axum**: HTTP server framework
- **tokio**: Async runtime
- **tracing** / **tracing-subscriber**: Structured logging
- **serde** / **serde_json**: JSON serialization
- **hex**: Hex encoding/decoding utilities
- **dotenvy**: .env file loading

## Future Work / Potential Extensions

1. **Persistence layer**: Currently, all state is in-memory. Adding a database layer (e.g., PostgreSQL via sqlx) could enable:
   - Faster startup (don't replay all logs from genesis)
   - State snapshots for debugging
   - Query history (e.g., all deposits over a time range)

2. **Metrics**: Add prometheus-style metrics for:
   - Sync lag (current block vs last synced block)
   - API request latency
   - Event processing rates
   - Root divergence events (if any)

3. **Fallback / redundancy**: Run multiple instances with a load balancer or gossip protocol to ensure service availability.

4. **Contract changes**: If `TesseraContract` emits new event types or modifies the batch preimage layout, this crate will need updates to:
   - Add new event handlers in `sync.rs`
   - Update batch parsing constants in `constants.rs`
   - Update `contract.rs` ABI bindings (via `sol!` macro)

