# Doxa State Sync — Implementation Notes for Agents

## Overview

The `doxa-state-sync` crate is a standalone Rust binary + library that syncs on-chain state from `DoxaContract` and exposes it via an HTTP API (using Axum). It runs as a long-lived service that performs an initial genesis sync on startup, then continuously polls the chain for new events in a background loop.

**Location in codebase**: `/doxa-state-sync/`

**Targets**:
- Binary: `doxa-state-sync` (main HTTP server)
- Library: `doxa_state_sync` (public API for embedders)

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

The `StateSyncState` struct maintains eight interconnected indexes:

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
- **`config_tree`**: A `MainPoolConfigTree<HashOutput>` (from `doxa-client`) that mirrors the on-chain config tree.
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
   - `TransactionBatchSubmitted(piCommitment, batchPoseidonRoot)` *(preimage fetched from calldata)*
   - `BridgeTxBatchSubmitted(piCommitment, batchPoseidonRoot)` *(preimage fetched from calldata)*
   - `TransactionBatchProven(piCommitment, newTreeRoot, leafIndex)`
   - `BridgeTxBatchProven(piCommitment, newTreeRoot, leafIndex)`
   - `SubpoolOwnerAssigned(subpoolId, owner)`
   - `SubpoolRootUpdated(subpoolId, newSubpoolRoot, newConfigRoot)`
   - `DepositAvailable(noteCommitment, value, recipient, assetId)` *(block number and asset ID from event)*
   - `DepositValidated(noteCommitment)`
   - `DepositWithdrawn(noteCommitment)`

2. **Batch submissions**: Submission events emit `piCommitment` and `batchPoseidonRoot`, but NOT the `batchPreimage`. The preimage is fetched from the transaction calldata via `eth_getTransactionByHash` and decoded using `decode_tx_batch_calldata()` or `decode_bridge_batch_calldata()`. Extract all account and note commitments, storing them in `pending_batch_leaves` with `confirmed = false`.

3. **Batch proofs**: When a `*BatchProven` event is seen, call `StateSyncState::confirm_batch()` which:
   - Inserts the `batchPoseidonRoot` as a new leaf in `state_tree`
   - Builds a subtree from the pending leaves and caches it in `confirmed_batch_subtrees`
   - Marks all commitments in that batch as `confirmed = true`
   - Moves the batch from pending to confirmed
   - Moves all pending nullifiers for that batch to confirmed

4. **Config tree initialization**: For genesis sync only, after processing all `SubpoolOwnerAssigned` events, fetch the current `subpoolRoots[id]` from the contract for each assigned subpool (via `subpoolRoots(subpool_id)` view call), then rebuild the entire `config_tree` from scratch using all collected roots. After genesis sync completes, verify that the local leaf count matches the on-chain IMT leaf count via `imtLeafCount()` as a sanity check.

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

Contains Alloy `sol!` macro bindings for `DoxaContract` ABI. Multiple utility functions for Goldilocks field encoding:

**Basic conversions** (8-byte big-endian u64 per element):
- **`hash_to_bytes32(h: &HashOutput) -> B256`**: Converts a `HashOutput` to its byte representation (each field element as 8-byte big-endian).
- **`bytes32_to_hash(b: &B256) -> anyhow::Result<HashOutput>`**: Reverse conversion with validation.
- **`bytes_slice_to_hashes(raw: &[[u8; 32]]) -> anyhow::Result<Vec<HashOutput>>`**: Batch conversion of raw byte arrays to validated `HashOutput` values.

**LE-packed uint256 conversions** (used for on-chain contract calls like `subpoolRoots`):
- **`hash_to_u256_le(h: &HashOutput) -> U256`**: Packs `HashOutput` into a little-endian `uint256` (layout: `e0 | (e1 << 64) | (e2 << 128) | (e3 << 192)`).
- **`u256_le_to_hash(v: U256) -> anyhow::Result<HashOutput>`**: Inverse conversion with field range validation.
- **`bytes32_be_to_u256_le(b: &[u8; 32]) -> U256`**: Converts big-endian `[u8; 32]` to LE-packed `uint256`.

**GL-preimage format** (byte-swapped 4-byte halves per field element, used in contract batch structs):
- **`hash_to_preimage_bytes32(h: &HashOutput) -> B256`**: Encodes `HashOutput` in GL-preimage format (`[lo_BE4][hi_BE4]` per element).
- **`raw_to_preimage_bytes32(raw: &[u8; 32]) -> B256`**: Swaps the two 4-byte halves for each of the 4 field elements.
- **`preimage_bytes32_to_raw(b: &B256) -> [u8; 32]`**: Inverse of above (used in sync to decode commitments from preimage calldata).

These are necessary because ZK circuits operate over the Goldilocks field (p = 2⁶⁴ − 2³² + 1), and `HashOutput` is 4 Goldilocks elements. Different encoding schemes are used in different contexts (on-chain state, contract calldata, uint256 packing) to match the contract's expectations.

### Constants (`constants.rs`)

Compile-time constants matching `DoxaContract.sol`:
- **Batch structure**: `PRIV_TX_BATCH_SIZE = 64`, `NOTE_BATCH = 7`, `BRIDGE_TX_HALF_SIZE = 256`, `BATCH_SUBTREE_DEPTH = 9`
- **TX batch preimage offsets**: Header (96B), then 64 slots of 520B each
- **Bridge-TX preimage offsets**: Header (96B), 256 withdraw slots (616B each), 256 deposit slots (216B each)
- **Total preimage lengths**: `TX_PREIMAGE_LEN`, `BRIDGE_TX_PREIMAGE_LEN` (compile-time asserts verify these)

These are hard-coded and must match the contract. They are NOT read from the contract at runtime.

**Dynamic values** that ARE read from the contract at startup:
- `configTreeDepth` — via `DoxaContract::configTreeDepth()` view call
- `treeDepth` — via `DoxaContract::treeDepth()` view call

## Known Limitations & Deferred Improvements

The codebase has been reviewed and approved. The following suggestions (non-blocking) were noted by the reviewer:

1. **Poll-sync rebuild optimization** (`sync_config_tree`):
   - The config tree rebuild runs unconditionally in poll mode, even when no new subpools were assigned in the current poll interval, wasting a full tree rebuild on steady-state ticks.
   - **Fix**: Add a guard `if !assigned_logs.is_empty()` before the rebuild.
   - **Priority**: Low (tree is small; cost is minimal).

2. **Partial mutation window in confirm_batch** (`state.rs`, `confirm_batch` method):
   - If any `subtree.insert()` call fails after `insert_state_tree_leaf()` succeeds, the state tree has a new leaf but the batch metadata (subtree, pi_to_batch_root, commitment confirmations, nullifier moves) is incomplete.
   - **Mitigation**: In practice this cannot happen (exactly 512 inserts into a depth-9 tree with 512-leaf capacity), but a defensive guard (clone leaves vec and build subtree before mutating state) would remove the dependency on that invariant.
   - **Priority**: Low (invariant is rock-solid).

3. **Root divergence visibility** (`state.rs`, `confirm_batch` method):
   - When `local_root != new_tree_root` after confirming a batch, the service logs a warning but still inserts the diverged root into `confirmed_roots`.
   - **Suggestion**: Consider surfacing divergences more visibly (health-check flag, metric, or refusing new traffic).
   - **Priority**: Low (unlikely in practice; would require contract or sync bug).

4. **Extract batch root from preimage** (`sync.rs`, `extract_batch_root_from_preimage`):
   - Both submission events emit `batchPoseidonRoot` as a field, but the code re-parses it from the preimage header (first 32 bytes).
   - **Suggestion**: Store `batchPoseidonRoot` from the event in the submission map to make the code more robust against future header layout changes.
   - **Priority**: Low (header layout is stable).

## Testing & Validation

- **Compilation**: `cargo check -p doxa-state-sync` — verified clean (no errors/warnings)
- **Integration tests** (13 tests in `tests/integration.rs`, all anvil-based with `forge build` + `anvil` required):
  - `test_empty_chain_sync` — genesis sync on fresh contract
  - `test_poll_sync_incremental` — exhaustive two-TX-batch incremental sync test
  - `test_bridge_batch_scenarios` — bridge batch submission and proof scenarios
  - `test_randomized_batch_ordering` — random batch submission/proof ordering
  - `test_subpool_lifecycle` — subpool owner assignment and root updates
  - `test_deposit_lifecycle` — deposit tracking through all status transitions
  - `test_deposit_validated_via_bridge_batch` — deposits validated within a bridge batch
  - `test_api_commitment_queries` — `/commitment/merkle-path` endpoint
  - `test_api_nullifier_queries` — `/nullifier/status` endpoint
  - `test_api_batch_status_queries` — `/batch/status` endpoint for TX batches
  - `test_api_bridge_batch_status` — `/batch/status` endpoint for bridge batches
  - `test_api_deposits` — `/deposits` endpoint with filtering
  - `test_api_subpool` — `/subpool/full-proof` endpoint
- **Test infrastructure** (`tests/common/mod.rs`): Anvil-based contract deployment, transaction signing, and batch submission helpers
- **Manual validation**: Local demo script (`scripts/local_test_flow.sh`) and full E2E test suite

## Common Tasks

### Running the Service

```bash
export DOXA_RPC_URL="http://localhost:8545"
export DOXA_CONTRACT_ADDRESS="0x..."  # deployed contract address
export DOXA_GENESIS_BLOCK="0"  # optional; default 0 (start block for genesis sync)
export DOXA_STATE_SYNC_POLL_INTERVAL="12"  # optional; default 12s
export DOXA_STATE_SYNC_BIND_ADDR="0.0.0.0:3001"  # optional; default 0.0.0.0:3001

cargo run -p doxa-state-sync --release
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
RUST_LOG=doxa_state_sync=debug cargo run -p doxa-state-sync --release
RUST_LOG=doxa_state_sync=trace cargo run -p doxa-state-sync --release  # very verbose
```

Key log points:
- Genesis sync start/completion
- Poll sync errors (event processing)
- Root divergence warnings
- State tree insertions and batch confirmations

## Dependencies

- **doxa-client**: Pool config tree, SubpoolId types, leaf commitment logic
- **doxa-trees**: Generic Merkle tree implementation
- **doxa-utils**: Goldilocks field hashing, HashOutput type
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

4. **Contract changes**: If `DoxaContract` emits new event types or modifies the batch preimage layout, this crate will need updates to:
   - Add new event handlers in `sync.rs`
   - Update batch parsing constants in `constants.rs`
   - Update `contract.rs` ABI bindings (via `sol!` macro)

