# 12. Optimistic Two-Phase Throughput Plan

## Objective
Increase transaction throughput by decoupling state-application from proof generation:

1. Sequencer accepts private transactions.
2. Sequencer immediately applies the tree updates locally and registers a non-final update on-chain.
3. Prover works asynchronously.
4. Sequencer confirms the pending on-chain update when proofs arrive.

This preserves eventual ZK finality while removing prover latency from the hot path.

## Current Constraints
Current flow is effectively single-lane and proof-gated:

- Sequencer keeps one global in-flight batch and waits for prover result before advancing.
- Contract only supports proof-verified final root updates (no pending update queue for trees).
- Recovery logic replays finalized root updates only.

Result: throughput is bounded by proof round-trip time.

## Target Model
Adopt a two-phase model per update:

1. Register phase (optimistic / non-final): accepted and visible as pending.
2. Confirm phase (proof-backed): finalized once proof is verified.

The contract must support many pending updates and confirmation over time, similar to pending deposit lifecycle behavior.

## New Contract API Requirement (Transactions)
Add a transaction-atomic API that updates all four trees in one logical batch.

### Tree index constants
```solidity
uint8 constant TREE_NOTES_COMMITMENT   = 0;
uint8 constant TREE_NOTES_NULLIFIER    = 1;
uint8 constant TREE_ACCOUNTS_COMMITMENT = 2;
uint8 constant TREE_ACCOUNTS_NULLIFIER  = 3;
```

### Register all four roots at once
```solidity
function registerTransactionBatchUpdate(
    bytes32 newNotesCommitmentRoot,
    bytes32[] calldata noteCommitmentsOut,
    bytes32 newNotesNullifierRoot,
    bytes32[] calldata noteNullifiersIn,
    bytes32 newAccountsCommitmentRoot,
    bytes32[] calldata accountCommitmentsOut,
    bytes32 newAccountsNullifierRoot,
    bytes32[] calldata accountNullifiersIn,
    bytes32[4] calldata piCommitments // one per tree, index matches TREE_* constants
                                      // each entry = uint32[8] PI digest packed into bytes32
) external onlyOperator returns (uint256 batchId);
```

### Confirm one root at a time
Each root's proof is confirmed in a separate transaction. A batch is fully confirmed once all four trees are confirmed.

```solidity
function confirmTreeUpdate(
    uint256 batchId,
    uint8   treeIndex,  // TREE_* constant
    Proof calldata treeProof,
    Proof calldata inputsProof
) external onlyOperator;
```

`confirmTreeUpdate` reverts with `AlreadyConfirmed()` if `treeIndex` is already set in `confirmedMask`. Emits `TransactionBatchConfirmed` and deletes the pending record only when all four trees are confirmed (`confirmedMask == 0xF`).

### Capacity constant and pre-allocated buffer
```solidity
uint256 public constant MAX_PENDING_BATCHES = X; // compile-time constant
```

`MAX_PENDING_BATCHES` is a **compile-time constant**. Its primary purpose is to pre-allocate a fixed-size storage buffer so that every register and confirm writes into an already-warm slot (2,900 gas) rather than a cold one (20,000 gas). Storage uses a fixed array, not a mapping:

```solidity
PendingBatch[MAX_PENDING_BATCHES] public pendingBatches;
```

The constructor pre-warms all slots by writing a sentinel value to each one, converting all array slots from cold to warm before the first batch is ever registered.

`registerTransactionBatchUpdate` reverts with `PendingQueueFull()` if all `MAX_PENDING_BATCHES` slots are currently occupied (i.e. `_pendingCount == MAX_PENDING_BATCHES`).

### Slot assignment
Slots are addressed by a circular index: `slotIndex = batchId % MAX_PENDING_BATCHES`. Each `PendingBatch` entry stores its own `batchId` field so stale/recycled slots can be distinguished from the current occupant. A slot is free when its `batchId` field is `0` (batchIds are 1-based).

### Stored pending-batch record

```solidity
struct PendingBatch {
    uint256 batchId;          // 0 = free slot; set on register, cleared on full confirmation
    bytes32 newNotesCommitmentRoot;
    bytes32 newNotesNullifierRoot;
    bytes32 newAccountsCommitmentRoot;
    bytes32 newAccountsNullifierRoot;
    bytes32[4] piCommitments; // one per tree, index matches TREE_* constants
                              // each = uint32[8] Keccak-256 PI digest packed into bytes32
                              // = public input[0..7] for the Groth16 verifier of that tree
    uint8 confirmedMask;      // bit i set when tree i confirmed; batch complete at 0xF
}
```

Each `piCommitments[i]` is computed by the sequencer (via `keccak256_field_elements_native`) for the corresponding tree proof and submitted at register time. Each per-root `confirmTreeUpdate` reads `piCommitments[treeIndex]` directly — no leaf data re-submission needed and confirm-call gas is bounded. The bitmask `confirmedMask` tracks partial completion; the slot is freed (batchId reset to 0, `_pendingCount` decremented) only when `confirmedMask` reaches `0xF`.

### Semantics
- `registerTransactionBatchUpdate` is optimistic/non-final, updates all 4 latest roots atomically, writes into the pre-warmed slot at `batchId % MAX_PENDING_BATCHES` (roots + 4 PI commitments + `confirmedMask = 0`), and reverts with `PendingQueueFull()` if `_pendingCount == MAX_PENDING_BATCHES`.
- `confirmTreeUpdate` resolves the slot via `batchId % MAX_PENDING_BATCHES`, verifies `slot.batchId == batchId` (revert `UnknownBatch()` if not), reads `piCommitments[treeIndex]` as the expected Groth16 public inputs, verifies the two proofs, and sets `confirmedMask |= (1 << treeIndex)`. Reverts with `AlreadyConfirmed()` if that bit was already set.
- When `confirmedMask` reaches `0xF` (all four trees confirmed), emit `TransactionBatchConfirmed`, reset `slot.batchId = 0` and `slot.confirmedMask = 0` (freeing the slot back to warm-but-empty), and decrement `_pendingCount`.
- Existing per-tree methods remain for non-transaction paths (e.g. deposit-only flows), but private transaction path uses the new transaction-batch API.

## Design Principles
- Atomic register, incremental confirm: all four roots are registered together; each root's proof is confirmed in a separate transaction.
- Deterministic batch identity (`batchId`) for retry/recovery and prover correlation.
- Pre-allocated fixed buffer: `MAX_PENDING_BATCHES` is a compile-time constant sizing a `PendingBatch[MAX_PENDING_BATCHES]` array. The constructor pre-warms all slots so every register/confirm is a warm `SSTORE` (2,900 gas), never a cold one (20,000 gas). Slots are recycled via `batchId % MAX_PENDING_BATCHES`.
- Bounded pending queue: contract enforces at most `MAX_PENDING_BATCHES` live batches at any time; `register` reverts when full.
- Self-contained batch records: each pending entry stores roots + 4 PI commitments so each per-root confirm requires no leaf data re-submission.
- Clear root semantics:
  - `latest` root: includes registered (pending) updates.
  - `confirmed` root: includes only proof-confirmed updates.
- Recovery must reconstruct both registered and confirmed states.

## Implementation Plan

### Phase 1: Contract State Model and Events
Extend contract state to track pending tree updates and transaction batches.

- Add `uint256 public constant MAX_PENDING_BATCHES` (compile-time constant).
- Add `PendingBatch[MAX_PENDING_BATCHES] public pendingBatches` (fixed-size pre-allocated array).
- Add `uint256 private _pendingCount` to track current occupancy.
- In the constructor, pre-warm all slots by writing a sentinel (e.g. `confirmedMask = 0xFF`) then clearing it, ensuring every slot is warm before first use.
- Track `latest` and `confirmed` roots per tree.
- Add events:
  - `TransactionBatchRegistered(batchId, newNotesCommitmentRoot, newNotesNullifierRoot, newAccountsCommitmentRoot, newAccountsNullifierRoot, piCommitments[4])`
  - `TreeUpdateConfirmed(batchId, treeIndex)`
  - `TransactionBatchConfirmed(batchId)` — emitted once all four trees are confirmed.
  - Keep existing finalized event for compatibility/indexing where useful.

Validation in register phase:
- Revert `PendingQueueFull()` if `_pendingCount == MAX_PENDING_BATCHES`.
- Compute `slotIndex = batchId % MAX_PENDING_BATCHES`; revert `SlotConflict()` if `pendingBatches[slotIndex].batchId != 0` (should never happen if count check passes, but defensive).
- Batch length checks (`0 < len <= batchSize`).
- Tree continuity checks against current `latest` roots.
- Deposit-state checks needed for notes commitment side-effects.
- Write roots, `piCommitments[4]`, `batchId`, `confirmedMask = 0` into the pre-warmed slot; increment `_pendingCount`.

Validation in `confirmTreeUpdate` phase:
- Compute `slotIndex = batchId % MAX_PENDING_BATCHES`.
- Revert `UnknownBatch()` if `pendingBatches[slotIndex].batchId != batchId`.
- Revert `InvalidTreeIndex()` if `treeIndex > 3`.
- Revert `AlreadyConfirmed()` if bit `treeIndex` already set in `confirmedMask`.
- Use `piCommitments[treeIndex]` as the expected Groth16 public inputs for the two proof verifications.
- Set `confirmedMask |= (1 << treeIndex)` and emit `TreeUpdateConfirmed(batchId, treeIndex)`.
- If `confirmedMask == 0xF`: emit `TransactionBatchConfirmed(batchId)`, reset `slot.batchId = 0` and `slot.confirmedMask = 0` (slot returns to warm-empty state), decrement `_pendingCount`.

### Phase 2: Contract Safety for Pending Notes
Prevent withdrawal/state races while notes are registered but unconfirmed.

Options:
- Add an intermediate deposit status, or
- Add explicit lock map tied to `batchId`.

Requirement:
- `withdrawPendingDeposit` must reject notes currently staged in an unconfirmed tx batch.

### Phase 3: Sequencer Concurrency Refactor
Replace global single in-flight batch with multi-batch optimistic lanes.

- Introduce `TxBatch` (contains all 4 leaf sets, computed `piCommitments[4]`, and metadata).
- On private-tx ingestion:
  - verify tx proof,
  - apply tree updates locally immediately,
  - compute `piCommitments[i]` via `keccak256_field_elements_native` for each of the 4 tree proofs,
  - call `registerTransactionBatchUpdate(..., piCommitments)`,
  - enqueue 4 independent async proving jobs keyed by `(batchId, treeIndex)`.
- Block ingestion (return `PendingQueueFull` to client) when on-chain queue is at `MAX_PENDING_BATCHES`.
- Sequencer must continue accepting/registering new tx batches while earlier batches are still proving.

### Phase 4: Prover Interface and Correlation
Update prover request/response protocol to support async correlation and bundle semantics.

- Extend request with `batchId`, `treeIndex`, and per-tree payload.
- Each proof job produces one tree proof + one inputs proof for a single tree.
- Return responses that can arrive out-of-order; sequencer matches by `(batchId, treeIndex)`.

### Phase 5: Confirmation Pipeline
When a proof for `(batchId, treeIndex)` arrives:

- Call `confirmTreeUpdate(batchId, treeIndex, treeProof, inputsProof)`.
- On success: mark `(batchId, treeIndex)` confirmed locally; if all 4 confirmed, mark batch done.
- On failure/timeout: retry with backoff for that `(batchId, treeIndex)` pair independently.

Policy:
- Each tree confirm is independently retryable.
- A batch is fully finalized only when `confirmTreeUpdate` has succeeded for all four `treeIndex` values.

### Phase 6: Persistence and Recovery
Upgrade durable state and replay logic.

- Persist pending transaction batches (registered but unconfirmed).
- Persist proof-attempt status and retry counters.
- On startup:
  - reconcile on-chain registered/confirmed events,
  - rebuild local latest/confirmed cursor,
  - requeue unresolved pending batches for proving/confirm.

Recovery must handle:
- sequencer crash after register but before any proving job is enqueued,
- crash after a tree proof is generated but before `confirmTreeUpdate` is submitted,
- crash after `confirmTreeUpdate` submitted but before receipt (re-check `confirmedMask` on-chain to avoid duplicate call → `AlreadyConfirmed` revert),
- partial batch state: some trees confirmed on-chain, others not yet (resume from on-chain `confirmedMask`).

### Phase 7: Compatibility and Incremental Rollout
Keep existing per-tree APIs operational while introducing transaction-batch path.

- Feature flag new path in sequencer.
- Shadow-mode metrics first (without switching traffic).
- Then route private tx endpoint to transaction-batch path.

## Data and API Changes (Server)

### Current architecture (baseline)

The sequencer maintains four independent in-memory pending pools (one per tree) plus four `Option<InFlightBatch>` fields — one batch in flight per tree at a time. The flow is sequential: pool fills → prove → finalize on-chain → apply locally. There is no concept of a shared batch ID across trees, no optimistic register step, and no partial-confirmation state. `ProveRequest` and `ProveOutcome` carry no correlation key.

Contract bindings (`contract.rs`) expose four independent `record*TreeUpdate` functions, each finalizing a single tree atomically after proof. Recovery (`sequencer/recovery.rs`) replays `ValidatedBatchFinalized` events, one tree at a time.

### `types.rs` — Small, surgical

Current `ProveRequest` and `ProveOutcome` variants carry no correlation key. Changes:

- Add `batch_id: u64` and `tree_index: u8` to both `ProveRequest` variants, or unify into a single `ProveRequest::TreeUpdate { batch_id, tree_index, batch_proof, associated_input_proofs }`.
- Add `batch_id: u64` and `tree_index: u8` to `ProveOutcome::Success` so the sequencer routes incoming results to the correct pending confirm without a side-channel lookup.
- `SolidityProof` and `ProveOutcome::Failure` are unchanged.

### `prover.rs` / `prover_client.rs` — Trivial

The prover service stays a **stateless per-request service**. Changes:

- `ProverRuntime::prove()`: use `tree_index` to select the circuit (`{0,2}` → `commitment_prover`; `{1,3}` → `nullifier_prover`) instead of pattern-matching the enum variant. Thread `batch_id`/`tree_index` through to the returned `ProveOutcome`.
- `HttpProverClient::prove()`: transparent pass-through; no logic change.
- No proof generation, circuit, or artifact changes.

### `contract.rs` — Medium

**Remove** (for the private-tx path): `recordNotesCommitmentTreeUpdate`, `recordNotesNullifierTreeUpdate`, `recordAccountsCommitmentTreeUpdate`, `recordAccountsNullifierTreeUpdate`, and the `ValidatedBatchFinalized` event.

**Add:**
```rust
// register — optimistic, returns batchId
function registerTransactionBatchUpdate(..., bytes32[4] piCommitments) -> uint256 batchId;

// confirm — per-tree, proof-backed
function confirmTreeUpdate(uint256 batchId, uint8 treeIndex, Proof treeProof, Proof inputsProof);

// events
event TransactionBatchRegistered(uint256 indexed batchId, ...);
event TreeUpdateConfirmed(uint256 indexed batchId, uint8 treeIndex);
event TransactionBatchConfirmed(uint256 indexed batchId);
```

**Update root accessors:** The contract exposes `latestNotesCommitmentRoot` and `confirmedNotesCommitmentRoot` per tree. The sequencer uses `latest*Root` for preflight continuity checks at register time, and `confirmed*Root` for startup reconciliation.

### `sequencer/mod.rs` — Large structural rework

Current state: four `Option<InFlightBatch>` fields (one per tree); sequencer blocks on one batch per tree.

**Replace with:**
```rust
registered_pending_batches: BTreeMap<u64, TxBatch>,     // batch_id → batch
proving_jobs: HashMap<(u64, u8), ProveJobState>,         // (batch_id, tree_index) → state
confirm_retry_queue: VecDeque<(u64, u8)>,                // pending confirm retries
next_batch_id: u64,                                      // local counter; reconciled with chain on recovery
```

**New `TxBatch` struct** (replaces `InFlightBatch` for the private-tx path):
```rust
struct TxBatch {
    batch_id: u64,
    pi_commitments: [[u32; 8]; 4],      // one per tree; submitted at register time
    per_tree: [InFlightBatch; 4],        // indexed by tree_index
    local_confirmed_mask: u8,            // mirrors on-chain confirmedMask
}
```

`InFlightBatch` keeps its existing payload (job leaf data, real/padded commitments) but drops the `TreeJob` enum — tree identity is carried by position in `per_tree`.

### `sequencer/pipeline.rs` — Large, new flows

**Remove:** the four `maybe_finalize_*` branches that call `record*TreeUpdate`. The prove-then-finalize flow is replaced entirely for private-tx.

**New flow — on private-tx ingestion:**
1. Check `registered_pending_batches.len() == MAX_PENDING_BATCHES`; if so return `PendingQueueFull` immediately.
2. Verify the transaction proof.
3. Apply local tree updates for all 4 trees immediately.
4. Compute `pi_commitments[i]` via `keccak256_field_elements_native` for each tree's new public inputs.
5. Call `registerTransactionBatchUpdate(...)` on-chain → receive `batch_id`.
6. On revert: roll back local tree updates (reinsert leaves into pending pools via existing `reinsert_batch()`).
7. On success: store `TxBatch` in `registered_pending_batches`; enqueue 4 independent `ProveRequest::TreeUpdate { batch_id, tree_index, ... }` jobs via `submit_prove_request_with_retry`.

**New flow — on `ProveOutcome::TreeUpdateSuccess { batch_id, tree_index, ... }` arrival:**
1. Look up `registered_pending_batches[batch_id]`.
2. Call `confirmTreeUpdate(batch_id, tree_index, tree_proof, inputs_proof)` on-chain.
3. On success: `batch.local_confirmed_mask |= (1 << tree_index)`.
4. If `local_confirmed_mask == 0xF`: remove batch from `registered_pending_batches`.
5. On failure/timeout: push `(batch_id, tree_index)` to `confirm_retry_queue`; retry with backoff independently of other trees in the same batch.

**Key difference from today:** local tree state is applied before the register call. If `registerTransactionBatchUpdate` reverts, `reinsert_batch()` is called for all 4 trees to restore pending state.

### `sequencer/api.rs` — Small

- `/private-tx` handler: trigger the new atomic register flow instead of pushing to 4 separate per-tree channels.
- Return `HTTP 429` (or a structured error) with `PendingQueueFull` when the queue is saturated.
- All existing per-tree endpoints (`/notes/commitment`, `/notes/nullifier`, `/accounts/commitment`, `/accounts/nullifier`) remain unchanged for the deposit-only path.

### `sequencer/recovery.rs` — Significant rework

Current recovery scans `ValidatedBatchFinalized` events and replays per-tree.

**New startup reconciliation:**
1. Scan `TransactionBatchRegistered` events → rebuild `registered_pending_batches` with stored roots and `pi_commitments`.
2. Scan `TreeUpdateConfirmed` events → reconstruct `local_confirmed_mask` per batch.
3. For each batch with `local_confirmed_mask < 0xF`: requeue unconfirmed `(batch_id, tree_index)` pairs:
   - If proof was generated locally (persisted): re-submit `confirmTreeUpdate` directly.
   - If proof not available: re-enqueue `ProveRequest::TreeUpdate` for that tree.
4. Before re-submitting a confirm: read on-chain `confirmedMask` (via `pendingBatches[slotIndex].confirmedMask`) to detect the already-confirmed case and avoid the `AlreadyConfirmed()` revert.

**Crash scenarios handled:**
- Crash after register but before any prove job enqueued → requeue all 4 prove jobs.
- Crash after proof generated but before `confirmTreeUpdate` submitted → re-submit confirm.
- Crash after confirm submitted but before receipt → read on-chain mask; skip if already set.
- Partial `confirmed_mask` (some trees confirmed, others not) → resume from on-chain mask.

## Testing Plan

### Solidity tests
- Verify all slots are pre-warmed at construction (no cold SSTORE on first register).
- Register up to `MAX_PENDING_BATCHES` batches without confirmation; verify `_pendingCount` increments and each occupies the correct `batchId % MAX_PENDING_BATCHES` slot.
- Verify `PendingQueueFull()` revert on the `MAX_PENDING_BATCHES + 1`th register call.
- Confirm all 4 trees across separate blocks; verify `TreeUpdateConfirmed` on each and `TransactionBatchConfirmed` + slot freed (batchId reset to 0) only at the 4th.
- Verify `_pendingCount` decrements only after all 4 trees confirmed, not on partial confirmation.
- Verify slot is reusable after full confirmation: a new batch with `batchId = oldBatchId + MAX_PENDING_BATCHES` writes into the same slot index.
- Verify `UnknownBatch()` revert if `slot.batchId` doesn't match (stale slot access).
- Verify `AlreadyConfirmed()` revert on duplicate `confirmTreeUpdate` for the same `(batchId, treeIndex)`.
- Verify each `confirmTreeUpdate` reads `piCommitments[treeIndex]` and rejects a proof with a wrong commitment for that slot.
- Verify out-of-order per-tree confirmation works correctly (e.g. confirm trees 3, 1, 0, 2).
- Ensure withdraw lock behavior for staged notes.

### Sequencer tests
- Continues registering new `TxBatch`es while earlier batches are still proving.
- Out-of-order `ProveOutcome::TreeUpdateSuccess` completions routed correctly by `(batch_id, tree_index)`.
- Partial batch confirmation (some trees done, others pending) does not remove the batch from `registered_pending_batches`.
- `registerTransactionBatchUpdate` revert triggers `reinsert_batch()` for all 4 trees, restoring pending state.
- Independent retry per `(batch_id, tree_index)` without re-proving other trees in the same batch.
- `PendingQueueFull` returned to `/private-tx` API caller when `registered_pending_batches.len() == MAX_PENDING_BATCHES`.

### Recovery tests
- Crash after register but before any prove job enqueued → all 4 prove jobs re-enqueued on restart.
- Crash after proof generated but before `confirmTreeUpdate` submitted → confirm re-submitted from persisted proof.
- Crash after `confirmTreeUpdate` submitted but before receipt → on-chain mask read; duplicate call avoided.
- Partial `confirmed_mask` on-chain (e.g. trees 0 and 2 confirmed, 1 and 3 not) → only the unconfirmed trees re-queued.
- Idempotent replay: already-confirmed `(batch_id, tree_index)` pairs skipped without error.

### End-to-end tests
- Extend scripted integration to include multi-batch optimistic register + delayed confirmation path.

## Open Decisions
1. Confirmation ordering policy:
   - strictly in-order confirms vs out-of-order allowed.
2. Public consumer root target:
   - whether clients consume `latest` or `confirmed` roots for specific operations.
3. Unprovable pending batch handling:
   - cancel/revert mechanism vs operator pause/manual intervention.

## Suggested Delivery Slices
1. **Contract** — `PendingBatch` storage, `MAX_PENDING_BATCHES` buffer, `registerTransactionBatchUpdate`, `confirmTreeUpdate`, events. No sequencer changes yet.
2. **`types.rs` + `prover.rs`** — Add `batch_id`/`tree_index` to `ProveRequest`/`ProveOutcome`; route by `tree_index` in `ProverRuntime`. Trivial, unblocks everything downstream.
3. **`contract.rs`** — New ABI bindings for register/confirm/events; updated root accessors.
4. **Sequencer register path** (`sequencer/mod.rs` + `pipeline.rs`) — `TxBatch`, new state maps, optimistic register + local tree apply, `reinsert_batch` on revert. Feature-flagged.
5. **Sequencer confirm pipeline** (`pipeline.rs`) — `ProveOutcome::TreeUpdateSuccess` handler, `confirmTreeUpdate` call, per-`(batch_id, tree_index)` retry.
6. **`sequencer/recovery.rs`** — Replay `TransactionBatchRegistered`/`TreeUpdateConfirmed` events; reconstruct `confirmed_mask`; requeue unfinished jobs.
7. **Full integration switch** — Route `/private-tx` to new path; remove old `record*TreeUpdate` call sites; e2e test pass.
