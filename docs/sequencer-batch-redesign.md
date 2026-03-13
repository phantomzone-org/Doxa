# Sequencer Batch Assembly Redesign

## Problem

The current sequencer manages four independent pending queues (NC, NN, AC, AN)
that are popped and padded separately at batch time.  This causes **ordering
mismatches**: the AC tree leaf at position `i` may not correspond to the TX
proof at slot `i`, because:

1. Deposits add NC leaves without corresponding AC/AN/NN leaves, skewing the
   NC queue relative to the others.
2. `real_account_slots` is derived from unsorted AN positions, but the prover
   builds TX proofs in slot order — any desynchronisation between queues makes
   the positional SA cross-checks (AC, NC) fail.
3. Sorting AN/NN happens after batch assembly, further decoupling slot indices
   from the trees that need positional alignment.

## Design Principles

| Principle | Rationale |
|---|---|
| **Slot-centric batch** | The batch is an array of `account_batch_size` **slots**. Each slot is either a *private TX* or a *deposit/empty*. All four trees derive their leaves from these slots. |
| **Deposit mini-batching** | Deposits pack up to 8 real NC notes into a single slot. A new deposit either fills the next NC position in the current open deposit slot, or allocates a new slot if the current one is full (or doesn't exist). AC, AN, NN are fully dummy-padded when the slot is first created. NC dummy padding is deferred to `finalize()` (fills remaining `nc[filled..8]` positions). |
| **Single source of truth** | For real TX slots, all four tree leaves (AC, AN, NC, NN) are extracted **from the TX proof PIs**. For deposit/empty slots, leaves are deterministic **dummy padding** (except the deposit's 1 real NC note). The sequencer never separately tracks `output_account_leaf` / `output_notes` — leaf values come from either the proof or the padding, never from client-submitted metadata. |
| **Prover receives final data** | The `ProveRequest` carries fully-ordered leaf arrays and slot-indexed TX proofs. The prover does **no** sorting, no slot detection, no reordering. |

## Progress

| # | Task | Status |
|---|---|--------|
| 1 | Update dummy-leaf derivation to `H(leaf_index \|\| current_root)` | [x] |
| 2 | Define `BatchSlot` enum and `BatchBuilder` struct | [x] |
| 3 | Rewrite deposit handler to allocate a slot immediately | [x] |
| 4 | Rewrite private-TX handler to allocate a slot immediately | [x] |
| 5 | Replace `start_batch` with `BatchBuilder::finalize` | [x] |
| 6 | Simplify prover: remove sorting / slot-detection logic | [x] |
| 7 | Update `ProveRequest` to remove `real_account_slots` indirection | [x] |
| 8 | Update integration test (`real_proof_pipeline`) to match | [x] |
| 9 | Run full SA + pipeline tests | [x] |

---

## Step 1 — Update dummy-leaf derivation (prerequisite)

The current `pad_leaves` in `tessera-server/src/dummy.rs` derives the dummy
seed as `H(tree_type || batch_start_index || ALL_real_leaves)`.  This requires
knowing **all** real leaves upfront, which is incompatible with immediate
per-slot padding.

**Replace with:** `field_safe_keccak256(leaf_index || current_root)`.

This derivation only needs the tree's current root (available at any time) and
the absolute leaf index, so dummies can be computed **immediately** when a
deposit or empty slot is allocated — no need to wait for the full batch.

The Solidity contract does **not** need updating: it receives the full leaf
arrays as calldata, verifies sort order, and computes the super PI commitment
— it never re-derives dummy leaves.

---

## Step 2 — `BatchSlot` and `BatchBuilder`

### New types (in `tessera-server/src/sequencer/batch.rs`)

```rust
/// One account-level slot in a batch.
pub enum BatchSlot {
    /// Real private TX: all four trees have real leaves.
    PrivateTx {
        /// Client-supplied PrivTx proof bytes (is_real = 1).
        tx_proof: Vec<u8>,
        /// AC leaf: extracted from tx_proof PI[7..11].
        ac: [u8; 32],
        /// AN leaf: extracted from tx_proof PI[3..7].
        an: [u8; 32],
        /// NC leaves (8): extracted from tx_proof PI[43..75].
        nc: [[u8; 32]; 8],
        /// NN leaves (8): extracted from tx_proof PI[11..43].
        nn: [[u8; 32]; 8],
    },
    /// Deposit mini-batch: up to 8 real NC notes packed into one slot.
    /// AC, AN, NN are fully dummy-padded at slot creation time.
    /// NC positions `0..nc_filled` are real deposit notes; the rest are
    /// filled with dummies at `finalize()` time.
    Deposit {
        /// AC leaf: dummy (materialized at slot creation).
        ac: [u8; 32],
        /// AN leaf: dummy (materialized at slot creation).
        an: [u8; 32],
        /// NC leaves (8): nc[0..nc_filled] = real deposit notes,
        /// nc[nc_filled..8] = filled with dummies at finalize().
        nc: [[u8; 32]; 8],
        /// How many NC positions are filled with real deposit notes.
        nc_filled: usize,
        /// NN leaves (8): all dummies (materialized at slot creation).
        nn: [[u8; 32]; 8],
    },
    /// Empty: all four trees padded with deterministic dummies.
    /// All leaves are materialized at `add_empty()` / `finalize()` time.
    Empty {
        ac: [u8; 32],
        an: [u8; 32],
        nc: [[u8; 32]; 8],
        nn: [[u8; 32]; 8],
    },
}

/// Incrementally builds a batch of `account_batch_size` slots.
///
/// Tree batch sizes:
///   - AC, AN: `account_batch_size` leaves (1 per slot).
///   - NC, NN: `note_batch_size = account_batch_size × NOTES_PER_SLOT` leaves (8 per slot).
pub struct BatchBuilder {
    slots: Vec<BatchSlot>,
    account_batch_size: usize,
    note_batch_size: usize, // == account_batch_size * NOTES_PER_SLOT
    /// Index of the current open deposit mini-batch slot (`nc_filled < 8`).
    /// `None` when no open deposit slot exists.
    open_deposit: Option<usize>,
}
```

### Invariant

`slots.len() <= account_batch_size` at all times.  The batch is "full" when
`slots.len() == account_batch_size`.

Each slot contributes exactly:
- **1** AC leaf + **1** AN leaf (→ `account_batch_size` total each)
- **8** NC leaves + **8** NN leaves (→ `note_batch_size` total each)

### `BatchBuilder::finalize`

When called (batch full or timer expires):

1. **Finalize open deposit slots**: for any `Deposit` with `nc_filled < 8`,
   fill `nc[nc_filled..8]` with dummy leaves (current NC root + leaf indices).
2. **Pad remaining slots** with fully materialized `BatchSlot::Empty { ac, an, nc, nn }`
   up to `account_batch_size` (dummy leaves computed from current tree roots + leaf indices).
3. **Build leaf arrays** uniformly from slot data (all variants carry `ac`, `an`, `nc`, `nn`):
   - `ac_leaves[s]` (len = `account_batch_size`) = `slots[s].ac`.
   - `an_leaves_unsorted[s]` (len = `account_batch_size`) = `slots[s].an`.
   - `nc_leaves[s*8 + j]` (len = `note_batch_size`) = `slots[s].nc[j]`.
   - `nn_leaves_unsorted[s*8 + j]` (len = `note_batch_size`) = `slots[s].nn[j]`.
4. **Sort AN and NN** (as `[u64; 4]` big-endian, matching `HashOutput::Ord`).
   The sequencer owns sorting because it performs the optimistic on-chain
   update — the contract receives already-sorted nullifier leaves.
5. **Assert sorting** of `an_sorted` and `nn_sorted` before submitting to the
   contract (defensive check at sequencer exit point).
6. **Build tree native proofs** from the leaf arrays (commitment trees use
   unsorted AC/NC; nullifier trees use sorted AN/NN).
7. **Determine `real_account_slots`** trivially: indices where slot is `PrivateTx`.
8. Assemble and return a `ProveRequest` containing the 4 tree native proofs,
   the padded leaf arrays, `real_account_slots`, and `tx_proofs_by_slot`
   (only real PrivateTx proof bytes, keyed by slot index).

The **prover**, on receiving a `ProveRequest`:
1. **Re-asserts sorting** of `an_sorted_leaves` and `nn_sorted_leaves` before
   starting any proof (fail-fast if the sequencer produced bad data).
2. Generates dummy PrivTx proofs for Deposit/Empty slots, extracting
   override values directly from the padded leaf arrays:
   - `override_ac` = `ac_leaves[s]`
   - `override_an` = `an_sorted[s]`
   - `override_nc[j]` = `nc_leaves[s*8 + j]`
   - `override_nn[j]` = `nn_sorted[s*8 + j]`

This ensures dummy TX proof PIs exactly match the tree leaves the SA will
verify against.

### Dummy-leaf derivation

Dummy leaves are derived as:

```
dummy_leaf = field_safe_keccak256(leaf_index || current_root)
```

where `current_root` is the **current root of the corresponding tree** at
batch-assembly time, and `leaf_index` is the absolute leaf index in that tree
(i.e. `batch_start_index + slot_offset`).  `field_safe_keccak256` clears the
MSB of each 8-byte limb so the result is a valid Goldilocks field element.

This replaces the current `pad_leaves` logic in `tessera-server/src/dummy.rs`
which uses `H(leaf_index || H(tree_type || batch_start_index || real_leaves))`.
The new scheme is simpler, requires no knowledge of other real leaves, and
produces unique padding per tree state.

**Important:** for Deposit/Empty slots, the dummy AN/NN values go into the
unsorted arrays *before* sorting.  The sorted arrays are what the nullifier
trees see.  The dummy TX proofs' AN/NN overrides must come from the **sorted**
arrays at their final positions — same as today.

---

## Step 3 — Deposit handler

Current: pushes 1 NC leaf to `notes_commitment_state.pending_requests`.

New: calls `batch_builder.add_deposit(nc_note)`.  The `BatchBuilder`:
1. Checks if the last slot is a `Deposit` with `nc_filled < 8`.
2. **Yes** → appends `nc_note` at `nc[nc_filled]`, increments `nc_filled`.
3. **No** → allocates a new `Deposit` slot with AC, AN, NN fully dummy-padded
   (using current tree roots + leaf indices), sets `nc[0] = nc_note`,
   `nc_filled = 1`.

Remaining NC positions (`nc[nc_filled..8]`) are filled with dummies at
`finalize()` time.  No separate pending queue for deposits.

---

## Step 4 — Private TX handler

Current: pushes to 4 separate queues (NC ×8, NN ×8, AC ×1, AN ×1) with
independent `order_key` values.  Stores `tx_proofs_by_an_leaf`.

New: validates the TX, then calls `batch_builder.add_private_tx(tx_proof_bytes)`.
The `BatchBuilder`:
1. Deserializes the proof to extract PI values (AC, AN, NC×8, NN×8).
2. Validates AN is not already nullified (duplicate check).
3. Records a `PrivateTx { ... }` slot with all leaf values **extracted from the proof PIs**.

This eliminates the mismatch risk: tree leaves come from the same proof the SA
will verify.

---

## Step 5 — Replace `start_batch` with `BatchBuilder::finalize`

The current `start_batch` in `pipeline.rs`:
- Pops from 4 queues
- Pads each independently
- Sorts NN/AN
- Derives `real_account_slots` by scanning unsorted AN for known real leaves
- Builds `ProveRequest`

New `finalize`:
- Iterates `slots[0..account_batch_size]`
- Builds leaf arrays directly from slot data
- Sorts AN/NN
- `real_account_slots` = indices where slot is `PrivateTx` (trivial)
- `tx_proofs_by_slot` = slot index → proof bytes for PrivateTx slots

The `pending_requests` / `pending_commitments` / `BTreeMap` machinery in
`TreeState` is no longer needed for batch assembly — it's replaced by the
slot array.  The actual tree state (roots, WAL) still lives in `TreeState`.

---

## Step 6 — Simplify prover

The prover's `build_and_aggregate_tx_proofs` currently:
- Iterates slots, checks `real_account_slots.contains(&s)`
- For real: uses client proof
- For dummy: generates dummy proof with AN/NN overrides from sorted leaves
- Pads to aggregation tree leaf count

With the new design, the prover receives padded leaf arrays and
`real_account_slots` + `tx_proofs_by_slot` from the sequencer.  On entry:

1. **Assert sorting** of `an_sorted_leaves` and `nn_sorted_leaves` (fail-fast
   before any expensive proving if the sequencer produced bad data).
2. Generate dummy PrivTx proofs for non-real slots, extracting overrides
   directly from the padded leaf arrays:

```
For each slot s not in real_account_slots:
  override_ac = ac_leaves[s]
  override_an = an_sorted[s]
  override_nc[j] = nc_leaves[s*8 + j]  for j in 0..8
  override_nn[j] = nn_sorted[s*8 + j]  for j in 0..8
  → prove_dummy_priv_tx(seed=s, override_ac, override_an, override_nc, override_nn)
```

The prover no longer sorts, derives padding, or detects slot assignments —
it trusts the sequencer's pre-built arrays (after asserting sort order).

---

## Step 7 — Update `ProveRequest`

```rust
pub struct ProveRequest {
    pub batch_id: u64,
    // ── Tree native proofs ──
    pub notes_commitment_proof: BatchCommitmentProof<HashOutput>,
    pub notes_nullifier_proof: BatchInsertProof<HashOutput>,
    pub accounts_commitment_proof: BatchCommitmentProof<HashOutput>,
    pub accounts_nullifier_proof: BatchInsertProof<HashOutput>,
    // ── Padded leaf arrays (single source of truth for dummy TX overrides) ──
    pub nc_leaves: Vec<[u8; 32]>,        // len == note_batch_size (= account_batch_size × 8), arrival order
    pub nn_sorted_leaves: Vec<[u8; 32]>, // len == note_batch_size, sorted
    pub ac_leaves: Vec<[u8; 32]>,        // len == account_batch_size, arrival order
    pub an_sorted_leaves: Vec<[u8; 32]>, // len == account_batch_size, sorted
    // ── TX slot info ──
    pub real_account_slots: Vec<usize>,              // indices with is_real=1
    pub tx_proofs_by_slot: HashMap<usize, Vec<u8>>,  // real slots only
}
```

The leaf arrays are the **single source of truth** for both tree proofs and
dummy TX override values.  The prover uses them to generate dummy proofs
whose PIs exactly match the tree leaves.

---

## Step 8 — Update integration test

`real_proof_pipeline.rs` already follows the correct pattern (extract leaves
from TX PIs, sort AN/NN, keep NC/AC in arrival order).  Minor updates:
- Use `BatchSlot` types if the test exercises the new batch builder.
- Otherwise, the existing `run_mixed_pipeline` already matches the new design's
  data flow and just needs comments updated.

---

## Step 9 — Run tests

```bash
cargo test -p tessera-trees --release -- proof_aggregation::super_aggregator
cargo test -p tessera-server --release --test real_proof_pipeline
```

---

## Appendix: Dummy-leaf derivation specification

### Rust side (`tessera-server/src/dummy.rs`)

Replace the current derivation:

```
H(leaf_index || H(tree_type || batch_start_index || packed_real_leaves))
```

with:

```
field_safe_keccak256(leaf_index || current_root)
```

- `leaf_index`: absolute index in the tree (`batch_start_index + slot_offset`),
  encoded as `uint256` big-endian (32 bytes).
- `current_root`: the tree's root hash at batch-assembly time, encoded as
  `bytes32` (4 × `uint64` big-endian limbs = 32 bytes).
- `field_safe_keccak256`: `keccak256` followed by clearing bit 63 of each
  8-byte limb (ensures each limb < 2^63 < Goldilocks prime).

This is simpler (no need to hash all real leaves into a seed), deterministic
given the tree state, and produces unique values per position.

The Solidity contract does not re-derive dummy leaves — it receives full leaf
arrays, verifies nullifier sort order, and computes the super PI commitment.
No contract change is needed.

---

## Files to modify

| File | Change |
|---|---|
| `tessera-server/src/sequencer/batch.rs` | **New.** `BatchSlot`, `BatchBuilder`, `finalize`. |
| `tessera-server/src/sequencer/mod.rs` | Replace 4 pending queues with `BatchBuilder`. Rewrite deposit + private-TX handlers. |
| `tessera-server/src/sequencer/pipeline.rs` | Replace `start_batch` with `batch_builder.finalize()`. |
| `tessera-server/src/types.rs` | Simplify `ProveRequest` (remove sorted leaves, slot map). |
| `tessera-server/src/prover.rs` | Remove `build_and_aggregate_tx_proofs` slot-detection logic; just aggregate `tx_proof_bytes` in order. |
| `tessera-server/src/dummy.rs` | Replace `pad_leaves` derivation with `H(leaf_index \|\| current_root)`. |
| `tessera-server/tests/real_proof_pipeline.rs` | Minor comment updates. |

## Non-goals

- Changing the SA circuit or its cross-check gadgets.
- Changing the tree circuits or the aggregator.
- Changing the client binary.
- Changing the `field_safe` masking strategy (MSB-clear per 8-byte limb).
