# Batch Nullifier Insertion — Fix Plan

Addresses all issues from `docs/batch_insertion_soundness_review.md`.

## Progress Tracker

| # | Task | Status |
|---|------|--------|
| 1 | Restructure proof generation: sequential predecessor updates | TODO |
| 2 | Remove `pred_old_siblings` for chained leaves (mask=false) | TODO |
| 3 | Implement Phase A verification (`old_root -> mid_root`) | TODO |
| 4 | Implement Phase B verification (`mid_root -> new_root`) | TODO |
| 5 | Wire emptiness check against `mid_root` | TODO |
| 6 | Clean up: duplicate constraint, unused fields, debug prints | TODO |
| 7 | Add adversarial tests | TODO |

---

## Step 1 — Restructure proof generation: sequential predecessor updates

**File**: `native.rs`, `insert_batch`

**Problem**: `pred_old_siblings[i]` are all captured against `old_root` (before any mutation). They cannot verify the `old_root -> mid_root` transition because each predecessor update invalidates siblings for subsequent predecessors.

**Key insight**: if we capture siblings and apply the tree update one predecessor at a time, each sibling set is valid against the running root. The same siblings serve for both authentication AND the update transition — no separate auth pass needed.

**Change**: replace the current two-phase pattern (capture all siblings, then batch-update tree) with a sequential loop:

```rust
// BEFORE (current):
for i in 0..batch_size {
    // ... compute pred_new_next ...
    if mask[i] { self.nodes[pred_paths[i]] = ...; }
    let siblings = self.tree.merkle_path(pred_paths[i], 0, depth)?;  // all against old_root
    pred_old_siblings.push(siblings);
}
// then batch-update tree leaves + update_sparse_paths

// AFTER:
for i in 0..batch_size {
    // ... compute pred_new_next ...
    if mask[i] {
        // 1. Capture siblings against the CURRENT running root
        let siblings = self.tree.merkle_path(pred_paths[i], 0, depth)?;
        pred_old_siblings.push(siblings);

        // 2. Apply single-leaf update immediately
        self.nodes[pred_paths[i]] = Node::new(
            pred_values[i],
            pred_new_next_indexes[i],
            pred_new_next_values[i],
        );
        self.tree.update_leaf(pred_paths[i], self.nodes[pred_paths[i]].compute_hash())?;
    }
}
// tree is now at mid_root — no update_sparse_paths needed
```

**Data change**: `pred_old_siblings` shrinks from `batch_size` entries to `K` entries (one per masked predecessor). The `i`-th entry is against the root after `i-1` previous masked updates.

---

## Step 2 — Remove `pred_old_siblings` for chained leaves

**File**: `native.rs`, `BatchInsertProof` struct + `insert_batch` + `verify`

Follows directly from step 1. Chained leaves (mask=false) no longer need siblings at all — the chain constraints bind them to their chain leader's authenticated predecessor.

**Struct change**: `pred_old_siblings: Vec<Vec<H::Digest>>` keeps the same type but now has `K` entries instead of `N`. The verifier iterates over masked predecessors only.

To keep the mapping clear, add a helper vec or change the iteration pattern. Two options:

**Option A** — Flat vec of `K` sibling paths, iterated with a mask-aware counter:
```rust
let mut sibling_cursor = 0;
for i in 0..batch_size {
    if mask[i] {
        // use pred_old_siblings[sibling_cursor]
        sibling_cursor += 1;
    }
}
```

**Option B** — Keep `N`-length vec but fill chained entries with empty vecs (wastes a bit of space, simpler indexing). Not recommended for the circuit.

**Recommendation**: Option A for both native and future circuit.

---

## Step 3 — Implement Phase A verification (`old_root -> mid_root`)

**File**: `native.rs`, `BatchInsertProof::verify`

Replace the current loop at lines 377-393 (which authenticates all predecessors against `old_root`) with a sequential root-transition loop:

```rust
let mut running_root = old_root;
let mut sibling_cursor = 0;

for i in 0..batch_size {
    if !mask[i] {
        continue;  // chained — no siblings, no root transition
    }

    let siblings = &self.pred_old_siblings[sibling_cursor];
    sibling_cursor += 1;

    // 1. Authenticate old predecessor against running_root
    let old_pred_hash = H::commit_node(
        &self.pred_values[i],
        self.pred_old_next_indexes[i],
        &self.pred_old_next_values[i],
    );
    if Self::compute_root(&old_pred_hash, siblings, self.pred_paths[i], self.start_index)
        != running_root
    {
        return false;
    }

    // 2. Compute updated predecessor hash and derive next root
    let new_pred_hash = H::commit_node(
        &self.pred_values[i],
        self.pred_new_next_indexes[i],
        &self.pred_new_next_values[i],
    );
    running_root = Self::compute_root(
        &new_pred_hash,
        siblings,
        self.pred_paths[i],
        self.start_index,
    );
}

let mid_root = running_root;
```

This replaces BOTH the old authentication loop (lines 377-393) AND the incomplete mid_root code (lines 481-513).

**Cost**: `K` Merkle-path recomputations (2 hashes per level per predecessor: one to verify, one to derive next root — but siblings are shared so it's really 2 * K * depth hash calls).

---

## Step 4 — Implement Phase B verification (`mid_root -> new_root`)

**File**: `native.rs`, `BatchInsertProof::verify`

After step 3 produces `mid_root`, verify the batch subtree insertion:

```rust
// 1. Compute each new leaf hash
let mut leaf_hashes: Vec<H::Digest> = Vec::with_capacity(batch_size);
for i in 0..batch_size {
    let (next_index, next_value) = if i == batch_size - 1 {
        (self.pred_old_next_indexes[i], self.pred_old_next_values[i])
    } else if self.mask[i + 1] {
        (self.pred_old_next_indexes[i], self.pred_old_next_values[i])
    } else {
        (self.start_index + i + 1, self.new_node_values[i + 1])
    };

    leaf_hashes.push(H::commit_node(&self.new_node_values[i], next_index, &next_value));
}

// 2. Build batch subtree bottom-up
let mut level = leaf_hashes;
for _ in 0..log_batch_size {
    let mut next_level = Vec::with_capacity(level.len() / 2);
    for j in (0..level.len()).step_by(2) {
        next_level.push(H::hash_2_to_1(&level[j], &level[j + 1], false));
    }
    level = next_level;
}
let batch_subtree_root = level[0];

// 3. Walk upper siblings to tree root
//    (reuse authenticate_empty_batch logic but with batch_subtree_root instead of empty)
let upper_siblings = &self.new_node_upper_siblings_after_pred_update;
let computed_new_root = Self::compute_subtree_root(
    &batch_subtree_root,
    upper_siblings,
    self.start_index,
    log_batch_size,
    self.start_index + batch_size,  // num_leaves after insertion
);

if computed_new_root != self.new_root {
    return false;
}
```

**Note on `num_leaves`**: `compute_root` and `hash_root` commit the number of leaves. After the batch insertion, `num_leaves = start_index + batch_size`. Verify this matches what `hash_root` expects.

**New helper**: extract the upper-sibling walk from `authenticate_empty_batch` into a shared helper (e.g. `compute_subtree_root`) used by both emptiness checks and Phase B.

---

## Step 5 — Wire emptiness check against `mid_root`

**File**: `native.rs`, `BatchInsertProof::verify`

After step 3 produces `mid_root`, add:

```rust
if !Self::authenticate_empty_batch(
    self.start_index,
    log_batch_size,
    &self.new_node_upper_siblings_after_pred_update,
    &mid_root,
    self.start_index,  // num_leaves at mid_root = start_index (no batch yet)
) {
    return false;
}
```

The existing check against `old_root` (using `new_node_upper_siblings_before_pred_update`) stays. Both checks together prove the batch slots remained empty through the predecessor update phase.

**Note on `num_leaves` for `hash_root`**: at `old_root`, `num_leaves = start_index`. At `mid_root`, `num_leaves` is still `start_index` (predecessors were updated in-place, no new leaves added). Verify `authenticate_empty_batch` passes the correct value.

---

## Step 6 — Clean up

**File**: `native.rs`

### 6a. Remove duplicate constraint
In `connect_mid` (current lines 311-315 and 329-333):
```rust
// DUPLICATED — remove one of these:
res &= conditional_eq(!other.mask, &self.pred_new_next_value, &other.pred_new_next_value);
```

### 6b. Remove unused `leaf_next` fields from right helper
The right helper's `leaf_next_value` / `leaf_next_index` are never read by `connect_mid`. Remove lines 422-432 and the corresponding `ConstraintHelper` fields for the right side (or set them to dummy values).

### 6c. Remove debug `println!` statements
Lines 484, 489, 494, 498, 503 — remove all `println!` calls.

### 6d. Remove the commented-out mid_root code
Lines 481-513 — the entire block is replaced by step 3.

### 6e. Remove `Hash` unused import
Line 6: `hasher::{Hash, MerkleHash}` — `Hash` is unused in this module (only used in tests).

---

## Step 7 — Add adversarial tests

**File**: `native.rs`, test module

Add tests that tamper with proof fields and assert verification **fails**:

| Test | Tampering | Expected failure point |
|------|-----------|----------------------|
| `test_tampered_new_root` | Flip a bit in `new_root` | Phase B: `computed_new_root != new_root` |
| `test_tampered_old_root` | Flip a bit in `old_root` | Phase A: predecessor auth fails |
| `test_swapped_leaves` | Swap `new_node_values[0]` and `[1]` | Linked-list: sorted order violated |
| `test_fake_predecessor` | Change `pred_values[0]` | Phase A: Merkle path mismatch |
| `test_mask_true_to_false` | Set `mask[0] = false` | `connect_first`: `mask[0]` must be true |
| `test_mask_false_to_true` | Set a chain mask to true | Phase A: predecessor auth fails (wrong siblings) |
| `test_duplicate_leaf` | Insert same value twice | `sort_leaves` rejects duplicates |
| `test_nonempty_slot` | Insert at an occupied position | Emptiness check fails |

---

## Verification flow after all fixes

```
verify():
  1. Assert mask[0] == true
  2. Phase A: old_root -> mid_root
     for each masked predecessor (sequential):
       - auth old_pred_hash + siblings -> running_root
       - compute new_pred_hash + same siblings -> next running_root
     mid_root = final running_root
  3. Emptiness checks:
     - authenticate_empty_batch(old_root, upper_siblings_before)
     - authenticate_empty_batch(mid_root, upper_siblings_after)
  4. Linked-list constraints (connect_first / connect_mid / connect_last)
  5. Phase B: mid_root -> new_root
     - compute N leaf hashes
     - build batch subtree
     - walk upper_siblings_after -> must equal new_root
  6. Return true
```
