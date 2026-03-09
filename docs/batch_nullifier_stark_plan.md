# Batch Nullifier Insertion — STARK Implementation Plan

## Progress

| # | Task | Status |
|---|------|--------|
| 1 | Define `BatchInsertionLinkTargets` struct | |
| 2 | Define `BatchNullifierInsertProofTargets` struct | |
| 3 | Implement `BatchInsertionLinkTargets::new()` | |
| 4 | Implement `BatchNullifierInsertProofTargets::new()` | |
| 5 | Implement `compute_root_circuit` (reuse pattern) | |
| 6 | Implement `compute_upper_root_circuit` | |
| 7 | Implement `compute_sparse_root_update_circuit` | |
| 8 | Implement Phase A constraints (`connect_phase_a`) | |
| 9 | Implement witness generation (`set`) | |
| 10 | Write test: build circuit + prove + verify | |

---

## Overview

The batch nullifier insertion STARK proves the state transition
`old_root → mid_root → new_root` in a single circuit.
This plan covers **witness allocation** and **Phase A** only
(predecessor updates: `old_root → mid_root`).
Phase B (batch subtree insertion) and linked-list constraints
will be added in a follow-up.

**File**: `tessera-trees/src/tree/nullifier_tree/proofs/batch_insertion/stark.rs`

---

## 1. `BatchInsertionLinkTargets`

One per batch entry. Mirrors `BatchInsertionLink<H>` from native.

```rust
pub struct BatchInsertionLinkTargets {
    // mask: whether this is a chain lead (true) or chained (false)
    pub mask: BoolTarget,

    // New leaf
    pub leaf_index: Target,
    pub leaf_value: HashOutTarget,
    pub leaf_next_index: Target,
    pub leaf_next_value: HashOutTarget,

    // Predecessor
    pub pred_path: Vec<BoolTarget>,       // depth bits
    pub pred_value: HashOutTarget,
    pub pred_old_next_index: Target,
    pub pred_old_next_value: HashOutTarget,
    pub pred_new_next_index: Target,
    pub pred_new_next_value: HashOutTarget,
    pub pred_old_siblings: Vec<HashOutTarget>,  // depth siblings

    // Range-check witnesses for pred_value < leaf_value < pred_old_next_value
    pub u: Vec<Target>,            // 2 * HASH_SIZE
    pub v: Vec<Target>,            // 2 * HASH_SIZE
    pub c_ax: Vec<BoolTarget>,     // 2 * HASH_SIZE - 1
    pub c_xb: Vec<BoolTarget>,     // 2 * HASH_SIZE - 1
}
```

### `new(builder, depth)` — all private targets

All targets are private witnesses (public inputs are on the proof struct).

- `mask`: `builder.add_virtual_bool_target_safe()`
- `leaf_index`, `leaf_next_index`, `pred_old_next_index`, `pred_new_next_index`: `builder.add_virtual_target()`
- `leaf_value`, `leaf_next_value`, `pred_value`, `pred_old_next_value`, `pred_new_next_value`: `builder.add_virtual_hash()`
- `pred_path`: `depth` × `builder.add_virtual_bool_target_safe()`
- `pred_old_siblings`: `depth` × `builder.add_virtual_hash()`
- Range-check: same pattern as `NullifierInsertProofTargets`

### `set(pw, link)` — witness population

Maps each field of `BatchInsertionLink<H>` to its corresponding target:

```
pw.set_bool_target(self.mask, link.mask)
pw.set_target(self.leaf_index, F::from_canonical_u64(link.leaf_index as u64))
pw.set_hash_target(self.leaf_value, link.leaf_value.to_hash_out())
pw.set_target(self.leaf_next_index, F::from_canonical_u64(link.leaf_next_index as u64))
pw.set_hash_target(self.leaf_next_value, link.leaf_next_value.to_hash_out())
// pred_path: bit extraction from link.pred_path (same as single insertion)
for i in 0..depth {
    pw.set_bool_target(self.pred_path[i], ((link.pred_path >> i) & 1) == 1)
}
pw.set_hash_target(self.pred_value, link.pred_value.to_hash_out())
pw.set_target(self.pred_old_next_index, ...)
pw.set_hash_target(self.pred_old_next_value, ...)
pw.set_target(self.pred_new_next_index, ...)
pw.set_hash_target(self.pred_new_next_value, ...)
// pred_old_siblings: loop depth
// range-check: populate_inclusion_witness(pred_value, leaf_value, pred_old_next_value)
```

---

## 2. `BatchNullifierInsertProofTargets`

Top-level proof structure.

```rust
pub struct BatchNullifierInsertProofTargets {
    // Public inputs
    pub old_root: HashOutTarget,
    pub new_root: HashOutTarget,
    pub start_index: Target,

    // Per-leaf links (batch_size entries)
    pub links: Vec<BatchInsertionLinkTargets>,

    // Emptiness proof siblings (depth - log_batch_size each)
    pub upper_siblings_before_pred_update: Vec<HashOutTarget>,
    pub upper_siblings_after_pred_update: Vec<HashOutTarget>,
}
```

### `new(builder, depth, batch_size)` — allocation

```
old_root = builder.add_virtual_hash_public_input()
new_root = builder.add_virtual_hash_public_input()
start_index = builder.add_virtual_target()

log_batch = batch_size.trailing_zeros()
upper_depth = depth - log_batch

links = (0..batch_size).map(|_| BatchInsertionLinkTargets::new(builder, depth))
upper_siblings_before = builder.add_virtual_hashes(upper_depth)
upper_siblings_after = builder.add_virtual_hashes(upper_depth)
```

### `set(pw, proof)` — witness population

```
pw.set_hash_target(old_root, proof.old_root)
pw.set_hash_target(new_root, proof.new_root)
pw.set_target(start_index, proof.start_index)
for (link_targets, link) in links.zip(proof.links) {
    link_targets.set(pw, link)
}
// upper siblings before/after
```

---

## 3. Phase A Constraints: `old_root → mid_root`

### 3.1. Authenticate each masked predecessor against `old_root`

For each link where `mask == true`:

```
old_pred_hash = H::commit_node_circuit(pred_value, pred_old_next_index, pred_old_next_value)
computed_root = compute_root_circuit(old_pred_hash, pred_old_siblings, pred_path, start_index)
builder.connect_hashes(computed_root, old_root)
```

For chained links (`mask == false`), the siblings are copies of the chain lead,
so they also authenticate against `old_root` with the same pred values.
However, we only need to authenticate each **unique** predecessor once.

**Circuit approach**: authenticate ALL links against `old_root` (masked and unmasked alike).
Since chained links have identical pred fields and siblings to their chain lead,
this is redundant but sound and uniform — no conditional logic needed.
The STARK trace processes every row identically for Phase A authentication.

```
for each link in links:
    old_pred_hash = H::commit_node_circuit(pred_value, pred_old_next_index, pred_old_next_value)
    computed_root = compute_root_circuit(old_pred_hash, pred_old_siblings, pred_path, start_index)
    builder.connect_hashes(computed_root, old_root)
```

### 3.2. Compute `mid_root` via sparse root update

This is the most complex piece. The native `compute_sparse_root_update` uses a
dynamic `BTreeMap` — not circuit-friendly. We need a static circuit equivalent.

**Key insight**: The predecessors are sorted by path (since leaves are sorted and
predecessors are looked up in tree order). Chained links share the same path.
The unique masked predecessor paths form a sorted set of at most `batch_size` entries.

**Circuit strategy — unrolled bottom-up merge**:

The circuit replicates the bottom-up Merkle recomputation for all `depth` levels.
At each level, for each masked predecessor:

1. Compute old parent hash from `old_leaf_hash` and sibling
2. Compute new parent hash from `new_leaf_hash` and sibling
3. When two masked predecessors are siblings (adjacent paths at this level),
   use each other's freshly computed hash instead of the proof sibling

Since the number of active paths halves (at most) at each level and we know
the paths at circuit build time... **wait** — we do NOT know paths at build time.
Paths are witnesses.

**Alternative approach — conditional sibling replacement**:

For each masked predecessor `i` at each level `l`:
- Check if predecessor `i-1` is the sibling of predecessor `i` at level `l`
  (i.e., they share the same parent: `pred_path[i] >> (l+1) == pred_path[i-1] >> (l+1)`)
- If so, replace the proof sibling with the freshly computed hash from `i-1`
- This works because masked predecessors are in sorted order

But this requires checking path equality in-circuit, which adds constraints.

**Simplest sound approach for Phase A — sequential predecessor updates**:

Instead of the sparse batch update, process masked predecessors **sequentially**:

```
current_root = old_root
for each link where mask:
    // Authenticate old pred against current_root
    old_hash = commit_node(pred_value, pred_old_next_index, pred_old_next_value)
    computed = compute_root(old_hash, pred_old_siblings, pred_path, start_index)
    connect(computed, current_root)

    // Compute new root after this single update
    new_hash = commit_node(pred_value, pred_new_next_index, pred_new_next_value)
    current_root = compute_root(new_hash, pred_old_siblings, pred_path, start_index)

mid_root = current_root
```

**Problem**: this requires fresh siblings for each intermediate root, but we only
have siblings against `old_root`. After the first predecessor update, the siblings
for subsequent predecessors are stale.

This is exactly why the native code uses the sparse update algorithm.

**Recommended approach — in-circuit sparse merge**:

Process all `depth` levels bottom-up with a fixed-size array of `batch_size` entries.
At each level:

```
for i in 0..num_masked:
    parent_pos = path[i] >> (level + 1)
    sibling_pos = path[i] ^ 1  (at current level)

    // Check if the previous masked predecessor is our sibling
    is_sibling = (i > 0) && (parent_pos_of[i] == parent_pos_of[i-1])

    // If sibling is also updated, use its new hash; otherwise use proof sibling
    effective_old_sibling = select(is_sibling, old_hash[i-1], siblings[i][level])
    effective_new_sibling = select(is_sibling, new_hash[i-1], siblings[i][level])

    // Compute parent hashes
    old_hash[i] = hash(old_hash[i], effective_old_sibling, direction)
    new_hash[i] = hash(new_hash[i], effective_new_sibling, direction)
```

After `depth` levels, all entries converge to the same root position (0).
The last entry's old hash must equal `old_root`, and its new hash is `mid_root`.

**Circuit complexity**: For `K` masked predecessors and depth `D`, this is
`K × D` hash operations (same as the native algorithm). Since `K ≤ batch_size`,
worst case is `batch_size × depth` hashes.

**But**: we don't know `K` at compile time (it depends on the mask).
We need to process all `batch_size` entries at every level, using
conditional logic for non-masked entries.

**Final recommended approach — fixed-width unrolled merge**:

Process ALL `batch_size` links at every level. For non-masked links,
propagate the chain lead's hash (no-op via select). For masked links,
do the real hash computation.

At each level `l`, for each link `i`:

```
// Skip if not masked: propagate previous link's current hash
old_hash[i] = select(mask[i], computed_old_parent, old_hash[i-1])
new_hash[i] = select(mask[i], computed_new_parent, new_hash[i-1])
```

At the end of all `depth` levels:
```
connect(old_hash[batch_size-1], old_root)   // cross-check
mid_root = new_hash[batch_size-1]
```

This is `batch_size × depth` hash calls plus `batch_size × depth` selects.
Uniform, no dynamic data structures, fully unrollable.

### Implementation plan for `connect_phase_a`

```rust
fn connect_phase_a<H, F, D>(
    builder: &mut CircuitBuilder<F, D>,
    links: &[BatchInsertionLinkTargets],
    old_root: HashOutTarget,
    start_index: Target,
) -> HashOutTarget  // returns mid_root
```

**Step-by-step**:

1. Initialize `old_hashes[i]` and `new_hashes[i]` for each link:
   ```
   old_hashes[i] = commit_node(pred_value, pred_old_next_index, pred_old_next_value)
   new_hashes[i] = commit_node(pred_value, pred_new_next_index, pred_new_next_value)
   ```

2. For each level `l` in `0..depth`:
   For each link `i` in `0..batch_size`:

   a. Extract direction bit: `dir = pred_path[i][l]`

   b. Get sibling from proof: `proof_sibling = pred_old_siblings[i][l]`

   c. Check if previous masked link is our sibling at this level:
      - Compute parent position bits for `i` and `i-1`
      - `is_sibling_of_prev = (i > 0) && mask[i] && (parent_i == parent_{i-1})`
      - In circuit: compare path bits `[l+1..depth]` between link `i` and `i-1`
      - Simplified: at level `l`, two paths are siblings iff they share bits `[l+1..]`
        and differ at bit `l`. Since masked preds are sorted, if `i-1` is also masked
        and they share the same parent, they must be siblings.

   d. Select effective sibling:
      ```
      old_sibling = select(is_sibling_of_prev, old_hashes_prev_at_this_level, proof_sibling)
      new_sibling = select(is_sibling_of_prev, new_hashes_prev_at_this_level, proof_sibling)
      ```

   e. Compute parent hash (with direction and root-level special case):
      ```
      computed_old = hash_or_hash_root(old_hashes[i], old_sibling, dir, level, depth, start_index)
      computed_new = hash_or_hash_root(new_hashes[i], new_sibling, dir, level, depth, start_index)
      ```

   f. Propagate for non-masked links (select identity):
      ```
      old_hashes[i] = select(mask[i], computed_old, old_hashes[i > 0 ? i-1 : i])
      new_hashes[i] = select(mask[i], computed_new, new_hashes[i > 0 ? i-1 : i])
      ```

3. Final cross-check and mid_root extraction:
   ```
   builder.connect_hashes(old_hashes[batch_size - 1], old_root)
   mid_root = new_hashes[batch_size - 1]
   ```

### Sibling detection simplification

At level `l`, two sorted masked predecessors at positions `i-1` and `i` are siblings iff:
- Both are masked
- Their paths agree on all bits above level `l`
  i.e., `path[i-1][l+1..] == path[i][l+1..]`
- Their paths differ at bit `l` (one is 0, other is 1)

Since paths are sorted (masked predecessors come from sorted leaves),
and we process left-to-right, the only possible sibling overlap is with the
immediately preceding masked link. This simplifies the circuit.

In practice, checking `parent_pos_equal` can be done incrementally:
start with `all_bits_above_equal = true` at the top level and propagate down,
or simply check equality of path bits `[l+1..depth]` at each level.

A simpler approach: precompute a `BoolTarget is_sibling[i]` for each level and link,
equal to `mask[i] && mask[i-1] && (pred_path[i] ^ pred_path[i-1] == (1 << l))`.
But XOR in circuit is expensive for arbitrary widths.

**Simplest circuit-friendly check**: at level `l`, link `i` and `i-1` share a parent
iff `pred_path[i] >> (l+1) == pred_path[i-1] >> (l+1)`. In the circuit, the path is
already decomposed as `BoolTarget` bits. So:

```
same_parent = AND of (pred_path[i][k] == pred_path[i-1][k]) for k in l+1..depth
```

This is `depth - l - 1` equality checks per (link, level) pair.
Total: `sum_{l=0}^{depth-1} batch_size × (depth - l - 1)` ≈ `batch_size × depth² / 2`.

For `batch_size=128, depth=32`: ~65K equality gates. Acceptable.

**Optimization**: accumulate top-down. Start at level `depth-1` where
`same_parent` requires 0 bit checks (always true if they share the top).
At each lower level, AND in one more bit equality. This gives O(1) extra
work per (link, level) pair, for a total of `batch_size × depth` AND gates.

---

## 4. Helper Circuits

### `compute_root_circuit` (full depth, leaf to root)

Reuse from `NullifierInsertProofTargets` — identical implementation.

### `compute_upper_root_circuit` (subtree root to tree root)

Identical to `BatchCommitmentProofTargets::compute_root_circuit` —
takes `upper_siblings`, `upper_path_bits`, `num_leaves`.

---

## 5. Test Plan

```rust
#[test]
fn test_batch_nullifier_insert_phase_a() {
    const DEPTH: usize = 8;   // small for fast test
    const BATCH_SIZE: usize = 4;

    // 1. Build native tree, insert 7 leaves, batch-insert 4
    // 2. Get BatchInsertProof
    // 3. Allocate targets: BatchNullifierInsertProofTargets::new(builder, DEPTH, BATCH_SIZE)
    // 4. Connect Phase A only: targets.connect_phase_a::<H, F, D>(builder)
    // 5. Set witnesses: targets.set(pw, proof)
    // 6. Build + prove + verify
}
```

---

## 6. File Structure

```
tessera-trees/src/tree/nullifier_tree/proofs/batch_insertion/
├── mod.rs          # add: mod stark; pub use stark::*;
├── native.rs       # existing
└── stark.rs        # NEW
```
