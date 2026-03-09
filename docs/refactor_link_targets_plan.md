# Refactor: Push constraint logic into `BatchInsertionLinkTargets`

## Goal

Move per-link and pairwise constraint logic from `BatchNullifierInsertProofTargets` methods
into `BatchInsertionLinkTargets`, so that:

- `BatchInsertionLinkTargets` owns all **low-level connect** methods.
- `BatchNullifierInsertProofTargets` phases become thin loops that call those methods.
- The low-level methods are independently testable.

## Progress

| # | Task | Status |
|---|------|--------|
| 1 | Move helpers to `BatchInsertionLinkTargets` | |
| 2 | Add per-link constraint method | |
| 3 | Add pairwise transition constraint method | |
| 4 | Add first-link / last-link constraint methods | |
| 5 | Add Phase A per-link method | |
| 6 | Add witness `set` method | |
| 7 | Rewrite `BatchNullifierInsertProofTargets` phases as loops | |
| 8 | Add low-level unit tests | |
| 9 | Run full test suite, fmt, clippy | |

---

## Step 1: Move helpers to `BatchInsertionLinkTargets`

Move `connect_if`, `connect_hash_if`, and `select_hash` from
`BatchNullifierInsertProofTargets` to `BatchInsertionLinkTargets` (as associated functions,
they don't reference `self`). These are pure builder utilities with no dependency on the
top-level struct.

Also move `compute_root_circuit` and `hash_parent_root` — they are generic Merkle path
helpers used by both Phase A (per-link) and Phase C (top-level). They stay as associated
functions on `BatchInsertionLinkTargets`.

`compute_upper_root_circuit` stays on `BatchNullifierInsertProofTargets` since it operates
on the upper siblings owned by that struct (or move it too — it's the same logic as
`compute_root_circuit` but for upper paths).

## Step 2: Add per-link constraint method

Add `BatchInsertionLinkTargets::connect_link_constraints`:

```rust
/// Per-link constraints (independent of neighbors).
///
/// - Range check: pred_value < leaf_value < pred_old_next_value
/// - Mask implications: mask => pred_new_next == leaf
pub fn connect_link_constraints<H, F, const D: usize>(
    &self,
    builder: &mut CircuitBuilder<F, D>,
)
```

This extracts the body of the `for i in 0..batch_size` inner loop (constraints 1, 2, 5)
from `connect_phase_b`.

## Step 3: Add pairwise transition constraint method

Add `BatchInsertionLinkTargets::connect_transition_constraints`:

```rust
/// Transition constraints between this link (i) and the next link (i+1).
///
/// - leaf_index[i] + 1 == leaf_index[i+1]
/// - Combined constraints 6/15, 7/16 via select on next.mask
/// - Chaining constraints 9–14 via connect_if with !next.mask
pub fn connect_transition_constraints<H, F, const D: usize>(
    &self,
    builder: &mut CircuitBuilder<F, D>,
    next: &BatchInsertionLinkTargets,
)
```

This extracts the `if i < batch_size - 1` block from `connect_phase_b`.

## Step 4: Add first-link / last-link constraint methods

```rust
/// Constraint 18: mask[0] == true (first link must be a chain lead).
pub fn connect_first_link<F, const D: usize>(
    &self,
    builder: &mut CircuitBuilder<F, D>,
)

/// Constraints 19–20: last link's leaf_next == pred_old_next.
pub fn connect_last_link<F, const D: usize>(
    &self,
    builder: &mut CircuitBuilder<F, D>,
)
```

## Step 5: Add Phase A per-link method

```rust
/// Authenticates this link's predecessor against old_root and mid_root.
///
/// - Computes pred_old_hash from (pred_value, pred_old_next_index, pred_old_next_value)
///   and verifies it against old_root via pred_old_siblings.
/// - Computes pred_new_hash from (pred_value, pred_new_next_index, pred_new_next_value)
///   and verifies it against mid_root via pred_new_siblings.
pub fn connect_pred_auth<H, F, const D: usize>(
    &self,
    builder: &mut CircuitBuilder<F, D>,
    old_root: HashOutTarget,
    mid_root: HashOutTarget,
    num_leaves: Target,
)
```

Also add a method to derive mid_root from a link's pred_new authentication:

```rust
/// Derives mid_root from this link's pred_new authentication path.
pub fn compute_mid_root<H, F, const D: usize>(
    &self,
    builder: &mut CircuitBuilder<F, D>,
    num_leaves: Target,
) -> HashOutTarget
```

## Step 6: Add witness `set` method

Move the per-link witness population from `BatchNullifierInsertProofTargets::set` into:

```rust
impl BatchInsertionLinkTargets {
    pub fn set<H, F>(
        &self,
        pw: &mut PartialWitness<F>,
        link: &BatchInsertionLink<H>,
    ) -> Result<()>
    where
        H: MerkleHash,
        H::Digest: ToHashOut<F>,
        F: Field + PrimeField64,
    { ... }
}
```

`BatchNullifierInsertProofTargets::set` then becomes:
```rust
for (link_targets, link) in self.links.iter().zip(proof.links.iter()) {
    link_targets.set(pw, link)?;
}
```

## Step 7: Rewrite `BatchNullifierInsertProofTargets` phases as loops

**Phase A** becomes:
```rust
pub fn connect_phase_a(...) -> HashOutTarget {
    let mid_root = self.links[0].compute_mid_root::<H, F, D>(builder, self.start_index);
    for link in &self.links {
        link.connect_pred_auth::<H, F, D>(builder, self.old_root, mid_root, self.start_index);
    }
    mid_root
}
```

**Phase B** becomes:
```rust
pub fn connect_phase_b(...) {
    self.links[0].connect_first_link(builder);
    for link in &self.links {
        link.connect_link_constraints::<H, F, D>(builder);
    }
    for i in 0..self.links.len() - 1 {
        self.links[i].connect_transition_constraints::<H, F, D>(builder, &self.links[i + 1]);
    }
    self.links.last().unwrap().connect_last_link(builder);
}
```

**Phase C** stays mostly on `BatchNullifierInsertProofTargets` since it operates on
top-level fields (upper_siblings, start_index, old_root, new_root) and builds the batch
subtree across all links. The only per-link call is `commit_node_circuit` for leaf hashes,
which could become a `leaf_hash_circuit` method on `BatchInsertionLinkTargets`:

```rust
pub fn leaf_hash_circuit<H, F, const D: usize>(
    &self,
    builder: &mut CircuitBuilder<F, D>,
) -> HashOutTarget
```

## Step 8: Add low-level unit tests

Test the `BatchInsertionLinkTargets` methods in isolation by building minimal circuits:

1. **`test_link_range_check`**: Create a single link, call `connect_link_constraints`,
   populate with valid witness → prove succeeds. Tamper with leaf_value outside range → prove
   fails.

2. **`test_link_transition_constraints`**: Create two links, call
   `connect_transition_constraints`, populate with valid witness (both masked and chained
   cases) → prove succeeds. Break leaf_index sequencing → prove fails.

3. **`test_link_first_last`**: Create a single link, call `connect_first_link` +
   `connect_last_link`, verify constraints hold.

4. **`test_link_pred_auth`**: Create a single link with known Merkle tree, call
   `connect_pred_auth`, verify root authentication succeeds. Tamper with sibling → prove
   fails.

## Step 9: Run full test suite, fmt, clippy

```bash
cargo fmt
cargo clippy -p tessera-trees
cargo test -p tessera-trees --release -- batch_nullifier
```

Verify all existing tests still pass unchanged.
