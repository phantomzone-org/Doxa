# Real-Proof Integration Test & SuperAggregator Permutation Fix

## Progress

| # | Task | Status |
|---|------|--------|
| 1 | Root cause analysis | Done |
| 2 | Implement GF(p²) multi-set equality gadget | Done |
| 3 | Update SuperAggregator cross-check (AN, NN) + conditional connect (AC, NC) | Done |
| 4 | Update prover: per-slot dummy proofs with AN/NN overrides from tree padding | Done |
| 5 | Remove global sort of NC/AC in sequencer pipeline | Done |
| 6 | Write integration test (real proofs end-to-end) | Done |
| 7 | Run test, verify fix | Done |

---

## 1. Root Cause Analysis

### Problem

The SuperAggregator proof fails with:
```
Wire was set twice with different values: 0 != 248986144077147266
```
when any TX slot has `is_real=1` (real PrivTx proof). Works with all-dummy
proofs (`is_real=0`) because the cross-check is gated by `is_real`.

### Current Cross-Check (super_aggregator.rs:407-452)

For each TX slot `s`, the circuit enforces positional correspondence:
```
is_real * (tx_pi[s*75 + offset] - tree_pi[position]) == 0
```
where `position = s` for AN/AC and `position = s*8+j` for NN/NC.

### Why It Fails

- **Nullifier trees (AN, NN)** sort leaves internally via `sort_leaves()`.
  The proof PIs contain globally sorted leaves.
- **Commitment trees (AC, NC)** append in insertion order (no sort).
- The sequencer also explicitly sorts all 4 batches in `pipeline.rs`.

After NN global sort, notes from different TX slots interleave. AN sort and
NN sort are **two independent permutations** — no pipeline-level reordering
can make both match the fixed slot mapping simultaneously.

### Tree Behavior Summary

| Tree | Type | Internal sort? | PI leaf order |
|------|------|---------------|---------------|
| AN | Nullifier | Yes (`sort_leaves`) | Globally sorted |
| NN | Nullifier | Yes (`sort_leaves`) | Globally sorted |
| AC | Commitment | No | Insertion order |
| NC | Commitment | No | Insertion order |

---

## 2. Fix: Multi-Set Equality over GF(p²)

### Approach

Replace the positional cross-check for **AN and NN** with a product-based
multi-set equality check over the quadratic extension field GF(p²).

For AC and NC (commitment trees, no internal sort): keep positional checks
but ensure the sequencer passes leaves in slot-grouped order (remove the
explicit `ac_padded_bytes.sort()` and `nc_padded_bytes.sort()`).

### Protocol

For a set of N values {a_i} (TX PIs) and {b_i} (tree leaves):

1. Derive `γ ∈ GF(p²)` via Fiat-Shamir (Poseidon hash of all tree PIs).
2. Compress each 4-field hash to a single GF(p²) element:
   `fp(h) = h[0] + γ·h[1] + γ²·h[2] + γ³·h[3]`
3. Compute running products in GF(p²):
   `P_a = ∏ fp(a_i)`,  `P_b = ∏ fp(b_i)`
4. Assert `P_a == P_b`.

### Security

- Schwartz-Zippel over GF(p²): soundness error ≤ `N / p² ≈ 2^{-118}` for
  N=1024, well within plonky2's ~100-bit security target.
- Multi-set equality + Poseidon collision resistance (≈ 2^{-128}) gives
  effective 1:1 mapping guarantee.

### Toy Example

```
TX note nullifiers (slot-grouped):  [7, 3, 9, 1]
NN tree leaves (globally sorted):   [1, 3, 7, 9]

γ = 5 (over base field for illustration):
P_tx   = (7+5)(3+5)(9+5)(1+5) = 12 × 8 × 14 × 6 = 8064
P_tree = (1+5)(3+5)(7+5)(9+5) =  6 × 8 × 12 × 14 = 8064  ✓

Tampered tree [1, 3, 7, 8]:
P_tree = 6 × 8 × 12 × 13 = 7488 ≠ 8064  ✗ caught
```

### Which Cross-Checks Change

| Tree | Current | New |
|------|---------|-----|
| AN (nullifier, 128 accounts) | Positional: `tx[s].AN == an[s]` | Product check over GF(p²) |
| NN (nullifier, 1024 notes) | Positional: `tx[s].NN[j] == nn[s*8+j]` | Product check over GF(p²) |
| AC (commitment, 128 accounts) | Positional: `tx[s].AC == ac[s]` | **Keep positional** (no sort) |
| NC (commitment, 1024 notes) | Positional: `tx[s].NC[j] == nc[s*8+j]` | **Keep positional** (no sort) |

---

## 3. Circuit Implementation

### 3a. GF(p²) Multi-Set Equality Gadget

**File:** `tessera-trees/src/proof_aggregation/super_aggregator.rs` (or new
helper module)

```rust
/// Assert that two sets of 4-field hashes are equal as multi-sets,
/// using a product argument over GF(p²).
///
/// γ is derived via Fiat-Shamir from `fiat_shamir_inputs`.
fn assert_multiset_eq<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    set_a: &[HashOutTarget],    // e.g. TX AN/NN values
    set_b: &[HashOutTarget],    // e.g. tree AN/NN leaves
    fiat_shamir_inputs: &[Target],  // all tree PIs for domain separation
)
```

Steps:
1. Hash `fiat_shamir_inputs` → `[F; 4]` via `hash_n_to_hash_no_pad`.
2. Build `γ: ExtensionTarget<D>` from the first 2 hash elements.
3. Precompute `γ² = γ·γ`, `γ³ = γ²·γ`.
4. For each hash `h` in both sets:
   `fp(h) = h[0] + γ·h[1] + γ²·h[2] + γ³·h[3]` (in GF(p²))
5. Running product: `P = ∏ fp(h_i)` (in GF(p²), starting from `one_ext`).
6. `builder.connect_extension(P_a, P_b)`.

### 3b. Update SuperAggregator Circuit (`super_aggregator.rs`)

Replace the AN positional cross-check loop:
```rust
// OLD: is_real * (tx_an - an_leaf[s]) == 0
// NEW: collect all AN values, product-check against AN tree leaves
```

Replace the NN positional cross-check loop:
```rust
// OLD: is_real * (tx_nn[j] - nn_leaf[s*8+j]) == 0
// NEW: collect all NN values, product-check against NN tree leaves
```

Keep AC and NC positional checks as-is (commitment trees, no sort).

**Handling dummy slots:** No `is_real` gating is needed in the circuit.
The prover generates dummy TX proofs (`is_fake=true`) whose AN/AC/NN/NC
PIs match the tree padding values. Since the PrivTx circuit does not
constrain PIs when `is_fake=true`, the prover is free to set them to
any value. Both products naturally include identical values for dummy
slots, so the multi-set equality holds unconditionally over all N
elements.

### 3c. Prover: Dummy Proof PI Alignment

**Workflow:**
1. Sequencer pads tree batches (always 1024 NN/NC, 128 AN/AC) and sends
   padded batches + N real TX proofs to the prover.
2. For each slot not covered by a real TX proof (`is_fake=false`), the
   prover generates a dummy TX proof (`is_fake=true`) whose AN/AC/NN/NC
   PIs are set to the corresponding tree leaf values at that slot.
   The origin of those leaves (consume requests, sequencer padding, etc.)
   is irrelevant — any leaf not claimed by a real proof becomes a PI
   to a dummy proof.
3. All 128 TX proofs (real + dummy) are aggregated. The dummy proof PIs
   match the tree leaves exactly, so no circuit-level gating is required.

No changes needed in the SuperAggregator circuit for dummy handling —
the alignment is enforced at the prover level.

---

## 4. Sequencer Pipeline Fix (`pipeline.rs`)

### Remove explicit sort of AC and NC

```rust
// REMOVE these two lines:
nc_padded_bytes.sort();  // line 280
ac_padded_bytes.sort();  // line 308
```

AC and NC commitment trees append in insertion order. The sequencer must
pass them in **slot-grouped order** so that position `s` / `s*8+j`
corresponds to TX slot `s`.

### Keep explicit sort of AN and NN

```rust
// KEEP (or let tree sort internally — both are fine):
nn_padded_bytes.sort();  // line 294
an_padded_bytes.sort();  // line 322
```

The nullifier trees sort internally anyway. The explicit pre-sort is
redundant but harmless. The product check handles arbitrary ordering.

### Slot-grouped insertion for NC/AC

When building the batch, NC and AC leaves must be arranged as:
```
AC: [slot0_ac, slot1_ac, ..., slotN_ac]
NC: [slot0_nc[0..8], slot1_nc[0..8], ..., slotN_nc[0..8]]
```
where slot ordering follows the AN-sorted order (since TX proofs in the
aggregation tree will be placed to match AN sort order).

Concretely in `start_batch`:
1. Build per-slot tuples: `(AN, AC, [NN×8], [NC×8], tx_proof)`.
2. Pad to `account_batch_size` with dummy slots.
3. Sort slots by AN leaf value.
4. Flatten into 4 batches:
   - AN/NN: pass to nullifier tree (tree sorts internally, product check)
   - AC/NC: pass in slot order (commitment tree appends, positional check)

---

## 5. Integration Test

**File:** `tessera-server/tests/real_proof_pipeline.rs` (new)

Small config: `account_batch_size=2`, `note_batch_size=16`, aggregator
`arity=2, depth=1`.

1. Build PrivTx circuit, generate 2 real proofs (different seeds).
2. Extract PI values (AN, AC, NN, NC) from each proof.
3. Build 4 tree batches in correct slot order.
4. Build tree circuits, prove.
5. Build TX aggregator, aggregate 2 proofs.
6. Build SuperAggregator from 5 inner circuit data objects.
7. Prove SuperAggregator with 5 proofs.
8. Verify root proof.

---

## 6. Files to Modify

| File | Change |
|------|--------|
| `tessera-trees/src/proof_aggregation/super_aggregator.rs` | Add GF(p²) multi-set gadget; replace AN/NN cross-checks |
| `tessera-server/src/prover.rs` | Dummy proof PI alignment: generate dummy proofs with PIs matching tree padding |
| `tessera-server/src/sequencer/pipeline.rs` | Remove NC/AC sort; slot-grouped insertion |
| `tessera-server/tests/real_proof_pipeline.rs` (new) | Integration test |
| `tessera-server/src/bin/super_aggregator_artifacts.rs` | Rebuild needed (circuit changed) |
| `tessera-server/src/bin/client.rs` | Already fixed (per-tx seeds, correct PI offsets) |

---

## 7. Circuit Cost Estimate

| Component | Operations | Gates (approx) |
|-----------|-----------|----------------|
| Fiat-Shamir γ derivation | 1 Poseidon hash | ~500 |
| γ², γ³ precomputation | 2 ext muls | ~6 |
| AN fingerprints (128 × 2 sets) | 256 × (3 ext muls + 3 ext adds) | ~4.5K |
| AN products (128 × 2) | 256 ext muls | ~768 |
| NN fingerprints (1024 × 2 sets) | 2048 × (3 ext muls + 3 ext adds) | ~36K |
| NN products (1024 × 2) | 2048 ext muls | ~6K |
| **Total** | | **~48K gates** |

Negligible vs the existing Keccak gadget (~200K+ gates).
