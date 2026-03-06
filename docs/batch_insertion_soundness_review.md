# Batch Nullifier Insertion — Soundness Review

## Status Table

| # | Check | Status | Severity |
|---|-------|--------|----------|
| 1 | Predecessor authentication against `old_root` | OK | — |
| 2 | Linked-list constraints (sorted order, non-membership, chaining) | OK | — |
| 3 | Emptiness proof of batch slots in `old_root` | OK | — |
| 4 | `old_root -> mid_root` (predecessor update transition) | MISSING | CRITICAL |
| 5 | `mid_root -> new_root` (batch subtree insertion) | MISSING | CRITICAL |
| 6 | Emptiness proof of batch slots in `mid_root` | PRESENT (unused) | — |
| 7 | `connect_last` soundness for chained last element | OK | — |
| 8 | Duplicate constraint in `connect_mid` (lines 311-315 / 329-333) | COSMETIC | LOW |

---

## 1. What the proof claims

Given public inputs `(old_root, new_root, start_index)`:

- `batch_size` sorted, unique leaves were inserted at positions `[start_index .. start_index + batch_size)`
- Every leaf has a valid predecessor proving non-membership
- The tree transitions correctly from `old_root` to `new_root`

The proof must establish three root transitions:

```
old_root ──[update predecessors]──> mid_root ──[insert batch subtree]──> new_root
```

---

## 2. What the verifier currently checks

### 2a. Predecessor authentication (lines 377-393) — OK

For every leaf `i`, the verifier reconstructs `H::commit_node(pred_value, pred_old_next_index, pred_old_next_value)` and walks the Merkle path to confirm it produces `old_root`.

- Authenticates that each predecessor genuinely exists in the pre-insertion tree.
- Chained leaves (mask=false) re-authenticate the same predecessor — correct but redundant.

### 2b. Linked-list constraints (lines 395-469) — OK

The `connect_first / connect_mid / connect_last` helpers enforce:

| Constraint | Where |
|---|---|
| `mask[0] == true` | `connect_first` |
| If mask[i]: `pred_new_next == (leaf_index, leaf_value)` | `connect_first/mid/last` |
| `pred_value < leaf_value < pred_old_next_value` | all |
| `leaf_next_value > leaf_value` | `connect_mid` |
| If mask[i+1] (break): `leaf_next == pred_old_next`, `other.pred_value > self.leaf_value` | `connect_mid` |
| If !mask[i+1] (chain): same pred, same pred_new_next, `leaf_next == other.leaf` | `connect_mid` |
| Last leaf: `leaf_next == pred_old_next` | `connect_last` |
| `leaf_index[i] + 1 == leaf_index[i+1]` | `connect_mid` |

These collectively enforce:

1. **Sorted batch order**: `leaf[0] < leaf[1] < ... < leaf[N-1]`
2. **Non-membership**: each leaf falls in its predecessor's gap
3. **Correct pointer wiring**: predecessor update, chain links, and successor inheritance
4. **Consecutive indices**: no gaps in the batch

### 2c. Emptiness proof against `old_root` (lines 471-479) — OK

`authenticate_empty_batch` builds the empty subtree hash for `log_batch_size` levels and walks the upper siblings to `old_root`.

Proves that positions `[start_index .. start_index + batch_size)` were all-empty before the batch.

### 2d. `new_root` verification — MISSING (CRITICAL)

The verifier **never checks `new_root`**. It returns `true` at line 515 without verifying any root transition. A malicious prover can:

1. Supply valid predecessors against `old_root`
2. Supply valid linked-list constraints
3. Supply valid emptiness proof
4. Set `new_root` to any arbitrary value

The proof is not binding on `new_root`.

---

## 3. What is missing for soundness

### 3a. Phase A: `old_root -> mid_root` (predecessor updates)

The predecessors sit at **arbitrary** tree positions. Updating predecessor `i` changes its leaf hash, which ripples up the Merkle tree. If predecessors `i` and `j` share internal nodes, updating `i` invalidates the siblings captured for `j`.

The current proof only stores `pred_old_siblings[i]` — all captured against `old_root`. These suffice for **authentication** (step 2a) but **cannot** be used to verify the sequential transition `old_root -> ... -> mid_root`, because each update shifts the root and stales subsequent siblings.

**Conclusion**: additional witness data is needed for this phase.

### 3b. Phase B: `mid_root -> new_root` (batch insertion)

The batch occupies a contiguous, aligned subtree. This is efficient:

1. Compute each new leaf hash: `H::commit_node(leaf_value, leaf_next_index, leaf_next_value)` — N hashes
2. Build the batch subtree bottom-up — `N * log2(N)` hashes (with `N/2 + N/4 + ... + 1`)
3. Walk the upper siblings from `new_node_upper_siblings_after_pred_update` to the root — `depth - log2(N)` hashes
4. Result must equal `new_root`

All data for this phase is already in the proof (`new_node_upper_siblings_after_pred_update`). It just needs to be wired into the verifier.

### 3c. Phase A+B bridge: emptiness against `mid_root`

`new_node_upper_siblings_after_pred_update` is already captured. The verifier should confirm the batch slots are **still empty** in `mid_root` (predecessor updates don't touch batch slots, but the verifier should check this). This is already present in the proof but unused.

---

## 4. Approaches for Phase A in the STARK circuit

### Option 1: Sequential predecessor updates (simple, baseline)

Add to the proof: for each masked predecessor (in order), a full sibling path against the **running** intermediate root.

```
root_0 = old_root
for each i where mask[i]:
    verify(old_pred_hash[i], siblings_i, root_i)  // must match running root
    compute new_pred_hash[i]
    root_{i+1} = recompute_root(new_pred_hash[i], siblings_i)
mid_root = root_k
```

**Cost**: `K * depth` hashes, where `K = count(mask[i] == true)`.

**Witness size**: K full sibling paths (each `depth` digests).

This is essentially the chained approach for the predecessor half, but the batch-subtree insertion (Phase B) still saves work.

### Option 2: Sparse Merkle multiproof (complex, optimal)

Provide the minimal union of all K Merkle paths as a single tree structure. Verify it against `old_root`, swap the K leaf hashes, recompute `mid_root` in one upward pass.

**Cost**: at most `K * depth` hashes but likely fewer due to path sharing at upper levels. For K predecessors in a depth-D tree, the combined structure has at most `K * D` but typically `O(K * log(N/K) + D)` nodes.

**Circuit complexity**: significantly harder — requires a variable-topology hash DAG, or a fixed-size trace with masking. Likely not worth it for a first implementation.

### Option 3: Hybrid — sequential updates, shared upper path

Observe that all predecessor paths converge toward the root. If predecessors are sorted by path, adjacent updates share most of their upper siblings.

Provide: for each masked predecessor, only the **new** siblings (the ones that changed since the previous update). Reuse unchanged upper siblings from the prior step.

**Cost**: between `K * depth` and `K * log(K) + depth`, depending on path overlap.

**Recommendation**: start with Option 1. It's the simplest, and the STARK savings come primarily from Phase B (the batch subtree).

---

## 5. Cost comparison

Let `N` = batch size, `D` = tree depth, `K` = number of distinct predecessors (`<= N`).

| Approach | Hash operations | Witness (digests) |
|---|---|---|
| Naive chained (N single inserts) | `2 * N * D` | `2 * N * D` |
| Batch (Option 1 for Phase A) | `K * D + N * log2(N) + (D - log2(N))` | `K * D + (D - log2(N))` |
| Savings | `(2N - K) * D - N * log2(N)` | `(2N - K - 1) * D + (N + 1) * log2(N)` |

When `K ~ N` (no chaining): savings ~ `N * (D - log2(N))` hashes.
When `K ~ 1` (max chaining): savings ~ `(2N - 1) * D - N * log2(N)` hashes.

For `N = 16, D = 32`: naive = 1024 hashes, batch = ~576 (K=N) to ~192 (K=1). Significant.

---

## 6. Structural issues for STARK translation

### 6a. `mask` must be a witness, not a public input

Currently `mask` is in the proof struct alongside public inputs. In the STARK circuit, `mask` should be a **private witness** — the verifier doesn't need to know which predecessors chain. The constraints enforce consistency regardless.

### 6b. `connect_mid` has a duplicated constraint

Lines 311-315 and 329-333 both check `conditional_eq(!other.mask, &self.pred_new_next_value, &other.pred_new_next_value)`. Remove one.

### 6c. Right helper's `leaf_next` is computed but unused

In the verification loop (lines 422-432), the right helper's `leaf_next_value` and `leaf_next_index` are populated but never read by `connect_mid` (which only accesses `other.{mask, pred_*, leaf_index, leaf_value}`). These fields can be dropped from the right helper.

### 6d. Redundant predecessor authentication for chained leaves

When mask[i]=false, `pred_old_siblings[i]` duplicates a previous masked entry's siblings (same predecessor, same tree state). In the STARK circuit, skip the Merkle path check for mask[i]=false rows — the chain constraints already bind them to the authenticated predecessor.

### 6e. `pred_old_siblings` are insufficient for mid_root

As discussed in section 3a, these siblings are all against `old_root`. The proof generation needs to be extended to capture sequential intermediate siblings for each predecessor update. The `insert_batch` function would need an additional loop that applies updates one-by-one and snapshots siblings between each.

---

## 7. Recommended next steps

1. **Implement Phase B verification** (`mid_root -> new_root`): straightforward, all data already present
2. **Extend proof generation** to capture sequential predecessor-update siblings
3. **Implement Phase A verification** (`old_root -> mid_root`): sequential updates using new siblings
4. **Bridge**: verify emptiness against both `old_root` and `mid_root`
5. **Remove** debug `println!` statements and duplicate constraints
6. **Add adversarial tests**: tampered `new_root`, swapped leaves, fake predecessors, mask manipulation
7. **Design STARK trace layout** based on the verified native logic
