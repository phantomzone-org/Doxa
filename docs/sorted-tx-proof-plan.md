# Fix: Align TX Proofs with Sorted Nullifier Tree Ordering

## Progress Tracker

| # | Task | Status |
|---|------|--------|
| 1 | Sequencer: sort all 4 padded batches before proofs | DONE |
| 2 | Prover: build TX leaf proofs from sorted tree data | DONE |
| 3 | SuperAggregator: unconditional `connect(tx_t, tree_t)` | DONE |
| 4 | Contract: receive full batches for all 4 trees | DONE |
| 5 | Update tests (Solidity + Rust) | DONE |
| 6 | Rebuild SuperAggregator artifacts | TODO |

---

## 1. Problem

NN/AN `insert_batch` sorts leaves (`native.rs:368`). NN/AN circuit PIs are in
**sorted** order. TX proof PIs are in **submission** order. The SuperAggregator
cross-checks by positional index → mismatch when `is_real=1` → wire conflict.

Batch 1 (deposit-consume, `is_real=0` everywhere) passes trivially.
Batch 2 (private TX, `is_real=1`) fails.

---

## 2. Solution

**Sequencer sorts all 4 padded batches** (NC, NN, AC, AN) before building any
proofs or sending data on-chain. The prover builds TX leaf proofs directly from
the sorted tree data. Since the TX leaf circuit is trivial (no constraints),
this is cheap.

After sorting, NN/AN `insert_batch` sort is a no-op (pre-sorted input), and
NC/AC `insert_batch` appends in the given (sorted) order. All 4 tree PIs are
in the same sorted order.

The SuperAggregator cross-check changes from conditional (`select`) to
unconditional (`connect`), since every TX slot (real or dummy) now carries the
actual tree leaf values. `is_real` remains as a boolean PI but is not used in
the cross-check.

The contract receives full batches for all 4 trees (not just NN/AN). This
removes `_reconstructBatchWithDummies` entirely.

---

## 3. Changes

### 3.1 Sequencer (`pipeline.rs` — both `start_batch` and `register_tx_batch`)

After `build_proving_commitments` for all 4 trees, sort each padded batch:

```rust
// Sort all 4 padded batches by value.
nn_padded_bytes.sort();
nc_padded_bytes.sort();
an_padded_bytes.sort();
ac_padded_bytes.sort();

// Convert to hashes for insert_batch.
let nn_hashes = contract::bytes_slice_to_hashes(&nn_padded_bytes)?;
let nc_hashes = contract::bytes_slice_to_hashes(&nc_padded_bytes)?;
let an_hashes = contract::bytes_slice_to_hashes(&an_padded_bytes)?;
let ac_hashes = contract::bytes_slice_to_hashes(&ac_padded_bytes)?;
```

Send full batches to contract (all 4 arrays are `batchSize` elements):

```rust
bridge.registerTransactionBatchUpdate(
    new_nc_root, nc_full,   // full sorted NC batch
    new_nn_root, nn_full,   // full sorted NN batch
    new_ac_root, ac_full,   // full sorted AC batch
    new_an_root, an_full,   // full sorted AN batch
).send().await?;
```

Pass sorted leaf bytes in `ProveRequest` so the prover can build TX proofs:

```rust
ProveRequest {
    batch_id,
    notes_commitment_proof: nc_proof,
    notes_nullifier_proof: nn_proof,
    accounts_commitment_proof: ac_proof,
    accounts_nullifier_proof: an_proof,
    // Sorted leaf data for TX proof construction:
    nc_sorted_bytes, nn_sorted_bytes,
    ac_sorted_bytes, an_sorted_bytes,
    real_account_slots: Vec<usize>,  // which sorted AN positions are real
}
```

### 3.2 Prover (`prover.rs`)

Build all 128 TX leaf proofs from the sorted tree data. The TX leaf circuit is
trivial (73 PIs, no constraints), so proving is fast:

```rust
for s in 0..account_batch_size {
    let is_real = real_account_slots.contains(&s);
    // PI[0]     = is_real
    // PI[1..33] = nn_sorted[s*8..(s+1)*8]  (4 fields each)
    // PI[33..65]= nc_sorted[s*8..(s+1)*8]  (4 fields each)
    // PI[65..69]= an_sorted[s]             (4 fields)
    // PI[69..73]= ac_sorted[s]             (4 fields)
    let proof = tx_leaf_circuit.prove(pw)?;
}
```

Aggregate 128 leaf proofs via existing TX aggregator (unchanged).

### 3.3 SuperAggregator (`super_aggregator.rs`)

Remove the `select(is_real, tree_t, zero)` guard. Use unconditional connect:

```rust
// BEFORE
let expected = builder.select(is_real, nn_t, zero);
builder.connect(tx_t, expected);

// AFTER
builder.connect(tx_t, nn_t);
```

`is_real` is still asserted boolean and registered as PI (for downstream use)
but no longer participates in the cross-check. Rebuild SuperAggregator
artifacts after this change.

### 3.4 Contract (`TesseraRollup.sol`)

- All 4 arrays become full `batchSize` batches (NC/AC change from real-only).
- Remove `_reconstructBatchWithDummies`.
- Keep `_requireSorted` for NN and AN.
- All 4 use `_packBytes32Array` (calldata) for `superPiCommitment`.

### 3.5 Tests

- Solidity: update `registerTransactionBatchUpdate` calls to pass full batches.
- Rust `super_aggregator::tests`: dummy TX slots carry tree leaf values
  (not zeros).

---

## 4. What Does NOT Change

- Tree circuits (NC, NN, AC, AN) — unchanged.
- TX leaf circuit — unchanged (73 PIs, trivial).
- TX aggregator — unchanged.
- BN128 / Groth16 wrapping — unchanged.
- Client — unchanged (sends same `PrivateTxRequest`).
- Only SuperAggregator artifacts need rebuilding.
