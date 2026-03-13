# BatchBuilder PI Accessor Methods

## Goal

Enable comparing the i-th TX public inputs between `BatchBuilder` (pre-finalization)
and `FinalizedBatch` (post-finalization) by exposing dedicated accessor methods and
splitting padding out of `finalize()`.

## Progress

| # | Task | Status |
|---|------|--------|
| 1 | Extract `pad()` from `finalize()` | ◻ |
| 2 | Add `BatchBuilder::tx_pi(i)` | ◻ |
| 3 | Add `FinalizedBatch::tx_pi(i)` | ◻ |
| 4 | Add unit test comparing PIs pre/post finalize | ◻ |

---

## 1. Extract `pad()` from `finalize()`

**File:** `tessera-server/src/sequencer/batch.rs`

Currently `finalize()` (lines 269–397) does three things in sequence:
1. Fill remaining NC positions in open `Deposit` slots with dummies (lines 270–289)
2. Pad remaining slots with `Empty` up to `account_batch_size` (lines 291–311)
3. Build leaf arrays, sort AN/NN, return `FinalizedBatch` (lines 313–397)

**Change:** Extract steps 1 + 2 into a new `pub fn pad(&mut self)` method.

```rust
/// Fill remaining NC positions in open deposit slots with dummies and
/// pad remaining slots with `Empty` up to `account_batch_size`.
///
/// Idempotent: calling `pad()` on an already-padded builder is a no-op.
pub fn pad(&mut self) {
    // 1. Finalize open deposit slots: fill nc[nc_filled..8] with dummies.
    for (slot_idx, slot) in self.slots.iter_mut().enumerate() {
        if let BatchSlot::Deposit { nc, nc_filled, .. } = slot {
            let nc_base = self.nc_start + slot_idx * NOTES_PER_SLOT;
            for (j, nc_slot) in nc.iter_mut().enumerate()
                .skip(*nc_filled)
                .take(NOTES_PER_SLOT - *nc_filled)
            {
                *nc_slot = derive_dummy_leaf(nc_base + j, &self.nc_root);
            }
            *nc_filled = NOTES_PER_SLOT;
        }
    }

    // 2. Pad remaining slots with Empty.
    while self.slots.len() < self.account_batch_size {
        let slot_idx = self.slots.len();
        let ac = derive_dummy_leaf(self.ac_start + slot_idx, &self.ac_root);
        let an = derive_dummy_leaf(self.an_start + slot_idx, &self.an_root);
        let nc_base = self.nc_start + slot_idx * NOTES_PER_SLOT;
        let nc: [[u8; 32]; 8] =
            core::array::from_fn(|j| derive_dummy_leaf(nc_base + j, &self.nc_root));
        let nn_base = self.nn_start + slot_idx * NOTES_PER_SLOT;
        let nn: [[u8; 32]; 8] =
            core::array::from_fn(|j| derive_dummy_leaf(nn_base + j, &self.nn_root));
        self.slots.push(BatchSlot::Empty { ac, an, nc, nn });
    }
}
```

Then `finalize()` becomes:

```rust
pub fn finalize(mut self) -> FinalizedBatch {
    self.pad();
    // ... steps 3–5 unchanged (build leaf arrays, sort, return) ...
}
```

**Notes:**
- `pad()` is idempotent — deposit slots with `nc_filled == 8` are skipped, and
  the `while` loop is a no-op when `slots.len() == account_batch_size`.
- `pad()` takes `&mut self` (non-consuming), so the builder remains usable
  for `tx_pi()` calls afterward.

---

## 2. Add `BatchBuilder::tx_pi(i)`

**File:** `tessera-server/src/sequencer/batch.rs`

Add an accessor that returns the i-th slot's four leaf groups **after padding**.

```rust
/// Return type for per-slot TX public inputs.
pub struct SlotPI {
    pub ac: [u8; 32],
    pub an: [u8; 32],
    pub nc: [[u8; 32]; 8],
    pub nn: [[u8; 32]; 8],
}

impl BatchBuilder {
    /// Return the public inputs (AC, AN, NC, NN leaves) for the i-th slot.
    ///
    /// **Must be called after `pad()`** — panics if `i >= slots.len()`.
    pub fn tx_pi(&self, i: usize) -> SlotPI {
        match &self.slots[i] {
            BatchSlot::PrivateTx { ac, an, nc, nn, .. }
            | BatchSlot::Deposit { ac, an, nc, nn, .. }
            | BatchSlot::Empty { ac, an, nc, nn } => SlotPI {
                ac: *ac,
                an: *an,
                nc: *nc,
                nn: *nn,
            },
        }
    }
}
```

**Notes:**
- Works before or after `pad()`, but before padding the NC positions of
  partially-filled `Deposit` slots will contain zeros (not dummies).
  Callers comparing against `FinalizedBatch` should call `pad()` first.

---

## 3. Add `FinalizedBatch::tx_pi(i)`

**File:** `tessera-server/src/sequencer/batch.rs`

Returns the same `SlotPI` struct for slot `i` from the finalized arrays.
AN/NN are returned in **arrival order** (un-sorted) by inverting the permutation.

```rust
impl FinalizedBatch {
    /// Return the public inputs for the i-th slot (arrival order).
    ///
    /// AC and NC are stored in arrival order already.
    /// AN and NN are stored sorted — this method inverts the sort
    /// permutation to recover slot-order values.
    pub fn tx_pi(&self, i: usize) -> SlotPI {
        let ac = self.ac_leaves[i];

        // an_sort_perm[i] = sorted position of slot i
        let an = self.an_sorted[self.an_sort_perm[i]];

        let nc_base = i * NOTES_PER_SLOT;
        let nc: [[u8; 32]; 8] =
            core::array::from_fn(|j| self.nc_leaves[nc_base + j]);

        // nn_sort_perm maps per-note index → sorted position
        let nn_base = i * NOTES_PER_SLOT;
        let nn: [[u8; 32]; 8] =
            core::array::from_fn(|j| self.nn_sorted[self.nn_sort_perm[nn_base + j]]);

        SlotPI { ac, an, nc, nn }
    }
}
```

---

## 4. Unit test

Add a test that populates a `BatchBuilder` with a mix of real TXs and deposits,
calls `pad()`, then `finalize()`, and asserts `bb.tx_pi(i) == fb.tx_pi(i)` for
every slot.

```rust
#[test]
fn tx_pi_matches_after_finalize() {
    let (ac, an, nc, nn) = make_trees();
    let mut bb = BatchBuilder::new(ACCOUNT_BATCH, &ac, &an, &nc, &nn);

    // 1 real TX + 2 deposits
    bb.add_private_tx(
        vec![0xFF],
        dummy_leaf(1), dummy_leaf(2),
        [dummy_leaf(3); 8], [dummy_leaf(4); 8],
    ).unwrap();
    bb.add_deposit(dummy_leaf(10)).unwrap();
    bb.add_deposit(dummy_leaf(11)).unwrap();

    // Pad in place so we can read PIs before consuming
    bb.pad();

    // Snapshot PIs from builder
    let builder_pis: Vec<SlotPI> = (0..ACCOUNT_BATCH)
        .map(|i| bb.tx_pi(i))
        .collect();

    // Finalize (consumes builder)
    let fb = bb.finalize();

    // Compare slot-by-slot
    for i in 0..ACCOUNT_BATCH {
        let fb_pi = fb.tx_pi(i);
        assert_eq!(builder_pis[i].ac, fb_pi.ac, "AC mismatch at slot {i}");
        assert_eq!(builder_pis[i].an, fb_pi.an, "AN mismatch at slot {i}");
        assert_eq!(builder_pis[i].nc, fb_pi.nc, "NC mismatch at slot {i}");
        assert_eq!(builder_pis[i].nn, fb_pi.nn, "NN mismatch at slot {i}");
    }
}
```

---

## Implementation order

1 → 2 → 3 → 4 (sequential, all in `batch.rs`)
