# SuperAggregator Wire Conflict — Root Cause & Fix

## Problem

The SuperAggregator `prove()` fails with:

```
Partition containing Wire(Wire { row: N, column: M }) was set twice
with different values: X != Y
```

This occurs when `n_tx_slots > 2` (i.e. any aggregator depth > 1).
The 2-TX test (depth=1) passes; the 4-TX and 128-TX tests fail.

## Root Cause

**`builder.connect(a, b)` merges wire partitions.**

When two gate outputs are connected — or when many gate outputs are
all connected to the same cached `builder.zero()` target — plonky2
merges all their wires into a single partition.  During witness
generation, each gate's generator independently tries to write its
computed value to the canonical representative wire of the merged
partition.  The second write panics even if the values agree, and
certainly panics when they differ.

### Affected patterns

1. **Multi-set equality (`assert_multiset_eq`)**

   ```rust
   builder.connect_extension(prod_a, prod_b);
   ```

   `prod_a` and `prod_b` are both outputs of `mul_extension` chains.
   `connect_extension` calls `connect` on each base-field component,
   merging two `MulExtensionGate` output wires into one partition.
   Both generators try to write → conflict.

2. **Conditional positional connect (AC / NC)**

   ```rust
   let gated = builder.mul(is_real.target, diff);
   builder.connect(gated, builder.zero());
   ```

   `builder.zero()` is a **cached singleton** target.  Connecting N
   different `gated` targets to it creates one partition of N+1 wires.
   N `ArithmeticGate` generators all try to write to the canonical
   representative → conflict.

### Why 2-TX works

With `n_tx_slots = 2`:
- AC has `2 × 4 = 8` conditional connects to `builder.zero()`.
- NC has `2 × 8 × 4 = 64` conditional connects.
- The multi-set products are short (2 elements each).

Plonky2's partition merging for small counts may still work because
the generator scheduling happens to set the canonical wire first.
With 4+ slots the scheduling no longer aligns, exposing the conflict.

## Validated Fix (multi-set equality)

Replace `connect_extension(prod_a, prod_b)` with:

```rust
let diff = builder.sub_extension(prod_a, prod_b);
let zero_ext = builder.zero_extension();
for i in 0..D {
    builder.connect(diff.0[i], zero_ext.0[i]);
}
```

`sub_extension` produces a **fresh** gate output.  Each component
connects only one gate output to `zero_ext.0[i]` (which is
`builder.zero()`) — exactly 2 wires per partition, not N.

**Status: validated, 4-TX all-dummy passes with this fix alone
(AC/NC disabled).**

## Pending Fix (conditional positional connect for AC / NC)

The same principle applies: avoid connecting N gate outputs to the
same cached zero.  Two possible approaches:

### Option A — `sub` + per-pair connect (recommended)

Compute the difference and connect each pair independently, never
reusing `builder.zero()` across iterations:

```rust
for k in 0..4 {
    let tx_t = tx_proof.public_inputs[tx_base + TX_DATA_OFFSET + 4 + k];
    let ac_t = ac_proof.public_inputs[LEAF_OFFSET + s * 4 + k];
    let diff = builder.sub(tx_t, ac_t);
    let gated = builder.mul(is_real.target, diff);
    // Fresh virtual target per constraint, individually constrained to 0.
    let z = builder.add_virtual_target();
    builder.connect(z, builder.zero());   // z is in a 2-wire partition with zero
    builder.connect(gated, z);            // gated joins that 2-wire partition → 3 wires
}
```

This limits each partition to 3 wires (gated, z, zero) — but zero is
shared.  If this still conflicts, use Option B.

### Option B — accumulate into a single check

Accumulate all `is_real * (tx_t - ac_t)` values with random
coefficients and assert the sum is zero with one `connect`:

```rust
let mut acc = builder.zero();
let mut power = builder.one();
// `r` = random challenge derived from tree PIs (Fiat-Shamir)
for each (s, k) {
    let gated = builder.mul(is_real.target, diff);
    let term = builder.mul(power, gated);
    acc = builder.add(acc, term);
    power = builder.mul(power, r);
}
builder.connect(acc, builder.zero());  // single connect
```

One partition of 2 wires (acc output + zero).  No multi-write.
Soundness: random linear combination over Goldilocks gives
negligible false-positive probability.

### Option C — register as public inputs

Make each `gated` value a public input of the SA circuit and verify
they are all zero in the external verifier / on-chain.  Changes the
PI layout (currently 8 Keccak words) so requires contract updates.

## Steps to Complete

| # | Task | Status |
|---|------|--------|
| 1 | Fix `assert_multiset_eq`: `sub_extension` + per-component connect | Done |
| 2 | Fix AC conditional connect: `select` + per-pair connect | Done |
| 3 | Fix NC conditional connect: same `select` pattern as AC | Done |
| 4 | Re-enable all cross-checks in `setup_builder` | Done |
| 5 | Run 4-TX all-dummy test | — (covered by step 8) |
| 6 | Run 4-TX 2-real + 2-dummy test | — (covered by step 8) |
| 7 | Run 2-TX test (regression) | Done |
| 8 | Run SA unit tests (`cargo test -p tessera-trees --release`) | Done (23/23 pass) |
| 9 | Scale up to 128-TX test | Pending |
| 10 | Clean up debug comments, `cargo fmt`, `cargo clippy` | Done |

## Validated Fix (conditional positional connect for AC / NC)

Instead of `is_real * (tx_t - ac_t) → connect(gated, zero)` (which merges
N gate outputs into one partition via the cached `builder.zero()`), use:

```rust
let val = builder.select(is_real, tx_t, ac_t);
builder.connect(val, ac_t);
```

- When `is_real=1`: `val = tx_t` → connect enforces `tx_t == ac_t`.
- When `is_real=0`: `val = ac_t` → connect is trivially `ac_t == ac_t`.

Each connect creates an independent 2-wire partition `{val_i, ac_t_i}`.
No connection to the global zero singleton — no N-way partition merge.

## Current State of `super_aggregator.rs`

- Multi-set equality (AN, NN): **fixed and enabled** (sub_extension pattern).
- AC conditional connect: **fixed and enabled** (select pattern).
- NC conditional connect: **fixed and enabled** (select pattern).
- All 23 unit tests pass.
