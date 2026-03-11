# Plonky2 Wire Partition Conflicts — Comprehensive Guide

## The Error

```
Partition containing Wire(Wire { row: N, column: M }) was set twice
with different values: X != Y
```

This panic occurs during **witness generation** when two or more gate
generators write **different** values to the same canonical wire.  It is
a plonky2 framework-level error, not a logic bug in the circuit
constraints themselves.

---

## Background: How Plonky2 Handles `connect`

### Wire Partitions

Plonky2 maintains a **Union-Find** data structure over all wires in the
circuit.  Each wire belongs to exactly one partition, and each partition
has a single **canonical representative** wire.

When you call:

```rust
builder.connect(a, b);
```

plonky2 **merges** the partition of `a` and the partition of `b` into a
single partition.  This is *transitive*: if `a` is connected to `c`
elsewhere, then after `connect(a, b)`, wire `b` is also in the same
partition as `c`.

### Witness Generation

Each gate has a **generator** — a closure that reads the gate's input
wires and writes the computed value to the gate's output wire.  During
witness generation:

1. The partial witness is initialized with any pre-set values (e.g.
   public inputs, proof targets set by the prover).
2. Generators run reactively — a generator fires when its inputs become
   available.  Each write is **redirected** to the canonical
   representative of the wire's partition.
3. If a canonical representative already holds a value, plonky2 checks
   that the new write **matches**.  Duplicate same-value writes succeed.
   Different values → **panic**.

### Key Insight: Same-Value Writes Are Safe

Connecting N gate outputs to `builder.zero()` creates a partition of
N+1 wires.  N generators all write to the canonical representative.
**If all computed values are zero (constraint satisfied), all writes
agree and plonky2 accepts the duplicates.**  This is why patterns like
`builder.assert_zero(diff)` inside loops (e.g. `enforce_add_eq`, called
thousands of times in the same circuit) work without issues.

The panic only occurs when generators write **different** values.

---

## The SuperAggregator Bug

### What We Know

The SuperAggregator `prove()` failed with the "set twice" panic when
`n_tx_slots > 2`.  The error went away after replacing
`connect_extension(prod_a, prod_b)` with `sub_extension` +
per-component connect in `assert_multiset_eq`.

### What We Proved Via Reproduction Tests

Three minimal reproduction tests (`test_repro_connect_extension_*`)
demonstrate that **`connect_extension` works correctly in isolation**:

- Two `mul_extension` chains with identical inputs + `connect_extension`
  → **passes** (same values, duplicate writes accepted).
- Two chains with different inputs + `connect_extension` → **correctly
  fails** (different values detected).
- Full multiset fingerprint pattern (Poseidon challenges, same set) +
  `connect_extension` → **passes**.

### Root Cause: Unknown

The `sub_extension` refactor fixed the bug in the full SA circuit, but
`connect_extension` is not inherently broken.  The root cause is likely
an **interaction specific to the large circuit** (5 recursive proof
verifications + cross-checks + Keccak), where partition merging from
`connect_extension` creates a transitive chain that pulls in generators
from unrelated parts of the circuit (e.g. proof verification internals).
In a large circuit, wires that appear independent may share partitions
through intermediate gates, and `connect_extension` adds more merge
points that can trigger latent conflicts.

The `sub_extension` pattern avoids this by keeping the two chain
endpoints as **inputs** to a fresh gate, rather than merging their
output partitions.

---

## Defensive Patterns

Even though `connect_extension` works in simple circuits, the
`sub_extension` pattern is strictly safer because it never merges two
gate output partitions.  Use these patterns defensively:

### Pattern 1: `sub` / `sub_extension` + Connect to Zero

**Use case:** Assert `a == b` (base or extension field).

```rust
// Base field:
let diff = builder.sub(a, b);
builder.connect(diff, builder.zero());

// Extension field:
let diff = builder.sub_extension(a, b);
let zero_ext = builder.zero_extension();
for i in 0..D {
    builder.connect(diff.0[i], zero_ext.0[i]);
}
```

**Why it's safe:** `sub` / `sub_extension` creates a fresh gate output
that **reads** both operands.  The original partitions of `a` and `b`
are not merged.  Only the fresh diff output connects to zero.

### Pattern 2: `select` + `connect` (Conditional Equality)

**Use case:** Assert `a == b` when `flag == 1`, no constraint when
`flag == 0`.

```rust
let val = builder.select(flag, a, b);
builder.connect(val, b);
```

- When `flag=1`: `val = a` → enforces `a == b`.
- When `flag=0`: `val = b` → trivially `b == b`.

**Why it's safe:** Each `connect(val_i, b_i)` creates an independent
partition.  No shared target across iterations (as long as `b_i` targets
are distinct, e.g. different proof PI indices).

### Pattern 3: `assert_zero` in a Loop

**Use case:** Assert N values are all zero.

```rust
for i in 0..N {
    let diff = builder.sub(a[i], b[i]);
    builder.assert_zero(diff);  // connects to cached zero
}
```

**This is safe.** All generators compute 0 (for a valid witness), and
plonky2 tolerates duplicate same-value writes.  The zero partition grows
by N wires, but no conflict occurs.

---

## When to Use Which Pattern

```
Need: a == b (unconditional)?
├─ Simple/small circuit → connect(a, b) is fine
├─ Large circuit with proof verifications
│   └─ Use sub(a, b) + connect(diff, zero) to be safe
└─ Extension field
    └─ Use sub_extension(a, b) + per-component connect to zero

Need: a == b only when flag == 1?
└─ Use select(flag, a, b) + connect(val, b)

Need: N values all == 0?
└─ assert_zero(x) in a loop is fine
```

---

## Summary Table

| Pattern | Safe? | Notes |
|---------|-------|-------|
| `assert_zero(x)` × N | **Yes** | All generators write 0, duplicates OK |
| `connect(a, b)` in simple circuit | **Yes** | No partition conflicts in small circuits |
| `connect(a, b)` in large circuit | **Fragile** | May create transitive partition merges with unrelated generators |
| `connect_extension(a, b)` in large circuit | **Fragile** | Same risk as above, D connections |
| `sub(a, b)` + `connect(diff, zero)` | **Yes** | Fresh gate, no output partition merge |
| `sub_extension` + component connect | **Yes** | Extension-field version of above |
| `select(flag, a, b)` + `connect(val, b)` | **Yes** | Independent partitions per pair |
