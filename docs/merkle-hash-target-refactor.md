# Refactor: Const-Generic `MerkleHashTarget<N>`

**Goal**: Replace the hardcoded `HashOutTarget` (4 elements) in the `MerkleHashCircuit` trait
with a const-generic `MerkleHashTarget<const N: usize>([Target; N])`.
This eliminates the pack/unpack overhead in the Keccak-256 Merkle implementation
and makes the hash size a compile-time parameter.

---

## Progress Tracker

| # | Task | Status |
|---|------|--------|
| 1 | Define `MerkleHashTarget<N>` in `hasher.rs` | `[ ]` |
| 2 | Add helper methods on `MerkleHashTarget<N>` | `[ ]` |
| 3 | Refactor `MerkleHashCircuit` trait to use `MerkleHashTarget<N>` | `[ ]` |
| 4 | Update `HashOutput` (Poseidon, N=4) impl | `[ ]` |
| 5 | Rewrite `KeccakHashOutput` (N=8) impl — remove pack/unpack | `[ ]` |
| 6 | Update `HASH_SIZE` usages and inclusion circuit | `[ ]` |
| 7 | Update `tessera-trees` consumer files | `[ ]` |
| 8 | Update `tessera-client` consumer files | `[ ]` |
| 9 | `cargo fmt` + `cargo clippy` + tests | `[ ]` |

---

## 1. Define `MerkleHashTarget<N>` (`hasher.rs`)

```rust
/// Circuit-level hash target with a compile-time element count.
///
/// - Poseidon: `MerkleHashTarget<4>` (maps 1:1 to plonky2's `HashOutTarget`)
/// - Keccak-256: `MerkleHashTarget<8>` (one u32 word per element, no packing)
#[derive(Clone, Copy, Debug)]
pub struct MerkleHashTarget<const N: usize> {
    pub elements: [Target; N],
}
```

## 2. Helper Methods on `MerkleHashTarget<N>`

These replace the plonky2 built-ins (`add_virtual_hash`, `connect_hashes`,
`set_hash_target`) which only work with 4-element `HashOutTarget`.

```rust
impl<const N: usize> MerkleHashTarget<N> {
    /// Allocate N virtual targets.
    pub fn add_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            elements: core::array::from_fn(|_| builder.add_virtual_target()),
        }
    }

    /// Allocate N virtual targets and register them as public inputs.
    pub fn add_virtual_public_input<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            elements: core::array::from_fn(|_| builder.add_virtual_public_input()),
        }
    }

    /// Connect two hash targets element-wise (equality constraint).
    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a: &Self,
        b: &Self,
    ) {
        for i in 0..N {
            builder.connect(a.elements[i], b.elements[i]);
        }
    }

    /// Conditional connect: if flag == 1, connect a == b.
    pub fn conditional_connect<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        flag: BoolTarget,
        a: &Self,
        b: &Self,
    ) {
        for i in 0..N {
            builder.conditional_assert_eq(flag.target, a.elements[i], b.elements[i]);
        }
    }

    /// Per-element select: if dir == 1 pick `a`, else pick `b`.
    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        dir: BoolTarget,
        a: &Self,
        b: &Self,
    ) -> Self {
        Self {
            elements: core::array::from_fn(|i| builder.select(dir, a.elements[i], b.elements[i])),
        }
    }

    /// Set witness values from a field-element slice.
    pub fn set_witness<F: Field>(
        pw: &mut PartialWitness<F>,
        target: &Self,
        values: &[F; N],
    ) -> anyhow::Result<()> {
        for i in 0..N {
            pw.set_target(target.elements[i], values[i])?;
        }
        Ok(())
    }
}
```

### Conversion to/from plonky2 `HashOutTarget` (N=4 only)

```rust
impl MerkleHashTarget<4> {
    pub fn from_hash_out_target(h: HashOutTarget) -> Self {
        Self { elements: h.elements }
    }

    pub fn to_hash_out_target(&self) -> HashOutTarget {
        HashOutTarget { elements: self.elements }
    }
}
```

This keeps backward compatibility for code that still uses plonky2's `HashOutTarget`
directly (e.g. `builder.hash_n_to_hash_no_pad` returns `HashOutTarget`).

## 3. Refactor `MerkleHashCircuit` Trait

**Before:**
```rust
pub trait MerkleHashCircuit<F: Field, const D: usize>: Clone + Debug {
    type Digest: ToHashOut<F>;
    const HEAD: HashOut<F>;
    const TAIL: HashOut<F>;
    fn hash_2_to_1_circuit(..., cur: HashOutTarget, sib: HashOutTarget, dir: BoolTarget) -> HashOutTarget;
    fn hash_root_circuit(..., num_leaves: Target, left: HashOutTarget, right: HashOutTarget) -> HashOutTarget;
    fn commit_node_circuit(..., value: HashOutTarget, next_index: Target, next_value: HashOutTarget) -> HashOutTarget;
}
```

**After:**
```rust
pub trait MerkleHashCircuit<F: Field, const D: usize>: Clone + Debug {
    /// Number of field elements in a hash (4 for Poseidon, 8 for Keccak).
    const HASH_SIZE: usize;

    type Digest: ToHashOut<F>;

    /// Circuit-level hash target type alias.
    type HashTarget: Copy + Clone + Debug;

    const HEAD: Self::Digest;
    const TAIL: Self::Digest;

    fn hash_2_to_1_circuit(
        builder: &mut CircuitBuilder<F, D>,
        cur: Self::HashTarget,
        sib: Self::HashTarget,
        dir: BoolTarget,
    ) -> Self::HashTarget
    where F: RichField + Extendable<D>;

    fn hash_root_circuit(
        builder: &mut CircuitBuilder<F, D>,
        num_leaves: Target,
        left: Self::HashTarget,
        right: Self::HashTarget,
    ) -> Self::HashTarget
    where F: RichField + Extendable<D>;

    fn commit_node_circuit(
        builder: &mut CircuitBuilder<F, D>,
        value: Self::HashTarget,
        next_index: Target,
        next_value: Self::HashTarget,
    ) -> Self::HashTarget
    where F: RichField + Extendable<D>;

    // ── Provided helpers (delegate to MerkleHashTarget<N>) ──

    fn add_virtual_hash(builder: &mut CircuitBuilder<F, D>) -> Self::HashTarget
    where F: RichField + Extendable<D>;

    fn connect_hashes(builder: &mut CircuitBuilder<F, D>, a: Self::HashTarget, b: Self::HashTarget)
    where F: RichField + Extendable<D>;

    fn select_hash(
        builder: &mut CircuitBuilder<F, D>,
        dir: BoolTarget,
        a: Self::HashTarget,
        b: Self::HashTarget,
    ) -> Self::HashTarget
    where F: RichField + Extendable<D>;

    fn set_hash_witness(
        pw: &mut PartialWitness<F>,
        target: Self::HashTarget,
        value: &Self::Digest,
    ) -> anyhow::Result<()>;
}
```

> **Alternative (simpler):** Instead of adding all these helper methods to the trait,
> just set `type HashTarget = MerkleHashTarget<N>` and have consumers call
> `MerkleHashTarget::add_virtual(builder)`, `MerkleHashTarget::connect(builder, a, b)`, etc.
> directly. The associated type carries `N`, so consumers stay generic.
> **This is the recommended approach** — it avoids bloating the trait.

### Recommended: Simpler trait

```rust
pub trait MerkleHashCircuit<F: Field, const D: usize>: MerkleHash {
    type HashTarget: Copy + Clone + Debug;

    /// Opaque context for circuit-build-time state (e.g. lookup table indices).
    /// Poseidon: `()`. Keccak: `KeccakCircuitContext { range_lut: usize }`.
    type CircuitContext: Copy + Clone + Debug;

    /// Register any lookup tables needed by circuit methods.
    /// Must be called exactly once per `CircuitBuilder`, before hash methods.
    fn register_luts(builder: &mut CircuitBuilder<F, D>) -> Self::CircuitContext
    where F: RichField + Extendable<D>;

    fn hash_target_elements(t: &Self::HashTarget) -> &[Target];

    fn add_virtual_hash(builder: &mut CircuitBuilder<F, D>) -> Self::HashTarget
    where F: RichField + Extendable<D>;

    fn connect_hashes(builder: &mut CircuitBuilder<F, D>, a: &Self::HashTarget, b: &Self::HashTarget)
    where F: RichField + Extendable<D>;

    fn select_hash(
        builder: &mut CircuitBuilder<F, D>,
        dir: BoolTarget,
        a: &Self::HashTarget,
        b: &Self::HashTarget,
    ) -> Self::HashTarget
    where F: RichField + Extendable<D>;

    fn set_hash_witness(
        pw: &mut PartialWitness<F>,
        target: &Self::HashTarget,
        value: &Self::Digest,
    ) -> anyhow::Result<()>;

    fn hash_2_to_1_circuit(
        builder: &mut CircuitBuilder<F, D>,
        ctx: &Self::CircuitContext,
        cur: Self::HashTarget,
        sib: Self::HashTarget,
        dir: BoolTarget,
    ) -> Self::HashTarget
    where F: RichField + Extendable<D>;

    fn hash_root_circuit(
        builder: &mut CircuitBuilder<F, D>,
        ctx: &Self::CircuitContext,
        num_leaves: Target,
        left: Self::HashTarget,
        right: Self::HashTarget,
    ) -> Self::HashTarget
    where F: RichField + Extendable<D>;

    fn commit_node_circuit(
        builder: &mut CircuitBuilder<F, D>,
        ctx: &Self::CircuitContext,
        value: Self::HashTarget,
        next_index: Target,
        next_value: Self::HashTarget,
    ) -> Self::HashTarget
    where F: RichField + Extendable<D>;
}
```

## 4. Update `HashOutput` (Poseidon, N=4)

```rust
impl MerkleHashCircuit<F, 2> for HashOutput {
    type HashTarget = MerkleHashTarget<4>;

    fn add_virtual_hash(builder: &mut CircuitBuilder<F, 2>) -> Self::HashTarget { ... }
    fn connect_hashes(builder: &mut CircuitBuilder<F, 2>, a: &Self::HashTarget, b: &Self::HashTarget) { ... }
    fn select_hash(builder: &mut CircuitBuilder<F, 2>, dir: BoolTarget, a: &Self::HashTarget, b: &Self::HashTarget) -> Self::HashTarget { ... }
    fn set_hash_witness(pw: &mut PartialWitness<F>, target: &Self::HashTarget, value: &Self::Digest) -> anyhow::Result<()> { ... }
    fn hash_target_elements(t: &Self::HashTarget) -> &[Target] { &t.elements }

    fn hash_2_to_1_circuit(...) -> Self::HashTarget {
        // Same as today but wrap result:
        let out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(data);
        MerkleHashTarget { elements: out.elements }
    }
    // ... hash_root_circuit, commit_node_circuit analogous
}
```

Existing code using `builder.add_virtual_hash()` changes to `H::add_virtual_hash(builder)`.
Existing code using `builder.connect_hashes(a, b)` changes to `H::connect_hashes(builder, &a, &b)`.
Existing code using `pw.set_hash_target(t, v)` changes to `H::set_hash_witness(&mut pw, &t, &v)`.

## 5. Rewrite `KeccakHashOutput` (N=8) — No Pack/Unpack

### 5a. Range LUT: Register Once

`add_u8_range_check_lookup_table(builder)` is **not idempotent** — each call creates a
duplicate table. The LUT must be registered exactly once per circuit and the index passed
to all methods that need it (`hash_root_circuit`, `commit_node_circuit`).

**Design:** Add a `range_lut: Option<usize>` field to the trait (or pass it via a context
struct). The simplest approach: add `register_luts` to the trait and store the LUT index
in the struct.

```rust
/// Keccak circuit context — holds the range-check LUT index.
/// Constructed once per circuit via `KeccakHashOutput::register_luts(builder)`.
#[derive(Clone, Copy, Debug)]
pub struct KeccakCircuitContext {
    pub range_lut: usize,
}

impl KeccakHashOutput {
    /// Register lookup tables required by the Keccak circuit hash methods.
    /// Call exactly once per `CircuitBuilder`, before any `hash_*_circuit` calls.
    pub fn register_luts<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> KeccakCircuitContext {
        KeccakCircuitContext {
            range_lut: add_u8_range_check_lookup_table(builder),
        }
    }
}
```

Then `hash_root_circuit` and `commit_node_circuit` receive the context:

**Option A — pass context to trait methods:**
Add an associated `type CircuitContext` to the trait (Poseidon: `()`, Keccak: `KeccakCircuitContext`).
All circuit methods gain a `ctx: &Self::CircuitContext` parameter.

**Option B — store LUT in struct (simpler but changes `KeccakHashOutput`):**
Make `KeccakHashOutput` carry the LUT index when used in circuit mode.
Downside: conflates native and circuit concerns.

**Option C — trait method `register_luts` + methods that need it take `Option<usize>`:**
Methods that don't need the LUT (e.g. `hash_2_to_1_circuit` for keccak) ignore it.

**Recommended: Option A** — cleanest separation. The trait becomes:

```rust
pub trait MerkleHashCircuit<F: Field, const D: usize>: MerkleHash {
    type HashTarget: Copy + Clone + Debug;
    type CircuitContext: Copy + Clone + Debug;

    /// Register any lookup tables needed by circuit methods.
    /// Returns () for hashers that don't need LUTs (e.g. Poseidon).
    fn register_luts(builder: &mut CircuitBuilder<F, D>) -> Self::CircuitContext
    where F: RichField + Extendable<D>;

    fn hash_2_to_1_circuit(
        builder: &mut CircuitBuilder<F, D>,
        ctx: &Self::CircuitContext,
        cur: Self::HashTarget,
        sib: Self::HashTarget,
        dir: BoolTarget,
    ) -> Self::HashTarget
    where F: RichField + Extendable<D>;

    // ... hash_root_circuit, commit_node_circuit also take `ctx`
}
```

For Poseidon: `type CircuitContext = (); fn register_luts(_) -> () {}`
For Keccak: `type CircuitContext = KeccakCircuitContext; fn register_luts(b) -> KeccakCircuitContext { ... }`

### 5b. `MerkleHashCircuit` impl

```rust
impl MerkleHashCircuit<F, 2> for KeccakHashOutput {
    type HashTarget = MerkleHashTarget<8>;
    type CircuitContext = KeccakCircuitContext;

    fn register_luts(builder: &mut CircuitBuilder<F, 2>) -> Self::CircuitContext
    where F: RichField + Extendable<2>,
    {
        KeccakCircuitContext {
            range_lut: add_u8_range_check_lookup_table(builder),
        }
    }

    fn add_virtual_hash(builder: &mut CircuitBuilder<F, 2>) -> Self::HashTarget {
        MerkleHashTarget::<8>::add_virtual(builder)
    }

    fn connect_hashes(builder: &mut CircuitBuilder<F, 2>, a: &Self::HashTarget, b: &Self::HashTarget) {
        MerkleHashTarget::connect(builder, a, b);
    }

    fn select_hash(
        builder: &mut CircuitBuilder<F, 2>,
        dir: BoolTarget,
        a: &Self::HashTarget,
        b: &Self::HashTarget,
    ) -> Self::HashTarget {
        MerkleHashTarget::select(builder, dir, a, b)
    }

    fn set_hash_witness(
        pw: &mut PartialWitness<F>,
        target: &Self::HashTarget,
        value: &Self::Digest,
    ) -> anyhow::Result<()> {
        MerkleHashTarget::set_witness(pw, target, &value.0)
    }

    fn hash_target_elements(t: &Self::HashTarget) -> &[Target] { &t.elements }

    fn hash_2_to_1_circuit(
        builder: &mut CircuitBuilder<F, 2>,
        _ctx: &Self::CircuitContext, // keccak256 gadget doesn't need the range LUT
        cur: Self::HashTarget,
        sib: Self::HashTarget,
        dir: BoolTarget,
    ) -> Self::HashTarget {
        // Direct — no unpack needed, elements are already u32 targets
        let left = Self::select_hash(builder, dir, &sib, &cur);
        let right = Self::select_hash(builder, dir, &cur, &sib);

        let mut input = Vec::with_capacity(16);
        input.extend_from_slice(&left.elements);
        input.extend_from_slice(&right.elements);
        let hash: [Target; 8] = builder.keccak256::<ConfigNative>(&input);
        MerkleHashTarget { elements: hash }
    }

    fn hash_root_circuit(
        builder: &mut CircuitBuilder<F, 2>,
        ctx: &Self::CircuitContext,
        num_leaves: Target,
        left: Self::HashTarget,
        right: Self::HashTarget,
    ) -> Self::HashTarget {
        // num_leaves fits in one field element → split to [hi, lo] u32 pair
        let [nl_hi, nl_lo] = decompose_field_to_u32_pair(builder, num_leaves, ctx.range_lut);

        let mut input = Vec::with_capacity(18);
        input.push(nl_hi.0);
        input.push(nl_lo.0);
        input.extend_from_slice(&left.elements);
        input.extend_from_slice(&right.elements);
        let hash: [Target; 8] = builder.keccak256::<ConfigNative>(&input);
        MerkleHashTarget { elements: hash }
    }

    fn commit_node_circuit(
        builder: &mut CircuitBuilder<F, 2>,
        ctx: &Self::CircuitContext,
        value: Self::HashTarget,
        next_index: Target,
        next_value: Self::HashTarget,
    ) -> Self::HashTarget {
        let [idx_hi, idx_lo] = decompose_field_to_u32_pair(builder, next_index, ctx.range_lut);

        let mut input = Vec::with_capacity(18);
        input.push(idx_hi.0);
        input.push(idx_lo.0);
        input.extend_from_slice(&value.elements);
        input.extend_from_slice(&next_value.elements);
        let hash: [Target; 8] = builder.keccak256::<ConfigNative>(&input);
        MerkleHashTarget { elements: hash }
    }
}
```

**Key changes vs. previous version:**
- `unpack_hash_to_u32s` and `pack_u32s_to_hash` are **deleted entirely**.
  The 8 elements of `MerkleHashTarget<8>` are already u32 targets — no conversion needed.
- `add_u8_range_check_lookup_table` is called **once** in `register_luts()`,
  not per hash call. The LUT index is passed via `ctx: &KeccakCircuitContext`.

## 6. Update `HASH_SIZE` and Inclusion Circuit

### 6a. `HASH_SIZE`

The current `pub(crate) const HASH_SIZE: usize = 4` is used in:

- `hasher.rs`: `HashOutput(pub [F; HASH_SIZE])` — Poseidon-specific, keep as-is
- `inclusion_circuit.rs`: sizing of u, v, c_ax, c_xb arrays (currently `2 * HASH_SIZE`)
- `single_insertion/stark.rs`, `batch_insertion/stark.rs`: same pattern
- `tessera-client/src/plonky2_gadgets/priv_tx/cb.rs`: `HASH_SIZE` for element loops

**Approach:** The inclusion circuit's `inclusion()` function already takes `&[Target]` slices,
so it's naturally generic. The sizing (`2 * HASH_SIZE`) just needs to come from the hash type.
Add a `const HASH_SIZE: usize` to `MerkleHashCircuit` (or read it from the associated type).

For the consumer code that builds `IndexRangeCheckTarget`, change:
```rust
// Before:
let u = (0..2 * HASH_SIZE).map(|_| builder.add_virtual_target()).collect();

// After: use H::HASH_SIZE or a const from the hash type
let u = (0..2 * H::HASH_SIZE).map(|_| builder.add_virtual_target()).collect();
```

The `IndexRangeCheckTarget` struct should also store `a`, `x`, `b` as `H::HashTarget`
instead of `HashOutTarget`.

### 6b. `inclusion_circuit.rs`

The `IndexRangeCheckTarget` is `#[cfg(test)]` only — lower priority.
The `inclusion()` and `populate_inclusion_witness()` functions take slices and are already generic.
The `split_and_flatten` function decomposes each field element into [hi, lo] u32 pairs.

**Important**: For Keccak-256 where each element is already a u32 (< 2^32),
`split_and_flatten` will produce `[0, word]` pairs (hi=0 for all).
This is correct but doubles the number of limbs unnecessarily.
If needed, a specialized `KeccakHashOutput` inclusion check could skip the split.
For now, the generic approach works — optimize later if it matters.

## 7. Update `tessera-trees` Consumer Files

Each file needs the same mechanical changes. The pattern is:

| Before | After |
|--------|-------|
| `HashOutTarget` in type position | `H::HashTarget` |
| `builder.add_virtual_hash()` | `H::add_virtual_hash(builder)` |
| `builder.connect_hashes(a, b)` | `H::connect_hashes(builder, &a, &b)` |
| `pw.set_hash_target(t, v.to_hash_out())` | `H::set_hash_witness(&mut pw, &t, &v)` |
| `builder.add_virtual_hash_public_input()` | `H::add_virtual_public_input(builder)` (new helper) |
| `HashOutTarget { elements: from_fn(\|i\| builder.select(...)) }` | `H::select_hash(builder, dir, &a, &b)` |
| `.elements[i]` access | `H::hash_target_elements(&t)[i]` or `t.elements[i]` |
| (none — implicit) | `let ctx = H::register_luts(&mut builder);` once at circuit setup |
| `H::hash_2_to_1_circuit(builder, cur, sib, dir)` | `H::hash_2_to_1_circuit(builder, &ctx, cur, sib, dir)` |
| `H::hash_root_circuit(builder, n, l, r)` | `H::hash_root_circuit(builder, &ctx, n, l, r)` |
| `H::commit_node_circuit(builder, v, idx, nv)` | `H::commit_node_circuit(builder, &ctx, v, idx, nv)` |

### Files to update:

1. **`commitment_tree/proofs/batch_insertion/stark.rs`**
   - `compute_root_circuit<H, F, D>`: change `HashOutTarget` params/returns → `H::HashTarget`
   - Element-wise select → `H::select_hash`
   - `connect_hashes` → `H::connect_hashes`
   - `set_hash_target` → `H::set_hash_witness`

2. **`nullifier_tree/proofs/batch_insertion/stark.rs`**
   - Same pattern as above
   - `connect_hash_if` helper → use `H::conditional_connect` or per-element

3. **`nullifier_tree/proofs/single_insertion/stark.rs`**
   - Same pattern
   - `NullifierInsertProofTargets` stores `HashOutTarget` fields → change to `H::HashTarget`
   - BUT: `H` is not known at struct definition time. Options:
     - Make the struct generic: `NullifierInsertProofTargets<HT>` where `HT = H::HashTarget`
     - Or use `MerkleHashTarget<N>` directly with a const generic

4. **`nullifier_tree/proofs/chained_insertion/stark.rs`**
   - Delegates to `NullifierInsertProofTargets` — follows from (3)

5. **`nullifier_tree/proofs/single_insertion/generator.rs`**
   - Same delegation pattern

6. **`nullifier_tree/proofs/utils/inclusion_circuit.rs`**
   - `IndexRangeCheckTarget` (`#[cfg(test)]`): change `Vec<HashOutTarget>` → `Vec<H::HashTarget>`
   - `inclusion()` and `populate_inclusion_witness()` take slices — no change needed

## 8. Update `tessera-client` Consumer Files

Same mechanical pattern. Files:

1. **`merkle.rs`** — `conditional_merkle_verify_commitment_tree_gadget` and related
2. **`priv_tx/mod.rs`** — newtype wrappers use `HashOutTarget` internally
3. **`priv_tx/cb.rs`** — circuit builder extensions
4. **`priv_tx/targets.rs`** — many newtypes: `AccountCommitmentTarget(HashOutTarget)`, etc.
5. **`deposit_tx/mod.rs`** — deposit circuit
6. **`deposit_tx/cb.rs`** — deposit circuit builder
7. **`deposit_tx/targets.rs`** — deposit targets

**The `targets.rs` files** are the trickiest: structs like
`AccountCommitmentTarget(pub(crate) HashOutTarget)` need to become generic or use a
type alias. Options:
- `AccountCommitmentTarget<const N: usize>(pub(crate) MerkleHashTarget<N>)`
- Or define a type alias: `type HT = MerkleHashTarget<4>` and change later

**Recommendation:** Since `tessera-client` currently only uses Poseidon trees,
keep using `MerkleHashTarget<4>` there for now. The refactor makes the types
*ready* for Keccak but doesn't force parameterization of every client struct.
When Keccak trees are needed in client circuits, those structs can be parameterized.

## 9. Cargo fmt + Clippy + Tests

After all changes:

```bash
cargo fmt
cargo clippy -p tessera-trees -p tessera-server -p tessera-client --tests
cargo test -p tessera-trees --release -- keccak_hasher
cargo test -p tessera-trees --release -- hasher
cargo test -p tessera-trees --release
cargo test -p tessera-client --release
```

---

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Large blast radius (10+ files) | Mechanical changes, same pattern everywhere |
| Struct generics propagation | Keep `tessera-client` on `MerkleHashTarget<4>` for now |
| `split_and_flatten` suboptimal for Keccak | Works correctly, optimize later |
| Breaking `NullifierInsertProofTargets` | Add const generic `N` to struct |

## Non-Goals

- Changing the `MerkleHash` (native) trait — it already works with `type Digest`
- Changing the `DataCommitment` / PI commitment system — orthogonal
- Optimizing the inclusion circuit for keccak's u32 elements — future work
- Parameterizing `tessera-client` target newtypes — future work when keccak trees needed
