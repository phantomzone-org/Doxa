# SuperAggregator Boolean Slot Mask

## Problem

The SuperAggregator circuit has in-circuit `builder.connect()` constraints that enforce:

```
TX[slot s, note_commitment j]  == NC[leaf s×8+j]
TX[slot s, note_nullifier j]   == NN[leaf s×8+j]
TX[slot s, account_commitment] == AC[leaf s]
TX[slot s, account_nullifier]  == AN[leaf s]
```

For **consume-only batches** (no private transactions), the pipeline sends:
- NC: 128 real consumed-note commitments (non-zero)
- NN / AC / AN: deterministic dummy-padded values
- TX aggregator: 16 canonical padding proofs (all-zero PIs)

This causes a Plonky2 witness conflict: the constraint requires
`TX[note_commitment j] == NC[leaf j]`, but `TX` is zero while `NC` is non-zero.

The same problem appears for **partial TX batches** (e.g. 4 real private txs, 12 padding
slots): NC slots 4–15 contain consume-request notes (non-zero), but the padding TX proofs
for those slots have all-zero PIs.

---

## Design

### `is_real` Boolean Embedded in the TX Leaf Circuit

Add one boolean public input to the **TX leaf circuit** as `PI[0]`:

```
TX leaf PI layout (73 fields total):
  [0]      = is_real  (bool: 1 = real private tx, 0 = padding)
  [1..33]  = note_nullifiers  (8 × 4 Goldilocks fields, from NN tree)
  [33..65] = note_commitments (8 × 4 Goldilocks fields, from NC tree)
  [65..69] = account_nullifier (4 fields, from AN tree)
  [69..73] = account_commitment (4 fields, from AC tree)
```

**Canonical padding proof**: prove the TX leaf circuit with `is_real = 0` and all
72 data fields zero. This proof is always constructible regardless of what internal
TX constraints will eventually be added, because the circuit explicitly permits the
all-zero case when `is_real = 0`.

**Real TX proof**: `is_real = 1`, data fields set by the private-TX prover circuit.

Because the TX aggregator uses `ReducerKind::None`, the root proof exposes all
`16 × 73 = 1168` raw leaf field elements. The SuperAggregator reads `is_real[s]`
directly from `tx_proof.public_inputs[s * 73]`.

### SuperAggregator Constraint Change

The SuperAggregator reads `is_real[s]` from the TX root proof (not a free external
input), asserts it is boolean, then applies the conditional constraint:

```rust
let is_real_t = tx_proof.public_inputs[s * 73];
builder.assert_bool(is_real_t);
let is_real = BoolTarget::new_unsafe(is_real_t);

let expected = builder.select(is_real, tree_t, zero);
builder.connect(tx_data_t, expected);
```

Semantics:
- `is_real = 1`: `expected = tree_t` → `tx_data_t == tree_t` (real TX enforced)
- `is_real = 0`: `expected = 0`     → `tx_data_t == 0`      (canonical padding enforced)

### Soundness

| Attack | Result |
|--------|--------|
| Set `is_real=0` for a real private TX (data ≠ 0) | Circuit rejects: `tx_data_t ≠ 0 = expected` |
| Set `is_real=1` but TX note_commitment ≠ NC leaf | Circuit rejects: `tx_data_t ≠ tree_t = expected` |
| Set `is_real=0` for a consume-only slot (data = 0) | Circuit accepts; correct and intended |
| Set `is_real=1` for a padding slot (all-zero TX AND NC) | Circuit accepts (0 == 0); harmless |

`is_real` is read **from the TX proof's own public inputs** (certified by the TX leaf
circuit), not supplied as a free external witness. A downstream contract can inspect
the TX root proof's raw PIs to determine which slots were active.

### Public Input Layout

SuperAggregator root proof: **8 Goldilocks field elements** (Keccak-256 digest) — unchanged
from the original design. No mask PIs are added.

TX root proof: `16 × 73 = 1168` raw field elements (`ReducerKind::None`).

---

## Progress Tracker

| Step | File(s) | Status |
|------|---------|--------|
| 0 | `tessera-server/src/bin/aggregator_artifacts.rs` | [x] |
| 1 | `tessera-trees/src/proof_aggregation/super_aggregator.rs` | [x] |
| 2 | `tessera-server/src/prover.rs` – `AssociatedInputAggregatorService` | [x] |
| 3 | `tessera-server/src/prover.rs` – `SuperAggregatorService::prove` + `prove_request` | [x] |
| 4 | Tests in `super_aggregator.rs` | [x] |
| 5 | Rebuild `aggregator_artifacts` then `super_aggregator_artifacts` | [ ] |
| 6 | Update `sync_verifiers_from_artifacts.sh` / Solidity | [ ] |

> **Note**: The Step 1 implementation that was previously written (mask as free
> SuperAggregator public inputs) must be **reverted** before applying Step 1 below.
> Run `git checkout tessera-trees/src/proof_aggregation/super_aggregator.rs`.

---

## Step 0 — Update TX Leaf Circuit in `aggregator_artifacts.rs`

Change `N_PI` from 72 to 73 and prepend `is_real` as `PI[0]`.

```rust
const TX_DATA_PI: usize = 72; // unchanged: 8 nullifiers + 8 commitments + 1+1 accounts (×4)
const TX_LEAF_PI: usize = TX_DATA_PI + 1; // +1 for is_real boolean at PI[0]
// replace `const N_PI: usize = 72;` with TX_LEAF_PI throughout
```

Update `build_leaf_circuit`:

```rust
fn build_leaf_circuit(
    n_data_pi: usize,
) -> (CircuitData<F, ConfigNative, D>, BoolTarget, Vec<Target>) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    // PI[0] = is_real boolean
    let is_real = builder.add_virtual_bool_target_safe();
    builder.register_public_input(is_real.target);
    // PI[1..73] = data fields (unchanged layout)
    let targets: Vec<Target> = (0..n_data_pi).map(|_| builder.add_virtual_target()).collect();
    for &t in &targets {
        builder.register_public_input(t);
    }
    (builder.build::<ConfigNative>(), is_real, targets)
}
```

Update `prove_leaf` to accept `is_real: bool`:

```rust
fn prove_leaf(
    circuit: &CircuitData<F, ConfigNative, D>,
    is_real_t: BoolTarget,
    targets: &[Target],
    is_real: bool,
    values: &[u64],
) -> Result<ProofWithPublicInputs<F, ConfigNative, D>> {
    assert_eq!(targets.len(), values.len());
    let mut pw = PartialWitness::new();
    pw.set_bool_target(is_real_t, is_real)?;
    for (&t, &v) in targets.iter().zip(values.iter()) {
        pw.set_target(t, F::from_canonical_u64(v))?;
    }
    circuit.prove(pw)
}
```

Update the root PI count assertion:

```rust
assert_eq!(
    root.proof.public_inputs.len(),
    n_leaves * TX_LEAF_PI,  // 16 × 73 = 1168
    ...
);
```

Sample proofs (lines 100–113): pass `is_real = true` with the existing deterministic
data values (shift `vals` to be the 72 data fields, `is_real=true`).

---

## Step 1 — `super_aggregator.rs` Circuit Changes

> Revert the previous implementation first, then apply these changes.

### 1a. Add `BoolTarget` import

```rust
use plonky2::iop::target::BoolTarget;
```

### 1b. `SuperAggregatorTargets` — no `mask_targets` field

The struct keeps its original 10 fields. No addition.

### 1c. In `setup_builder` — update `n_tx_slots` derivation

Replace:
```rust
// old: tx_total_pi % 72 == 0, n_tx_slots = tx_total_pi / 72
```
With:
```rust
const TX_LEAF_PI_SIZE: usize = 73; // is_real(1) + data(72)
let tx_total_pi = inner.tx_common.num_public_inputs;
assert_eq!(
    tx_total_pi % TX_LEAF_PI_SIZE,
    0,
    "TX root PI count must be a multiple of TX_LEAF_PI_SIZE (73)"
);
let n_tx_slots = tx_total_pi / TX_LEAF_PI_SIZE;
```

### 1d. In `setup_builder` — replace cross-constraint loop

Replace the entire loop with the `is_real`-gated version:

```rust
const TX_LEAF_PI_SIZE: usize = 73;
const TX_DATA_OFFSET: usize = 1; // PI[0] is is_real; data starts at PI[1]
const NC_LEAF_OFFSET: usize = 8; // old_root[4] + new_root[4]
const NN_LEAF_OFFSET: usize = 5; // old_root[4] + new_node_path[1]

#[allow(clippy::needless_range_loop)]
for s in 0..n_tx_slots {
    let tx_base = s * TX_LEAF_PI_SIZE;
    let zero = builder.zero();

    // Read is_real from TX root proof PI[tx_base]; assert and wrap as BoolTarget.
    let is_real_t = tx_proof.public_inputs[tx_base];
    builder.assert_bool(is_real_t);
    let is_real = BoolTarget::new_unsafe(is_real_t);

    // note nullifiers (TX data[0..32]) — from NN tree
    for j in 0..notes_per_slot {
        for k in 0..4 {
            let tx_t = tx_proof.public_inputs[tx_base + TX_DATA_OFFSET + j * 4 + k];
            let nn_t =
                nn_proof.public_inputs[NN_LEAF_OFFSET + (s * notes_per_slot + j) * 4 + k];
            let expected = builder.select(is_real, nn_t, zero);
            builder.connect(tx_t, expected);
        }
    }
    // note commitments (TX data[32..64]) — from NC tree
    for j in 0..notes_per_slot {
        for k in 0..4 {
            let tx_t = tx_proof.public_inputs[tx_base + TX_DATA_OFFSET + 32 + j * 4 + k];
            let nc_t =
                nc_proof.public_inputs[NC_LEAF_OFFSET + (s * notes_per_slot + j) * 4 + k];
            let expected = builder.select(is_real, nc_t, zero);
            builder.connect(tx_t, expected);
        }
    }
    // account nullifier (TX data[64..68]) — from AN tree
    for k in 0..4 {
        let tx_t = tx_proof.public_inputs[tx_base + TX_DATA_OFFSET + 64 + k];
        let an_t = an_proof.public_inputs[NN_LEAF_OFFSET + s * 4 + k];
        let expected = builder.select(is_real, an_t, zero);
        builder.connect(tx_t, expected);
    }
    // account commitment (TX data[68..72]) — from AC tree
    for k in 0..4 {
        let tx_t = tx_proof.public_inputs[tx_base + TX_DATA_OFFSET + 68 + k];
        let ac_t = ac_proof.public_inputs[NC_LEAF_OFFSET + s * 4 + k];
        let expected = builder.select(is_real, ac_t, zero);
        builder.connect(tx_t, expected);
    }
}
```

### 1e. `SuperAggregator::prove` — revert to 5 arguments

```rust
pub fn prove(
    &self,
    nc: ProofNative,
    nn: ProofNative,
    ac: ProofNative,
    an: ProofNative,
    tx: ProofNative,
) -> Result<ProofNative>
```

No mask witness to set; `is_real` values come from `tx`'s own public inputs.

### 1f. Root proof: 8 Keccak public inputs (unchanged)

No change to the Keccak section. Root proof PI count remains **8**.

---

## Step 2 — `prover.rs` Simplify `AssociatedInputAggregatorService`

Remove ALL of the following workaround code added for the old approach:

- `leaf_circuit: CircuitDataNative` field from `AssociatedInputAggregatorService`
- `leaf_targets: Vec<Target>` field from `AssociatedInputAggregatorService`
- `prove_consume_slot` method

The canonical padding proof is generated from the 73-PI leaf circuit with `is_real=false`:

```rust
let n_pi = aggregator.leaf_common().num_public_inputs; // 73
// Rebuild the leaf circuit to generate the canonical padding proof.
let leaf_config = CircuitConfig::standard_recursion_config();
let mut builder = CircuitBuilder::<F, D>::new(leaf_config);
let is_real_t = builder.add_virtual_bool_target_safe();
builder.register_public_input(is_real_t.target);
let data_targets: Vec<Target> =
    (0..n_pi - 1).map(|_| builder.add_virtual_target()).collect();
for &t in &data_targets {
    builder.register_public_input(t);
}
let leaf_circuit = builder.build::<ConfigNative>();
let mut pw = PartialWitness::new();
pw.set_bool_target(is_real_t, false)?;
for &t in &data_targets {
    pw.set_target(t, F::ZERO)?;
}
let padding_proof = leaf_circuit.prove(pw)?;
leaf_circuit.verify(padding_proof.clone())?;
let canonical_padding_proof = padding_proof.to_bytes();
```

Revert `from_artifacts_and_pool` return to:

```rust
Ok(Self {
    aggregator: Arc::new(aggregator),
    pool,
    canonical_padding_proof,
})
```

---

## Step 3 — `prover.rs` Simplify `prove_request`

Remove the `consume_slot_proofs` / `tx_proofs` block entirely (step e in the current code).

The aggregate call reverts to:

```rust
let tx_agg_root = match Self::aggregate_associated_input_proofs(
    &self.aggregator,
    &request.associated_tx_proofs,
) { ... };
```

`SuperAggregatorService::prove` reverts to 5 args:

```rust
match self
    .super_aggregator
    .prove(nc_proof, nn_proof, ac_proof, an_proof, tx_agg_root)
{ ... }
```

`super_pi_commitment` extraction is unchanged — 8 Keccak words at `pis[0..8]`.

---

## Step 4 — Tests in `super_aggregator.rs`

Update `build_all_leaves` to use `73` for the TX leaf circuit (`n_tx_slots * 73`).

Update the existing test and add five new tests covering all cases:
- The TX leaf circuit in tests has 73 PIs: PI[0] = is_real, PI[1..73] = data.
- For consume-only: TX proof has `is_real=0`, all data=0; NC has non-zero leaves → passes.
- For full TX: TX proof has `is_real=1`, data matches tree → passes.
- For partial: mixed is_real values, data matches for active slots → passes.
- Soundness: `is_real=0` but non-zero data → fails.
- Soundness: `is_real=1` but data ≠ NC leaf → fails.

Root proof PI count: `assert_eq!(root.public_inputs.len(), 8)`.

---

## Step 5 — Rebuild Artifacts

The TX leaf circuit PI count changed (72 → 73), so **aggregator artifacts must be rebuilt
first**. The TX root `CommonCircuitData` changes, so **super_aggregator artifacts must be
rebuilt second**.

```bash
rm -rf tessera-server/artifacts/associated-input-aggregator
TESSERA_NOTE_BATCH_SIZE=128 TESSERA_ACCOUNT_BATCH_SIZE=16 \
cargo run --bin aggregator_artifacts --release --manifest-path tessera-server/Cargo.toml

rm -rf tessera-server/artifacts/super-aggregator
TESSERA_NOTE_BATCH_SIZE=128 TESSERA_ACCOUNT_BATCH_SIZE=16 \
cargo run --bin super_aggregator_artifacts --release --manifest-path tessera-server/Cargo.toml
```

Commitment/nullifier tree artifacts do **not** change.

---

## Step 6 — Update Solidity Verifier

The SuperAggregator root PI count is **unchanged** (8 Goldilocks words). However, because
the SuperAggregator circuit internally changed (73-PI TX inputs), the BN128 wrapper and
Groth16 artifacts must be regenerated:

```bash
scripts/sync_verifiers_from_artifacts.sh
```

Re-deploy the verifier contract and update `TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS` in
`tessera-server/.env` if running locally.

---

## Notes

- The rejected approach (mask as free SuperAggregator public inputs) required 24 root PIs
  and an external boolean witness. This design keeps root PIs at **8** and embeds the mask
  in the TX proof itself.
- Steps 0 and 1 compile as separate crates but are tightly coupled via
  `tx_common.num_public_inputs` — implement them together.
- The `super_aggregator_artifacts` binary exercises the full circuit and verifies the
  root proof internally — a failed build indicates a circuit bug.
- Run `cargo clippy -p tessera-trees -p tessera-server --release` after all code changes
  before rebuilding artifacts.
