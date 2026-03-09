# Migrate Nullifier Trees from Chained Insertion to Batch Insertion

## Overview

Replace `NullifierChainedInsertProof` / `ChainedInsertProofTargets` with
`BatchInsertProof` / `BatchNullifierInsertProofTargets` in both the sequencer
pipeline and the prover runtime.  This aligns nullifier trees with commitment
trees, which already use batch insertion.

## Motivation

| Aspect | Chained (current) | Batch (target) |
|---|---|---|
| PI layout | Non-uniform: `new_root` buried before last value, extra `new_node_path` field | Uniform: `old_root[4] \|\| new_root[4] \|\| leaves[N×4]` — identical to commitment trees |
| SuperAggregator preimage | Requires PI reordering + skip logic | Straight pass-through (same as NC/AC) |
| Witness size | K × full single-proof witnesses | Shared predecessor paths, smaller total |
| Root extraction | `proof.proofs.last().unwrap().new_root` | `proof.new_root` (direct field) |

### Key Observation — PI Layout Alignment

`BatchNullifierInsertProofTargets::new` registers public inputs as:

```
old_root[4]  (add_virtual_hash_public_input)
new_root[4]  (add_virtual_hash_public_input)
leaf_values[batch_size × 4]  (register_public_inputs per link)
```

Total: `(batch_size + 2) × 4` fields — **exactly the same layout as
`BatchCommitmentProofTargets`**.  This means:
- No PI reordering needed in the SuperAggregator.
- The NN/AN slots become identical to the NC/AC slots.
- Cross-check indexing with TX PIs simplifies (no `new_node_path` offset).

## Progress Tracker

| # | Task | Status |
|---|------|--------|
| 1 | Update `ProveRequest` type | ☐ |
| 2 | Update `NullifierProverService` | ☐ |
| 3 | Update sequencer `pipeline.rs` — `start_batch` | ☐ |
| 4 | Update sequencer `pipeline.rs` — `register_tx_batch` | ☐ |
| 5 | Update `SequencerTree` impl for `NullifierTree` | ☐ |
| 6 | Update `ProverRuntime::try_prove_request` root extraction | ☐ |
| 7 | Update `SuperAggregator` circuit + PI preimage | ☐ |
| 8 | Update `log_super_pi_preimage_debug` | ☐ |
| 9 | Rebuild artifacts | ☐ |
| 10 | Run tests | ☐ |

---

## Step 1 — Update `ProveRequest` type

**File**: `tessera-server/src/types.rs`

Change the nullifier proof fields from `NullifierChainedInsertProof<Hash>` to
`BatchInsertProof<Hash>`:

```rust
// BEFORE
use tessera_trees::tree::{BatchCommitmentProof, NullifierChainedInsertProof};

pub struct ProveRequest {
    pub notes_nullifier_proof: NullifierChainedInsertProof<Hash>,
    pub accounts_nullifier_proof: NullifierChainedInsertProof<Hash>,
    // ...
}

// AFTER
use tessera_trees::tree::{BatchCommitmentProof, BatchInsertProof};

pub struct ProveRequest {
    pub notes_nullifier_proof: BatchInsertProof<Hash>,
    pub accounts_nullifier_proof: BatchInsertProof<Hash>,
    // ...
}
```

**Prerequisite**: Ensure `BatchInsertProof` derives `Serialize, Deserialize,
Clone, Debug` (check `batch_insertion/native.rs`).  If not, add the derives.
Same for `BatchInsertionLink`.

---

## Step 2 — Update `NullifierProverService`

**File**: `tessera-server/src/prover.rs`

Replace `ChainedInsertProofTargets` with `BatchNullifierInsertProofTargets`:

```rust
// BEFORE
use tessera_trees::tree::{ChainedInsertProofTargets, NullifierChainedInsertProof};

pub struct NullifierProverService {
    circuit_data: CircuitDataNative,
    targets: ChainedInsertProofTargets,
}

impl NullifierProverService {
    pub fn init(batch_size: usize) -> Result<Self> {
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let targets = ChainedInsertProofTargets::new::<F, D>(&mut builder, 32, batch_size);
        targets.connect::<Hash, F, D>(&mut builder);
        // ...
    }

    pub fn prove(&self, batch_proof: &NullifierChainedInsertProof<Hash>) -> Result<ProofNative> {
        self.targets.set::<Hash, F, 32>(&mut pw, batch_proof)?;
        // ...
    }
}

// AFTER
use tessera_trees::tree::{BatchNullifierInsertProofTargets, BatchInsertProof};

pub struct NullifierProverService {
    circuit_data: CircuitDataNative,
    targets: BatchNullifierInsertProofTargets,
}

impl NullifierProverService {
    pub fn init(batch_size: usize) -> Result<Self> {
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let targets = BatchNullifierInsertProofTargets::new::<F, D>(&mut builder, 32, batch_size);
        targets.connect::<Hash, F, D>(&mut builder);
        // ...
    }

    pub fn prove(&self, batch_proof: &BatchInsertProof<Hash>) -> Result<ProofNative> {
        BatchNullifierInsertProofTargets::set::<Hash, F>(&mut pw, batch_proof)?;
        // ...
    }
}
```

**Note**: Verify that `BatchNullifierInsertProofTargets::set` exists and takes
`&mut PartialWitness` + `&BatchInsertProof<Hash>`.  The current signature is
`set<H, F>(pw, proof) -> Result<()>` (stark.rs:218–253).

---

## Step 3 — Update sequencer `start_batch`

**File**: `tessera-server/src/sequencer/pipeline.rs`, lines 334–384

Replace `insert_chained` with `insert_batch` for both nullifier trees:

```rust
// BEFORE (lines 342-344)
let mut nn_tmp = self.notes_nullifier_state.tree.clone();
let nn_proof = nn_tmp.insert_chained(nn_hashes.clone())?;
anyhow::ensure!(nn_proof.verify(), "NN native proof verification failed");

// AFTER
let mut nn_tmp = self.notes_nullifier_state.tree.clone();
let nn_proof = nn_tmp.insert_batch(nn_hashes.clone())?;
anyhow::ensure!(nn_proof.verify(), "NN native proof verification failed");
```

Same for AN (lines 366-368).

### Root extraction simplification

```rust
// BEFORE (lines 371-377)
let new_nn_root = contract::hash_to_bytes32(
    &nn_proof.proofs.last()
        .ok_or_else(|| anyhow::anyhow!("NN proof is empty"))?
        .new_root,
);

// AFTER
let new_nn_root = contract::hash_to_bytes32(&nn_proof.new_root);
```

Same for AN (lines 379-385).

### Tree advancement (lines 453-461)

```rust
// BEFORE
self.notes_nullifier_state.tree.insert_chained(nn_hashes.clone())?;
self.accounts_nullifier_state.tree.insert_chained(an_hashes.clone())?;

// AFTER
self.notes_nullifier_state.tree.insert_batch(nn_hashes.clone())?;
self.accounts_nullifier_state.tree.insert_batch(an_hashes.clone())?;
```

---

## Step 4 — Update sequencer `register_tx_batch`

**File**: `tessera-server/src/sequencer/pipeline.rs`, lines 788–835

Identical pattern to Step 3.  Replace all `insert_chained` → `insert_batch`
and simplify root extraction for NN and AN.

Locations:
- Line 797: `nn_tmp.insert_chained(...)` → `nn_tmp.insert_batch(...)`
- Lines 799-805: simplify `new_nn_root` extraction to `nn_proof.new_root`
- Line 828: `an_tmp.insert_chained(...)` → `an_tmp.insert_batch(...)`
- Lines 830-836: simplify `new_an_root` extraction to `an_proof.new_root`
- Line 914: `self.notes_nullifier_state.tree.insert_chained(...)` → `.insert_batch(...)`
- Line 920: `self.accounts_nullifier_state.tree.insert_chained(...)` → `.insert_batch(...)`

---

## Step 5 — Update `SequencerTree` impl for `NullifierTree`

**File**: `tessera-server/src/states/mod.rs`, lines 76–98

```rust
// BEFORE
impl SequencerTree for NullifierTree<Hash> {
    fn insert_verified(&mut self, leaves: Vec<Hash>) -> Result<Hash> {
        let proof = self.insert_chained(leaves)?;
        anyhow::ensure!(proof.verify(), "nullifier tree proof verification failed");
        proof.proofs.last()
            .map(|p| p.new_root)
            .ok_or_else(|| anyhow::anyhow!("nullifier proof contains no insertions"))
    }
}

// AFTER
impl SequencerTree for NullifierTree<Hash> {
    fn insert_verified(&mut self, leaves: Vec<Hash>) -> Result<Hash> {
        let proof = self.insert_batch(leaves)?;
        anyhow::ensure!(proof.verify(), "nullifier tree proof verification failed");
        Ok(proof.new_root)
    }
}
```

---

## Step 6 — Update `ProverRuntime::try_prove_request` root extraction

**File**: `tessera-server/src/prover.rs`, lines 473–486

```rust
// BEFORE
let nullifier_notes_new_root = request.notes_nullifier_proof
    .proofs.last()
    .ok_or_else(|| anyhow::anyhow!("notes nullifier proof contains no insertions"))?
    .new_root;
let nullifier_accounts_new_root = request.accounts_nullifier_proof
    .proofs.last()
    .ok_or_else(|| anyhow::anyhow!("accounts nullifier proof contains no insertions"))?
    .new_root;

// AFTER
let nullifier_notes_new_root = request.notes_nullifier_proof.new_root;
let nullifier_accounts_new_root = request.accounts_nullifier_proof.new_root;
```

---

## Step 7 — Update `SuperAggregator` circuit + PI preimage

**File**: `tessera-trees/src/proof_aggregation/super_aggregator.rs`

This is the most impactful change.  Because the batch insertion PI layout is
`old_root[4] || new_root[4] || leaves[N×4]` — identical to commitment trees —
the SuperAggregator can treat NN/AN exactly like NC/AC.

### 7a. Update PI count assertions (lines 362–373)

```rust
// BEFORE: NN has (batch_size×4 + 9) PIs; extra 1 for new_node_path
// Batch size was inferred by: (nn_pi_count - 9) / 4

// AFTER: NN has (batch_size + 2) × 4 PIs — same formula as NC
let note_batch_size = inner.nc_common.num_public_inputs / 4 - 2;
assert_eq!(
    inner.nn_common.num_public_inputs,
    inner.nc_common.num_public_inputs,
    "NN and NC must have the same PI count with batch insertion"
);
let account_batch_size = inner.ac_common.num_public_inputs / 4 - 2;
assert_eq!(
    inner.an_common.num_public_inputs,
    inner.ac_common.num_public_inputs,
    "AN and AC must have the same PI count with batch insertion"
);
```

### 7b. Update TX cross-check indexing (lines 404–460)

The NN/AN leaf offset changes from 5 (skipping `new_node_path`) to 8 (after
`old_root[4] + new_root[4]`), and there is no longer a special case for the
last value:

```rust
// BEFORE
const NN_LEAF_OFFSET: usize = 5; // old_root[4] + new_node_path[1]
// Last value at nn_proof.public_inputs.len() - 4

// AFTER
const NN_LEAF_OFFSET: usize = 8; // old_root[4] + new_root[4] — same as NC
// All values are sequential; no special last-value handling
```

The note nullifier cross-check loop simplifies:

```rust
// BEFORE
for j in 0..notes_per_slot {
    let leaf_idx = s * notes_per_slot + j;
    let nn_val_base = if leaf_idx < note_batch_size - 1 {
        NN_LEAF_OFFSET + leaf_idx * 4
    } else {
        nn_proof.public_inputs.len() - 4
    };
    // ...
}

// AFTER
for j in 0..notes_per_slot {
    let leaf_idx = s * notes_per_slot + j;
    let nn_val_base = NN_LEAF_OFFSET + leaf_idx * 4;  // uniform, no branch
    // ...
}
```

Same simplification for the AN cross-check:

```rust
// BEFORE
let an_val_base = if s < account_batch_size - 1 {
    NN_LEAF_OFFSET + s * 4
} else {
    an_proof.public_inputs.len() - 4
};

// AFTER
let an_val_base = NN_LEAF_OFFSET + s * 4;  // NN_LEAF_OFFSET is now 8
```

### 7c. Simplify Keccak preimage assembly (lines 462–498)

Since NN/AN now have the same layout as NC/AC, the reordering logic is
eliminated entirely:

```rust
// BEFORE: 30+ lines of manual reordering for NN/AN
let all_pi: Vec<_> = nc_proof.public_inputs.iter().copied()
    .chain(nn_proof.public_inputs[..4].iter().copied())         // old_root
    .chain(nn_proof.public_inputs[nn_nrs..nn_nrs+4].iter().copied()) // new_root
    .chain(nn_proof.public_inputs[5..nn_nrs].iter().copied())   // values[0..N-2]
    .chain(nn_proof.public_inputs[nn_nrs+4..].iter().copied())  // value[N-1]
    .chain(ac_proof.public_inputs.iter().copied())
    .chain(an_proof.public_inputs[..4].iter().copied())
    .chain(an_proof.public_inputs[an_nrs..an_nrs+4].iter().copied())
    .chain(an_proof.public_inputs[5..an_nrs].iter().copied())
    .chain(an_proof.public_inputs[an_nrs+4..].iter().copied())
    .collect();

// AFTER: straight concatenation — all 4 trees use the same layout
let all_pi: Vec<_> = nc_proof.public_inputs.iter().copied()
    .chain(nn_proof.public_inputs.iter().copied())
    .chain(ac_proof.public_inputs.iter().copied())
    .chain(an_proof.public_inputs.iter().copied())
    .collect();
```

### 7d. Update module-level doc comment (lines 31–48)

Remove the paragraph about non-obvious raw PI layout and the reordering.
Update the PI count table to reflect NN/AN now having the same count as NC/AC.

---

## Step 8 — Update `log_super_pi_preimage_debug`

**File**: `tessera-server/src/prover.rs`, lines 543–607

The native-side debug logger mirrors the circuit's preimage assembly.  Remove
the NN/AN reordering logic:

```rust
// BEFORE
let nn_len = nn.public_inputs.len();
let nn_nrs = nn_len - 8;
let nn_pis: Vec<F> = nn.public_inputs[..4].iter()
    .chain(nn.public_inputs[nn_nrs..nn_nrs+4].iter())
    .chain(nn.public_inputs[5..nn_nrs].iter())
    .chain(nn.public_inputs[nn_nrs+4..].iter())
    .copied().collect();
let nn_bytes = fields_to_bytes(&nn_pis);

// AFTER
let nn_bytes = fields_to_bytes(&nn.public_inputs);
```

Same for AN.

---

## Step 9 — Rebuild Artifacts

The SuperAggregator circuit changes (Step 7) mean all artifacts are
invalidated.  After code changes:

```bash
rm -rf artifacts/super_aggregator/
cargo run --bin super_aggregator_artifacts --release
```

This rebuilds:
- `circuit_data.bin` (new circuit with simplified PI wiring)
- `nn_common.bin` / `nn_verifier.bin` (new inner circuit data)
- `an_common.bin` / `an_verifier.bin`
- BN128 wrapper artifacts
- Groth16 trusted-setup artifacts

**Note**: The inner commitment-tree circuits (NC, AC) and TX aggregator
circuits are unchanged, but since the SuperAggregator bakes in all 5 verifier
datas, the root circuit must be rebuilt anyway.

---

## Step 10 — Run Tests

```bash
# Unit tests for batch insertion (already passing)
cargo test -p tessera-trees --release -- batch_insertion

# Full prover pipeline test (if available)
cargo test -p tessera-server --release

# Clippy
cargo clippy -p tessera-trees -p tessera-server
```

---

## Checklist of Files Modified

| File | Changes |
|------|---------|
| `tessera-server/src/types.rs` | `NullifierChainedInsertProof` → `BatchInsertProof` |
| `tessera-server/src/prover.rs` | `NullifierProverService` circuit + prove method; `try_prove_request` root extraction; `log_super_pi_preimage_debug` |
| `tessera-server/src/sequencer/pipeline.rs` | `start_batch` + `register_tx_batch`: `insert_chained` → `insert_batch`, root extraction |
| `tessera-server/src/states/mod.rs` | `SequencerTree for NullifierTree` impl |
| `tessera-trees/src/proof_aggregation/super_aggregator.rs` | PI assertions, TX cross-check, Keccak preimage, doc comments |
| `tessera-trees/src/tree/nullifier_tree/proofs/batch_insertion/native.rs` | Add `Serialize, Deserialize, Clone, Debug` derives if missing |

## Public-Input Re-exports

Verify that `BatchNullifierInsertProofTargets` and `BatchInsertProof` are
re-exported from the `tessera_trees::tree` module (via `proofs/mod.rs` →
`batch_insertion/mod.rs`).  The current `pub use batch_insertion::*;` should
cover this, but confirm the prover's import path resolves.

## Risk Assessment

- **On-chain contract unchanged**: The Keccak preimage layout
  `old_root || new_root || full_batch` per tree is preserved — the contract
  does not know or care whether the proof used chaining or batching internally.
- **Artifact rebuild required**: This is a breaking change for existing
  artifacts.  Coordinate with deployment.
- **Backward incompatibility**: In-flight `ProveRequest`s using the old
  `NullifierChainedInsertProof` format will fail deserialization.  Deploy
  sequencer + prover atomically.
