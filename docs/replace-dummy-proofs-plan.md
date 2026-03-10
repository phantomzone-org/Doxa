# Plan: Replace Server Dummy TX Leaf Proofs with Real Client Proofs

## Progress Tracker

| # | Task | Status |
|---|------|--------|
| 1 | Architecture analysis & PI ordering comparison | Done |
| 2 | Resolve PI ordering mismatch (server → match client) | Done |
| 3 | Plumb client proof bytes through sequencer to prover | Done |
| 4 | Replace trivial leaf circuit with recursive verifier | Done |
| 5 | Update artifact generation binary | Done |
| 6 | Handle padding (fake TX proofs for empty slots) | Done |
| 7 | Update API verification to use PrivTx circuit artifacts | Done |
| 8 | Rebuild artifacts & E2E test | TODO |

---

## 1. Architecture Analysis

### Current Server Flow (Private TX)

```
Client ──POST /private-tx──▶ API
   body: { input_notes, output_notes, input_account_commitment,
           output_account_commitment, tx_proof }

API ──────────────────────▶ Sequencer
   PrivateTxRequest { input_notes: Vec<[u8;32]>, output_notes: Vec<[u8;32]>,
                      input_account_leaf: [u8;32], output_account_leaf: [u8;32],
                      tx_proof: Vec<u8> }                    ◀── tx_proof STORED BUT NEVER USED

Sequencer ──start_batch()─▶ Prover
   ProveRequest { sorted leaves for NC/NN/AC/AN, real_account_slots }
                                                             ◀── tx_proof NOT FORWARDED

Prover ──build_and_aggregate_tx_proofs()──▶
   For each slot s in [0..account_batch_size):
     Reconstruct 72 data fields FROM SORTED TREE LEAVES     ◀── IGNORES client proof entirely
     prove_leaf(is_real, data)                               ◀── trivial circuit, no constraints
   Pad to 128, aggregate (arity=2, depth=7)
   Root proof: 128 × 73 = 9344 PIs
```

**Problem**: The `tx_proof` submitted by the client is optionally verified at the API layer
but **never reaches the prover**. The prover generates trivial leaf proofs from tree data with
zero soundness — any data can be injected.

### PI Ordering Mismatch

**Client (`priv_tx/mod.rs:254-270`):**
```
PI[0]     = not_fake_tx           (1 field)
PI[1..5]  = accin_null            (4 fields)  ◀─ account nullifier FIRST
PI[5..9]  = accout_comm           (4 fields)  ◀─ account commitment SECOND
PI[9..41] = effective_inotes_null (32 fields)  8 × 4
PI[41..73]= effective_onotes_comm (32 fields)  8 × 4
```

**Server (`prover.rs:449-465`):**
```
PI[0]     = is_real               (1 field)
PI[1..33] = nn_sorted[s*8..]     (32 fields)  ◀─ note nullifiers FIRST
PI[33..65]= nc_sorted[s*8..]     (32 fields)  ◀─ note commitments SECOND
PI[65..69]= an_sorted[s]         (4 fields)   account nullifier
PI[69..73]= ac_sorted[s]         (4 fields)   account commitment
```

**Mismatch**: Client puts accounts at PI[1..9], notes at PI[9..73].
Server puts notes at PI[1..65], accounts at PI[65..73].

---

## 2. Resolve PI Ordering Mismatch

Two options:

**(a) Reorder client `register_public_input` calls** to match server ordering.
- Pros: No server changes; PI layout matches what the SuperAggregator already expects.
- Cons: Client circuit change; must rebuild client artifacts.

**(b) Reorder server data construction** to match client ordering.
- Pros: No client changes; client PI ordering is arguably more natural (account → notes).
- Cons: Must update server `build_and_aggregate_tx_proofs()` AND the SuperAggregator
  constraints that read specific PI indices.

**Recommendation**: **(a)** — reorder the client. The server's PI ordering is baked into the
SuperAggregator which is the most expensive artifact to rebuild. The client circuit is cheaper
to regenerate and hasn't shipped artifacts yet.

### Change in `tessera-client/src/plonky2_gadgets/priv_tx/mod.rs`

Reorder the `register_public_input` block (lines ~254-270) from:

```rust
// Current: account-first
builder.register_public_input(not_fake_tx.target);
for &t in accin_null.iter() { builder.register_public_input(t); }
for &t in accout_comm.iter() { builder.register_public_input(t); }
for null in effective_inotes_null.iter() { for &t in null.iter() { builder.register_public_input(t); } }
for comm in effective_onotes_comm.iter() { for &t in comm.iter() { builder.register_public_input(t); } }
```

To:

```rust
// New: notes-first (matches server aggregator layout)
builder.register_public_input(not_fake_tx.target);
for null in effective_inotes_null.iter() { for &t in null.iter() { builder.register_public_input(t); } }
for comm in effective_onotes_comm.iter() { for &t in comm.iter() { builder.register_public_input(t); } }
for &t in accin_null.iter() { builder.register_public_input(t); }
for &t in accout_comm.iter() { builder.register_public_input(t); }
```

New layout:
```
PI[0]     = not_fake_tx           (1)
PI[1..33] = effective_inotes_null (32)  8 note nullifiers × 4
PI[33..65]= effective_onotes_comm (32)  8 note commitments × 4
PI[65..69]= accin_null            (4)   account nullifier
PI[69..73]= accout_comm           (4)   account commitment
```

This exactly matches the server's `build_and_aggregate_tx_proofs()` data construction.

---

## 3. Plumb Client Proof Bytes Through Sequencer to Prover

Currently `tx_proof: Vec<u8>` is stored in `PrivateTxRequest` but dropped before reaching
the prover. We need to carry it through.

### 3a. Sequencer: associate proof bytes with account slots

**File: `sequencer/mod.rs`**

The sequencer distributes leaves to 4 independent tree queues (NC, NN, AC, AN).
The `tx_proof` must be associated with the **AN leaf** (account nullifier) since
`real_account_slots` is determined by matching AN leaves.

Add a map to the Sequencer:
```rust
// Maps AN leaf bytes → client tx_proof bytes
tx_proofs_by_an_leaf: HashMap<[u8; 32], Vec<u8>>,
```

When processing a `PrivateTxRequest`, insert:
```rust
self.tx_proofs_by_an_leaf.insert(tx_req.input_account_leaf, tx_req.tx_proof);
```

### 3b. Pipeline: include proof bytes in ProveRequest

**File: `sequencer/pipeline.rs`**

After sorting AN leaves and determining `real_account_slots`, build a map of
slot index → proof bytes:

```rust
let tx_proofs_by_slot: HashMap<usize, Vec<u8>> = an_padded_bytes
    .iter()
    .enumerate()
    .filter_map(|(i, leaf)| {
        self.tx_proofs_by_an_leaf.remove(leaf).map(|proof| (i, proof))
    })
    .collect();
```

### 3c. Extend ProveRequest

**File: `types.rs`**

```rust
pub struct ProveRequest {
    // ... existing fields ...
    pub tx_proofs_by_slot: HashMap<usize, Vec<u8>>,  // NEW: slot → client proof bytes
}
```

---

## 4. Replace Trivial Leaf Circuit with Recursive Verifier

This is the core change. The trivial leaf circuit (no constraints) becomes a circuit that
recursively verifies the client's PrivTx proof.

### 4a. Build the PrivTx inner circuit

Use `tessera-client`'s `priv_tx_circuit()` to obtain its `CircuitData`. Extract:
- `inner_common: CommonCircuitData<F, D>` — gate layout, degree, PI count
- `inner_verifier: VerifierCircuitData<F, C, D>` — verification key

### 4b. Build the recursive leaf circuit

```rust
let config = CircuitConfig::standard_recursion_config();
let mut builder = CircuitBuilder::<F, D>::new(config);

// Add verification targets for inner PrivTx proof
let inner_proof_target = builder.add_virtual_proof_with_pis(&inner_common);
let inner_verifier_target = builder.constant_verifier_data(&inner_verifier);

// Verify the inner proof
builder.verify_proof::<ConfigNative>(
    &inner_proof_target,
    &inner_verifier_target,
    &inner_common,
);

// Register same 73 PIs (forwarded from inner proof)
// PI[0] = not_fake_tx (= is_real)
// PI[1..73] = data fields
for &pi in &inner_proof_target.public_inputs {
    builder.register_public_input(pi);
}

let leaf_circuit = builder.build::<ConfigNative>();
```

The resulting leaf circuit:
- Has **73 public inputs** (same count as before)
- **Cryptographically verifies** the inner PrivTx proof
- PIs are directly forwarded from the verified inner proof

### 4c. Update `prove_leaf()`

**File: `prover.rs`**

Old signature:
```rust
fn prove_leaf(&self, is_real: bool, data: &[F]) -> Result<Vec<u8>>
```

New signature:
```rust
fn prove_leaf(&self, inner_proof_bytes: &[u8]) -> Result<Vec<u8>>
```

Implementation:
```rust
fn prove_leaf(&self, inner_proof_bytes: &[u8]) -> Result<Vec<u8>> {
    let inner_proof = ProofWithPublicInputs::<F, ConfigNative, D>::from_bytes(
        inner_proof_bytes.to_vec(),
        &self.inner_common,
    )?;

    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&self.inner_proof_target, &inner_proof)?;

    let proof = self.leaf_circuit.prove(pw)?;
    Ok(proof.to_bytes())
}
```

### 4d. Update `build_and_aggregate_tx_proofs()`

**File: `prover.rs`**

Old logic:
```rust
for s in 0..account_batch_size {
    let is_real = real_account_slots.contains(&s);
    let data = /* reconstruct 72 fields from sorted leaves */;
    leaf_proofs.push(agg_service.prove_leaf(is_real, &data)?);
}
```

New logic:
```rust
for s in 0..account_batch_size {
    let inner_proof_bytes = match tx_proofs_by_slot.get(&s) {
        Some(proof) => proof.clone(),
        None => self.dummy_inner_proof_bytes.clone(),  // pre-cached fake proof
    };
    leaf_proofs.push(agg_service.prove_leaf(&inner_proof_bytes)?);
}
```

The 72 data fields no longer need to be reconstructed from tree leaves — they come
directly from the verified inner proof's public inputs.

---

## 5. Update Artifact Generation Binary

**File: `src/bin/aggregator_artifacts.rs`**

Replace the trivial `build_leaf_circuit()` with the recursive verifier from Step 4b.

```rust
fn build_leaf_circuit() -> (CircuitData, ProofTarget) {
    // 1. Build inner PrivTx circuit
    let inner_circuit = priv_tx_circuit::<PoseidonHash, F, D>(&mut builder, ...);
    let inner_common = inner_circuit.common.clone();
    let inner_verifier = inner_circuit.verifier_only.clone();

    // 2. Build recursive wrapper
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let pt = builder.add_virtual_proof_with_pis(&inner_common);
    let vt = builder.constant_verifier_data(&inner_verifier);
    builder.verify_proof::<ConfigNative>(&pt, &vt, &inner_common);
    for &pi in &pt.public_inputs {
        builder.register_public_input(pi);
    }
    (builder.build::<ConfigNative>(), pt)
}
```

Also generate and cache a **dummy inner proof** (with `not_fake_tx=0`) for padding slots.

Serialize new artifacts:
- `leaf_circuit.bin` (recursive verifier circuit data)
- `leaf_common.bin`, `leaf_verifier.bin` (for API-layer verification)
- `dummy_inner_proof.bin` (pre-generated fake PrivTx proof)

**Cargo.toml**: Add `tessera-client` as a dependency of `tessera-server`.

---

## 6. Handle Padding (Fake TX Proofs for Empty Slots)

The aggregator pads to 128 leaf proofs. Empty slots need valid inner proofs.

### Generate a dummy PrivTx proof at artifact build time

Use `tessera-client`'s `set_fake_*_witness()` to generate a proof with `not_fake_tx=0`.
This proof is valid (the circuit accepts it) but asserts nothing about real state.

```rust
let dummy_pw = set_fake_priv_tx_witness(&inner_circuit, &targets)?;
let dummy_proof = inner_circuit.prove(dummy_pw)?;
// Serialize to dummy_inner_proof.bin
```

At runtime, the prover loads this once and reuses it for all non-real slots:
```rust
struct AssociatedInputAggregatorService {
    // ... existing fields ...
    dummy_inner_proof_bytes: Vec<u8>,  // loaded from dummy_inner_proof.bin
}
```

---

## 7. Update API Verification to Use PrivTx Circuit Artifacts

**File: `sequencer/api.rs`**

The `LeafProofVerifier` currently loads `leaf_common.bin` + `leaf_verifier.bin` which
correspond to the **trivial** leaf circuit. After the change:

- **`TESSERA_AGGREGATOR_ARTIFACTS_PATH`**: points to the recursive leaf circuit artifacts.
  API verification would verify the recursive wrapper, not the inner PrivTx proof.

Better approach: add a **separate config** for the inner PrivTx circuit verifier:
```rust
// New: verify client's raw PrivTx proof at API intake
pub(super) struct PrivTxProofVerifier {
    verifier_data: VerifierCircuitData<F, ConfigNative, D>,
}
```

Load from `priv_tx_common.bin` + `priv_tx_verifier.bin` (generated from the inner circuit).

This gives **defense in depth**: bad proofs are rejected early at the API before reaching
the sequencer/prover.

---

## 8. Rebuild Artifacts & E2E Test

### Artifact rebuild sequence

```bash
rm -rf artifacts/aggregator artifacts/priv_tx
cargo run --bin aggregator_artifacts --release
```

Outputs:
- `artifacts/priv_tx/` — inner PrivTx circuit common + verifier data
- `artifacts/aggregator/` — recursive leaf circuit + GenericAggregator tree + dummy proof
- `artifacts/super_aggregator/` — unchanged (same 5-proof input shape)

### Test plan

1. **Unit**: Build PrivTx circuit, generate real proof with `set_spend_tx_witness`,
   wrap in recursive leaf circuit, verify.
2. **Unit**: Generate fake proof with `set_fake_*_witness`, wrap, verify PI[0]==0.
3. **Integration**: Full batch — mix of real client proofs + padding dummies →
   aggregate → SuperAggregator → Groth16 → on-chain verify.
4. **Regression**: Ensure `real_account_slots` detection still works with sorted leaves.

---

## Files Changed Summary

| File | Change |
|------|--------|
| `tessera-client/src/plonky2_gadgets/priv_tx/mod.rs` | Reorder PI registration (notes first, accounts last) |
| `tessera-server/Cargo.toml` | Add `tessera-client` dependency |
| `tessera-server/src/types.rs` | Add `tx_proofs_by_slot` to `ProveRequest` |
| `tessera-server/src/sequencer/mod.rs` | Add `tx_proofs_by_an_leaf` map; populate on TX intake |
| `tessera-server/src/sequencer/pipeline.rs` | Build `tx_proofs_by_slot` from sorted AN leaves; include in `ProveRequest` |
| `tessera-server/src/sequencer/api.rs` | Add `PrivTxProofVerifier` using inner circuit artifacts |
| `tessera-server/src/prover.rs` | Rebuild `AssociatedInputAggregatorService`: recursive leaf circuit, new `prove_leaf()`, dummy proof caching |
| `tessera-server/src/bin/aggregator_artifacts.rs` | Build recursive leaf circuit from PrivTx inner circuit; generate dummy proof |

## Dependency Order

```
Step 2 (PI reorder in client)
  ↓
Step 5 (artifact binary — builds inner circuit, recursive wrapper, dummy proof)
  ↓
Step 4 (prover.rs — recursive prove_leaf, dummy caching)
  ├── Step 3 (sequencer plumbing — proof bytes flow)
  └── Step 7 (API verifier update)
  ↓
Step 6 (padding logic update)
  ↓
Step 8 (rebuild + test)
```
