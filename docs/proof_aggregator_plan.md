# Proof Aggregator Implementation Plan: `PrivTxAggregator` & `BridgeTxAggregator`

## Context

We need to implement two aggregators that each reduce an entire finalized batch of TX proofs to a **single Plonky2 proof** ready for BN128 wrapping and on-chain submission.

**Goal:** Replace the legacy `SuperAggregatorV2` / `DepositSuperAggregatorV2` pattern with clean, modular, `BatchHelper`-aligned implementations. The design principle is to mirror the doxa-client circuit crate pattern: named target structs allocated/consumed sequentially, with no raw numerical offset constants anywhere in circuit constraint code.

Both aggregators produce a proof whose **only public output** is the `super_pi_commitment`: a Keccak-256 digest of the batch PI preimage as defined by `BatchHelper::pi_commitment`.

---

## Architecture Overview

### `PrivTxAggregator` (`priv_tx_aggregator.rs`)

```
64 PrivTx proofs
    └─ GenericAggregator (arity=8, depth=2)  →  tx_agg_proof  (4672 PIs)
512 leaves from output_commitments
    └─ SubtreeRootCircuit (512 leaves)        →  sr_proof      (2052 PIs)
                          ↓
               PrivTxSuperCircuit
    (verify both, cross-check, common-PI check, Keccak)
                          ↓
               final_proof  [8 u32 public inputs = super_pi_commitment]
```

### `BridgeTxAggregator` (`bridge_tx_aggregator.rs`)

```
256 Withdraw proofs
    └─ GenericAggregator (arity=4, depth=4)  →  w_agg_proof  (21 760 PIs)
256 Deposit proofs
    └─ GenericAggregator (arity=4, depth=4)  →  d_agg_proof  ( 8 960 PIs)
512 leaves from output_commitments
    └─ SubtreeRootCircuit (512 leaves)        →  sr_proof     ( 2 052 PIs)
                          ↓
              BridgeTxSuperCircuit
    (verify all three, cross-check, common-PI check, Keccak)
                          ↓
              final_proof  [8 u32 public inputs = super_pi_commitment]
```

---

## Key Constants (from doxa-client)

```rust
NOTE_BATCH:           usize = 7
PRIV_TX_BATCH_SIZE:   usize = 64
BRIDGE_TX_BATCH_SIZE: usize = 512   // 256 withdrawals + 256 deposits
SUBTREE_BATCHSIZE:    usize = 512
```

`pi_size` per slot is **always derived** from the aggregated circuit at build time:
```rust
let pi_size = tx_common.num_public_inputs / PRIV_TX_BATCH_SIZE; // = 73
```

### Native API (off-circuit — no raw offsets needed)

`BatchHelper`/`PIHelper` fully abstract the PI layout for the proving pipeline:
- `proof.output_commitments()` → SR leaf inputs per slot
- `proof.batch_unique_pis()` → unique preimage fields per slot
- `proof.batch_common_pis()` → act_root ++ mainpool_config_root (once per batch)
- `batch.pi_commitment::<SolidityKeccak256>()` → complete native Keccak commitment

### Keccak preimage layout (matches `BatchHelper::pi_commitment`)

```
batch_poseidon_root[4 GL]          ← SR proof root
act_root[4 GL]                     ← private witness
mainpool_config_root[4 GL]         ← private witness
unique_pis_slot_0                  ← not_fake_tx + accin_null + accout_comm + type-specific fields
...
unique_pis_slot_N
```

Each GL field → `[lo_u32, hi_u32]` (matching `BatchHelper::push_fields`).

---

## Step 1 — Expose doxa-client PI target types and add `from_pis()` constructors

**Design principle:** Use the existing doxa-client target types (`TxCircuitPublicTargets`, `WithdrawTxPublicTargets`, `DepositTxPublicTargets`) DIRECTLY in the aggregator files. This requires:
1. Making the types and their fields `pub` in doxa-client
2. Adding a `from_pis()` constructor to each type that reads fields sequentially via `split_at` (same order as `register()` — no named offset constants)

All circuit constraint code in the aggregator then uses ONLY the named fields of these types.

### 1a — Visibility changes in doxa-client

In `doxa-client/src/plonky2_gadgets/priv_tx/targets.rs`:
- `pub(crate) struct RootTarget` → `pub struct RootTarget`
- `pub(crate) struct MainPoolConfigRootTarget` → `pub struct MainPoolConfigRootTarget`
- `pub(crate) struct AccountCommitmentTarget` → `pub struct AccountCommitmentTarget`
- `pub(crate) struct AccountNullifierTarget` → `pub struct AccountNullifierTarget`
- `pub(crate) struct NoteCommitmentTarget` → `pub struct NoteCommitmentTarget`
- `pub(crate) struct NoteNullifierTarget` → `pub struct NoteNullifierTarget`
- `pub struct TxCircuitPublicTargets` fields: all `pub(crate)` → `pub`

In `doxa-client/src/plonky2_gadgets/withdraw_tx/targets.rs`:
- `pub(crate) struct WithdrawTxPublicTargets` → `pub struct WithdrawTxPublicTargets`; fields `pub(crate)` → `pub`

In `doxa-client/src/plonky2_gadgets/deposit_tx/targets.rs`:
- `pub struct DepositTxPublicTargets` fields: `pub(crate)` → `pub`
- `pub(crate) struct DepositNoteCommitmentTarget` → `pub struct DepositNoteCommitmentTarget`

### 1b — Add `from_pis()` to doxa-client target types

Add to `TxCircuitPublicTargets` in `priv_tx/targets.rs` (sequential cursor — no named offsets):

```rust
/// Construct from a flat PI slice. Reads fields in the same order as register().
pub fn from_pis(pis: &[Target]) -> Self {
    let (root_s, rest)  = pis.split_at(4);
    let (main_s, rest)  = rest.split_at(4);
    let (nft_s, rest)   = rest.split_at(1);
    let (ain_s, rest)   = rest.split_at(4);
    let (aout_s, rest)  = rest.split_at(4);
    let (inull_s, rest) = rest.split_at(NOTE_BATCH * 4);
    let (ocomm_s, _)    = rest.split_at(NOTE_BATCH * 4);
    Self {
        root:                 RootTarget(HashOutTarget { elements: root_s.try_into().unwrap() }),
        mainpool_config_root: MainPoolConfigRootTarget(HashOutTarget { elements: main_s.try_into().unwrap() }),
        not_fake_tx:          BoolTarget::new_unsafe(nft_s[0]),
        accin_null:           AccountNullifierTarget(HashOutTarget { elements: ain_s.try_into().unwrap() }),
        accout_comm:          AccountCommitmentTarget(HashOutTarget { elements: aout_s.try_into().unwrap() }),
        inotes_null:          core::array::from_fn(|j| NoteNullifierTarget(HashOutTarget { elements: inull_s[j*4..j*4+4].try_into().unwrap() })),
        onotes_comm:          core::array::from_fn(|j| NoteCommitmentTarget(HashOutTarget { elements: ocomm_s[j*4..j*4+4].try_into().unwrap() })),
    }
}
```

Add analogous `from_pis()` to `WithdrawTxPublicTargets` and `DepositTxPublicTargets` following their respective `register()` order.

### 1c — Circuit helper methods on doxa-client types

Add to `TxCircuitPublicTargets`:
```rust
/// SR leaf order: [AC, NC0..NC6] — uses only named fields
pub fn output_commitments(&self) -> [[Target; 4]; 1 + NOTE_BATCH] {
    core::array::from_fn(|j| {
        if j == 0 { self.accout_comm.0.elements }
        else { self.onotes_comm[j-1].0.elements }
    })
}

/// Unique PIs for Keccak preimage (not_fake_tx onwards) — uses only named fields
pub fn unique_pi_targets(&self) -> Vec<Target> {
    let mut out = vec![self.not_fake_tx.target];
    out.extend(self.accin_null.0.elements);
    out.extend(self.accout_comm.0.elements);
    for nn in &self.inotes_null { out.extend(nn.0.elements); }
    for nc in &self.onotes_comm { out.extend(nc.0.elements); }
    out
}
```

Add `output_commitment()` and `unique_pi_targets()` to `WithdrawTxPublicTargets` and `DepositTxPublicTargets` similarly.

Helper function in each aggregator file (uses `TxCircuitPublicTargets::from_pis` — no local raw indexing):
```rust
fn priv_tx_slot(agg_pis: &[Target], slot: usize, pi_size: usize) -> TxCircuitPublicTargets {
    TxCircuitPublicTargets::from_pis(&agg_pis[slot * pi_size..(slot + 1) * pi_size])
}
```

### 1c — `SrSlotTargets` (both files)

```rust
/// Structured access to SubtreeRoot proof PI targets.
/// PI layout: [root[4] | leaf_0[4] | ... | leaf_{N-1}[4]]
struct SrTargets<'a> {
    pis: &'a [Target],
}

impl<'a> SrTargets<'a> {
    fn root(&self) -> [Target; 4] { self.pis[..4].try_into().unwrap() }
    fn leaf(&self, idx: usize) -> [Target; 4] {
        self.pis[4 + idx * 4..4 + idx * 4 + 4].try_into().unwrap()
    }
}
```

### 1d — Shared circuit helpers (both files)

**`field_to_le_u32_pair`** (matching `BatchHelper::push_fields` encoding — lo_u32 first, hi_u32 second):
```rust
fn field_to_le_u32_pair(builder: &mut CircuitBuilder<F, D>, f: Target, lut: usize) -> [Target; 2] {
    let [hi, lo] = decompose_field_to_u32_pair(builder, f, lut);
    [lo.0, hi.0]
}

fn fields_to_u32_words(builder: &mut CircuitBuilder<F, D>, fields: &[Target], lut: usize) -> Vec<Target> {
    fields.iter().flat_map(|&f| field_to_le_u32_pair(builder, f, lut)).collect()
}
```

---

## Step 2 — `PrivTxSuperCircuit` (in `priv_tx_aggregator.rs`)

### Struct

```rust
pub struct PrivTxSuperCircuit {
    pub circuit_data: CircuitDataNative,
    targets: PrivTxSuperTargets,
    inner: PrivTxSuperCircuitData,
}

pub struct PrivTxSuperCircuitData {
    pub tx_common:   CommonCircuitData<F, D>,
    pub tx_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
    pub sr_common:   CommonCircuitData<F, D>,
    pub sr_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
}

struct PrivTxSuperTargets {
    tx_proof: ProofWithPublicInputsTarget<D>,
    sr_proof: ProofWithPublicInputsTarget<D>,
    // No private witnesses needed — common PIs are read directly from tx_proof
}
```

### `setup_builder` function

All PI sizes derived from the actual circuits at build time — no hardcoded constants:

```rust
fn setup_builder(inner: &PrivTxSuperCircuitData) -> (CircuitBuilder<F, D>, PrivTxSuperTargets) {
    let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());

    // 1. Allocate proof targets and constant-fold verifier data
    let tx_proof = builder.add_virtual_proof_with_pis(&inner.tx_common);
    let tx_vd    = builder.constant_verifier_data(&inner.tx_verifier);
    let sr_proof = builder.add_virtual_proof_with_pis(&inner.sr_common);
    let sr_vd    = builder.constant_verifier_data(&inner.sr_verifier);

    // 2. Verify both proofs in-circuit
    builder.verify_proof::<ConfigNative>(&tx_proof, &tx_vd, &inner.tx_common);
    builder.verify_proof::<ConfigNative>(&sr_proof, &sr_vd, &inner.sr_common);

    // 3. Derive pi_size — no hardcoded constants
    let pi_size = inner.tx_common.num_public_inputs / PRIV_TX_BATCH_SIZE;
    assert_eq!(pi_size * PRIV_TX_BATCH_SIZE, inner.tx_common.num_public_inputs);
    assert_eq!(inner.sr_common.num_public_inputs, (1 + SUBTREE_BATCHSIZE) * 4);

    // 4. Build named target wrappers — ALL PI access via named fields from here
    let sr = SrTargets { pis: &sr_proof.public_inputs };
    let slots: Vec<PrivTxSlotTargets> = (0..PRIV_TX_BATCH_SIZE)
        .map(|s| priv_tx_slot(&tx_proof.public_inputs, s, pi_size))
        .collect();

    // 5. Cross-check: SR leaves == TX output_commitments (unconditional — SR is built from ALL
    //    proofs, real and fake, so equality holds for every slot)
    for (s, slot) in slots.iter().enumerate() {
        for (j, tx_comm) in slot.output_commitments().iter().enumerate() {
            let sr_leaf = sr.leaf(s * (1 + NOTE_BATCH) + j);
            for k in 0..4 {
                builder.connect(tx_comm[k], sr_leaf[k]);
            }
        }
    }

    // 6. Assert uniform common PIs: connect all slots' root/mainpool_config_root to slot 0
    //    (builder.connect on HashOutTarget — no private witnesses needed)
    for slot in slots.iter().skip(1) {
        builder.connect_hashes(slot.root.0, slots[0].root.0);
        builder.connect_hashes(slot.mainpool_config_root.0, slots[0].mainpool_config_root.0);
    }

    // 7. Build Keccak preimage (all via named fields — no raw indices)
    //    act_root and main_cfg come from slot 0 (guaranteed equal to all slots)
    let lut = add_u8_range_check_lookup_table(&mut builder);
    let mut u32_words = vec![];
    // batch_poseidon_root
    u32_words.extend(fields_to_u32_words(&mut builder, &sr.root(), lut));
    // common PIs once — taken from slot 0 (all slots asserted equal above)
    u32_words.extend(fields_to_u32_words(&mut builder, &slots[0].root.0.elements, lut));
    u32_words.extend(fields_to_u32_words(&mut builder, &slots[0].mainpool_config_root.0.elements, lut));
    // unique_pis per slot (via named accessor — no raw indices)
    for slot in &slots {
        u32_words.extend(fields_to_u32_words(&mut builder, &slot.unique_pi_targets(), lut));
    }

    // 8. Keccak-256 → 8 u32 public inputs
    let keccak_out = solidity_keccak256(&mut builder, &u32_words);
    for &w in &keccak_out { builder.register_public_input(w); }

    let targets = PrivTxSuperTargets { tx_proof, sr_proof, act_root, main_pool_cfg_root };
    (builder, targets)
}
```

### `impl PrivTxSuperCircuit`

```rust
pub fn build(inner: PrivTxSuperCircuitData) -> Result<Self> {
    let (builder, targets) = setup_builder(&inner);
    let circuit_data = builder.build::<ConfigNative>();
    Ok(Self { circuit_data, targets, inner })
}

pub fn prove(&self, tx: ProofNative, sr: ProofNative) -> Result<ProofNative> {
    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&self.targets.tx_proof, &tx)?;
    pw.set_proof_with_pis_target(&self.targets.sr_proof, &sr)?;
    self.circuit_data.prove(pw)
}

pub fn store_artifacts(&self, path: &Path) -> Result<()>
pub fn from_artifacts(path: &Path) -> Result<Self>
pub fn has_artifacts(path: &Path) -> bool
```

**Artifact files** (under `path/super-circuit/`):
- `circuit_data.bin` (with `DoxaGeneratorSerializer`)
- `tx_common.bin`, `tx_verifier.bin`, `sr_common.bin`, `sr_verifier.bin`

---

## Step 3 — `PrivTxAggregator` (in `priv_tx_aggregator.rs`)

### Struct

```rust
pub struct PrivTxAggregator {
    tx_aggregator: GenericAggregator<F, ConfigNative, D>,
    subtree_root:  SubtreeRootCircuit,
    super_circuit: PrivTxSuperCircuit,
}
```

### `impl PrivTxAggregator`

```rust
pub fn build(
    priv_tx_leaf_common:   CommonCircuitData<F, D>,
    priv_tx_leaf_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
) -> Result<Self> {
    let tx_aggregator = GenericAggregator::new(
        GenericAggregatorConfig { arity: 8, depth: 2 },
        priv_tx_leaf_common,
        priv_tx_leaf_verifier,
    )?;
    let subtree_root = SubtreeRootCircuit::build(SUBTREE_BATCHSIZE);
    let root_level = tx_aggregator.levels.last().unwrap();
    let inner = PrivTxSuperCircuitData {
        tx_common:   root_level.circuit_data.common.clone(),
        tx_verifier: root_level.circuit_data.verifier_only.clone(),
        sr_common:   subtree_root.circuit_data.common.clone(),
        sr_verifier: subtree_root.circuit_data.verifier_only.clone(),
    };
    let super_circuit = PrivTxSuperCircuit::build(inner)?;
    Ok(Self { tx_aggregator, subtree_root, super_circuit })
}

pub fn prove(&self, batch: &PrivateTxBatch) -> Result<ProofNative> {
    let leaf_proofs: Vec<ProofNative> = batch.proofs().iter()
        .map(|p| p.proof().clone()).collect();
    let tx_agg = self.tx_aggregator.aggregate(leaf_proofs)?;
    let leaves: Vec<HashOutput> = batch.proofs().iter()
        .flat_map(|p| p.output_commitments()).collect();
    assert_eq!(leaves.len(), SUBTREE_BATCHSIZE);
    let sr_proof = self.subtree_root.prove(&leaves)?;
    self.super_circuit.prove(tx_agg.proof, sr_proof)
}

pub fn store_artifacts(&self, path: &Path) -> Result<()>
pub fn from_artifacts(path: &Path, leaf_gate_ser: &dyn GateSerializer<F, D>) -> Result<Self>
pub fn has_full_artifacts(path: &Path) -> Result<bool>
```

**Artifact directory layout:**
```
priv-tx-aggregator/
├── generic-agg/          ← GenericAggregator artifacts (manifest + level_{0,1}.bin)
├── subtree-root/         ← SubtreeRootCircuit artifact
└── super-circuit/        ← PrivTxSuperCircuit artifacts
```

---

## Step 4 — `BridgeTxSuperCircuit` (in `bridge_tx_aggregator.rs`)

### Struct

```rust
pub struct BridgeTxSuperCircuit {
    pub circuit_data: CircuitDataNative,
    targets: BridgeTxSuperTargets,
    inner: BridgeTxSuperCircuitData,
}

pub struct BridgeTxSuperCircuitData {
    pub w_common:   CommonCircuitData<F, D>,
    pub w_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
    pub d_common:   CommonCircuitData<F, D>,
    pub d_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
    pub sr_common:  CommonCircuitData<F, D>,
    pub sr_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
}

struct BridgeTxSuperTargets {
    w_proof:  ProofWithPublicInputsTarget<D>,
    d_proof:  ProofWithPublicInputsTarget<D>,
    sr_proof: ProofWithPublicInputsTarget<D>,
    // No private witnesses — common PIs read directly from w_proof/d_proof slots
}
```

### `setup_builder` function

Same structural pattern as PrivTx but with 3 inner proofs:

```rust
fn setup_builder(inner: &BridgeTxSuperCircuitData) -> (CircuitBuilder<F, D>, BridgeTxSuperTargets) {
    const HALF: usize = BRIDGE_TX_BATCH_SIZE / 2; // = 256

    // 1-2. Allocate proof targets, verify all three in-circuit

    // 3. Derive pi_sizes — no hardcoded constants
    let w_pi_size = inner.w_common.num_public_inputs / HALF; // = 85
    let d_pi_size = inner.d_common.num_public_inputs / HALF; // = 35

    // 4. Build named target wrappers
    let sr = SrTargets { pis: &sr_proof.public_inputs };
    let w_slots: Vec<WithdrawSlotTargets> = (0..HALF)
        .map(|s| withdraw_slot(&w_proof.public_inputs, s, w_pi_size))
        .collect();
    let d_slots: Vec<DepositSlotTargets> = (0..HALF)
        .map(|s| deposit_slot(&d_proof.public_inputs, s, d_pi_size))
        .collect();

    // 5. Cross-check SR leaves (unconditional — SR is built from ALL proofs)
    //    Withdraw slots → SR[0..HALF], deposit slots → SR[HALF..2*HALF]
    for (s, slot) in w_slots.iter().enumerate() {
        let sr_leaf = sr.leaf(s);
        for k in 0..4 { builder.connect(slot.output_commitment()[k], sr_leaf[k]); }
    }
    for (s, slot) in d_slots.iter().enumerate() {
        let sr_leaf = sr.leaf(HALF + s);
        for k in 0..4 { builder.connect(slot.output_commitment()[k], sr_leaf[k]); }
    }

    // 6. Assert uniform common PIs across all w_slots and d_slots
    //    Connect all slots to w_slots[0] via builder.connect_hashes (no private witnesses)
    for slot in w_slots.iter().skip(1) {
        builder.connect_hashes(slot.root.0, w_slots[0].root.0);
        builder.connect_hashes(slot.mainpool_config_root.0, w_slots[0].mainpool_config_root.0);
    }
    for slot in &d_slots {
        builder.connect_hashes(slot.root.0, w_slots[0].root.0);
        builder.connect_hashes(slot.mainpool_config_root.0, w_slots[0].mainpool_config_root.0);
    }

    // 7. Build Keccak preimage (all via named fields; common PIs from w_slots[0])
    //    u32_words = sr.root | w_slots[0].root | w_slots[0].mainpool_config_root | w_unique_pis... | d_unique_pis...

    // 8. Keccak-256 → 8 u32 public inputs
}
```

### `impl BridgeTxSuperCircuit`

Same API as `PrivTxSuperCircuit` but `prove(&self, w_agg: ProofNative, d_agg: ProofNative, sr: ProofNative) -> Result<ProofNative>` (no private witnesses).

---

## Step 5 — `BridgeTxAggregator` (in `bridge_tx_aggregator.rs`)

### Struct

```rust
pub struct BridgeTxAggregator {
    w_aggregator:  GenericAggregator<F, ConfigNative, D>,
    d_aggregator:  GenericAggregator<F, ConfigNative, D>,
    subtree_root:  SubtreeRootCircuit,
    super_circuit: BridgeTxSuperCircuit,
}
```

### `impl BridgeTxAggregator`

```rust
pub fn build(
    withdraw_leaf_common:   CommonCircuitData<F, D>,
    withdraw_leaf_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
    deposit_leaf_common:    CommonCircuitData<F, D>,
    deposit_leaf_verifier:  VerifierOnlyCircuitData<ConfigNative, D>,
) -> Result<Self>
// w_aggregator: arity=4, depth=4 (4^4=256 withdraw slots)
// d_aggregator: arity=4, depth=4 (4^4=256 deposit slots)

pub fn prove(&self, batch: &BridgeTxBatch) -> Result<ProofNative>
// batch.proofs()[0..256] = withdrawals, [256..512] = deposits
// SR leaves: batch.proofs().iter().flat_map(|p| p.output_commitments()) — withdraw first, deposit second

pub fn store_artifacts(&self, path: &Path) -> Result<()>
pub fn from_artifacts(&self, path: &Path, w_gate_ser: &dyn GateSerializer<F, D>, d_gate_ser: &dyn GateSerializer<F, D>) -> Result<Self>
pub fn has_full_artifacts(path: &Path) -> Result<bool>
```

**Artifact directory layout:**
```
bridge-tx-aggregator/
├── withdraw-agg/         ← GenericAggregator (arity=4, depth=4)
├── deposit-agg/          ← GenericAggregator (arity=4, depth=4)
├── subtree-root/
└── super-circuit/
```

---

## Step 6 — Native PI Commitment Helper

Both aggregators delegate to existing `BatchHelper::pi_commitment`:

```rust
// In priv_tx_aggregator.rs
pub fn compute_pi_commitment_native(batch: &PrivateTxBatch) -> Result<[u8; 32]> {
    batch.pi_commitment::<SolidityKeccak256>()
}

// In bridge_tx_aggregator.rs
pub fn compute_pi_commitment_native(batch: &BridgeTxBatch) -> Result<[u8; 32]> {
    batch.pi_commitment::<SolidityKeccak256>()
}
```

---

## Step 7 — Testing Pipeline

### Cheap tests (`#[test]`, no ZK proving)

```rust
// priv_tx_aggregator.rs
#[test] fn priv_tx_agg_config_is_valid()      // GenericAggregatorConfig{8,2}.validate() == Ok
#[test] fn priv_tx_sr_leaf_count_matches()    // PRIV_TX_BATCH_SIZE*(1+NOTE_BATCH) == SUBTREE_BATCHSIZE
#[test] fn priv_tx_preimage_word_count()      // 24 + 64*(1+4+4+7*4+7*4)*2 = 24 + 64*130 = 8344

// bridge_tx_aggregator.rs
#[test] fn bridge_tx_w_agg_config_is_valid()  // GenericAggregatorConfig{4,4}.validate() == Ok
#[test] fn bridge_tx_d_agg_config_is_valid()
#[test] fn bridge_tx_half_is_arity_power()    // 256 == 4^4
#[test] fn bridge_tx_preimage_word_count()    // 24 + 256*(w_unique)*2 + 256*(d_unique)*2
```

### Integration tests (`#[test] #[ignore]`, ZK proving — run with `--release --include-ignored`)

```rust
#[test] #[ignore] fn priv_tx_e2e_single_slot_matches_pi_commitment()
#[test] #[ignore] fn priv_tx_e2e_full_batch()
#[test] #[ignore] fn priv_tx_artifact_roundtrip()
#[test] #[ignore] fn priv_tx_final_proof_pis_match_native_commitment()

#[test] #[ignore] fn bridge_tx_e2e_minimal_batch()
#[test] #[ignore] fn bridge_tx_e2e_full_batch()
#[test] #[ignore] fn bridge_tx_artifact_roundtrip()
#[test] #[ignore] fn bridge_tx_final_proof_pis_match_native_commitment()
```

### How to run

```bash
# Cheap tests only:
cargo test -p doxa-server aggregator_service

# All tests including slow ZK (release recommended):
cargo test -p doxa-server --release aggregator_service -- --include-ignored
```

---

## Implementation Order

1. **Step 1**: Add slot target structs + helpers to both files
2. **Step 2**: Implement `PrivTxSuperCircuit` (`setup_builder`, `build`, `prove`, artifacts)
3. **Step 3**: Implement `PrivTxAggregator` (`build`, `prove`, artifacts)
4. **Step 4**: Implement `BridgeTxSuperCircuit`
5. **Step 5**: Implement `BridgeTxAggregator`
6. **Steps 6-7**: Native helpers + all tests (cheap first)

---

## Verification Checklist

- [ ] `cargo build -p doxa-server` compiles with no warnings
- [ ] `cargo test -p doxa-server aggregator_service` all cheap tests pass
- [ ] `PrivTxAggregator::prove` final proof has exactly 8 public inputs
- [ ] `BridgeTxAggregator::prove` final proof has exactly 8 public inputs
- [ ] `final_proof.public_inputs` (8 u32) == `batch.pi_commitment::<SolidityKeccak256>()` (32 bytes)
- [ ] Artifact store/load round-trip produces valid proofs
- [ ] `BN128WrapperService::wrap_groth16(final_proof)` succeeds

---

## Critical Files

| File | Role |
|------|------|
| `doxa-server/src/aggregator_service/priv_tx_aggregator.rs` | **Primary** — PrivTxSuperCircuit + PrivTxAggregator |
| `doxa-server/src/aggregator_service/bridge_tx_aggregator.rs` | **Primary** — BridgeTxSuperCircuit + BridgeTxAggregator |
| `doxa-server/src/aggregator_service/generic_aggregator/aggregator.rs` | Reference — GenericAggregator::new, aggregate |
| `doxa-server/src/aggregator_service/generic_aggregator/artifacts.rs` | Reference — store_artifacts, from_artifacts |
| `doxa-server/src/prover_service/subtree_root.rs` | Reuse — SubtreeRootCircuit |
| `doxa-server/src/batch_helper.rs` | Reuse — BatchHelper, SolidityKeccak256 |
| `doxa-server/src/prover_service/priv_tx/batch_helper.rs` | Reuse — PrivateTxBatch |
| `doxa-server/src/prover_service/bridge_tx/batch_helper.rs` | Reuse — BridgeTxBatch |
| `doxa-server/src/proof_aggregation/tx_super_aggregator_v2.rs` | Reference — batch_assert_zero, field_to_u32 helpers |
| `doxa-client/src/plonky2_gadgets/priv_tx/targets.rs` | **Modify** — make types/fields pub, add `from_pis()` + helpers to `TxCircuitPublicTargets` |
| `doxa-client/src/plonky2_gadgets/withdraw_tx/targets.rs` | **Modify** — make types/fields pub, add `from_pis()` + helpers to `WithdrawTxPublicTargets` |
| `doxa-client/src/plonky2_gadgets/deposit_tx/targets.rs` | **Modify** — make types/fields pub, add `from_pis()` + helpers to `DepositTxPublicTargets` |
| `doxa-client/src/lib.rs` | Constants: NOTE_BATCH, PRIV_TX_BATCH_SIZE, etc. |
