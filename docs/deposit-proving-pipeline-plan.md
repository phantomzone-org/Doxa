# Deposit Proving Pipeline — Implementation Plan

## Progress Tracker

| Step | Title                                           | Status |
|------|-------------------------------------------------|--------|
| 1    | Constants and PI-offset definitions             | TODO   |
| 2    | `tessera-client` public exports                 | TODO   |
| 3    | `DepositSuperAggregatorV2` circuit              | TODO   |
| 4    | `deposit_tx_artifacts` binary                   | TODO   |
| 5    | `ConsumeProveRequest` breaking change           | TODO   |
| 6    | `DepositProverService` + `ProverRuntimeV2`      | TODO   |
| 7    | `InProcessProver` updates                       | TODO   |
| 8    | `tessera-e2e/README.md` updates                 | TODO   |

---

## Background

Tessera has two on-chain proving pipelines:

- **TX pipeline** (implemented): PrivTx leaf → GenericAggregator (ARITY=2, depth=6, 64 slots) → SubtreeRootCircuit (512 NC leaves) → SuperAggregatorV2 → BN128 → Groth16
- **Deposit pipeline** (this plan): DepositTx leaf → GenericAggregator (ARITY=2, depth=6, 64 slots) → SubtreeRootCircuit (64 `deposit_note_comm` leaves) → DepositSuperAggregatorV2 → BN128 → Groth16

The Groth16 proof is submitted to `TesseraRollupV2.proveDepositBatch(piCommitment, proof)`.  The `piCommitment` is a Keccak-256 hash computed both in-circuit by `DepositSuperAggregatorV2` and on-chain by `_computeDepositPiCommitment`.

### Deposit TX public inputs (31 total)

| Index range | Field                 | Width |
|-------------|-----------------------|-------|
| PI[0]       | `not_fake_tx`         | 1     |
| PI[1..5]    | `act_root`            | 4     |
| PI[5..9]    | `accin_null`          | 4     |
| PI[9..13]   | `accout_comm`         | 4     |
| PI[13..17]  | `deposit_note_comm`   | 4     |
| PI[17..22]  | `eth_address`         | 5     |
| PI[22..30]  | `deposit_note.amount` | 8     |
| PI[30]      | `asset_id`            | 1     |

Constants:
- `DEPOSIT_LEAF_PI_SIZE = 31`
- `DEPOSIT_IS_REAL_OFFSET = 0`  (`not_fake_tx`)
- `DEPOSIT_DATA_OFFSET = 1`     (first data field = `act_root`)
- `DEPOSIT_ACCIN_NULL_OFFSET = 5`
- `DEPOSIT_ACCOUT_COMM_OFFSET = 9`
- `DEPOSIT_NOTE_COMM_OFFSET = 13`

### Keccak preimage — canonical order

Must match `_computeDepositPiCommitment` in `TesseraRollupV2.sol` exactly:

```text
acRoot(uint256) | ncRoot(uint256) | mainPoolConfigRoot(bytes32) |
batchPoseidonRoot(uint256) | depositNoteCommitments[0..64](uint256[])
```

- **`acRoot` / `ncRoot`**: both set to the same on-chain Poseidon IMT root (private witness, 4 Goldilocks fields) — same convention as the TX pipeline.
- **`mainPoolConfigRoot`**: `bytes32` private witness (8 u32 big-endian words).
- **`batchPoseidonRoot`**: SubtreeRootCircuit output root (SR proof PI[0..4]), LE-packed `uint256`.
- **`depositNoteCommitments[0..64]`**: SR proof leaves (PI[4..4+64×4]), LE-packed `uint256` each.

No `accountCommitment`, `accountNullifier`, or `noteNullifiers` fields — the `DepositBatch` Solidity struct does not carry them.

> **Open design question DQ-1:** Should `_computeDepositPiCommitment` be extended with `accoutComms[0..64]` and/or `accNullifiers[0..64]`?  If the Solidity contract is updated to include those fields, the circuit must be updated to match before Step 3 is implemented.

---

## Step 1 — Constants and PI-offset definitions

**File:** `tessera-trees/src/proof_aggregation/deposit_super_aggregator_v2.rs` (top section)

```rust
pub const DEPOSIT_LEAF_PI_SIZE: usize = 31;
pub const DEPOSIT_IS_REAL_OFFSET: usize = 0;
pub const DEPOSIT_DATA_OFFSET: usize = 1;
pub const DEPOSIT_ACCIN_NULL_OFFSET: usize = 5;
pub const DEPOSIT_ACCOUT_COMM_OFFSET: usize = 9;
pub const DEPOSIT_NOTE_COMM_OFFSET: usize = 13;
```

Export from `tessera-trees/src/proof_aggregation/mod.rs`.

**Verification:** Unit test asserting `DEPOSIT_LEAF_PI_SIZE == 31` and that each offset + width ≤ 31.

---

## Step 2 — `tessera-client` public exports

**File:** `tessera-client/src/plonky2_gadgets/deposit_tx/mod.rs` + `tessera-client/src/lib.rs`

Add two new `pub` functions (analogous to `build_priv_tx_circuit` / `prove_dummy_priv_tx`):

### `build_deposit_tx_circuit`

```rust
pub fn build_deposit_tx_circuit() -> (tessera_trees::CircuitDataNative, DepositTxTargets) {
    use plonky2::plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig};
    use tessera_trees::tree::hasher::HashOutput;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<tessera_trees::F, { tessera_trees::D }>::new(config);
    let ctx = HashOutput::register_luts(&mut builder);
    let t = deposit_tx_circuit::<HashOutput, _, _>(&mut builder, &ctx);
    let circuit = builder.build::<tessera_trees::ConfigNative>();
    (circuit, t)
}
```

### `prove_dummy_deposit_tx`

```rust
pub fn prove_dummy_deposit_tx(
    circuit: &tessera_trees::CircuitDataNative,
    targets: &DepositTxTargets,
    act_root: tessera_trees::tree::hasher::HashOutput,
    mainpool_config_root: tessera_trees::tree::hasher::HashOutput,
) -> tessera_trees::ProofNative {
    let mut pw = plonky2::iop::witness::PartialWitness::new();
    set_fake_deposit_tx_witness(&mut pw, targets, act_root, mainpool_config_root);
    let proof = circuit.prove(pw).expect("dummy deposit_tx prove failed");
    circuit.verify(proof.clone()).expect("dummy deposit_tx verify failed");
    proof
}
```

`set_fake_deposit_tx_witness` stays `pub(crate)` — it is only called from within `tessera-client`.

**Add to `tessera-client/src/lib.rs`:**

```rust
pub use plonky2_gadgets::deposit_tx::{build_deposit_tx_circuit, prove_dummy_deposit_tx};
```

**Verification:** Unit test inside `deposit_tx/mod.rs` asserting `circuit_data.common.num_public_inputs == DEPOSIT_LEAF_PI_SIZE`.

---

## Step 3 — `DepositSuperAggregatorV2` circuit

**File:** `tessera-trees/src/proof_aggregation/deposit_super_aggregator_v2.rs` (new)

Mirror `super_aggregator_v2.rs` with the following differences:

### Struct layout

```rust
pub struct DepositSuperAggregatorV2CircuitData {
    pub deposit_common: CommonCircuitData<F, D>,
    pub deposit_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
    pub sr_common: CommonCircuitData<F, D>,
    pub sr_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
}

struct DepositSuperAggregatorV2Targets {
    deposit_proof: ProofWithPublicInputsTarget<D>,
    deposit_vd: VerifierCircuitTarget,
    sr_proof: ProofWithPublicInputsTarget<D>,
    sr_vd: VerifierCircuitTarget,
    act_root: [Target; 4],               // private witness (on-chain IMT root)
    main_pool_cfg_root_u32s: [Target; 8], // private witness (bytes32)
}
```

### `setup_builder` logic

1. **Derive batch sizes:**
   ```
   deposit_total_pi = deposit_common.num_public_inputs
   assert!(deposit_total_pi % DEPOSIT_LEAF_PI_SIZE == 0)
   n_deposit_slots = deposit_total_pi / DEPOSIT_LEAF_PI_SIZE   // = 64
   sr_batch_size = sr_common.num_public_inputs / 4 - 1         // = 64
   assert!(sr_batch_size == n_deposit_slots)
   ```

2. **Verify both proofs in-circuit.**

3. **`is_real` boolean assertion:** For each slot `s`, assert `deposit_proof.public_inputs[s * DEPOSIT_LEAF_PI_SIZE + DEPOSIT_IS_REAL_OFFSET]` is bool.

4. **Cross-check SR leaves vs `deposit_note_comm`:** For each slot `s`, field `k` in 0..4:
   ```
   deposit_nc = deposit_proof.public_inputs[s * DEPOSIT_LEAF_PI_SIZE + DEPOSIT_NOTE_COMM_OFFSET + k]
   sr_leaf    = sr_proof.public_inputs[4 + s * 4 + k]
   gated_diff = is_real[s] * (deposit_nc - sr_leaf)
   ```
   Batch-assert-zero all `gated_diff` values using Fiat-Shamir RLC (same `batch_assert_zero` helper as TX version — share it or duplicate it).

5. **Private witnesses:** `act_root[4]` and `main_pool_cfg_root_u32s[8]`.

6. **Keccak preimage** (matches `_computeDepositPiCommitment`):
   ```
   u32_targets = []
   // 1. acRoot (= ncRoot = act_root)
   u32_targets += pack_hash_le_to_u32s(act_root)
   // 2. ncRoot (same)
   u32_targets += pack_hash_le_to_u32s(act_root)
   // 3. mainPoolConfigRoot (8 raw u32 words)
   u32_targets += main_pool_cfg_root_u32s
   // 4. batchPoseidonRoot — SR proof PI[0..4]
   u32_targets += pack_hash_le_to_u32s(sr_proof.public_inputs[0..4])
   // 5. depositNoteCommitments[0..64] — SR proof leaves
   for i in 0..n_deposit_slots:
       u32_targets += pack_hash_le_to_u32s(sr_proof.public_inputs[4 + i*4 .. 4 + i*4 + 4])
   ```
   Hash → 8 output u32 words → register as 8 public inputs.

### Public API (mirrors SuperAggregatorV2)

```rust
impl DepositSuperAggregatorV2 {
    pub fn build(inner: DepositSuperAggregatorV2CircuitData) -> Result<Self>
    pub fn prove(
        &self,
        deposit_agg: ProofNative,
        sr: ProofNative,
        act_root: HashOutput,
        main_pool_cfg_root: [u8; 32],
    ) -> Result<ProofNative>
    pub fn compute_deposit_pi_commitment_native(
        act_root: HashOutput,
        main_pool_cfg_root: [u8; 32],
        batch_poseidon_root: HashOutput,
        deposit_note_commitments: &[HashOutput],
    ) -> [u32; 8]
    pub fn store_artifacts(&self, path: &Path) -> Result<()>
    pub fn from_artifacts(path: &Path) -> Result<Self>
    pub fn has_artifacts(path: &Path) -> bool
}
```

Artifact files: `circuit_data.bin`, `deposit_common.bin`, `deposit_verifier.bin`, `sr_common.bin`, `sr_verifier.bin`.

### Off-circuit validation

```rust
pub fn validate_deposit_subtree_nc_offcircuit(
    sr_pis: &[F],
    deposit_pis: &[F],
    n_deposit_slots: usize,
) -> Result<()>
```

For each real slot (where `deposit_pis[s * DEPOSIT_LEAF_PI_SIZE + DEPOSIT_IS_REAL_OFFSET] == F::ONE`), assert `sr_pis[4 + s*4 + k] == deposit_pis[s * DEPOSIT_LEAF_PI_SIZE + DEPOSIT_NOTE_COMM_OFFSET + k]` for `k in 0..4`.

### Export from `mod.rs`

```rust
pub mod deposit_super_aggregator_v2;
pub use deposit_super_aggregator_v2::{
    DEPOSIT_LEAF_PI_SIZE, DEPOSIT_IS_REAL_OFFSET, DEPOSIT_NOTE_COMM_OFFSET,
    DepositSuperAggregatorV2, DepositSuperAggregatorV2CircuitData,
    validate_deposit_subtree_nc_offcircuit,
};
```

### Tests (in the new file)

1. `test_build_deposit_pi_count` — build with 2-slot synthetic circuits, assert 8 output PIs.
2. `test_prove_and_deposit_pi_commitment_matches_native` — prove + verify, compare circuit PIs to `compute_deposit_pi_commitment_native`.
3. `test_cross_check_rejects_nc_mismatch` — wrong SR leaves → prove must fail.

**Note:** `pack_hash_le_to_u32s` is `fn` (private) in `super_aggregator_v2.rs`.  Move it to a shared internal helper in `tessera-trees/src/proof_aggregation/` or duplicate it.

---

## Step 4 — `deposit_tx_artifacts` binary

**File:** `tessera-e2e/src/bin/deposit_tx_artifacts.rs` (new)

Follow `super_aggregator_v2_artifacts.rs` structure exactly.  Key differences:

```
const DEPOSIT_BATCH_SIZE: usize = tessera_client::PRIV_TX_BATCH_SIZE; // 64
const SR_BATCH_SIZE: usize = DEPOSIT_BATCH_SIZE;  // 64 leaves (not 512)
```

### Steps

1. Build deposit_tx circuit + 1 dummy proof (`prove_dummy_deposit_tx`).
2. Build `GenericAggregator` (ARITY=2, depth=6) on deposit_tx circuit.
3. **O(log N) doubling** (6 merges, not 64 proofs):
   ```rust
   let mut current = dummy_inner_proof.clone();
   for level_idx in 0..agg_depth {
       let level = deposit_agg.level_circuit(level_idx)?;
       let inner_verifier = deposit_agg.inner_verifier_for_level(level_idx);
       let mut pw = PartialWitness::new();
       pw.set_verifier_data_target(&level.verifier_target, inner_verifier)?;
       for i in 0..ARITY { pw.set_proof_with_pis_target(&level.proof_targets[i], &current)?; }
       current = level.circuit_data.prove(pw)?;
   }
   ```
4. Extract 64 SR leaves from aggregated proof (`deposit_note_comm` at offset `DEPOSIT_NOTE_COMM_OFFSET` per slot).
5. Build `SubtreeRootCircuit(batch_size=64)` + prove on those 64 leaves.
6. Build `DepositSuperAggregatorV2`.
7. Prove DSAV2 with dummy inputs.
8. Store all artifacts.
9–11. BN128 + Groth16 trusted setup + round-trip test (identical to TX binary steps 9–11).
12. Copy `Verifier.sol` → `tessera-solidity/src/VerifierDepositSuperAggregatorV2.sol`; copy proof fixture.

### Artifact layout

```
$TESSERA_ARTIFACTS_DIR/deposit/
  deposit-aggregator/                         GenericAggregator (depth 6, 64 slots)
  deposit-aggregator/dummy_inner_deposit_proof.bin
  deposit-subtree-root/                       SubtreeRootCircuit (64 leaves)
  deposit-super-aggregator-v2/                DSAV2 Plonky2 circuit
  deposit-super-aggregator-v2/dummy_root_proof.bin
  deposit-super-aggregator-v2/dummy_inner_deposit_proof.bin
  deposit-super-aggregator-v2/plonky2-proof/  BN128 wrapper
  deposit-super-aggregator-v2/groth-artifacts/ Groth16 keys + Verifier.sol
```

### Run command

```bash
TESSERA_ARTIFACTS_DIR=/path/to/artifacts \
cargo run -p tessera-e2e --bin deposit_tx_artifacts --release
```

---

## Step 5 — `ConsumeProveRequest` breaking change

**File:** `tessera-server/src/types.rs`, `tessera-server/src/sequencer/batch.rs`

**Current:** `nc_leaves: Vec<[u8; 32]>` length = 512 (`PRIV_TX_BATCH_SIZE × NOTES_PER_SLOT`).

**New:** Length = 64 (`PRIV_TX_BATCH_SIZE`) — one `deposit_note_comm` per deposit TX slot.

Changes:
1. Update `ConsumeProveRequest.nc_leaves` doc-comment.
2. In `ConsumeBatchBuilder`: change `note_batch_size` → `deposit_batch_size = PRIV_TX_BATCH_SIZE = 64`. Finalization pads to 64 dummy leaves (one per empty slot), not 512.
3. Update `ConsumeBatchBuilder::finalize` so `nc_leaves` has length 64.
4. Update any assertions or tests that relied on length 512.

---

## Step 6 — `DepositProverService` + `ProverRuntimeV2` updates

**File:** `tessera-server/src/prover_v2.rs`

### New service wrapper

```rust
pub struct DepositSuperAggregatorV2Service {
    super_agg: DepositSuperAggregatorV2,
    bn128_wrapper: BN128Wrapper,
}

impl DepositSuperAggregatorV2Service {
    pub fn from_artifacts(path: &Path) -> Result<Self>
    pub fn prove_plonky2(
        &self, deposit_agg: ProofNative, sr: ProofNative,
        act_root: HashOutput, main_pool_cfg_root: [u8; 32],
    ) -> Result<(ProofNative, [u8; 32])>
    pub fn wrap_groth16(&self, root_proof: ProofNative) -> Result<SolidityProof>
}
```

`from_artifacts` loads DSAV2 circuit, BN128 wrapper, initialises Groth16 singleton.

> **DQ-2 — Groth16 singleton:** `Groth16Wrapper::init` uses a global FFI singleton.  If TX and deposit use different verifying keys, calling `init` twice will overwrite the first.  Confirm whether gnark supports multiple keyed singletons before implementing this step.  If not, either TX and deposit must share the same circuit, or separate processes are required.

### `DepositAssociatedInputAggregatorService`

Mirror `AssociatedInputAggregatorService` with:
- Leaf circuit built via `tessera_client::build_deposit_tx_circuit()`
- `n_leaves() = PRIV_TX_BATCH_SIZE = 64`

### `ProverRuntimeV2` struct

Add optional deposit fields:
```rust
deposit_subtree_root: Option<SubtreeRootProverService>,
deposit_aggregator: Option<DepositAssociatedInputAggregatorService>,
deposit_super_aggregator: Option<DepositSuperAggregatorV2Service>,
dummy_inner_deposit_proof_bytes: Option<Vec<u8>>,
```

### `ProverRuntimeV2::init` — new parameter

```rust
pub fn init(
    sr_artifacts_path: PathBuf,
    sr_batch_size: usize,
    super_aggregator_v2_artifacts_path: PathBuf,
    aggregator_artifacts_path: Option<PathBuf>,
    deposit_artifacts_path: Option<PathBuf>,      // new
    aggregation_prover_urls: Vec<String>,
    aggregation_prover_timeout_secs: u64,
) -> Result<Self>
```

When `deposit_artifacts_path = Some(base)`, load all four deposit services.

### Replace `prove_consume_request` placeholder

Real pipeline:
1. Aggregate deposit_tx leaf proofs (O(log N) doubling / dummy fill pattern).
2. Convert `nc_leaves` (len=64) to `Vec<HashOutput>`.
3. Prove `SubtreeRootCircuit` (64 leaves) → `batch_poseidon_root`.
4. Off-circuit cross-check via `validate_deposit_subtree_nc_offcircuit`.
5. `DepositSuperAggregatorV2::prove_plonky2` → SAV2 root proof + `super_pi_commitment`.
6. `wrap_groth16` → `SolidityProof`.

---

## Step 7 — `InProcessProver` updates

**File:** `tessera-e2e/src/prover_adapter.rs`

Detect `$TESSERA_ARTIFACTS_DIR/deposit/` and pass it as `deposit_artifacts_path` to `ProverRuntimeV2::init`.

---

## Step 8 — `tessera-e2e/README.md` updates

1. Add deposit pipeline row to the **Proving Pipeline Overview** table.
2. Add **Step 2 — Deposit TX proving artifacts** section with `deposit_tx_artifacts` command and output layout.
3. Update the full-rebuild command to include `deposit_tx_artifacts`.
4. Note the Groth16 singleton constraint (DQ-2).

---

## Open Design Questions

| ID   | Question | Must resolve before |
|------|----------|---------------------|
| DQ-1 | Should `_computeDepositPiCommitment` be extended with `accoutComms[0..64]` / `accNullifiers[0..64]`? Current Solidity does not include them. | Step 3 |
| DQ-2 | Does the gnark Groth16 FFI singleton support multiple verifying keys? If not, TX and deposit Groth16 cannot coexist in one process. | Step 6 |
| DQ-3 | Deposit `SubtreeRootCircuit` (batch_size=64) vs TX one (batch_size=512) must be separate artifacts. Confirm naming/layout is acceptable. | Step 4 |

---

## Dependency Ordering

```
Step 1  (constants)
Step 2  (tessera-client exports)       ← needs Step 1
Step 3  (DepositSuperAggregatorV2)     ← needs Steps 1, 2; blocked by DQ-1
Step 4  (deposit_tx_artifacts binary)  ← needs Steps 1, 2, 3
Step 5  (ConsumeProveRequest change)   ← independent; coordinate with Step 6
Step 6  (ProverRuntimeV2)              ← needs Steps 3, 4, 5; blocked by DQ-2
Step 7  (InProcessProver)              ← needs Step 6
Step 8  (README)                       ← needs Steps 4, 6, 7
```

Steps 1–4 can be implemented and tested independently before any server-side changes.

---

## Implementation Notes

- `pack_hash_le_to_u32s` is private in `super_aggregator_v2.rs` — move to a shared internal module or duplicate in the new file.
- Run `cargo fmt && cargo clippy -p tessera-trees -p tessera-server --release` after each step.
- Run tests with `--release`: `cargo test -p tessera-trees --release`.
- Artifact binaries silently skip if output dirs exist — always `rm -rf $TESSERA_ARTIFACTS_DIR/deposit` before a rebuild.
- `#[allow(clippy::too_many_arguments)]` is needed on functions with > 7 parameters.
