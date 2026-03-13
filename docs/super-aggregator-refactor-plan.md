# SuperAggregator Refactor Plan

Split `SuperAggregatorService::prove` into two independently callable stages
**within the same struct**:
1. **`prove_plonky2`** — SA Plonky2 proof only. Verifies 5 inner proofs,
   outputs root proof + Keccak commitment. Does not touch BN128/Groth16.
2. **`wrap_groth16`** — BN128-wraps then Groth16-proves a SA root proof.

`SuperAggregatorService` always loads both subsystems (no optional init).
The sub-provers (`SuperAggregator`, `BN128Wrapper`) each get their own
public initializer so tests can instantiate them independently.

Add a test for (1) that simulates values coming from the sequencer, using
the `BatchBuilder` → `FinalizedBatch` path. The test uses
`SuperAggregator::build` directly — no artifacts, no BN128/Groth16.

---

## Progress

| # | Task | Status |
|---|------|--------|
| 1 | Split `SuperAggregatorService::prove` into two methods | ☐ |
| 2 | Update `try_prove_request` call site | ☐ |
| 3 | Add sequencer-integrated SA Plonky2 test | ☐ |
| 4 | Cargo fmt + clippy + verify existing tests pass | ☐ |

---

## Step 1 — Split `SuperAggregatorService::prove` into two methods

**File:** `tessera-server/src/prover.rs`

### Struct stays the same:

```rust
pub struct SuperAggregatorService {
    super_agg: SuperAggregator,
    bn128_wrapper: BN128Wrapper,
}
```

`from_artifacts` is **unchanged** — always loads everything.

### Three methods (replace the old monolithic `prove`):

```rust
impl SuperAggregatorService {
    // from_artifacts — unchanged

    /// Stage 1: SA Plonky2 proof (5 inner proofs → root proof + 32-byte commitment).
    /// Does not touch BN128/Groth16.
    pub fn prove_plonky2(
        &self,
        nc: ProofNative,
        nn: ProofNative,
        ac: ProofNative,
        an: ProofNative,
        tx_agg: ProofNative,
    ) -> Result<(ProofNative, [u8; 32])> {
        let root_proof = self.super_agg
            .prove(nc, nn, ac, an, tx_agg)
            .map_err(|e| anyhow!("SA plonky2 prove: {e}"))?;

        // Extract super_pi_commitment: 8 PIs, each a u32 word (big-endian).
        let pis = &root_proof.public_inputs;
        anyhow::ensure!(pis.len() == 8, "SA root must have 8 PIs, got {}", pis.len());
        let mut commitment = [0u8; 32];
        for (i, fi) in pis.iter().enumerate() {
            let word = fi.to_canonical_u64() as u32;
            commitment[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        Ok((root_proof, commitment))
    }

    /// Stage 2: BN128 wrap + Groth16 prove of a SA root proof.
    pub fn wrap_groth16(&self, root_proof: ProofNative) -> Result<SolidityProof> {
        let bn128_proof = self.bn128_wrapper
            .wrap_proof_to_bn128(root_proof)
            .map_err(|e| anyhow!("SA BN128 wrap: {e}"))?;

        let (g16_proof, g16_pub_inp) = Groth16Wrapper::prove(bn128_proof)
            .map_err(|e| anyhow!("SA Groth16: {e}"))?;
        let solidity_json = Groth16Wrapper::proof_to_solidity_json(&g16_proof, &g16_pub_inp)
            .map_err(|e| anyhow!("SA solidity JSON: {e}"))?;
        Groth16Wrapper::verify(g16_proof, g16_pub_inp)
            .map_err(|e| anyhow!("SA Groth16 verify: {e}"))?;

        parse_solidity_proof_json(&solidity_json)
    }

    /// Combined: prove_plonky2 + wrap_groth16 (convenience, same signature as before).
    pub fn prove(
        &self,
        nc: ProofNative,
        nn: ProofNative,
        ac: ProofNative,
        an: ProofNative,
        tx_agg: ProofNative,
    ) -> Result<(SolidityProof, [u8; 32])> {
        let (root_proof, commitment) = self.prove_plonky2(nc, nn, ac, an, tx_agg)?;
        let solidity_proof = self.wrap_groth16(root_proof)?;
        Ok((solidity_proof, commitment))
    }
}
```

Delete the old monolithic `prove` body — its logic is now split across
`prove_plonky2` and `wrap_groth16`.

---

## Step 2 — Update `try_prove_request` call site

**File:** `tessera-server/src/prover.rs`, `try_prove_request` (~line 732).

Replace:
```rust
let (solidity_proof, super_pi_commitment) = self
    .super_aggregator
    .prove(nc_proof, nn_proof, ac_proof, an_proof, tx_agg_root)?;
```

With:
```rust
info!(batch_id, "running SuperAggregator Plonky2 proof");
let (sa_root_proof, super_pi_commitment) = self
    .super_aggregator
    .prove_plonky2(nc_proof, nn_proof, ac_proof, an_proof, tx_agg_root)?;

info!(batch_id, "wrapping SA root proof (BN128 + Groth16)");
let solidity_proof = self
    .super_aggregator
    .wrap_groth16(sa_root_proof)?;
```

`ProverRuntime` struct and `init` are **unchanged**.

---

## Step 3 — Add sequencer-integrated SA Plonky2 test

**File:** `tessera-server/tests/real_proof_pipeline.rs` — add a new test function.

### Test: `test_sa_plonky2_from_batch_builder`

Goal: exercise `BatchBuilder` → `FinalizedBatch` → tree proofs → TX aggregation
→ `SuperAggregator::prove` (**Plonky2 only, no BN128/Groth16**), verifying
that sequencer-produced batches with mixed real+dummy slots pass the SA
circuit, including off-circuit checks.

This test uses `SuperAggregator::build` directly from `tessera-trees` — it
needs **zero artifact files** and **zero BN128/Groth16 dependencies**.
It does not go through `SuperAggregatorService` at all.

Batch size: 4 accounts (arity=2, depth=2), 2 real + 2 dummy (auto-padded).

**Outline:**

```
1. Build PrivTx circuit + generate 2 real proofs (seeds 42, 99).
2. Build 4 empty trees (depth=32, with nullifier padding for account/note batch sizes).
3. Instantiate BatchBuilder(4, &ac_tree, &an_tree, &nc_tree, &nn_tree).
4. For each real proof:
   a. Extract AC/AN/NC/NN from PIs as [u8; 32].
   b. bb.add_private_tx(proof.to_bytes(), ac, an, nc, nn).
5. let batch = bb.finalize();  // pads slots 2-3 with dummies
6. Build tree proofs from FinalizedBatch arrays:
   - NC commitment tree: insert nc_leaves (arrival order).
   - AC commitment tree: insert ac_leaves (arrival order).
   - NN nullifier tree: insert nn_sorted.
   - AN nullifier tree: insert an_sorted.
   - Build circuit + prove for each.
7. Build GenericAggregator (arity=2, depth=2).
8. For each slot 0..4:
   - Real (in batch.tx_proofs_by_slot): deserialize proof bytes as ProofNative.
   - Dummy: prove_dummy_priv_tx with:
     override_an = bytes32_to_f4(&batch.an_sorted[batch.an_sort_perm[s]])
     override_nn[j] = bytes32_to_f4(&batch.nn_sorted[batch.nn_sort_perm[s*8+j]])
9. Aggregate all 4 TX proofs via GenericAggregator::aggregate.
10. Run off-circuit PI cross-checks (validate_ac/nc/an/nn_offcircuit).
11. Build SuperAggregator::build from the 5 inner circuit datas.
12. sa.prove(nc, nn, ac, an, tx_agg) — Plonky2 only, no BN128/Groth16.
13. Assert root proof has 8 PIs.
14. sa.circuit_data.verify(root).
```

### Why this test matters

The existing `run_mixed_pipeline` helper builds tree leaves manually from
TX proof PIs (bypassing `BatchBuilder`). This new test validates the full
`BatchBuilder` → `FinalizedBatch` → sort permutation → dummy override path
end-to-end at the Plonky2 level, catching bugs like the AN/NN permutation
mismatch that only manifests when the sequencer sorts leaves.

---

## Step 4 — Cargo fmt + clippy + verify

```bash
cargo fmt -p tessera-server
cargo clippy -p tessera-trees -p tessera-server
cargo test -p tessera-server --test real_proof_pipeline --release -- \
  test_sa_plonky2_from_batch_builder --nocapture
```

Also verify existing tests still pass:
```bash
cargo test -p tessera-server --test real_proof_pipeline --release -- \
  test_real_proof_pipeline_all_real test_pipeline_4tx_2real_2dummy \
  test_pipeline_4tx_all_dummy --nocapture
```
