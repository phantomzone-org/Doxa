# Plan: Real-Proof E2E Testing Framework

## Context

The existing `tessera-server/tests/e2e_v2.rs` covers the full on-chain lifecycle but uses
`AcceptAllVerifier` (fake Groth16) and the sequencer's test API (raw leaf values, no Plonky2
proofs). The goal is a new E2E framework that exercises the full cryptographic pipeline:
real Plonky2 PrivTx proofs → real GenericAggregator → real SubtreeRootCircuit →
real SuperAggregatorV2 → real BN128 → real Groth16 on-chain verification.
The only concession to testability is `ToyUSDT` (no real ERC20 needed).

### Key design insights

**Two-level tree / root independence:**
The on-chain IMT (depth = `TESSERA_TREE_DEPTH`) stores `batchPoseidonRoot` values as leaves (one
per proven batch). Its root is `currentRoot`. The PrivTxCircuit's Merkle proofs (`accin_merkle_proof`,
`inotes_nct_proofs`) are against a **client-local flat CommitmentTree** of depth 32 (`ACT_DEPTH`).
The SAV2 receives `root` as a private witness and embeds it in the `piCommitment`; it does NOT
cross-check it against the PrivTxCircuit leaf PIs (`TX_LEAF_PI_SIZE = 77`, which strips the last 8
root PIs). The contract only enforces `root ∈ confirmedRoots`. Therefore:
- The client's local tree root does **not** need to equal `currentRoot` on-chain.
- Any `confirmedRoot` may be used as `root` in a TX proof (genesis is always confirmed).
- Merkle proofs just need to be valid for the chosen local tree root.

**FreshAcc specifics:**
`root = HashOutput([0;4])` (genesis, always confirmed). No ACT/NCT membership proof needed.
The output account commitment is `ac` (a separate batch field), not part of `nc_leaves`.

**Spend specifics:**
Client inserts `accin.commitment()` and input note commitments into a local flat tree, then uses
`local_tree.get_root()` as the proof's `root`. No relation to the on-chain IMT root required.
The sequencer uses `self.confirmed_root` for the batch's `acRoot`/`ncRoot` in the piCommitment.

**Deposit validation:**
The same SAV2 circuit is used for deposit batches. Slots without a `consume_proof` use the
pre-loaded dummy Plonky2 proof. Real deposit proofs run through the full Groth16 pipeline.

---

## Progress Tracker

| Step | Description | Status |
|------|-------------|--------|
| 1 | New crate `tessera-e2e` in workspace | ☐ |
| 2 | `ClientState` struct + pool-config builder | ☐ |
| 3 | `prove_freshacc` helper | ☐ |
| 4 | `prove_spend` helper | ☐ |
| 5 | In-process `ProverClient` trait + `InProcessProver` adapter | ☐ |
| 6 | Sequencer: `HttpProverClient` → `Arc<dyn ProverClient>` | ☐ |
| 7 | E2E test: deposit → validate | ☐ |
| 8 | E2E test: FreshAcc TX → validate | ☐ |
| 9 | E2E test: Spend TX → validate (trivial, zero amounts) | ☐ |
| 10 | `cargo fmt` + `clippy` | ☐ |

---

## Step 1 — New crate `tessera-e2e`

```
tessera-e2e/
  Cargo.toml
  src/
    lib.rs            ← re-exports client_state, prover_adapter
    client_state.rs   ← TesseraClientState
    prover_adapter.rs ← InProcessProver
  tests/
    e2e_real_proofs.rs
```

`Cargo.toml` dependencies: `tessera-client`, `tessera-server`, `tessera-trees`, `alloy`,
`tokio`, `anyhow`, `rand`, `rand_chacha`, `plonky2`.

Add `tessera-e2e` to root `Cargo.toml` workspace members.

---

## Step 2 — `TesseraClientState`

File: `tessera-e2e/src/client_state.rs`

```rust
pub struct TesseraClientState {
    // ── Circuit (built once, ~1–2 min) ───────────────────────────────────
    pub circuit:  CircuitDataNative,
    pub targets:  PrivTxTargets<D>,

    // ── Pool config (must match deployed contract's poolConfigRoot) ───────
    pub approval_sk:  PrivateKey,
    pub rejection_sk: PrivateKey,
    pub consume_sk:   PrivateKey,
    pub subpool_id:   SubpoolId,
    pub main_pool:    MainPoolConfigTree,

    // ── Account state ─────────────────────────────────────────────────────
    pub account:  Option<StandardAccount>,
    pub acc_pos:  Option<usize>,        // leaf position in local_tree

    // ── Notes ─────────────────────────────────────────────────────────────
    pub notes: Vec<(StandardNote, usize)>,   // (note, pos_in_local_tree)

    // ── Local flat tree (depth = ACT_DEPTH = 32) ──────────────────────────
    /// Independent of the on-chain IMT. Root used only for Merkle proofs.
    pub local_tree: CommitmentTree<HashOutput>,
}
```

**Critical invariant:** insert ALL leaves before generating any Merkle paths.

Constructor `TesseraClientState::new(seed: u64) -> Self`:
- Samples keys deterministically from seed via `ChaCha8Rng::seed_from_u64(seed)`
- Builds `SubpoolConfigTree` and `MainPoolConfigTree` (subpool at index 0, id = `SubpoolId(F::ONE)`)
- Calls `build_priv_tx_circuit()` (cache and reuse; very expensive)
- `account = None`, `local_tree = CommitmentTree::new(ACT_DEPTH)`

`pub fn pool_config_root(&self) -> [u8; 32]` — LE-packed bytes32 for contract deployment.

---

## Step 3 — `prove_freshacc` helper

```rust
impl TesseraClientState {
    /// Prove a FreshAcc TX. Updates self.account and self.local_tree.
    pub fn prove_freshacc(&mut self, rng: &mut impl CryptoRng + Rng)
        -> ProofWithPublicInputs<F, ConfigNative, D>
```

Steps:
1. Sample `PrivateIdentifier`; create `accin = StandardAccount::new_with(priv_id, subpool_id)`.
2. Sample `new_spend_sk`; derive `new_spend_pk`.
3. Sample `dinotes`, `donotes` via `sample_dummy_notes(rng)`.
4. Derive `tx_hash = derive_priv_tx_hash(accin.nullifier(None), accout.commitment(), ...)`.
5. Sign: `approval_sig = schnorr_sign(&approval_sk, &tx_hash, k)`.
6. Prove: `prove_real_priv_tx(&circuit, &targets, PrivTxInputs::FreshAcc(...))`.
7. Build `accout` (nonce incremented, new spend_auth).
8. Insert `accout.commitment().0` into `local_tree` → save `acc_pos`.
9. Set `self.account = Some(accout)`.
10. Return proof.

---

## Step 4 — `prove_spend` helper

```rust
impl TesseraClientState {
    /// Prove a Spend TX. Requires account.is_some() and acc_pos.is_some().
    pub fn prove_spend(
        &mut self,
        rng: &mut impl CryptoRng + Rng,
        input_note_indices: &[usize],  // into self.notes
        output_notes: Vec<StandardNote>,
    ) -> ProofWithPublicInputs<F, ConfigNative, D>
```

Steps:
1. Collect `inotes` from `self.notes[i]` for each index.
2. Insert ALL output note commitments into `local_tree` (not yet present).
3. **Then** generate all Merkle proofs against `local_tree.get_root()`.
   - `accin_merkle_proof` from `local_tree.merkle_path(acc_pos, 0, ACT_DEPTH)`
   - One `CommitmentTreeMerkleProof<NCT_DEPTH>` per input note
4. Prove with `PrivTxInputs::Spend(SpendTxInputs { root: local_tree.get_root(), ... })`.
5. Update `self.account` (nonce++, AST) and append output notes to `self.notes`.
6. Insert new `accout.commitment()` into `local_tree`; update `acc_pos`.

---

## Step 5 — `ProverClient` trait + `InProcessProver`

### New file: `tessera-server/src/prover_client.rs`

```rust
#[async_trait]
pub trait ProverClient: Send + Sync {
    async fn prove_v2(&self, req: ProveRequestV2) -> anyhow::Result<ProveOutcomeV2>;
    async fn prove_consume(&self, req: ConsumeProveRequest) -> anyhow::Result<ConsumeOutcome>;
}
```

`HttpProverClient` already exists; add `impl ProverClient for HttpProverClient`.

### New file: `tessera-e2e/src/prover_adapter.rs`

```rust
pub struct InProcessProver { /* wraps ProverRuntimeV2 */ }

impl InProcessProver {
    /// Returns None if artifact dirs are absent (test will skip).
    pub fn from_artifacts(artifact_dir: &Path, batch_size: usize) -> Option<Self>
}

impl ProverClient for InProcessProver { ... }
```

---

## Step 6 — Sequencer: use `Arc<dyn ProverClient>`

In `tessera-server/src/sequencer/mod.rs`:

```rust
// Before:
prover_client: Option<HttpProverClient>,

// After:
prover_client: Option<Arc<dyn ProverClient>>,
```

Update `Sequencer::new` and all call sites in `pipeline.rs`.
Add a constructor variant `Sequencer::new_with_prover(config, prover: Arc<dyn ProverClient>)`
used by the E2E test to inject `InProcessProver`.

---

## Step 7 — E2E test: Deposit → Validate

**Test:** `e2e_deposit_real_proof` in `tessera-e2e/tests/e2e_real_proofs.rs`

```
1. Skip if InProcessProver::from_artifacts(...) returns None
2. Spawn Anvil
3. TesseraClientState::new(42)
4. Deploy PoseidonGoldilocks + VerifierSuperAggregatorV2 + ToyUSDT + TesseraRollupV2
   - poolConfigRoot = client.pool_config_root()
   - treeDepth = 32 - ceil(log2(TESSERA_ACCOUNT_BATCH_SIZE × 8))
5. Start sequencer in-process with InProcessProver
6. ToyUSDT.mint + approve
7. depositAndRegister(nc_bytes32, amount)
8. sequencer_handle.submit_deposit(nc_bytes, None).await
9. Poll TransactionBatchProven event (with timeout)
10. Assert getDeposit(nc) status == 2 (Validated)
11. Assert currentRoot advanced
```

---

## Step 8 — E2E test: FreshAcc TX → Validate

**Test:** `e2e_freshacc_real_proof`

```
(same setup as Step 7)

1. proof = client.prove_freshacc(&mut rng)
2. Extract AN, AC, NN[8], NC[8] from proof.public_inputs using goldilocks_4_to_bytes32
3. Serialize proof_bytes via plonky2::util::serialization::Write
4. sequencer_handle.submit_private_tx(None, an, ac, nn.to_vec(), nc.to_vec(), proof_bytes).await
5. Poll TransactionBatchProven event
6. Assert isNullifierUsed(an_u256) == true
7. Assert currentRoot advanced
```

---

## Step 9 — E2E test: Spend TX → Validate

**Test:** `e2e_spend_real_proof`

Initial scope (Phase 1): trivial spend with no real notes, zero amounts. Confirms the full
pipeline works for a Spend TX without requiring a mechanism to create spendable notes.

```
(FreshAcc batch proven first, as in Step 8)

1. proof = client.prove_spend(&mut rng, &[], vec![])  // zero inputs, zero outputs
   - accin = account from FreshAcc (nonce=1)
   - root  = local_tree.get_root() (contains account commitment)
   - all note slots = dummy
2. Extract AN, AC, NN, NC from proof
3. Submit to sequencer; poll TransactionBatchProven
4. Assert isNullifierUsed(an_u256) == true
5. Assert currentRoot advanced
```

---

## Open questions

1. **`treeDepth` value**: must satisfy `treeDepth + ceil(log2(batch_size × 8)) = 32`.
   For `TESSERA_ACCOUNT_BATCH_SIZE=2`: `ceil(log2(16)) = 4` → `treeDepth = 28`.
   Needs to be confirmed against the pre-built SubtreeRoot artifact size.

2. **Deposit validation circuit**: the deploy script says "same SAV2 circuit for TX and deposit
   until dedicated consume circuit built." If the deposit `piCommitment` preimage differs from
   the TX preimage, the same circuit cannot prove both. May need `AcceptAllVerifier` for deposits
   in Phase 1, with a dedicated consume circuit as Phase 2 work.

3. **Spendable notes**: FreshAcc produces only dummy `nc_leaves` (random hashes, not `StandardNote`
   commitments). Creating real spendable notes requires either a consume TX (deposit bridging) or
   an output-note-producing Spend TX. Deferred to Phase 2.

---

## Critical files

| File | Action |
|------|--------|
| `tessera-e2e/` | New crate |
| `tessera-e2e/src/client_state.rs` | New: `TesseraClientState` |
| `tessera-e2e/src/prover_adapter.rs` | New: `InProcessProver` |
| `tessera-e2e/tests/e2e_real_proofs.rs` | New: 3 tests |
| `tessera-server/src/prover_client.rs` | New: `ProverClient` trait |
| `tessera-server/src/sequencer/mod.rs` | `HttpProverClient` → `Arc<dyn ProverClient>` |
| `tessera-server/src/sequencer/pipeline.rs` | Update prover dispatch |
| `Cargo.toml` (workspace root) | Add `tessera-e2e` member |

## Environment variables

```bash
TESSERA_TREE_DEPTH=28              # 32 - ceil(log2(batch_size × 8)); batch_size=2 → 28
TESSERA_ACCOUNT_BATCH_SIZE=2
TESSERA_BATCH_TIMEOUT_SECS=5
TESSERA_E2E_ARTIFACT_DIR=./artifacts  # test skips if absent
```

## Verification commands

```bash
cargo build -p tessera-e2e --release

TESSERA_E2E_ARTIFACT_DIR=./artifacts \
cargo test -p tessera-e2e --release -- --nocapture

cargo clippy -p tessera-e2e -p tessera-server --release
```
