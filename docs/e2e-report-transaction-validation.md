# E2E Report: Validating Transactions

**Scope:** Everything needed to prove a TX batch on-chain — from sequencer flush
through the full Groth16 proof pipeline to confirmed nullifiers and an advanced
`currentRoot`.
**Prerequisites:** At least one transaction submitted to sequencer — see
[e2e-report-transaction-posting.md](e2e-report-transaction-posting.md).

---

## What "validating" means

A TX batch is confirmed when:
1. The operator calls `submitTransactionBatch` — stores batch data, computes `piCommitment`.
2. A Groth16 proof is accepted by `proveTransactionBatch` — nullifiers registered, tree updated.

After validation:
- All `noteNullifiers` and `accountNullifier` in the batch are permanently registered.
- `batchPoseidonRoot` is appended as a new leaf to the on-chain IMT.
- `currentRoot` advances; the new root is added to `confirmedRoots`.

---

## Two-phase batch model

### Phase 1 — `submitTransactionBatch` (operator only)

Source: [tessera-solidity/src/TesseraRollupV2.sol](../tessera-solidity/src/TesseraRollupV2.sol)

```solidity
struct TransactionBatch {
    // V2 has ONE on-chain IMT; both acRoot and ncRoot come from the same confirmedRoots set
    // and in practice will always be set to the same confirmed root (typically currentRoot).
    // The two separate fields are a structural legacy from V1, where ACT and NCT were genuinely
    // separate off-chain Merkle trees with independent roots. The PrivTxCircuit still exposes
    // them as distinct public inputs (PI[77-80] = act_root, PI[81-84] = nct_root) and the SAV2
    // circuit forwards both into the piCommitment hash — so both must be confirmed — but there
    // is no practical reason to set them to different values in V2.
    uint256   acRoot;              // must be in confirmedRoots — set to currentRoot
    uint256   ncRoot;              // must be in confirmedRoots — set to currentRoot
    bytes32   mainPoolConfigRoot;  // must equal current poolConfigRoot
    uint256[] noteCommitments;     // NC leaves for all slots (batch_size × 8 entries)
    uint256[] noteNullifiers;      // NN leaves for all slots (batch_size × 8 entries)
    uint256   accountCommitment;   // AC for this batch (aggregated across slots)
    uint256   accountNullifier;    // AN for this batch (aggregated across slots)
    uint256   batchPoseidonRoot;   // Poseidon(nc_leaves)
    bool      confirmed;
}

function submitTransactionBatch(TransactionBatch calldata batch)
    external onlyOperator whenNotPaused;
```

`piCommitment` computed on-chain:
```
keccak256(abi.encodePacked(
    acRoot, ncRoot, mainPoolConfigRoot, batchPoseidonRoot,
    accountCommitment, accountNullifier,
    noteCommitments[], noteNullifiers[]
))
```

Emits: `TransactionBatchSubmitted(bytes32 indexed piCommitment, uint256 batchPoseidonRoot)`

### Phase 2 — `proveTransactionBatch` (permissionless)

```solidity
struct Proof {
    uint256[8] proof;
    uint256[2] commitments;
    uint256[2] commitmentPok;
}

function proveTransactionBatch(bytes32 piCommitment, Proof calldata proof)
    external whenNotPaused;
```

Execution:
1. Decode `piCommitment` → 8 big-endian `uint32` public inputs via `keccakToPublicInputs`.
2. Call `txVerifier.verifyProof(proof.proof, proof.commitments, proof.commitmentPok, pubInputs)`.
3. Check `!nullifiers[n]` for every note nullifier and account nullifier.
4. Set `nullifiers[n] = true` for all of them.
5. Call `_appendLeaf(batchPoseidonRoot)` → update `currentRoot`, add to `confirmedRoots`.

Emits: `TransactionBatchProven(bytes32 piCommitment, uint256 newTreeRoot, uint256 leafIndex)`

---

## Sequencer-mediated flow (production)

Sources:
- [tessera-server/src/sequencer/pipeline.rs](../tessera-server/src/sequencer/pipeline.rs)
- [tessera-server/src/sequencer/batch.rs](../tessera-server/src/sequencer/batch.rs)
- [tessera-server/src/types.rs](../tessera-server/src/types.rs)

```
Client                       Sequencer                    Prover              Chain
  |-- submit_private_tx() -->|                            |                    |
  |                          | BatchBuilder.add()         |                    |
  |        (full or timeout) |                            |                    |
  |                          |-- ProveRequestV2 --------->|                    |
  |                          |   nc_leaves, tx_proofs     | GenericAggregator  |
  |                          |   root, main_pool_cfg_root | SubtreeRootCircuit |
  |                          |                            | SuperAggregatorV2  |
  |                          |                            | BN128 → Groth16    |
  |                          |<-- ProveOutcomeV2::Success |                    |
  |                          |   (solidity_proof,         |                    |
  |                          |    batch_poseidon_root,    |                    |
  |                          |    super_pi_commitment)    |                    |
  |                          |-- submitTransactionBatch() |------------------>|
  |                          |-- proveTransactionBatch()  |------------------>|
  |                          |<----------------------------------------Proven-|
```

### Flush trigger

The sequencer flushes the current batch when either condition is met:
- `BatchBuilder::is_full()` — all `TESSERA_ACCOUNT_BATCH_SIZE` slots occupied.
- `TESSERA_BATCH_TIMEOUT_SECS` elapsed since the first transaction entered the batch.

### ProveRequestV2 (Sequencer → Prover)

```rust
// tessera-server/src/types.rs
pub struct ProveRequestV2 {
    pub batch_id:           u64,
    pub nc_leaves:          Vec<[u8; 32]>,           // all NC leaves (slots × 8)
    pub root:               HashOutput,               // on-chain Poseidon IMT root at flush time
    pub main_pool_cfg_root: [u8; 32],
    pub tx_proofs_by_slot:  HashMap<usize, Vec<u8>>, // slot_index → Plonky2 proof bytes
}
```

### ProveOutcomeV2 (Prover → Sequencer)

```rust
pub enum ProveOutcomeV2 {
    Success {
        batch_id:             u64,
        batch_poseidon_root:  HashOutput,
        solidity_proof:       Box<SolidityProof>,
        super_pi_commitment:  [u8; 32],     // must match submitTransactionBatch piCommitment
    },
    Failure { batch_id: u64, error: String },
}

pub struct SolidityProof {
    pub proof:          [U256; 8],   // π_A, π_B (compressed), π_C
    pub commitments:    [U256; 2],
    pub commitment_pok: [U256; 2],
}
```

---

## Proof generation pipeline (prover_v2)

Source: [tessera-server/src/prover_v2.rs](../tessera-server/src/prover_v2.rs)

### Stage 1 — TX aggregation + SubtreeRoot (parallel)

```
For each slot 0..batch_size:
    if tx_proofs_by_slot contains slot → use real Plonky2 leaf proof
    else → use dummy proof (prove_dummy_priv_tx)

GenericAggregator:
    Input:  leaf_proof[0..batch_size]
    Output: aggregated_tx_proof  (recursively verifies all leaf proofs)

SubtreeRootCircuit:
    Input:  nc_leaves[0..batch_size×8]
    Output: sr_proof  (proves Poseidon(nc_leaves) = batch_poseidon_root)
```

### Stage 2 — SuperAggregatorV2

Source: [tessera-trees/src/proof_aggregation/super_aggregator_v2.rs](../tessera-trees/src/proof_aggregation/super_aggregator_v2.rs)

```rust
super_aggregator.prove(
    tx:             aggregated_tx_proof,
    sr:             sr_proof,
    root:           HashOutput,   // must equal acRoot/ncRoot in submitTransactionBatch
    main_pool_cfg:  [u8; 32],
) → sa_proof
```

Inside the circuit:
1. Verifies `aggregated_tx_proof`.
2. Verifies `sr_proof`.
3. Cross-checks NC leaves are consistent between the two proofs.
4. Computes Keccak-256 `piCommitment` and registers it as 8 `u32` public inputs.

### Stage 3 — BN128 wrapper → Groth16

```
gnark BN128 wrapper:
    Input:  sa_proof (Plonky2/Goldilocks)
    Output: Groth16 proof over BN254 → SolidityProof
```

---

## `piCommitment` field order (critical correctness invariant)

The SAV2 circuit and the contract's `_computeTxPiCommitment` must agree on this
exact field order and encoding. Any mismatch causes `ProofVerificationFailed`.

```
keccak256(abi.encodePacked(
    acRoot             uint256,    ← LE-packed HashOutput
    ncRoot             uint256,    ← LE-packed HashOutput
    mainPoolConfigRoot bytes32,
    batchPoseidonRoot  uint256,    ← LE-packed HashOutput
    accountCommitment  uint256,    ← LE-packed HashOutput (from last non-dummy slot)
    accountNullifier   uint256,    ← LE-packed HashOutput (from last non-dummy slot)
    noteCommitments[]  uint256[],  ← NC leaves in slot arrival order
    noteNullifiers[]   uint256[],  ← NN leaves in sorted order (big-endian sort)
))
```

LE packing: `uint256 = e0 | (e1<<64) | (e2<<128) | (e3<<192)` where `e[i]` are
the 64-bit Goldilocks field elements of a `HashOutput`.

---

## Nullifier enforcement — prove time, not submit time

Nullifiers are checked at `proveTransactionBatch` time, **not** at `submitTransactionBatch`.
Consequences:
- Two batches can be submitted in parallel with overlapping nullifiers.
- The second one proven will fail with `NullifierAlreadyUsed`.
- The circuit proves double-spend absence in zero knowledge; the contract enforces replay protection post-proof.

---

## Testing flow (AcceptAllVerifier — no real prover)

Source: [tessera-server/src/sequencer/testing.rs](../tessera-server/src/sequencer/testing.rs)

Deploy with `AcceptAllVerifier` as `txVerifier`. It accepts any proof, including all-zero.

### Shell (TESSERA_TESTING=1)

```bash
# 1. Submit one or more raw TX slots (no proof bytes)
curl -sS -X POST "$TESSERA_TEST_API_URL/test/transactions" \
  -H 'content-type: application/json' \
  -d '{
    "an":"0x0000000000000000000000000000000000000000000000000000000000000064",
    "ac":"0x0000000000000000000000000000000000000000000000000000000000000065",
    "nn":["0x00...c9","0x00...ca","0x00...cb","0x00...cc","0x00...cd","0x00...ce","0x00...cf","0x00...d0"],
    "nc":["0x00...12d","0x00...12e","0x00...12f","0x00...130","0x00...131","0x00...132","0x00...133","0x00...134"]
  }'
# => {"accepted":true}

# 2. Flush + confirm TX batch with zero proof
curl -sS --max-time 120 -X POST "$TESSERA_TEST_API_URL/test/transactions/validate"
# => {"accepted":true}  (blocks until proveTransactionBatch confirmed on-chain)
```

### Rust (TESSERA_TESTING=1)

```rust
// tessera-server/src/sequencer/handle.rs
handle.test_submit_tx(an, ac, nn_array, nc_array).await?;
handle.test_validate_txs().await?;  // blocks until on-chain confirmation
```

Under the hood (`testing.rs`):
```rust
// flush_batch_testing():
// 1. submit_tx_batch_on_chain(provider)     → submitTransactionBatch tx
// 2. inject ProveOutcomeV2::Success with zero SolidityProof + zero batch_poseidon_root
// 3. confirm_tx_batch(provider, fake)       → proveTransactionBatch tx
//    (AcceptAllVerifier accepts [0,0,0,0,0,0,0,0] proof)
```

---

## On-chain root advancement

After `proveTransactionBatch`:
```
leafCount  += 1
currentRoot = Poseidon(filledSubtrees[level], batchPoseidonRoot)   ← via _appendLeaf
confirmedRoots[currentRoot] = true
```

The new `currentRoot` is immediately usable as `root` (set as both `acRoot` and `ncRoot`) for the next batch.

---

## Environment variables

```bash
TESSERA_ACCOUNT_BATCH_SIZE=2          # batch_size (slots per batch; 2 for fast tests)
TESSERA_BATCH_TIMEOUT_SECS=5          # flush after this many seconds even if not full
TESSERA_PROVER_API_URL=http://127.0.0.1:8091     # prover_v2 HTTP server
TESSERA_PROVER_API_TIMEOUT_SECS=1800             # proving timeout
TESSERA_TESTING=1                                # enables /test/* endpoints
TESSERA_TEST_API_ADDR=127.0.0.1:8081
```

---

## Error conditions

| Error | Condition |
|-------|-----------|
| `RootNotConfirmed(uint256)` | acRoot or ncRoot (both set to `root`) not in `confirmedRoots` at submit time |
| `PoolConfigMismatch()` | mainPoolConfigRoot != current contract value |
| `BatchAlreadySubmitted(bytes32)` | piCommitment already in `pendingTxBatches` |
| `BatchNotFound(bytes32)` | piCommitment not in `pendingTxBatches` |
| `BatchAlreadyConfirmed(bytes32)` | batch already proven |
| `ProofVerificationFailed(bytes32, uint256[8])` | Groth16 verifier rejected proof |
| `NullifierAlreadyUsed(uint256)` | note or account nullifier already spent |
| `TreeFull()` | on-chain IMT at capacity |

---

## Verification after confirmation

```bash
# Root advanced
cast call $ROLLUP "currentRoot()(uint256)" --rpc-url $RPC

# Nullifier registered
cast call $ROLLUP "isNullifierUsed(uint256)(bool)" $AN --rpc-url $RPC

# New root is confirmed (usable in next batch)
cast call $ROLLUP "isConfirmedRoot(uint256)(bool)" $NEW_ROOT --rpc-url $RPC
```

---

## Full E2E pipeline reference

```
# Test mode (AcceptAllVerifier, TESSERA_TESTING=1)

# 1. Deploy
forge script tessera-solidity/script/Deploy.s.sol --broadcast ...
#    with TESSERA_TX_VERIFIER=<AcceptAllVerifier> TESSERA_DEPOSIT_VERIFIER=<AcceptAllVerifier>

# 2. Start sequencer
cargo run --bin sequencer --release

# 3. Deposit cycle
cast send $TOKEN "mint(address,uint256)" $USER 1000000 ...
cast send $TOKEN "approve(address,uint256)" $ROLLUP 1000000 ...
cast send $ROLLUP "depositAndRegister(bytes32,uint256)" $NC 1000000 ...
curl -X POST $TEST_API/test/deposits         -d '{"note_commitment":"'$NC'"}'
curl -X POST $TEST_API/test/deposits/validate

# 4. Transaction cycle
curl -X POST $TEST_API/test/transactions     -d '{"an":...,"ac":...,"nn":[...],"nc":[...]}'
curl -X POST $TEST_API/test/transactions/validate

# 5. Verify
cast call $ROLLUP "currentRoot()(uint256)"             --rpc-url $RPC
cast call $ROLLUP "isNullifierUsed(uint256)(bool)" $AN --rpc-url $RPC
cast call $ROLLUP "getDeposit(bytes32)((uint256,address,uint8))" $NC --rpc-url $RPC
#   => status should be 2 (Validated)
```
