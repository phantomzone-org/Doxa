# E2E Report: Validating Deposits

**Scope:** Everything needed to move a deposit from `Pending` → `Validated` on-chain,
including the two-phase batch model, sequencer pipeline, and test-mode shortcuts.
**Prerequisites:** Deposit must already be `Pending` — see
[e2e-report-deposit-posting.md](e2e-report-deposit-posting.md).

---

## What "validating" means

A deposit becomes `Validated` when:
1. The operator submits a `DepositBatch` containing the note commitment (`submitDepositBatch`).
2. A Groth16 proof is provided and accepted (`proveDepositBatch`).
3. The batch Poseidon root is appended to the on-chain IMT → new `currentRoot` confirmed.

After validation the note commitment lives permanently in the confirmed Merkle tree
and the depositor's ZK note becomes spendable in a future private transaction.

---

## Two-phase batch model

### Phase 1 — `submitDepositBatch` (operator only)

Source: [tessera-solidity/src/TesseraRollupV2.sol](../tessera-solidity/src/TesseraRollupV2.sol)

```solidity
struct DepositBatch {
    // V2 has ONE on-chain IMT; both acRoot and ncRoot come from the same confirmedRoots set
    // and in practice will always be set to the same confirmed root (typically currentRoot).
    // The two separate fields are a structural legacy from V1, where ACT and NCT were genuinely
    // separate off-chain Merkle trees. The PrivTxCircuit still exposes them as distinct public
    // inputs (PI[77-80] = act_root, PI[81-84] = nct_root) and the SAV2 circuit forwards both
    // into the piCommitment hash, so the contract requires both to be confirmed roots — but
    // there is no practical reason to set them to different values in V2.
    uint256   acRoot;                    // must be in confirmedRoots — set to currentRoot
    uint256   ncRoot;                    // must be in confirmedRoots — set to currentRoot
    bytes32   mainPoolConfigRoot;        // must equal current poolConfigRoot
    bytes32[] depositNoteCommitments;    // each must have status == Pending
    uint256   batchPoseidonRoot;         // Poseidon(nc_leaves) for this batch
    bool      confirmed;                 // always false at submit time
}

function submitDepositBatch(DepositBatch calldata batch)
    external onlyOperator whenNotPaused;
```

`piCommitment` computed on-chain:
```
keccak256(abi.encodePacked(
    acRoot, ncRoot, mainPoolConfigRoot, batchPoseidonRoot,
    depositNoteCommitments[]
))
```

Emits: `DepositBatchSubmitted(bytes32 indexed piCommitment, uint256 batchPoseidonRoot)`

### Phase 2 — `proveDepositBatch` (permissionless)

```solidity
struct Proof {
    uint256[8] proof;
    uint256[2] commitments;
    uint256[2] commitmentPok;
}

function proveDepositBatch(bytes32 piCommitment, Proof calldata proof)
    external whenNotPaused;
```

On success:
- Every `depositNoteCommitment` → `status = Validated`
- `batchPoseidonRoot` appended to on-chain IMT → `currentRoot` updated, added to `confirmedRoots`
- Emits `DepositValidated(bytes32 noteCommitment)` for each note
- Emits `DepositBatchProven(bytes32 piCommitment, uint256 newTreeRoot, uint256 leafIndex)`

---

## Proof verification internals

The `piCommitment` (bytes32) is decomposed into 8 big-endian `uint32` public inputs
for the Groth16 verifier:
```
inputs[0] = piCommitment[0..4]    (most-significant word)
inputs[7] = piCommitment[28..32]  (least-significant word)
```
This is `keccakToPublicInputs()` in the contract. The SAV2 circuit computes the same
Keccak-256 hash and registers the same 8 words as its public inputs.

---

## Sequencer-mediated flow (production)

Sources:
- [tessera-server/src/sequencer/handle.rs](../tessera-server/src/sequencer/handle.rs)
- [tessera-server/src/sequencer/batch.rs](../tessera-server/src/sequencer/batch.rs)
- [tessera-server/src/sequencer/pipeline.rs](../tessera-server/src/sequencer/pipeline.rs)

```
User                         Sequencer                      Chain
 |                               |                             |
 |-- submit_deposit(nc, proof) ->|                             |
 |   (SequencerHandle)           |-- getDeposit(nc) ---------->|
 |                               |<-- status=Pending -----------|
 |                               | [adds to ConsumeBatchBuilder]|
 |                               |                             |
 |             (batch full or batch_timeout_secs elapsed)      |
 |                               |-- submitDepositBatch() ---->|
 |                               |<-- DepositBatchSubmitted ----|
 |                               |-- [remote prover / Groth16] |
 |                               |-- proveDepositBatch() ----->|
 |                               |<-- DepositBatchProven -------|
```

### Sequencer API (Rust)

```rust
// tessera-server/src/sequencer/handle.rs
sequencer_handle.submit_deposit(
    note_commitment: [u8; 32],       // bytes32 from on-chain deposit
    consume_proof:   Option<Vec<u8>>, // Plonky2 deposit-tx proof; None for simple flow
).await?;
```

The sequencer:
1. Calls `getDeposit(note)` on-chain — rejects if status != Pending.
2. Packs the note into the current `ConsumeBatchBuilder` slot (up to 8 notes per slot).
3. Flushes when `is_full()` or `batch_timeout_secs` elapsed.
4. Calls `submit_consume_batch_on_chain` → sends `ConsumeProveRequest` to remote prover.
5. On `ConsumeOutcome::Success`, calls `proveDepositBatch` on-chain.

### Batch slot structure (deposit path)

```rust
// tessera-server/src/sequencer/batch.rs
BatchSlot::Deposit {
    nc:        [[u8; 32]; 8],  // nc[0..nc_filled] real, nc[nc_filled..8] dummy zeros
    nc_filled: usize,
    ac:        [u8; 32],       // dummy (zero)
    an:        [u8; 32],       // dummy (zero)
    nn:        [[u8; 32]; 8],  // all dummy (zero)
}
// finalize() → FinalizedBatch.nc_leaves + batch_poseidon_root
```

---

## `batchPoseidonRoot` — what it represents

- Poseidon Merkle root of all NC leaves in the batch (real + padding zeros).
- Computed client-side by `SubtreeRootCircuit` during proving.
- Appended as a single leaf to the on-chain IMT via `_appendLeaf(batchPoseidonRoot)`.
- The circuit proves `Poseidon(nc_leaves) = batchPoseidonRoot` in zero knowledge.

---

## Testing flow (AcceptAllVerifier — no real prover)

Source: [tessera-solidity/src/AcceptAllVerifier.sol](../tessera-solidity/src/AcceptAllVerifier.sol)

For E2E testing without a real prover, deploy with `AcceptAllVerifier` as `depositVerifier`.
It accepts any proof including all-zero proofs.

### Shell (TESSERA_TESTING=1)

```bash
# Sequencer must be started with TESSERA_TESTING=1 and AcceptAllVerifier deployed

# 1. Submit deposit note to sequencer test API (bypasses on-chain Pending check)
curl -sS -X POST "$TESSERA_TEST_API_URL/test/deposits" \
  -H 'content-type: application/json' \
  -d '{"note_commitment":"0x0000000000000000000000000000000000000000000000000000000000000001"}'
# => {"accepted":true}

# 2. Flush + confirm deposit batch with zero proof
curl -sS --max-time 120 -X POST "$TESSERA_TEST_API_URL/test/deposits/validate"
# => {"accepted":true}  (blocks until proveDepositBatch tx confirmed)
```

### Rust (TESSERA_TESTING=1)

```rust
// tessera-server/src/sequencer/handle.rs
let nc = [0u8; 31].iter().chain(&[1u8]).copied().collect::<Vec<_>>().try_into().unwrap();
handle.test_submit_deposit(nc).await?;
handle.test_validate_deposits().await?;  // blocks until on-chain confirmation
```

Under the hood (`testing.rs`):
```rust
// flush_consume_batch_testing():
// 1. submit_consume_batch_on_chain(provider)  → submitDepositBatch tx
// 2. inject ConsumeOutcome::Success with zero SolidityProof
// 3. confirm_consume_batch(provider, fake)    → proveDepositBatch tx (AcceptAllVerifier accepts)
```

---

## Deposit lifecycle summary

```
None ──(depositAndRegister)──> Pending
Pending ──(proveDepositBatch)──> Validated   ← note is now spendable
Pending ──(withdrawPendingDeposit)──> Withdrawn
```

States `Validated` and `Withdrawn` are terminal — no further transitions.

---

## Environment variables

```bash
TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=<rollup contract>
TESSERA_MONITORED_TOKEN=<token contract>
TESSERA_ACCOUNT_BATCH_SIZE=2          # slots per batch (2 for fast tests)
TESSERA_BATCH_TIMEOUT_SECS=5          # flush after this many seconds
TESSERA_TESTING=1                     # enables /test/* endpoints
TESSERA_TEST_API_ADDR=127.0.0.1:8081
```

---

## Error conditions

| Error | Condition |
|-------|-----------|
| `RootNotConfirmed(uint256)` | acRoot or ncRoot (both set to `root`) not in `confirmedRoots` |
| `PoolConfigMismatch()` | mainPoolConfigRoot != contract's current value |
| `InvalidDepositState(bytes32)` | deposit note is not Pending at submit time |
| `NoteNotFound(bytes32)` | noteCommitment has status == None |
| `BatchAlreadySubmitted(bytes32)` | piCommitment already in `pendingDepositBatches` |
| `BatchNotFound(bytes32)` | piCommitment not found (prove called before submit) |
| `BatchAlreadyConfirmed(bytes32)` | batch already proven |
| `ProofVerificationFailed(bytes32, uint256[8])` | Groth16 verifier rejected the proof |
| `TreeFull()` | on-chain IMT at capacity (leafCount == 2^treeDepth) |

---

## Verification after validation

```bash
# Check deposit status is now Validated (2)
cast call $ROLLUP "getDeposit(bytes32)((uint256,address,uint8))" $NC --rpc-url $RPC
# => (value, recipient, 2)

# Check currentRoot advanced
cast call $ROLLUP "currentRoot()(uint256)" --rpc-url $RPC

# Check new root is in confirmedRoots
cast call $ROLLUP "isConfirmedRoot(uint256)(bool)" $NEW_ROOT --rpc-url $RPC
```
