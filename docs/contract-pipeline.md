# Contract Pipeline

Source: `tessera-solidity/src/`

---

## Purpose

`TesseraRollupV2.sol` is the on-chain settlement layer. It maintains a Poseidon incremental Merkle tree (IMT) of confirmed state, tracks deposit lifecycle, prevents double-spending via a nullifier registry, and verifies Groth16 proofs produced by the off-chain prover.

---

## State

### Poseidon Incremental Merkle Tree

```
currentRoot           — latest confirmed root (updated on each proven batch)
confirmedRoots        — mapping(root → bool): all roots ever confirmed (replay protection)
filledSubtrees[level] — cached left-sibling hashes for O(depth) appends
zeros[level]          — precomputed zero-value hashes
leafCount             — total leaves ever inserted
```

Every successful `_appendLeaf(leaf)` call hashes up the IMT path, updates `currentRoot`, records it in `confirmedRoots`, and emits `NewTreeRoot(root, leafIndex)`.

### Nullifiers

```solidity
mapping(bytes32 => bool) public nullifiers;
```

Set permanently at prove-time. Once set, the same nullifier can never appear in a future batch.

### Deposits

```solidity
enum DepositStatus { None, Pending, Validated, Withdrawn }
mapping(bytes32 noteCommitment => Deposit) public deposits;

struct Deposit {
    uint256 amount;
    address depositor;
    DepositStatus status;
}
```

---

## Transaction Batch Lifecycle

### Phase 1 — Submit (operator-only)

```solidity
function submitTransactionBatch(TransactionBatch calldata batch) external onlyOperator
```

**`TransactionBatch` fields:**

| Field | Type | Description |
|-------|------|-------------|
| `acRoot` | `uint256` | Must be a `confirmedRoot` |
| `ncRoot` | `uint256` | Must be a `confirmedRoot` |
| `mainPoolConfigRoot` | `bytes32` | Must equal `poolConfigRoot` stored in contract |
| `batchPoseidonRoot` | `uint256` | Poseidon Merkle root of the 128 NC leaves |
| `accountCommitment` | `uint256` | AC for slot 0 (used in piCommitment hash) |
| `accountNullifier` | `uint256` | AN for slot 0 (used in piCommitment hash) |
| `noteCommitments` | `uint256[128]` | All NC leaves (LE-packed Goldilocks) |
| `noteNullifiers` | `uint256[128]` | All NN leaves (LE-packed Goldilocks), sorted |

**Checks performed:**
- Caller is operator
- `acRoot` and `ncRoot` are confirmed roots
- `mainPoolConfigRoot` matches stored pool config
- Computes `piCommitment = _computeTxPiCommitment(batch)` and stores it as a pending batch

Emits: `TransactionBatchSubmitted(piCommitment, batchPoseidonRoot)`

### Phase 2 — Prove (permissionless)

```solidity
function proveTransactionBatch(bytes32[8] calldata piCommitment, bytes calldata proof) external
```

**Actions:**
1. Looks up the pending batch for `piCommitment`
2. Calls `IVerifierSuperAggregatorV2.verifyProof(proof, piCommitment)` — reverts if invalid
3. Checks and sets all `noteNullifiers` in the nullifier registry (reverts on collision)
4. Calls `_appendLeaf(batchPoseidonRoot)` — updates IMT, emits new root
5. Deletes the pending batch entry

Emits: `TransactionBatchProven(piCommitment, newTreeRoot, leafIndex)`

---

## Deposit Batch Lifecycle

### User Entry Point

```solidity
function depositAndRegister(bytes32 noteCommitment, uint256 amount) external
```

Pulls `amount` of the configured ERC20 from caller, records `deposits[noteCommitment] = Deposit(amount, msg.sender, Pending)`.

```solidity
function withdrawPendingDeposit(bytes32 noteCommitment) external
```

Returns funds to depositor if status is still `Pending`.

### Phase 1 — Submit (operator-only)

```solidity
function submitDepositBatch(DepositBatch calldata batch) external onlyOperator
```

All `noteCommitments` in the batch must have status `Pending`. Computes `piCommitment = _computeDepositPiCommitment(batch)` and stores the pending entry.

Emits: `DepositBatchSubmitted(piCommitment, batchPoseidonRoot)`

### Phase 2 — Prove (permissionless)

```solidity
function proveDepositBatch(bytes32[8] calldata piCommitment, bytes calldata proof) external
```

Verifies the Groth16 proof, marks each deposited note as `Validated`, appends `batchPoseidonRoot` to the IMT.

Emits: `DepositBatchProven(piCommitment, newTreeRoot, leafIndex)`, `DepositValidated(noteCommitment)` per note

---

## Public Input Commitment (`piCommitment`)

The Groth16 proof's only public input is a single Keccak-256 hash, encoded as `bytes32[8]` (8 × big-endian u32 words). This matches the in-circuit output of `SuperAggregatorV2`.

**ABI encoding for TX batches** (`_computeTxPiCommitment`):

```
keccak256(abi.encodePacked(
    acRoot             (uint256, LE-packed Goldilocks),
    ncRoot             (uint256, LE-packed Goldilocks),
    mainPoolConfigRoot (bytes32, raw),
    batchPoseidonRoot  (uint256, LE-packed Goldilocks),
    accountCommitment  (uint256, LE-packed Goldilocks),
    accountNullifier   (uint256, LE-packed Goldilocks),
    noteCommitments[0..128] (uint256[], LE-packed),
    noteNullifiers[0..128]  (uint256[], LE-packed)
))
→ bytes32 → split into bytes32[8] (8 × 4-byte big-endian words)
```

The same pattern applies to deposit batches (deposit-specific fields substituted).

---

## Verifier Contracts

| Contract | Role |
|----------|------|
| `VerifierSuperAggregatorV2` | gnark-generated Groth16 verifier; BN254 pairing via precompile `0x08`; uses Pedersen commitments + proof-of-knowledge |
| `PoseidonGoldilocks` | On-chain Poseidon hash (Goldilocks field, width-12, x^7 S-box); used for IMT node hashing |

The Groth16 verifier is produced by the artifact pipeline: the gnark prover emits a `Verifier.sol` which is renamed to `VerifierSuperAggregatorV2.sol` and copied into `tessera-solidity/src/`.

---

## Field Encoding Convention

Goldilocks field elements are encoded into `uint256` **little-endian** across four 64-bit limbs:

```
uint256 = e0 | (e1 << 64) | (e2 << 128) | (e3 << 192)
```

Each limb must be < Goldilocks prime (`0xFFFFFFFF00000001`). This encoding is used for all roots, commitments, and nullifiers passed to/from the contract.

---

## Events

| Event | Trigger |
|-------|---------|
| `TransactionBatchSubmitted(piCommitment, batchPoseidonRoot)` | Successful `submitTransactionBatch` |
| `TransactionBatchProven(piCommitment, newTreeRoot, leafIndex)` | Successful `proveTransactionBatch` |
| `DepositBatchSubmitted(piCommitment, batchPoseidonRoot)` | Successful `submitDepositBatch` |
| `DepositBatchProven(piCommitment, newTreeRoot, leafIndex)` | Successful `proveDepositBatch` |
| `DepositValidated(noteCommitment)` | Per-note inside `proveDepositBatch` |
| `NewTreeRoot(root, leafIndex)` | Every `_appendLeaf` (internal) |

---

## Key Constants

| Constant | Value | Location |
|----------|-------|----------|
| `IMT_DEPTH` | 20 | `TesseraRollupV2.sol` |
| `BATCH_SIZE` | 128 | batch NC/NN array length |
| BN254 pairing precompile | `0x08` | `VerifierSuperAggregatorV2.sol` |
