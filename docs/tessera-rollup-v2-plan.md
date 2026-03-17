# Plan: TesseraRollupV2 — On-Chain Tree Contract

## Progress

### Contract (`tessera-solidity/src/TesseraRollupV2.sol`)

| Step | Description | Status |
|------|-------------|--------|
| 1 | Interfaces & imports | ✅ |
| 2 | Data structures | ✅ |
| 3 | Constructor | ✅ |
| 4 | Access-control + pause | ✅ |
| 5 | Poseidon incremental Merkle tree | ✅ |
| 6 | ERC20 deposit / withdraw | ✅ |
| 7 | `submitTransactionBatch` + `proveTransactionBatch` | ✅ |
| 8 | `submitDepositBatch` + `proveDepositBatch` | ✅ |
| 9 | View helpers + events + errors | ✅ |

### Backend (`tessera-server/` + `tessera-trees/`)

| Step | Description | Status |
|------|-------------|--------|
| 10 | New `ProveRequest` / `ConsumeProveRequest` types | ✅ |
| 11 | Simplify `BatchBuilder` / `FinalizedBatch` (drop trees + sorting) | ✅ |
| 12 | Simplify sequencer: drop 4 tree state machines, track `confirmed_root` | ✅ |
| 13 | New `SubtreeRootCircuit` — prove `root = PoseidonMerkle(leaves)` | ✅ |
| 14 | New `SuperAggregatorV2` (2 inner proofs: TX root + subtree root) | ✅ |
| 15 | Pre-computed fixed dummy TX proof | ✅ |
| 16 | New `ProverRuntime` wiring (drop 4 tree services, add batch-root prover) | ✅ |
| 17 | Consume pipeline (separate SA / verifier, reuse TX aggregation structure) | ✅ |
| 18 | Contract tests (`TesseraRollupV2.t.sol`) | ✅ |
| 19 | `SubtreeRootCircuit` unit tests | ✅ |
| 20 | `SuperAggregatorV2` unit tests | ✅ |
| 21 | `BatchBuilder` / sequencer unit tests | ✅ |
| 22 | E2E tests | ⬜ |

---

## Implementation Guide

### Dependency graph

```
Phase A  ─── Contract (steps 1-9)
             └── Phase B: Contract tests (step 18)

Phase C  ─── SubtreeRootCircuit (step 13)
             ├── Phase C1: SubtreeRootCircuit tests (step 19)
             └── Phase D: SuperAggregatorV2 (step 14)
                          ├── Phase D1: SA tests (step 20)
                          └── Phase E: ProverRuntime (steps 15-16)

Phase F  ─── BatchBuilder + types (steps 10-11)  [can start after Phase A ABI is stable]
             └── Phase G: Sequencer (step 12)
                          └── Phase H: Consume pipeline (step 17)

Phase I  ─── E2E tests (step 22)  [requires A + E + G]

Phase J  ─── BatchBuilder/sequencer unit tests (step 21)  [requires F + G]
```

Phases A and C are **fully independent** — work on them in parallel across two branches if possible.
Phase F can begin as soon as the `piCommitment` encoding (from Phase A) is finalised.

---

### Phase A — Contract (`tessera-solidity/src/TesseraRollupV2.sol`)
**Steps 1–9 | Where: `tessera-solidity/src/TesseraRollupV2.sol`**

Implement all steps sequentially top-to-bottom (the file builds in layers):

1. Copy interfaces from `TesseraRollup.sol` (IERC20MonitoredToken, IGroth16Verifier). Add `IPoseidonGoldilocks`.
2. Declare all state variables and structs as specified. Note: `TransactionBatch` and `DepositBatch` hold dynamic arrays — be mindful of calldata vs. memory when storing.
3. Constructor: build `zeros[]` chain using `poseidon.compress`; set `currentRoot = zeros[treeDepth]`; no `_genesisRoot` param.
4. Copy `setOperator`, `setPaused`, modifiers from V1 verbatim.
5. Implement `_appendLeaf` as the IMT pseudocode. Test this in isolation first (see Phase B).
6. Copy deposit/withdraw from V1 verbatim; no logic changes.
7. Implement `submitTransactionBatch` then `proveTransactionBatch`. Get `piCommitment` encoding exactly right (field order per Encoding Conventions section) — the Rust backend must match.
8. Implement `submitDepositBatch` / `proveDepositBatch` by cloning step 7 functions with deposit-specific changes.
9. Add all events, errors, and view helpers.

**Gate**: `forge build` must pass with zero warnings before moving to Phase B.

---

### Phase B — Contract tests
**Step 18 | Where: `tessera-solidity/test/TesseraRollupV2.t.sol`**

Run immediately after Phase A. Use `DummyVerifier.sol` and `ToyUSDT.sol` (both already exist).

Priority order within this phase:
1. `_appendLeaf` IMT tests first — these validate the on-chain Poseidon tree and root history. Cross-check roots against a native Rust reference (write a small `#[test]` that replicates the same appends and prints roots).
2. `submitTransactionBatch` + `proveTransactionBatch` happy + sad paths.
3. Deposit lifecycle.
4. Access control + pause.

**Gate**: all tests pass with `forge test`. The `currentRoot` values from IMT tests must match the Rust Poseidon reference before proceeding to Phase F (they share the packing convention).

---

### Phase C — `SubtreeRootCircuit`
**Step 13 | Where: `tessera-trees/src/proof_aggregation/subtree_root.rs`**

This is a new, self-contained circuit. Start from `BatchCommitmentProofTargets` in `tessera-trees/src/tree/commitment_tree/proofs/batch_insertion/stark.rs`:
- Copy `compute_root_circuit()` (lines ~141-170) — this is exactly the bottom-up Poseidon hash tree needed.
- Copy `set()` witness-setting and simplify (remove `root_old`, `start_index`, `upper_siblings` witness logic).
- Public inputs: `[root[4] || leaves[N×4]]` with N=128, depth=7.
- No old-root, no insertion, no chaining constraints.

**Gate**: `cargo test -p tessera-trees --release subtree_root` passes (step 19).

---

### Phase C1 — `SubtreeRootCircuit` tests
**Step 19 | Where: `tessera-trees/src/proof_aggregation/subtree_root.rs` (inline `#[cfg(test)]`)**

Write tests immediately after the circuit is done, before moving to Phase D. The depth-1 test (2 leaves) is the fastest to run and confirms the hash direction. Cross-check: compute the same root natively in Rust and assert equality.

**Gate**: all subtree root tests pass before Phase D begins.

---

### Phase D — `SuperAggregatorV2`
**Step 14 | Where: `tessera-trees/src/proof_aggregation/super_aggregator_v2.rs`**

Requires: Phase C complete (subtree root circuit + VK available).

Use `super_aggregator.rs` as the structural template:
- Reduce `SuperAggregatorCircuitData` from 5 inner verifier datas to 2 (TX root + subtree root).
- **Re-derive PI layout constants** (`TX_LEAF_PI_SIZE`, `IS_REAL_OFFSET`, `TX_DATA_OFFSET`) from the current TX proof circuit before wiring cross-checks — do not copy V1 values blindly.
- Wire cross-check: for each slot index `i`, assert `subtree_leaf[i] == tx_proof_note_commitment[i]` in-circuit (masked by `is_real`).
- Remove GF(p²) multiset gadget entirely.
- Output: `piCommitment` as 8 u32 words (same Keccak gadget as V1, but over V2 preimage field order).

**Gate**: `cargo test -p tessera-trees --release super_aggregator_v2` passes (step 20).

---

### Phase D1 — `SuperAggregatorV2` tests
**Step 20 | Where: `tessera-trees/src/proof_aggregation/super_aggregator_v2.rs` (inline `#[cfg(test)]`)**

Run immediately after Phase D. The critical test is `test_sa_v2_pi_commitment_matches_contract`: compute `keccak256(piCommitment fields)` in Rust and verify it matches what the Solidity `submitTransactionBatch` would compute for the same batch. This is the primary integration seam between contract and backend.

---

### Phase E — `ProverRuntime` + dummy proofs
**Steps 15–16 | Where: `tessera-server/src/prover.rs`, `tessera-server/src/bin/artifact_builder.rs`**

Requires: Phase D complete (SA V2 artifacts must exist).

Order within phase:
1. Update artifact builder to generate: `subtree_root_circuit.bin`, `super_aggregator_v2.bin`, `super_aggregator_v2_bn128.bin`, and dummy proof artifacts. Run it to produce artifacts before wiring the runtime.
2. Repurpose `CommitmentProverService` → `SubtreeRootProverService` (swap circuit type, keep service shape).
3. Delete `NullifierProverService` and the 4 tree service fields.
4. Update `build_and_aggregate_tx_proofs`: remove AN/NN sort permutation override block (lines ~500-545 in V1); fill dummy slots from pre-loaded artifact instead.
5. Rewrite `try_prove_request`: remove 4 tree proof calls; add subtree root proving call; keep Groth16 wrapping.
6. Delete off-circuit nullifier validation helpers.

**Gate**: prover binary compiles and the in-process proving test (all-dummy batch) produces a `SolidityProof` that passes `DummyVerifier` on the contract.

---

### Phase F — Types + `BatchBuilder`
**Steps 10–11 | Where: `tessera-server/src/types.rs`, `tessera-server/src/sequencer/batch.rs`**

Can start as soon as Phase A's `piCommitment` encoding is finalised (does not need circuits).

1. Replace `ProveRequest` in `types.rs`; add `ConsumeProveRequest`. Keep `SolidityProof` as-is; adapt `ProveOutcome` (remove `new_roots`).
2. In `batch.rs`: drop `argsort_bytes32_as_u256`, `nn_sort_perm`, `an_sort_perm`, `an_sorted`, `nn_sorted` from `FinalizedBatch`. Add `batch_poseidon_root: HashOutput` computed from a native Poseidon subtree over `nc_leaves`.
3. Rewrite `into_prove_request()` to produce the V2 `ProveRequest`.
4. Delete `nc_fixed/nn_fixed/ac_fixed/an_fixed` helpers (no longer passed as calldata).

**Gate**: `cargo test -p tessera-server --release batch` (step 21, partial — BatchBuilder tests).

---

### Phase G — Sequencer
**Step 12 | Where: `tessera-server/src/sequencer/mod.rs`, `pipeline.rs`, `recovery.rs`**

Requires: Phase F complete (V2 types + BatchBuilder compile).

1. `mod.rs`: delete 4 tree state/store fields; add `confirmed_root: HashOutput` + `confirmed_root_history: HashSet<HashOutput>`. Change pending batch map key from `u64` → `bytes32` (piCommitment).
2. `pipeline.rs`: replace `registerTransactionBatchUpdate` call with `submitTransactionBatch`; replace `confirmBatch` with `proveTransactionBatch`; update event parsing.
3. `recovery.rs`: replace tree WAL replay with `load_confirmed_roots(provider, contract, from_block)` — fetch `TransactionBatchProven`/`DepositBatchProven` events and return `(currentRoot, HashSet<roots>)`.

**Gate**: `cargo test -p tessera-server --release sequencer` (step 21, sequencer tests). Sequencer must compile and the mock-chain tests must pass.

---

### Phase H — Consume pipeline
**Step 17 | Where: same files as TX pipeline, plus `ConsumeProveRequest`**

Requires: Phase G complete (TX pipeline end-to-end working).

The consume pipeline is a second instantiation of the same pattern. Implement by cloning the TX pipeline with:
- `ConsumeProveRequest` instead of `ProveRequest`
- `depositVerifier` on-chain address
- Post-proof: mark deposit notes `Validated` instead of inserting nullifiers
- Separate artifact paths for consume SA

**Gate**: consume pipeline compiles; deposit batch lifecycle test passes.

---

### Phase I — E2E tests
**Step 22 | Where: `tessera-server/src/tests/e2e.rs`**

Requires: Phases A + E + G complete (contract deployed on anvil, prover working, sequencer working).

Run sequentially:
1. `test_e2e_tx_batch` first — simplest path (no deposits).
2. `test_e2e_second_batch_references_first_root` — validates root history chaining.
3. `test_e2e_deposit_batch` — consume pipeline.
4. `test_e2e_invalid_root_rejected` — error path.

**Gate**: all E2E tests pass with `cargo test -p tessera-server --release e2e`.

---

### Parallelisation opportunities

| Can run in parallel | Constraint |
|---|---|
| Phase A (contract) + Phase C (SubtreeRootCircuit) | Fully independent |
| Phase B (contract tests) + Phase C1 (subtree tests) | Each needs its own Phase complete |
| Phase F (types/BatchBuilder) + Phase C/D (circuits) | F needs Phase A ABI only |
| Phase D (SA V2) + Phase F (BatchBuilder) | Independent |

---

### Recommended branch strategy

```
main
 ├── feature/v2-contract          Phase A + B
 ├── feature/v2-circuits          Phase C + C1 + D + D1
 └── feature/v2-backend           Phase E + F + G + H + I
     (merge circuits branch first, then implement backend)
```

---

## Context

V1 (`TesseraRollup.sol`) stores only the four tree **roots** off-chain and advances them via ZK proofs.
V2 moves the commitment tree and nullifier set **onto the contract**, so the chain is the canonical source of truth for the entire tree state. This simplifies client verification and enables permissionless proof submission.

---

## Encoding Conventions

These conventions must be respected by both the Solidity contract and the Rust backend to ensure hash agreement.

### Goldilocks packing (`uint256` ↔ `[u64; 4]`)
A Poseidon `HashOutput` of 4 Goldilocks field elements is packed into a single `uint256` as:
```
uint256 = e0 | (e1 << 64) | (e2 << 128) | (e3 << 192)   // little-endian limbs
```
Each `eN` fits in 64 bits (Goldilocks field: `p = 2^64 - 2^32 + 1 < 2^64`). This matches the `PoseidonGoldilocks.compress` input/output convention used in the contract.

### `piCommitment` preimage (exact field order)
`piCommitment = keccak256(abi.encodePacked(fields...))` where `fields` are packed in this exact order:
```
acRoot          (uint256 — packed HashOutput)
ncRoot          (uint256)
mainPoolConfigRoot (uint256)
batchPoseidonRoot  (uint256)
accountCommitment  (uint256, one per slot)
accountNullifier   (uint256, one per slot)
noteCommitments    (uint256[], notes_per_slot × account_batch_size elements, row-major: slot0_note0, slot0_note1, ..., slotN_note7)
noteNullifiers     (uint256[], same layout as noteCommitments)
```
The Rust sequencer computes the identical hash using `keccak256` over the same packed bytes before calling `submitTransactionBatch`. The `SubtreeRootCircuit` / `SuperAggregatorV2` computes the same hash in-circuit (decomposing each `uint256` to `[hi_u32, lo_u32]` pairs before feeding into the Keccak gadget, matching V1 convention).

### Genesis root
The genesis root of an empty IMT of depth `D` equals `zeros[D]` — i.e., the root of a tree where every leaf is zero. It can be computed in the constructor without a parameter:
```solidity
// zeros[0] = 0
// zeros[i] = poseidon.compress(zeros[i-1], zeros[i-1])
// genesisRoot = zeros[treeDepth]
```
Remove `_genesisRoot` from the constructor parameter list; compute it during initialization.

### `SubtreeRootCircuit` concrete dimensions
- **Leaf count N** = `account_batch_size × notes_per_slot` = `16 × 8 = 128` (matches V1 batch sizing)
- **Subtree depth** = `log2(128) = 7`
- **PI layout**: `[root[4] || leaf0[4] || leaf1[4] || … || leaf127[4]]` — 4 + 128×4 = 516 field elements

---

## Key Design Decisions

### Single shared tree for TX and deposit batches
Both TX batches and deposit batches insert one leaf (their Poseidon batch root) into the same on-chain Poseidon Merkle tree.
**Constraint**: both batch types must use the same leaf format and the same circuit batch size, otherwise the Poseidon batch root is not comparable across types.
**Rationale**: a single root history is simpler for client code — all "confirmed batch roots" are in one set regardless of type.

### Poseidon on-chain tree (incremental append-only)
The tree uses `PoseidonGoldilocks.compress(left, right)` for every internal node.
Leaves are `uint256` values (4 Goldilocks elements packed LE, matching the prover's Poseidon HashOut format).
Implementation: standard incremental Merkle tree (IMT) — stores `filledSubtrees[depth]` (one left-sibling per level) and pre-computed `zeros[depth]` (zero hash at each level). Each `appendLeaf` call costs O(depth) Poseidon calls.

### Nullifier set as a flat mapping
`mapping(uint256 => bool) public nullifiers` replaces the V1 nullifier Merkle tree.
After a batch is proven, each note and account nullifier from the batch is inserted into the map.
The ZK circuit proves double-spend absence; the contract enforces it post-proof for replay protection.

### Optimistic two-phase model (register → prove)
Identical to V1:
1. **Submit** (anyone, or operator — TBD): pre-validate + store batch indexed by `keccak256(PI)`.
2. **Prove** (anyone): supply `piCommitment + Proof` → verify Groth16 → update state.

Pre-validation checks:
- `acRoot` and `ncRoot` are in `confirmedRoots` (set of all previously confirmed tree roots).
- Note nullifiers are not already in `nullifiers` (optional early rejection).

### Pool config root
`bytes32 public poolConfigRoot` — set at deploy time by operator, referenced as PI in every proof. The operator can update it (triggers a new circuit deployment).

---

## File to create

**`tessera-solidity/src/TesseraRollupV2.sol`** — replace current stub.

Reuse from existing code:
- `IERC20MonitoredToken` interface — copy verbatim (same as V1).
- `IGroth16Verifier` interface — copy verbatim (same as V1).
- `keccakToPublicInputs()` — copy verbatim from `TesseraRollup.sol:696`.
- `_packBytes32Array()` — copy verbatim from `TesseraRollup.sol:646`.
- Deposit lifecycle (deposit/withdraw) — copy from V1, no changes needed.
- `PoseidonGoldilocks` — import at deployment address; call `compress(left, right)`.

---

## Detailed Structure

### Interfaces (top of file)
```
IERC20MonitoredToken  (same as V1)
IGroth16Verifier      (same as V1)
IPoseidonGoldilocks   { function compress(uint256 left, uint256 right) external pure returns (uint256); }
```

### Constants
```
uint256 public constant MAX_TREE_DEPTH = 32;
```

### State variables
```solidity
// --- access control ---
address public operator;
bool    public paused;

// --- verifiers ---
IGroth16Verifier public immutable txVerifier;
IGroth16Verifier public immutable depositVerifier;

// --- token ---
address public immutable monitoredToken;

// --- pool config ---
bytes32 public poolConfigRoot;   // accepted circuit config root

// --- on-chain Poseidon Merkle tree ---
IPoseidonGoldilocks public immutable poseidon;
uint256 public immutable treeDepth;    // e.g. 20
uint256 public leafCount;
uint256 public currentRoot;
mapping(uint256 => uint256) public filledSubtrees;  // level => left-sibling hash
mapping(uint256 => uint256) public zeros;            // level => zero-hash at that level

// --- root history (set of all confirmed tree roots) ---
mapping(uint256 => bool) public confirmedRoots;

// --- nullifier set ---
mapping(uint256 => bool) public nullifiers;

// --- deposits ---
mapping(bytes32 => Deposit) public deposits;

// --- pending batches ---
mapping(bytes32 => TransactionBatch) public pendingTxBatches;
mapping(bytes32 => DepositBatch)     public pendingDepositBatches;
```

### Structs

```solidity
struct Deposit {
    uint256      value;
    address      recipient;
    DepositStatus status;
}

struct TransactionBatch {
    uint256  acRoot;           // account commitment root (must be in confirmedRoots)
    uint256  ncRoot;           // note commitment root (must be in confirmedRoots)
    bytes32  mainPoolConfigRoot;
    uint256[] noteCommitments;  // output note commitments
    uint256[] noteNullifiers;   // consumed note nullifiers
    uint256  accountCommitment;
    uint256  accountNullifier;
    uint256  batchPoseidonRoot; // root of Poseidon Merkle subtree over noteCommitments — inserted as leaf when proven
    bool     confirmed;
}

struct DepositBatch {
    uint256  acRoot;
    uint256  ncRoot;
    bytes32  mainPoolConfigRoot;
    bytes32[] depositNoteCommitments;  // note commitments being consumed from deposits
    uint256  batchPoseidonRoot;
    bool     confirmed;
}

struct Proof {
    uint256[8] proof;
    uint256[2] commitments;
    uint256[2] commitmentPok;
}
```

### Constructor parameters
```
address _txVerifier
address _depositVerifier
address _poseidon           // PoseidonGoldilocks deployed address
address _operator
address _monitoredToken
bytes32 _poolConfigRoot
uint256 _treeDepth          // e.g. 20
```

Constructor body:
1. Validate all non-zero constraints; require `_treeDepth <= MAX_TREE_DEPTH`.
2. Pre-compute `zeros[i]` chain: `zeros[0] = 0`, `zeros[i] = poseidon.compress(zeros[i-1], zeros[i-1])`.
3. Initialize `filledSubtrees[i] = zeros[i]` for all levels.
4. Set `currentRoot = zeros[_treeDepth]` (genesis = root of all-zero tree); `confirmedRoots[currentRoot] = true`.

### Core functions

#### `submitTransactionBatch`
```
function submitTransactionBatch(TransactionBatch calldata batch) external whenNotPaused
```
1. Require `confirmedRoots[batch.acRoot]` and `confirmedRoots[batch.ncRoot]`.
2. Require `batch.mainPoolConfigRoot == poolConfigRoot`.
3. Compute `piCommitment = keccak256(abi.encodePacked(batch fields))`.
4. Require `pendingTxBatches[piCommitment].batchPoseidonRoot == 0` (not already submitted).
5. Store `pendingTxBatches[piCommitment] = batch`.
6. Emit `TransactionBatchSubmitted(piCommitment, batch.batchPoseidonRoot)`.

#### `proveTransactionBatch`
```
function proveTransactionBatch(bytes32 piCommitment, Proof calldata proof) external whenNotPaused
```
1. Load batch; revert if not found or already confirmed.
2. `pubInputs = keccakToPublicInputs(piCommitment)`.
3. `try txVerifier.verifyProof(...) catch { revert ProofVerificationFailed(...); }`.
4. Mark `batch.confirmed = true`.
5. For each `nullifier` in `batch.noteNullifiers` and `batch.accountNullifier`: `nullifiers[nullifier] = true`.
6. `_appendLeaf(batch.batchPoseidonRoot)` — updates `currentRoot`; adds new root to `confirmedRoots`.
7. Emit `TransactionBatchProven(piCommitment, currentRoot)`.

#### `submitDepositBatch` / `proveDepositBatch`
Identical flow; `proveDepositBatch` additionally marks referenced deposit notes as `Validated`.

#### `_appendLeaf(uint256 leaf)` (internal)
Standard IMT append. Old roots stay in `confirmedRoots` forever (added when they first became `currentRoot`); only the newly computed root needs to be added here.
```
node = leaf
for i in 0..treeDepth:
    if (leafCount >> i) & 1 == 0:
        filledSubtrees[i] = node
        node = poseidon.compress(node, zeros[i])
    else:
        node = poseidon.compress(filledSubtrees[i], node)
leafCount++
currentRoot = node
confirmedRoots[node] = true
```

### Events
```solidity
event TransactionBatchSubmitted(bytes32 indexed piCommitment, uint256 batchPoseidonRoot);
event TransactionBatchProven(bytes32 indexed piCommitment, uint256 newTreeRoot, uint256 leafIndex);
event DepositBatchSubmitted(bytes32 indexed piCommitment, uint256 batchPoseidonRoot);
event DepositBatchProven(bytes32 indexed piCommitment, uint256 newTreeRoot, uint256 leafIndex);
event DepositAvailable(bytes32 indexed noteCommitment, uint256 value, address recipient);
event DepositWithdrawn(bytes32 indexed noteCommitment, uint256 value, address recipient);
event DepositValidated(bytes32 indexed noteCommitment);
event OperatorChanged(address indexed oldOp, address indexed newOp);
event PoolConfigRootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot);
event PausedChanged(bool isPaused);
```

### Errors
```solidity
error NotOperator();
error PausedErr();
error ZeroAddress();
error InvalidTreeDepth();
error RootNotConfirmed(uint256 root);
error PoolConfigMismatch();
error BatchAlreadySubmitted(bytes32 piCommitment);
error BatchNotFound(bytes32 piCommitment);
error BatchAlreadyConfirmed(bytes32 piCommitment);
error ProofVerificationFailed(bytes32 piCommitment, uint256[8] pubInputs);
error NullifierAlreadyUsed(uint256 nullifier);
error NoteNotFound(bytes32 noteCommitment);
error InvalidDepositState(bytes32 noteCommitment);
error DuplicateNoteCommitment(bytes32 noteCommitment);
error InvalidAmount();
error NoTokenReceived();
error NotDepositRecipient();
error TokenTransferFailed();
error TreeFull();
```

---

## Open questions resolved in plan

| Question | Decision |
|---|---|
| Same tree for TX and deposit batches? | **Yes** — single tree; both batch types share it. Both must use the same circuit batch size (enforced off-chain by prover config). |
| `acRoot`/`ncRoot` are roots of which tree? | **The single on-chain Poseidon tree** — any root in `confirmedRoots`. |
| Nullifier pre-check on submit? | Yes — reject if any nullifier already in the map. Saves wasted proving work. |
| Who can submit / prove? | Submit: `onlyOperator` (matches V1); Prove: anyone (permissionless). Can be parameterized later. |
| Pool config root — mutable? | Yes, operator can update via `setPoolConfigRoot`. New batches must use the current one. |

---

## Tests

### Contract (`tessera-solidity/test/TesseraRollupV2.t.sol`)

Run with `forge test --match-contract TesseraRollupV2Test`.

#### Poseidon incremental Merkle tree (`_appendLeaf`)
| Test | Assertion |
|---|---|
| `test_appendLeaf_first` | After 1 append, `leafCount == 1`, `currentRoot` matches Rust reference for leaf at index 0 |
| `test_appendLeaf_power_of_two` | After 2, 4, 8 appends, root matches Rust reference at each count |
| `test_appendLeaf_arbitrary` | After 3, 5, 7 appends, root matches Rust reference |
| `test_appendLeaf_adds_to_confirmedRoots` | Each append adds the new root to `confirmedRoots`; genesis root is also present |
| `test_appendLeaf_treeFullReverts` | Appending past `2^treeDepth` reverts with `TreeFull` |

#### `submitTransactionBatch`
| Test | Assertion |
|---|---|
| `test_submit_happy` | Valid batch (acRoot + ncRoot both genesis) stored, event emitted |
| `test_submit_unknownAcRoot` | Reverts `RootNotConfirmed` when `acRoot` not in `confirmedRoots` |
| `test_submit_unknownNcRoot` | Reverts `RootNotConfirmed` when `ncRoot` not in `confirmedRoots` |
| `test_submit_wrongPoolConfig` | Reverts `PoolConfigMismatch` when `mainPoolConfigRoot` doesn't match |
| `test_submit_nullifierAlreadyUsed` | Reverts `NullifierAlreadyUsed` when any nullifier already in set |
| `test_submit_duplicate` | Reverts `BatchAlreadySubmitted` on second identical submission |
| `test_submit_notOperator` | Reverts `NotOperator` when called by non-operator |
| `test_submit_whenPaused` | Reverts `PausedErr` when contract paused |

#### `proveTransactionBatch`
| Test | Assertion |
|---|---|
| `test_prove_happy` | DummyVerifier accepts; `batchPoseidonRoot` appended to tree; nullifiers added to set; `TransactionBatchProven` emitted; `confirmedRoots[newRoot]` true |
| `test_prove_unknownPiCommitment` | Reverts `BatchNotFound` |
| `test_prove_alreadyConfirmed` | Reverts `BatchAlreadyConfirmed` on second proof submission |
| `test_prove_invalidProof` | Reverts `ProofVerificationFailed` when verifier rejects |
| `test_prove_permissionless` | Any address (not just operator) can call successfully |
| `test_prove_nullifiersInserted` | After success, each note nullifier and account nullifier is `true` in `nullifiers` |
| `test_prove_rootHistoryPreserved` | Old `currentRoot` still in `confirmedRoots` after advance |

#### Deposit lifecycle
| Test | Assertion |
|---|---|
| `test_deposit_happy` | `depositAndRegister` transfers tokens, status `Pending`, event emitted |
| `test_withdraw_pending` | Recipient can withdraw; tokens returned; status `Withdrawn` |
| `test_withdraw_nonRecipient` | Reverts `NotDepositRecipient` |
| `test_submitDepositBatch_validatesNotes` | Referenced deposit note commitments must exist and be `Pending` |
| `test_proveDepositBatch_marksValidated` | After proof, all deposit notes advance to `Validated` |
| `test_withdraw_afterValidated` | Cannot withdraw a `Validated` deposit |

#### Access control + pause
| Test | Assertion |
|---|---|
| `test_setOperator` | Operator can transfer operator role |
| `test_setOperator_nonOperator` | Reverts `NotOperator` |
| `test_setPaused_blocksSubmit` | All mutating entry points revert `PausedErr` while paused |
| `test_setPoolConfigRoot` | Operator can update; old `poolConfigRoot` no longer accepted by new batches |

---

### `SubtreeRootCircuit` (`tessera-trees/src/proof_aggregation/subtree_root.rs`)

Run with `cargo test -p tessera-trees --release subtree_root`.

| Test | Assertion |
|---|---|
| `test_subtree_root_depth1` | Two leaves: circuit proves `root = compress(l0, l1)`; native reference agrees |
| `test_subtree_root_depth4` | 16 leaves: circuit root matches reference Poseidon Merkle built natively |
| `test_subtree_root_all_zeros` | All-zero leaves: circuit produces correct zero-tree root |
| `test_subtree_root_wrong_root_fails` | Supplying an incorrect `root` as PI makes the circuit proof invalid |
| `test_subtree_root_leaves_match_pi` | Extracted leaf PIs from proof match the input leaves |

---

### `SuperAggregatorV2` (`tessera-trees/src/proof_aggregation/super_aggregator_v2.rs`)

Run with `cargo test -p tessera-trees --release super_aggregator_v2`.

| Test | Assertion |
|---|---|
| `test_sa_v2_happy_all_real` | Full batch of real TX proofs + correct subtree root → valid SA proof; `piCommitment` matches reference Keccak |
| `test_sa_v2_happy_mixed` | Some real + some dummy slots → valid SA proof |
| `test_sa_v2_happy_all_dummy` | All dummy slots (pre-computed) → valid SA proof |
| `test_sa_v2_cross_check_fails` | TX proof note commitments don't match subtree leaves → SA circuit fails to prove |
| `test_sa_v2_pi_commitment_matches_contract` | `piCommitment` from SA == `keccak256(batch fields)` computed by the Solidity helper |

---

### `BatchBuilder` / `FinalizedBatch` (`tessera-server/src/sequencer/batch.rs`)

Run with `cargo test -p tessera-server --release batch`.

| Test | Assertion |
|---|---|
| `test_builder_add_private_tx` | Slot populated; `noteCommitments`, `noteNullifiers`, `accountCommitment`, `accountNullifier` correct |
| `test_builder_add_deposit` | Deposit slot populated; no nullifiers |
| `test_builder_pad` | Empty slots filled with zero values |
| `test_finalized_batch_poseidon_root` | `batch_poseidon_root` matches native Poseidon subtree over `noteCommitments` |
| `test_finalized_no_sort_fields` | `FinalizedBatch` has no `an_sort_perm` / `nn_sort_perm` fields (compile-time, via absence) |
| `test_prove_request_from_finalized` | `ProveRequest` fields match `FinalizedBatch` fields one-to-one |

---

### Sequencer state (`tessera-server/src/sequencer/mod.rs`)

Run with `cargo test -p tessera-server --release sequencer`.

| Test | Assertion |
|---|---|
| `test_confirmed_root_init` | On startup, `confirmed_root` equals `currentRoot()` from mock chain |
| `test_confirmed_root_updates_after_prove` | After `proveTransactionBatch` event received, `confirmed_root` advances |
| `test_flush_submits_batch` | `flush_batch()` calls `submitTransactionBatch` with correct calldata; no tree registration call |
| `test_flush_uses_confirmed_root_as_ac_nc` | `ac_root` and `nc_root` in submitted batch equal `confirmed_root` at flush time |

---

### E2E (`tessera-server/src/tests/e2e.rs`)

Run with `cargo test -p tessera-server --release e2e`.

| Test | Assertion |
|---|---|
| `test_e2e_tx_batch` | Sequencer builds batch → `submitTransactionBatch` on anvil → SA proof produced → `proveTransactionBatch` succeeds → `currentRoot` advances → new root in `confirmedRoots` |
| `test_e2e_deposit_batch` | Same pipeline for consume; deposit notes marked `Validated` post-proof |
| `test_e2e_second_batch_references_first_root` | Second batch uses first batch's proven tree root as `ncRoot`; pre-validation passes |
| `test_e2e_invalid_root_rejected` | Batch referencing an unconfirmed root is rejected by `submitTransactionBatch` |

---

## Backend Changes

### Context

V1 backend maintains 4 Merkle trees (NC, NN, AC, AN) and the SuperAggregator aggregates 5 inner proofs. Nullifier trees require sorted leaves + permutations + a GF(p²) multi-set equality check in the SA circuit to bind TX proof nullifier values to sorted tree PI.

V2 backend has **no trees**. The contract is the authoritative commitment tree. The backend is a batch constructor + prover. This removes all nullifier-tree complexity, all sorting logic, and reduces the SA circuit from 5 inner proofs to 2.

---

### What changes vs. V1

| Component | V1 | V2 |
|---|---|---|
| Backend trees | 4 (NC, NN, AC, AN) with WAL | None |
| Tree proof circuits | 4 (batch commitment/nullifier) | None |
| Sort permutations | AN + NN argsort per batch | Removed |
| Dummy proof generation | Dynamic (AN/NN field overrides per batch) | Fixed pre-computed reusable proof |
| SA inner proofs | 5 (NC, NN, AC, AN, TX root) | 2 (batch root + TX root) |
| GF(p²) multi-set equality in SA | Yes | Removed |
| New circuits | — | `SubtreeRootCircuit` |
| `ProveRequest` | 4 tree native proofs + sorted leaves + permutations | Batch PI fields + `batchPoseidonRoot` |
| On-chain submit call | `registerTransactionBatchUpdate()` (4 roots + all leaves) | `submitTransactionBatch()` (compact batch struct) |
| On-chain confirm call | `confirmBatch(batchId, proof)` | `proveTransactionBatch(piCommitment, proof)` |
| Sequencer state | 4 tree state machines + WAL | `confirmed_root: HashOutput` (synced from chain) |

---

### New circuit: `SubtreeRootCircuit`

**Location:** `tessera-trees/src/proof_aggregation/subtree_root.rs`

**Purpose:** Prove that a claimed root is the Poseidon Merkle root of a given set of leaves. No old-root / insertion / tree history involved.

**What it proves:**
Given `(root, leaves[N])`: `root = PoseidonMerkle(leaves)`, where the tree is built bottom-up using `Poseidon.compress(left, right)` at each level. Depth = `log2(N)`.

**Public inputs:**
`[root[4] || leaves[N×4]]`

`root` is the `batchPoseidonRoot` submitted on-chain and inserted as a leaf into the contract's tree upon proof verification.

**Role in SA V2:**
The SA verifies this proof in-circuit and extracts `root[4]` + `leaves` to cross-check against note commitments from the TX root proof.

**Why not reuse `BatchCommitmentProof`:**
`BatchCommitmentProof` proves a tree *insertion* (`old_root → new_root`), which carries unnecessary state. Here we only need to verify the subtree structure of the current batch in isolation — no prior tree state is relevant.

---

### New `SuperAggregatorV2`

**Location:** `tessera-trees/src/proof_aggregation/super_aggregator_v2.rs`

**Inner proofs (2, vs. 5 in V1):**
1. TX root proof — output of `GenericAggregator` over all per-slot TX proofs (same as V1)
2. Subtree root proof — output of `SubtreeRootCircuit`

**In-circuit:**
1. Verify TX root proof; extract per-slot PI (account commitments, nullifiers, note commitments, nullifiers, `is_real` flags).
2. Verify batch root proof; extract `(batchPoseidonRoot, piCommitment)`.
3. Cross-check: the note commitment leaves used in the batch root's Poseidon subtree match the note commitments from the TX proof PI, slot by slot. (Dummy slots masked by `is_real == 0`.)
4. Output: `piCommitment` (the Keccak-256 from the batch root circuit) — 8 Goldilocks field elements.

**No GF(p²) multi-set equality** — removed entirely. The binding between TX proofs and batch root is direct per-slot equality on note commitments (the subtree leaves).

---

### Fixed pre-computed dummy TX proof

V1 generates dummy proofs on the fly per batch because dummy slots need AN/NN field overrides matching sorted positions. In V2, dummy slots always have fixed PI (all zeros for commitments/nullifiers, `is_real = 0`), so:

- **Pre-compute once:** generate and serialize a dummy TX proof + pre-aggregated trees of dummy proofs for all power-of-two sizes (1, 2, 4, 8, 16 … up to `account_batch_size`).
- **Store as artifacts:** alongside circuit artifacts (e.g., `artifacts/dummy_tx_proof_agg_{n}.bin`).
- **At runtime:** fill empty slots from the pre-loaded artifact; no proving required.

This eliminates all runtime dummy proof generation entirely.

---

### `ProveRequest` V2

**`tessera-server/src/types.rs`** — replace existing `ProveRequest`:

```rust
pub struct ProveRequest {
    pub batch_id: u64,
    /// Confirmed tree root used as account reference (must be in on-chain confirmedRoots).
    pub ac_root: HashOutput,
    /// Confirmed tree root used as note reference.
    pub nc_root: HashOutput,
    pub main_pool_config_root: HashOutput,
    /// Per-slot account commitments (length = account_batch_size).
    pub account_commitments: Vec<HashOutput>,
    /// Per-slot account nullifiers.
    pub account_nullifiers: Vec<HashOutput>,
    /// Per-note commitments (length = account_batch_size × notes_per_slot).
    pub note_commitments: Vec<HashOutput>,
    /// Per-note nullifiers.
    pub note_nullifiers: Vec<HashOutput>,
    /// Poseidon root of the batch PI — pre-computed natively by the sequencer.
    /// This is the leaf that will be inserted into the on-chain tree upon proof verification.
    pub batch_poseidon_root: HashOutput,
    /// Real TX proofs keyed by slot index. Empty slots are filled from pre-computed dummy.
    pub tx_proofs_by_slot: HashMap<usize, Vec<u8>>,
}

pub struct ConsumeProveRequest {
    pub batch_id: u64,
    pub ac_root: HashOutput,
    pub nc_root: HashOutput,
    pub main_pool_config_root: HashOutput,
    /// Note commitments from deposits being consumed.
    pub deposit_note_commitments: Vec<[u8; 32]>,
    pub batch_poseidon_root: HashOutput,
    pub consume_proofs_by_slot: HashMap<usize, Vec<u8>>,
}
```

---

### Sequencer changes (`tessera-server/src/sequencer/`)

**Removed:**
- `notes_commitment_tree`, `notes_nullifier_tree`, `accounts_commitment_tree`, `accounts_nullifier_tree` state fields
- WAL commit logic for all 4 trees
- `recovery.rs` tree re-hydration from on-chain roots
- `an_sort_perm`, `nn_sort_perm`, `an_sorted`, `nn_sorted` in `FinalizedBatch`
- `_requireSorted` + `argsort_bytes32_as_u256` calls
- `into_prove_request()` tree proof building (4 `BatchCommitmentProof` / `BatchInsertProof` constructions)

**Added / changed:**
- `confirmed_root: HashOutput` — latest confirmed on-chain tree root (synced from `TransactionBatchProven` / `DepositBatchProven` events or queried on startup via `currentRoot()`).
- `confirmed_root_history: HashSet<HashOutput>` — local cache of `confirmedRoots` for quick pre-validation (populated from events; authoritative check is on-chain).
- `BatchBuilder` records `ac_root` and `nc_root` at batch-open time (from `confirmed_root`).
- `FinalizedBatch::batch_poseidon_root` — computed natively via Rust Poseidon (same `PoseidonGoldilocks` logic as `tessera-trees`).
- `flush_batch()` calls `submitTransactionBatch(batch)` instead of `registerTransactionBatchUpdate(4 roots + arrays)`.
- `confirm_tx_batch()` calls `proveTransactionBatch(piCommitment, proof)`.

**`pipeline.rs` flush flow (V2):**
```
1. finalize batch → FinalizedBatch (no sorting)
2. compute batch_poseidon_root natively
3. submitTransactionBatch(batch struct) → store piCommitment
4. submit ProveRequest (compact) to prover
5. on ProveOutcome::Success → proveTransactionBatch(piCommitment, proof)
6. update confirmed_root from chain event
```

---

### Prover changes (`tessera-server/src/prover.rs`)

**Removed:**
- `CommitmentProverService` × 2 (NC, AC batch proofs)
- `NullifierProverService` × 2 (NN, AN batch proofs)
- AN/NN override logic in dummy proof generation
- `ProverRuntime` fields: `notes_commitment_prover`, `notes_nullifier_prover`, `accounts_commitment_prover`, `accounts_nullifier_prover`

**Added:**
- `SubtreeRootProverService` — builds and proves `SubtreeRootCircuit` from `ProveRequest.note_commitments`.
- Pre-loaded dummy proof artifacts (`dummy_tx_proof_agg_*.bin`).

**Updated `ProverRuntime`:**
```rust
struct ProverRuntime {
    tx_aggregator: AssociatedInputAggregatorService,   // unchanged
    subtree_root_prover: SubtreeRootProverService,      // new
    super_aggregator: SuperAggregatorServiceV2,         // 2 inner proofs
    // consume pipeline (mirrors TX pipeline)
    consume_aggregator: AssociatedInputAggregatorService,
    consume_subtree_root_prover: SubtreeRootProverService,
    consume_super_aggregator: SuperAggregatorServiceV2,
}
```

**Prover pipeline (V2 TX):**
```
1. Deserialize real TX proofs from ProveRequest.tx_proofs_by_slot
2. Fill empty slots from pre-loaded dummy proof artifact (no generation)
3. tx_aggregator.prove() → tx_root_proof  (same binary-tree aggregation as V1)
4. subtree_root_prover.prove(note_commitments) → subtree_root_proof
5. super_aggregator_v2.prove(tx_root_proof, subtree_root_proof) → plonky2 SA proof
6. super_aggregator_v2.wrap_groth16(plonky2 SA proof) → SolidityProof
7. Return ProveOutcome::Success { pi_commitment, solidity_proof }
```

---

### Consume pipeline details

The consume pipeline (deposit batch proving) mirrors the TX pipeline structurally. Differences:

| Aspect | TX pipeline | Consume pipeline |
|---|---|---|
| Batch struct | `TransactionBatch` | `DepositBatch` |
| On-chain submit | `submitDepositBatch` | same function name |
| On-chain prove | `proveDepositBatch` | same function name |
| Verifier | `txVerifier` | `depositVerifier` |
| Per-slot proofs | PrivTx proof from client | Consume proof from client |
| Post-proof state | nullifiers inserted | deposit notes marked `Validated` |
| Subtree leaves | note commitments of the batch | note commitments of the consumed deposit notes |
| SA circuit | `SuperAggregatorV2` (tx instance) | `SuperAggregatorV2` (consume instance, same circuit different VK) |

`DepositBatch.batchPoseidonRoot` is the root of the same `SubtreeRootCircuit` over the consumed deposit note commitments, so the circuit is shared between both pipelines (different artifacts/VKs because the proof system context differs, but the Plonky2 circuit definition is the same).

---

### Sequencer startup and root history recovery

On startup the sequencer must rebuild `confirmed_root` and `confirmed_root_history` from on-chain state. The procedure replaces V1's tree WAL replay:

```
1. Call currentRoot() on contract → set confirmed_root.
2. Query all TransactionBatchProven and DepositBatchProven events from
   block 0 (or last-known checkpoint) to latest.
3. For each event, insert newTreeRoot into confirmed_root_history.
4. Also insert the genesis root (confirmedRoots[genesisRoot] = true by construction).
```

This is much lighter than V1 (no tree re-hydration, no WAL replay) — just event log scanning. The `confirmed_root_history` is a best-effort local cache; the authoritative check remains the on-chain `confirmedRoots` mapping.

`recovery.rs` simplifies to a single `async fn load_confirmed_roots(provider, contract_address, from_block) -> (HashOutput, HashSet<HashOutput>)`.

---

### New artifacts required

| Artifact | Generated by | Location |
|---|---|---|
| `subtree_root_circuit.bin` | `artifact_builder` | `artifacts/subtree_root_circuit.bin` |
| `super_aggregator_v2.bin` | `artifact_builder` | `artifacts/super_aggregator_v2.bin` |
| `super_aggregator_v2_bn128.bin` | `artifact_builder` | `artifacts/super_aggregator_v2_bn128.bin` |
| `consume_super_aggregator_v2.bin` | `artifact_builder` | `artifacts/consume_super_aggregator_v2.bin` |
| `dummy_tx_proof.bin` | `artifact_builder` | `artifacts/dummy_tx_proof.bin` |
| `dummy_tx_proof_agg_{n}.bin` for n=2,4,…,batch_size | `artifact_builder` | `artifacts/dummy_tx_proof_agg_{n}.bin` |

The artifact builder must be updated (step 16 in progress tracker) to add these generation steps after the existing TX aggregator circuit build.

---

### Files to create / modify

| File | Action |
|---|---|
| `tessera-trees/src/proof_aggregation/subtree_root.rs` | **Create** — `SubtreeRootCircuit`: `root = PoseidonMerkle(leaves)` |
| `tessera-trees/src/proof_aggregation/super_aggregator_v2.rs` | **Create** — `SuperAggregatorV2` (2 inner proofs: TX root + subtree root) |
| `tessera-trees/src/proof_aggregation/mod.rs` | **Modify** — export new modules |
| `tessera-server/src/types.rs` | **Modify** — new `ProveRequest`, add `ConsumeProveRequest` |
| `tessera-server/src/sequencer/batch.rs` | **Modify** — drop sorting/nullifier trees, add `batch_poseidon_root` |
| `tessera-server/src/sequencer/mod.rs` | **Modify** — drop 4 tree fields, add `confirmed_root` |
| `tessera-server/src/sequencer/pipeline.rs` | **Modify** — new submit/prove calls |
| `tessera-server/src/sequencer/recovery.rs` | **Modify** — simplify (only need `currentRoot` query) |
| `tessera-server/src/prover.rs` | **Modify** — new `ProverRuntime`, drop tree services |
| `tessera-server/src/bin/artifact_builder.rs` | **Modify** — add dummy proof pre-generation step |

---

## Salvage Notes (what to reuse from V1 for each step)

### Step 10 — `ProveRequest` / `ConsumeProveRequest` (`tessera-server/src/types.rs`)
- `SolidityProof` struct (lines ~74-79): **reuse as-is** — `[U256; 8]` + `[U256; 2]` × 2 matches V2 Groth16 format.
- `ProveOutcome` enum (lines ~44-69): **minor adapt** — remove `new_roots` fields (no tree roots to return); keep `Success { pi_commitment, solidity_proof }` and `Failure`.
- `ProveRequest`: **full replacement** — current struct carries 4 tree native proofs + sorted leaves + permutations; V2 struct is entirely different (see `ProveRequest V2` section above).

### Step 11 — `BatchBuilder` / `FinalizedBatch` (`tessera-server/src/sequencer/batch.rs`)
- `NOTES_PER_SLOT` constant (line ~16): **reuse as-is**.
- `BatchSlot` enum (lines ~28-67): **reuse as-is** — `PrivateTx`, `Deposit`, `Empty` variants unchanged.
- `SlotPI` struct (lines ~19-25): **reuse as-is**.
- `BatchBuilder::new/len/is_full/add_private_tx/add_deposit/pad` (lines ~126-358): **reuse as-is** — slot-level logic is unchanged.
- `BatchBuilder::finalize()` (lines ~364-451): **adapt** — remove `argsort_bytes32_as_u256` / sort permutation building; keep leaf array assembly.
- `FinalizedBatch` struct (lines ~70-89): **adapt** — drop `an_sort_perm`, `nn_sort_perm`, `an_sorted`, `nn_sorted`; add `batch_poseidon_root: HashOutput`.
- `FinalizedBatch::into_prove_request()` (lines ~516-562): **rewrite** — replaces 4 tree proof constructions with `batch_poseidon_root` computation (native Poseidon subtree over `nc_leaves`).
- `argsort_bytes32_as_u256`, `is_sorted_u256` (lines ~456-481): **delete** — no nullifier sorting in V2.
- `nc_fixed/nn_fixed/ac_fixed/an_fixed` helpers (lines ~565-591): **delete** — V2 doesn't pass these as calldata arrays to the contract.

### Step 12 — Sequencer state (`tessera-server/src/sequencer/mod.rs`)
- `registered_pending_batches: BTreeMap<u64, TxBatch>` (line ~116): **adapt** — change key from `u64 batchId` to `bytes32 piCommitment`; rename `TxBatch` → `PendingTxBatch`.
- `batch_builder`, `batch_pending_since` fields (lines ~121-124): **reuse as-is**.
- Main event loop dispatch structure (lines ~369-510): **reuse structure** — `Interval tick → maybe_flush`, `ProveOutcome → handle_prove_outcome`, `PrivateTx → add_private_tx`. Only bridge method names change.
- Four tree state/store fields (lines ~99-109): **delete** — replace with `confirmed_root: HashOutput` + `confirmed_root_history: HashSet<HashOutput>`.

### Step 13 — `SubtreeRootCircuit` (`tessera-trees/src/proof_aggregation/subtree_root.rs`)
- `BatchCommitmentProofTargets<N>` in `tessera-trees/src/tree/commitment_tree/proofs/batch_insertion/stark.rs` (lines ~20-68): **reference closely** — `connect()` (lines ~70-139) and `compute_root_circuit()` (lines ~141-170) implement exactly the Poseidon Merkle root computation needed. The subtree root circuit is essentially this without the old-root / insertion constraints: keep the bottom-up hash building, remove everything related to `root_old`, `start_index`, `upper_siblings_old/new`.
- The `set()` witness-setting method (lines ~172+): **copy and simplify** — remove old-root witness; only set leaf values and assert root.

### Step 14 — `SuperAggregatorV2` (`tessera-trees/src/proof_aggregation/super_aggregator_v2.rs`)
- `super_aggregator.rs` overall structure: **reference for shape** — circuit data loading, `prove_plonky2`, `wrap_groth16` methods, artifact path constants are all reusable patterns.
- `SuperAggregatorCircuitData` struct (lines ~137-148): **adapt** — reduce from 5 inner verifier datas to 2 (TX root + subtree root).
- PI layout constants (`TX_LEAF_PI_SIZE` ~113, `LEAF_OFFSET` ~116, `TX_DATA_OFFSET` ~123, `IS_REAL_OFFSET` ~127): **must re-verify** — these are V1 values. V2 TX proof PI layout may differ; recalculate before wiring SA cross-checks.
- GF(p²) multi-set equality gadget: **delete** — not needed in V2.

### Step 15 — Pre-computed dummy TX proof (`tessera-server/src/bin/artifact_builder.rs`)
- Existing dummy-proof generation infrastructure: **check `crate::dummy` module** — V1 already has a `dummy` module used by `batch.rs` to derive dummy AN/NN leaves. V2 dummy proof is simpler (fixed all-zero PI, `is_real=0`); extend the artifact builder to serialize the proof rather than regenerating per batch.
- Artifact loading pattern in `prover.rs` (`from_artifacts_and_pool` at lines ~157-189): **reuse pattern** — deserialize bytes, wrap in service struct.

### Step 16 — `ProverRuntime` wiring (`tessera-server/src/prover.rs`)
- `build_pool()` (lines ~363-387): **reuse as-is** — generic node pool builder.
- `bytes32_to_f4()` (lines ~844-850): **reuse as-is** — utility.
- `parse_solidity_proof_json()` (lines ~865-899): **reuse as-is** — generic JSON parsing.
- `CommitmentProverService` (lines ~81-111): **repurpose as `SubtreeRootProverService`** — the `prove()` method pattern (build circuit, set witness, generate proof) is identical; just swap circuit type.
- `NullifierProverService` (lines ~119-149): **delete** — no nullifier circuits in V2.
- `build_and_aggregate_tx_proofs()` (lines ~472-559): **adapt** — remove lines ~500-545 (AN/NN sort permutation override logic for dummy slots); reuse rest (real-slot proof deserialization, streaming aggregation).
- `try_prove_request()` (lines ~584-754): **major adapt** — remove PI consistency guards for NC/NN/AC/AN tree proofs (lines ~597-654); remove 4 tree proving calls; add subtree root proving call; keep Groth16 wrapping logic.
- Off-circuit validation helpers (`validate_ac_offcircuit` etc., lines ~700-755): **delete** — V2 removes tree PI cross-validation; replaced by simpler subtree root check.

### Step 17 — Consume pipeline
- Entire TX pipeline structure: **mirror directly** — `ConsumeProveRequest` mirrors `ProveRequest`; consume `flush_batch` / `confirm` mirrors TX equivalents. Implement as a second instantiation of the same services with different artifact paths and the `depositVerifier` on-chain address.
- `is_note_available()` (pipeline.rs, lines ~58-81): **reuse as-is** — queries deposit status; logic unchanged.

### Step 18 — Contract tests (`tessera-solidity/test/`)
- Existing `DummyVerifier.sol` (`tessera-solidity/src/DummyVerifier.sol`): **reuse as-is** — accepts all proofs; used to test the contract state machine without real Groth16.
- Existing test scaffolding in any `*.t.sol` files: **check for deploy helpers and ERC20 mock setup** to copy into `TesseraRollupV2.t.sol`.
- `ToyUSDT.sol`: **reuse as-is** — ERC20 mock for deposit tests.

### Steps 19-22 — Tests
- Existing `#[test]` functions in `batch.rs` (end of file): **run first** to confirm V1 tests pass before modifying; use as templates for V2 equivalents.
- Existing `super_aggregator.rs` test (if any): **reference for SA V2 test structure**.
- E2E test pattern from any existing `tests/` in `tessera-server`: **reuse anvil setup and contract deployment helpers**.
