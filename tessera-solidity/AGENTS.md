# tessera-solidity — Agent Context

## Project Purpose

`TesseraContract` is the on-chain component of the Tessera ZK rollup bridge. It provides:

- **ERC20 deposit escrow** — users lock tokens on-chain; the ZK circuit later proves inclusion.
- **On-chain Poseidon Incremental Merkle Tree (IMT)** — accumulates batch roots as leaves; acts as a commitment to all proven state transitions.
- **Two-phase ZK batch proving** (submit → prove) for two batch types:
  - **Private-TX batch** (`submitTransactionBatch` / `proveTransactionBatch`)
  - **Bridge-TX batch** (`submitBridgeTxBatch` / `proveBridgeTxBatch`)
- **mainPoolConfigRoot management** — a separate binary Poseidon Merkle tree whose leaves encode subpool configurations. Subpool owners can update their own leaf; the operator assigns subpool ownership.

---

## Repository Layout

```
tessera-solidity/
├── src/
│   ├── IMTLib.sol                     # Poseidon Incremental Merkle Tree library
│   ├── TesseraContract.sol            # Main contract (uses IMTLib)
│   ├── PoseidonGoldilocks.sol         # Poseidon hash over Goldilocks field
│   ├── TesseraBatchTransactionVerifier.sol  # gnark Groth16 verifier (auto-generated)
│   ├── AcceptAllVerifier.sol          # Test-only: accepts every proof
│   ├── ToyUSDT.sol                    # Test ERC20 token
│   ├── ToyUSDTWOperator.sol           # Variant with operator minting
│   └── ToyUser.sol                    # Convenience wrapper for E2E tests
├── test/
│   ├── TesseraContract.t.sol          # Unit tests for TesseraContract
│   ├── TesseraBatchTransactionVerifier.t.sol  # Integration tests (real Groth16 verifier)
│   ├── TestCompress.t.sol             # Poseidon compress unit tests
│   ├── DebugGenesis.t.sol             # Genesis root debugging
│   └── poseidon/
│       └── PoseidonGoldilocks.t.sol   # Poseidon implementation tests
├── script/
│   └── Deploy.s.sol                   # Foundry deployment script
├── AGENTS.md                          # This file
└── foundry.toml
```

---

## Key Concepts

### Goldilocks Field Encoding

The ZK circuits operate over the Goldilocks field (p = 2^64 − 2^32 + 1). Hash values are 4-element `HashOut` values encoded as a LE-packed `uint256`:

```
packed = el0 | (el1 << 64) | (el2 << 128) | (el3 << 192)
```

In Keccak preimages (on-chain), each element is serialised as `[lo_u32_BE(4B)][hi_u32_BE(4B)]` where `lo = uint32(el)`, `hi = uint32(el >> 32)`. This is called the *GL-preimage encoding*. The contract's `_glHashToU256` reverses this.

### Batch Lifecycle (Two-Phase Model)

**Phase 1 — Submit (operator only):**
1. Operator calls `submitTransactionBatch(batchPreimage)`.
2. Contract validates that the `act_root` in the preimage header is a `confirmedRoot` and `mainPoolConfigRoot` matches.
3. `piCommitment = keccak256(batchPreimage)` is stored in `pendingTxBatches`.
4. The full `batchPreimage` is NOT stored (gas); it is passed again in Phase 2.

**Phase 2 — Prove (permissionless):**
1. Anyone calls `proveTransactionBatch(batchPreimage, proof)`.
2. `piCommitment` is re-derived from `batchPreimage` and looked up in `pendingTxBatches`.
3. The Groth16 verifier checks `proof` against the 8-word Keccak decomposition of `piCommitment`.
4. On success: nullifiers are inserted, `batchPoseidonRoot` (preimage offset 0) is appended to the IMT as a leaf.

Bridge-TX batches follow the same two-phase model but additionally validate/advance deposit notes and handle withdrawal nullifiers.

### Preimage Layout

All batch preimages share a 96-byte header:

```
[0..32)   batchPoseidonRoot  — GL-preimage encoded bytes32
[32..64)  act_root           — must be in confirmedRoots
[64..96)  mainPoolConfigRoot — must equal contract state
```

TX batch slots (520 B each, starting at offset 96):
```
[0..8)    notFakeTx          — GL field, non-zero = real slot
[8..40)   accinNullifier     — GL-preimage encoded bytes32
[40..72)  accoutCommitment
[72..296) noteInNullifiers   — 7 × 32 B
[296..520) noteOutCommitments — 7 × 32 B
```

Bridge-TX preimage extends the header with 256 withdraw slots (616 B each) followed by 256 deposit slots (216 B each). See constants in `TesseraContract.sol` for exact offsets.

### Incremental Merkle Tree (IMT)

Implemented in `IMTLib.sol` as a library operating on `IMTLib.IMTState` storage structs.

- Depth is set at construction time (`treeDepth`, immutable).
- Zero-chain: `zeros[0] = 0`, `zeros[i] = poseidon.compress(zeros[i-1], zeros[i-1])`.
- Genesis root = `zeros[treeDepth]` (all-zero tree).
- Each `appendLeaf` call does O(treeDepth) Poseidon hashes and stores the new root in `confirmedRoots`.
- `validatedBatchRoots[leaf] = true` is set for every appended leaf (= batchPoseidonRoot).

Access from outside `TesseraContract`:
- `imtLeafCount()` — total leaves appended.
- `imtCurrentRoot()` — latest confirmed tree root.
- `isConfirmedRoot(uint256)` — check any historical root.

### mainPoolConfigRoot and Subpool System

`mainPoolConfigRoot` is the root of a binary Poseidon Merkle tree of depth `configTreeDepth`:

- **Leaf value** at position `subpool_id`: `poseidon.compress(subpool_id, subpoolRoot)`.
  - If the subpool has never been updated (`subpoolRoots[subpool_id] == 0`), the effective leaf is `0` (zero leaf), NOT `poseidon.compress(subpool_id, 0)`.
- **Genesis root** is computed at construction as `zeros[configTreeDepth]` (all-zero Poseidon tree). It is NOT stored separately — the zero chain is computed transiently.
- **Subpool owners** are assigned by the operator via `assignSubpoolOwner(subpoolId, owner)`.
  - `subpoolId = 0` is reserved and cannot be assigned.
- **Updating a leaf**: the subpool owner calls `updateSubpoolRoot(subpoolId, newSubpoolRoot, siblings[])`.
  - Caller provides the full sibling path (length = `configTreeDepth`).
  - Contract verifies the old leaf against `mainPoolConfigRoot`, then derives the new root.
  - The operator **cannot** directly set `mainPoolConfigRoot`.

### Deposit Lifecycle

```
None → Pending (depositAndRegister)
             ↓
       Validated (proveBridgeTxBatch)
             or
       Withdrawn (withdrawPendingDeposit, after withdrawalDelay blocks)
```

`withdrawalDelay` (operator-configurable, set at construction) imposes a minimum block delay between deposit and withdrawal, preventing a user from front-running the aggregation server's batch proof transaction.

---

## Constructor Parameters

```solidity
constructor(
    address _txVerifier,        // Groth16 verifier for private-TX batches
    address _bridgeTxVerifier,  // Groth16 verifier for bridge-TX batches
    address _poseidon,          // PoseidonGoldilocks contract
    address _operator,          // Initial operator
    address _monitoredToken,    // ERC20 token escrowed by bridge
    uint256 _treeDepth,         // IMT depth (e.g. 20); max 32
    uint256 _configTreeDepth,   // Config tree depth (e.g. 20); max 32
    uint256 _withdrawalDelay    // Min blocks between deposit and withdrawal
)
```

---

## Key Invariants

1. `batchPreimage` is NEVER stored on-chain. It must be re-supplied identically in the prove phase.
2. A `piCommitment` can only transition `pending → confirmed`, never backwards.
3. Nullifiers are checked before any state mutation (pre-check loop), then inserted in a second loop — atomic from an EVM perspective since both loops are in the same transaction.
4. Every root ever produced by `appendLeaf` is permanently in `confirmedRoots`.
5. `subpoolId = 0` cannot be assigned an owner.
6. The effective old leaf for an uninitialized subpool (subpoolRoots == 0) is `0`, not `poseidon(id, 0)`.
7. `mainPoolConfigRoot` can only change through `updateSubpoolRoot` (by subpool owners). The operator has no direct setter.

---

## Access Control Summary

| Function | Caller |
|---|---|
| `submitTransactionBatch` | Operator only |
| `submitBridgeTxBatch` | Operator only |
| `proveTransactionBatch` | Permissionless |
| `proveBridgeTxBatch` | Permissionless |
| `depositAndRegister` | Anyone (whenNotPaused) |
| `withdrawPendingDeposit` | Deposit recipient (after delay) |
| `assignSubpoolOwner` | Operator only |
| `updateSubpoolRoot` | Assigned subpool owner |
| `setOperator` | Operator only |
| `setPaused` | Operator only |
| `setWithdrawalDelay` | Operator only |

---

## Build and Test

```bash
# Install Foundry: https://getfoundry.sh
forge build
forge test
forge test -vvv          # verbose output
forge test --match-test test_appendLeaf  # run a specific test
```

### Deployment

Required env vars:
```
TESSERA_TREE_DEPTH         # e.g. 20
TESSERA_CONFIG_TREE_DEPTH  # e.g. 20
```

Optional:
```
TESSERA_TX_VERIFIER        # pre-deployed verifier address
TESSERA_DEPOSIT_VERIFIER   # pre-deployed verifier address
TESSERA_MONITORED_TOKEN    # ERC20 address
TESSERA_OPERATOR           # defaults to msg.sender
TESSERA_WITHDRAWAL_DELAY   # defaults to 0
```

```bash
forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
```

### Integration Tests

`TesseraBatchTransactionVerifier.t.sol` requires pre-generated fixture files produced by Rust artifact generators:

```bash
cargo run -p tessera-e2e --bin tx_artifacts --release
cargo run -p tessera-e2e --bin deposit_artifacts --release
```

Tests are skipped automatically if the fixture file `test/fixtures/groth16_proof.json` is absent.

---

## Notable Design Decisions

- **`batchPreimage` stays in calldata** — storing it on-chain would cost 3–12 M gas per batch. The piCommitment (a single `bool` slot) is the only on-chain record from the submit phase.
- **IMT as a library** — `IMTLib` operates on a `storage` pointer (`IMTState`) to allow embedding in any contract without proxy patterns.
- **Config tree zeros not stored** — the zero chain for the config tree is computed transiently at construction. Callers computing sibling paths for `updateSubpoolRoot` must compute config tree zeros locally using the same `poseidon.compress` zero-chain formula.
- **Deposit withdrawal delay** — set at deploy time and operator-adjustable, defaulting to 0. A non-zero value should be set in production to prevent gaming the aggregation server.
