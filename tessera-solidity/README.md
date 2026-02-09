# tessera-solidity

On-chain zk-rollup batch finalizer for the Tessera protocol. The
`DepositsRollupBridge` contract accepts batches of deposit data, verifies
Groth16 proofs of Merkle-tree state transitions, and advances the committed
state root.

## Architecture

```
                         Off-chain (Rust)                          On-chain (Solidity)
 ┌──────────────────────────────────────────────┐   ┌──────────────────────────────────────┐
 │                                              │   │                                      │
 │  PendingDeposit ──Poseidon──▶ leaf (Hash)    │   │         submitBatch(...)              │
 │            │                       │         │   │    ┌─────────────────────────┐        │
 │            │            CommitmentTree.insert │   │    │  Pending pool           │        │
 │            │              ▼                   │   │    │  (deposits + leaves     │        │
 │         root_old ──▶ root_new                │   │    │   + roots + sha256)     │        │
 │            │              │                   │   │    └────────────┬────────────┘        │
 │            ▼              ▼                   │   │                 │                     │
 │    SHA-256(root_old ‖ root_new ‖ leaves)     │   │         finalizeBatch(...)            │
 │            │                                  │   │                 │                     │
 │            ▼                                  │   │    Groth16 proof verification         │
 │    plonky2 circuit (proves SHA-256 preimage) │   │    via Verifier128 contract           │
 │            │                                  │   │                 │                     │
 │            ▼                                  │   │    ┌────────────▼────────────┐        │
 │    BN128 wrapper ──▶ Groth16 proof           │───│──▶ │  Validated pool          │        │
 │                                              │   │    │  stateRoot updated       │        │
 │    Artifacts: proof_solidity.json            │   │    │  batchNumber incremented  │        │
 │              bridge_calldata.json            │   │    └─────────────────────────┘        │
 └──────────────────────────────────────────────┘   └──────────────────────────────────────┘
```

## Two-Phase Batch Lifecycle

Each batch progresses through a two-phase lifecycle:

| Phase | Function | Status | Description |
|-------|----------|--------|-------------|
| 1 | `submitBatch` | `Pending` | Operator submits deposit data, pre-hashed leaves, and proposed new root. Contract computes SHA-256 commitment and stores everything. |
| 2 | `finalizeBatch` | `Validated` | Operator provides a Groth16 proof. Contract derives public inputs from the stored SHA-256 commitment, verifies the proof on-chain, and advances the state root. |

A pending batch can also be **cancelled** via `cancelPendingBatch` (e.g. if it
becomes stale after another batch is finalized first).

## Cryptographic Pipeline

The system chains three hash functions, each serving a distinct role:

```
  Poseidon (off-chain)        SHA-256 (circuit + on-chain)      keccak256 (on-chain only)
  ─────────────────────       ──────────────────────────────     ─────────────────────────
  deposit → leaf hash         commit = SHA-256(                  domainCommit = keccak256(
  (Merkle tree internal         root_old ‖ root_new ‖              chainid,
   hash function)                leaf_0 ‖ … ‖ leaf_127             address(this),
                               )                                    PROTOCOL_VERSION,
  Not available as EVM        Binds circuit public inputs           sha256Commit
  precompile → leaves         to the state transition.            )
  must be pre-computed        Verifiable on-chain via the         Storage key. Prevents
  off-chain and passed        SHA-256 precompile (0x02).          cross-chain / cross-
  to submitBatch.                                                  contract replay.
```

### Why three hashes?

- **Poseidon** is efficient inside arithmetic circuits (plonky2) but has no EVM
  precompile. The contract cannot derive leaves from deposits on-chain, so
  `submitBatch` accepts both raw deposits (for data availability) and
  pre-hashed leaves (for the SHA-256 commitment).

- **SHA-256** is both circuit-friendly (via a plonky2 gadget) and available as
  an EVM precompile. It binds the Groth16 public inputs to the state
  transition: `SHA-256(root_old || root_new || leaves)`. The 256-bit digest is
  split into 8 big-endian uint32 words for the verifier.

- **keccak256** provides domain separation for the storage key. It is cheap
  on-chain and wraps the SHA-256 commitment with chain-specific context.

## Data Encoding

### Goldilocks Field Elements

All field elements use the Goldilocks prime field (p = 2^64 - 2^32 + 1).
On-chain they are encoded as **8-byte big-endian uint64** values.

### Merkle Roots

A root is 4 Goldilocks elements packed into `bytes32`:

```
bytes[0..8]   = f[0] big-endian uint64
bytes[8..16]  = f[1] big-endian uint64
bytes[16..24] = f[2] big-endian uint64
bytes[24..32] = f[3] big-endian uint64
```

### Leaves

Each leaf is a Poseidon hash of a deposit (4 field elements = 32 bytes).
The `leaves` parameter to `submitBatch` is `BATCH_SIZE * 4 * 8 = 4096 bytes`.

### Groth16 Public Inputs

The SHA-256 digest is split into 8 big-endian uint32 words, each
zero-extended to uint256:

```
inputs[0] = (sha256_digest >> 224) & 0xFFFFFFFF   // most-significant
inputs[7] = sha256_digest & 0xFFFFFFFF             // least-significant
```

## Contract API

### Core Functions

| Function | Access | Description |
|----------|--------|-------------|
| `submitBatch(bytes32 newRoot, Deposit[] deposits, bytes leaves)` | operator | Submit a batch. Returns the domain-separated `commit` key. |
| `finalizeBatch(bytes32 commit, Proof proof)` | operator | Verify Groth16 proof and advance state. |
| `cancelPendingBatch(bytes32 commit)` | operator | Delete a pending batch. |

### Admin Functions

| Function | Access | Description |
|----------|--------|-------------|
| `setOperator(address)` | operator | Transfer operator role. |
| `setPaused(bool)` | operator | Emergency pause/unpause. |

### View Helpers

| Function | Description |
|----------|-------------|
| `getBatch(bytes32 commit)` | Read batch metadata (roots, status, deposits count). |
| `getBatchDeposit(bytes32 commit, uint256 index)` | Read a single deposit from a batch. |
| `sha256ToPublicInputs(bytes32 hash)` | Split SHA-256 digest into 8 uint32 public inputs. |
| `computeSha256Commitment(bytes32 oldRoot, bytes32 newRoot, bytes leaves)` | Compute the circuit-matching SHA-256 commitment. |
| `computeDomainCommitment(bytes32 sha256Commit)` | Compute the domain-separated storage key. |

### Types

```solidity
struct Deposit {
    bytes32 noteCommitment;  // Hash = [F;4] packed as 4x8-byte big-endian
    uint64  addr0;           // address[0] as Goldilocks element
    uint64  addr1;           // address[1]
    uint64  addr2;           // address[2]
    uint64  amount;          // amount as Goldilocks element
}

enum BatchStatus { None, Pending, Validated }

struct Batch {
    bytes32     oldRoot;
    bytes32     newRoot;
    bytes32     sha256Commit;
    uint64      blockNumber;
    BatchStatus status;
    Deposit[]   deposits;
}

struct Proof {
    uint256[8] proof;          // Groth16 A(2), B(4), C(2) in EIP-197 format
    uint256[2] commitments;    // Pedersen commitment G1 point
    uint256[2] commitmentPok;  // Proof of knowledge for commitment
}
```

### Constants

| Name | Value | Description |
|------|-------|-------------|
| `BATCH_SIZE` | 128 | Deposits per batch |
| `HASH_SIZE` | 4 | Goldilocks elements per hash |
| `FIELD_ELEMENT_BYTES` | 8 | Bytes per Goldilocks element |
| `LEAVES_BYTE_LEN` | 4096 | Expected `leaves` byte length (128 * 4 * 8) |
| `PROTOCOL_VERSION` | 1 | Domain separation version tag |

### Events

| Event | When |
|-------|------|
| `BatchSubmitted(commit, sha256Commit, oldRoot, newRoot, deposits, leaves)` | Batch enters pending pool |
| `BatchFinalized(commit, oldRoot, newRoot, batchNumber)` | Batch validated, state advanced |
| `BatchCancelled(commit)` | Pending batch deleted |
| `OperatorChanged(oldOp, newOp)` | Operator role transferred |
| `PausedChanged(isPaused)` | Pause state toggled |

### Custom Errors

| Error | Trigger |
|-------|---------|
| `NotOperator()` | Caller is not the operator |
| `PausedErr()` | Contract is paused |
| `InvalidDepositsLength()` | `deposits.length != 128` |
| `InvalidLeavesLength()` | `leaves.length != 4096` |
| `BatchAlreadyExists(commit)` | Commit key already in use |
| `BatchNotPending(commit)` | Batch is not in Pending state |
| `StaleRoot(current, expected)` | Batch's `oldRoot` does not match current `stateRoot` |
| `InvalidProof()` | Groth16 verification failed |

## Source Files

```
tessera-solidity/
├── src/
│   ├── DepositsRollupBridge.sol   # Main contract
│   └── Verifier128.sol            # gnark-generated Groth16 verifier (batch_size=128)
├── test/
│   ├── DepositsRollupBridge.t.sol            # 40 unit tests (mock verifiers)
│   └── DepositsRollupBridgeIntegration.t.sol # End-to-end test (real verifier + Rust artifacts)
└── foundry.toml
```

## Testing

### Unit Tests (40 tests)

Use three mock verifiers (accept, reject, check-inputs) to test all contract
logic in isolation:

| Section | Tests | Description |
|---------|-------|-------------|
| Constructor / State | 2 | Initial state, constants |
| submitBatch | 9 | Happy path, events, access control, input validation, duplicate prevention |
| finalizeBatch | 7 | Happy path, events, access control, stale root, invalid proof, public input derivation |
| cancelPendingBatch | 4 | Happy path, access control, not-pending, already-validated |
| Domain separation | 1 | Different chain ID produces different commit |
| sha256ToPublicInputs | 3 | Zero, all-ones, known SHA-256 vector |
| Atomicity | 1 | State unchanged on failed finalization |
| Multi-batch | 1 | Chained submit-finalize-submit-finalize |
| Stale batch | 1 | Cancel stale batch after another is finalized |
| Admin | 8 | setOperator, setPaused, transfer chain, pause/unpause flow |
| View helpers | 1 | computeSha256Commitment |

```bash
forge test --match-contract DepositsRollupBridgeTest -vv
```

### Integration Test (1 test)

Loads real Groth16 proof artifacts generated by the Rust `groth16_wrapper`
example and executes a full `submitBatch` -> `finalizeBatch` cycle against the
real `Verifier128` contract.

```bash
forge test --match-contract Integration -vv
```

### Run All Tests

```bash
cd tessera-solidity && forge test
```

## End-to-End Pipeline

The full pipeline from deposit generation to on-chain verification:

### 1. Generate Proof Artifacts (Rust)

```bash
cd tessera-trees
cargo run --example groth16_wrapper --release
```

This produces two JSON files in `examples/tmp/groth-artifacts/`:

- **`proof_solidity.json`** -- Groth16 proof formatted for the Solidity
  verifier: `{ proof: uint256[8], commitments: uint256[2], commitmentPok: uint256[2] }`

- **`bridge_calldata.json`** -- State transition data for the bridge contract:
  `{ oldRoot, newRoot, leaves, deposits[] }`

The Rust example performs the following steps:

1. Generate 128 random deposits (`noteCommitment`, `address[3]`, `amount`)
2. Hash each deposit via Poseidon to derive its Merkle leaf
3. Insert all leaves into a depth-32 `CommitmentTree`
4. Build a plonky2 circuit proving the batch insertion with SHA-256 commitment
5. Prove the circuit (native Goldilocks field)
6. Wrap the proof into a BN128-friendly format
7. Generate a Groth16 proof via gnark (Go FFI)
8. Export proof and bridge calldata as JSON

### 2. Run On-Chain Verification (Solidity)

```bash
cd tessera-solidity
forge test --match-contract Integration -vv
```

The integration test:

1. Loads `proof_solidity.json` and `bridge_calldata.json`
2. Deploys `Verifier128` and `DepositsRollupBridge` with the genesis root
3. Calls `submitBatch` with the new root, deposits, and leaves
4. Calls `finalizeBatch` with the Groth16 proof
5. Asserts that `stateRoot` advanced and the batch is `Validated`

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) (forge, cast, anvil)
- Rust toolchain (for `tessera-trees` proof generation)
- Go toolchain (for gnark Groth16 FFI backend)
