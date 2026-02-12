# pending-deposit (tessera-solidity)

On-chain zk-rollup deposit bridge for the Tessera protocol. The
`DepositsRollupBridge` contract accepts permissionless deposits from users,
records them on-chain, and allows a sequencer to finalize batches via
`finalizeBatch()` with a Groth16 proof that anchors the off-chain Merkle
root update.

## Architecture

```
                         Off-chain (Rust)                          On-chain (Solidity)
 ┌───────────────────────────────────────────────┐   ┌───────────────────────────────────────┐
 │                                               │   │                                       │
 │  Poll DepositPending events                   │   │   deposit(noteCommitment,value,recip) │
 │    -> accumulate commitments (128)            │   │     -> DepositPending event           │
 │                                               │   │     -> stored as Pending              │
 │  CommitmentTree.insert_batch(commitments)     │   │                                       │
 │    -> root_old -> root_new                    │   │   finalizeBatch(newRoot, startIdx,    │
 │                                               │   │                 proof)                │
 │  SHA-256(root_old || root_new || commitments) │   │     -> reads commitments from storage │
 │    -> circuit public inputs                   │   │     -> SHA-256 commitment (matches    │
 │                                               │   │        circuit)                       │
 │  plonky2 -> BN128 -> Groth16 proof            │   │     -> Groth16 verification           │
 │                                               │   │     -> deposits marked Validated      │
 │                                               │   │     -> merkleRoot advanced            │
 └───────────────────────────────────────────────┘   └───────────────────────────────────────┘
```

## Single-Step Batch Finalization

Users call `deposit()` directly on the contract. The sequencer watches for
`DepositPending` events, accumulates 128 commitments off-chain, builds a
Merkle tree proof, generates a Groth16 proof, and finalizes the batch in a
single `finalizeBatch()` call.

| Step | Actor | Description |
|------|-------|-------------|
| 1 | User | Calls `deposit(noteCommitment, value, recipient)`. Contract computes `commitment = sha256(DOMAIN_SEP \|\| noteCommitment \|\| value \|\| recipient)` with MSB clearing, stores the deposit as `Pending`, and emits `DepositPending`. |
| 2 | Sequencer | Polls `DepositPending` events, accumulates 128 commitments, inserts into Merkle tree, generates Groth16 proof. |
| 3 | Sequencer | Calls `finalizeBatch(newRoot, depositStartIndex, proof)`. Contract reads commitments from storage, computes SHA-256 circuit commitment, verifies the Groth16 proof, marks deposits as `Validated`, and advances `merkleRoot`. |

## Cryptographic Pipeline

### Commitment Encoding

Each deposit's commitment is computed as:

```
sha256(DOMAIN_SEP || noteCommitment || value || recipient)
```

where `DOMAIN_SEP = sha256("tessera.pending-deposit.v1")`.

The MSB of each 64-bit chunk is cleared so every chunk fits in the Goldilocks
field (< 2^63 < p). This is an injective mapping on the 252-bit truncated
digest, providing 126-bit collision security.

### SHA-256 Circuit Commitment

The plonky2 circuit commits its public data via SHA-256:

```
SHA256(merkleRoot_old || merkleRoot_new || commitment_0 || ... || commitment_127)
```

The resulting 256-bit digest is split into 8 big-endian uint32 words, which
become the Groth16 public inputs.

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
| `deposit(bytes32 noteCommitment, uint256 value, address recipient)` | permissionless | Record a pending deposit. Returns `depositId`. |
| `finalizeBatch(bytes32 newRoot, uint256 depositStartIndex, Proof proof)` | operator | Verify Groth16 proof and advance Merkle root. |

### Admin Functions

| Function | Access | Description |
|----------|--------|-------------|
| `setOperator(address)` | operator | Transfer operator role. |
| `setPaused(bool)` | operator | Emergency pause/unpause. |

### View Helpers

| Function | Description |
|----------|-------------|
| `getDeposit(uint256 depositId)` | Read a deposit record by ID. |
| `computeCommitment(bytes32 noteCommitment, uint256 value, address recipient)` | Compute the deposit commitment hash. |
| `sha256ToPublicInputs(bytes32 hash)` | Split SHA-256 digest into 8 uint32 public inputs. |

### Types

```solidity
enum DepositStatus { Pending, Validated }

struct Deposit {
    bytes32       commitment;  // sha256(DOMAIN_SEP || noteCommitment || value || recipient) w/ MSB clearing
    uint256       value;       // deposit value
    address       recipient;   // recipient address
    DepositStatus status;
}

struct Proof {
    uint256[8] proof;          // Groth16 A(2), B(4), C(2) in EIP-197 format
    uint256[2] commitments;    // Pedersen commitment G1 point
    uint256[2] commitmentPok;  // Proof of knowledge for commitment
}
```

### State Variables

| Name | Type | Description |
|------|------|-------------|
| `verifier` | `IGroth16Verifier` (immutable) | gnark-generated Groth16 verifier contract |
| `batchSize` | `uint256` (immutable) | Deposits per batch (e.g., 128) |
| `operator` | `address` | Centralized sequencer operator |
| `merkleRoot` | `bytes32` | Current committed Merkle root |
| `nextDepositId` | `uint256` | Monotonic deposit counter |
| `paused` | `bool` | Emergency pause switch |
| `deposits` | `mapping(uint256 => Deposit)` | Deposit records by ID |
| `DOMAIN_SEP` | `bytes32` (constant) | `sha256("tessera.pending-deposit.v1")` |

### Events

| Event | When |
|-------|------|
| `DepositPending(depositId, commitment, value, recipient)` | User deposits |
| `BatchValidated(batchId, newRoot)` | Batch finalized, Merkle root advanced |
| `OperatorChanged(oldOp, newOp)` | Operator role transferred |
| `PausedChanged(isPaused)` | Pause state toggled |

### Custom Errors

| Error | Trigger |
|-------|---------|
| `NotOperator()` | Caller is not the operator |
| `PausedErr()` | Contract is paused |
| `InvalidProof()` | Groth16 verification failed |
| `InsufficientDeposits()` | Not enough pending deposits for a batch |
| `DepositNotPending(depositId)` | Deposit is not in Pending state |

## Source Files

```
tessera-solidity/
├── src/
│   └── pending-deposit/
│       ├── DepositsRollupBridge.sol   # Main contract
│       └── Verifier.sol               # gnark-generated Groth16 verifier (batch_size=128)
├── test/
│   └── pending-deposit/
│       ├── DepositsRollupBridge.t.sol            # 34 unit tests (mock verifiers)
│       └── DepositsRollupBridgeIntegration.t.sol # End-to-end test (real verifier + Rust artifacts)
├── script/
│   └── pending-deposit/
│       └── Deploy.s.sol               # Deployment script for Verifier + Bridge
└── foundry.toml
```

## Testing

### Unit Tests (34 tests)

Use three mock verifiers (accept, reject, check-inputs) to test all contract
logic in isolation:

| Section | Tests | Description |
|---------|-------|-------------|
| Constructor / State | 2 | Initial state, domain separator constant |
| deposit | 5 | Happy path, events, multiple deposits, permissionless access, paused revert |
| computeCommitment | 3 | Determinism, different inputs, MSB clearing verification |
| finalizeBatch | 6 | Happy path, events, access control, insufficient deposits, not pending, invalid proof |
| sha256ToPublicInputs | 3 | Zero, all-ones, known SHA-256 vector |
| Public input derivation | 1 | End-to-end SHA-256 commitment matching with MockVerifierCheckInputs |
| Atomicity | 1 | State unchanged on failed finalization |
| Multi-batch | 2 | Sequential batch IDs, chained finalize flow |
| Admin | 6 | setOperator, setPaused, transfer chain, pause/unpause flow, events |
| View helpers | 3 | getDeposit before and after finalization, pause/unpause cycle |

```bash
forge test --match-contract DepositsRollupBridgeTest -vv
```

### Integration Test

Loads real Groth16 proof artifacts generated by the Rust proof pipeline
and executes a full deposit -> finalize cycle against the real `Verifier` contract.

```bash
forge test --match-contract Integration -vv
```

### Run All Tests

```bash
cd tessera-solidity && forge test
```

## Deployment

```bash
# 1. Start anvil
anvil

# 2. Compute genesis root
export TESSERA_GENESIS_ROOT=$(cargo run -p tessera-server --example genesis_root --release)

# 3. Deploy
cd tessera-solidity
forge script script/pending-deposit/Deploy.s.sol \
  --rpc-url http://localhost:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast
```

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) (forge, cast, anvil)
- Rust toolchain (for `tessera-trees` proof generation)
- Go toolchain (for gnark Groth16 FFI backend)
