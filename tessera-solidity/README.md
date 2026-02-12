# pending-deposit (tessera-solidity)

`DepositsRollupBridge` is the on-chain bridge contract for deposit lifecycle management:

- `Available`: deposit was recorded by a trusted source and can be withdrawn or consumed
- `Withdrawn`: deposit was withdrawn by the original depositor
- `Consumed`: deposit was consumed into the private system after proof verification

The contract no longer uses batch finalization (`finalizeBatch`) or a pending-deposit Merkle root.

## Lifecycle

1. Trusted source calls `recordDeposit(...)` -> deposit is stored as `Available`
2. Depositor may call `withdraw(depositId)` -> status becomes `Withdrawn`
3. Operator may call `consume(depositId, newConsumedRoot, proof)` -> status becomes `Consumed`

`withdraw` and `consume` are mutually exclusive because both require `Available`.

## Consume Proof Model

For `consume`, the contract verifies a Groth16 proof with public commitment:

`SHA256(consumedRoot_old || consumedRoot_new || deposit_commitment)`

The SHA-256 digest is split to 8 big-endian `uint32` words and passed as verifier public inputs.

## Core API

| Function | Access | Description |
|---|---|---|
| `recordDeposit(bytes32 noteCommitment, uint256 value, address depositor, address recipient)` | `trustedSource` | Records an `Available` deposit and returns `depositId` |
| `withdraw(uint256 depositId)` | depositor | Marks deposit as `Withdrawn` (only if `Available`) |
| `consume(uint256 depositId, bytes32 newConsumedRoot, Proof proof)` | operator | Verifies proof, marks as `Consumed`, updates `consumedRoot` |

## Admin API

| Function | Access | Description |
|---|---|---|
| `setOperator(address)` | operator | Transfer operator |
| `setTrustedSource(address)` | operator | Update trusted source |
| `setPaused(bool)` | operator | Pause/unpause state-changing calls |

## Contract State

| Variable | Description |
|---|---|
| `verifier` | Groth16 verifier contract |
| `operator` | Sequencer/operator address |
| `trustedSource` | Contract/account authorized to ingest deposits |
| `consumedRoot` | Current consumed/nullifier tree root |
| `nextDepositId` | Monotonic ID for new deposits |
| `deposits` | Deposit records by ID |
| `paused` | Global pause flag |

## Deposit Struct / Status

```solidity
enum DepositStatus { Available, Withdrawn, Consumed }

struct Deposit {
    bytes32       commitment;
    uint256       value;
    address       depositor;
    address       recipient;
    DepositStatus status;
}
```

## Events

- `DepositAvailable(depositId, commitment, depositor, value, recipient)`
- `DepositWithdrawn(depositId, depositor)`
- `DepositConsumed(depositId, oldRoot, newRoot)`
- `OperatorChanged(oldOp, newOp)`
- `TrustedSourceChanged(oldSource, newSource)`
- `PausedChanged(isPaused)`

## Deployment

The deploy script is at `script/pending-deposit/Deploy.s.sol`.

Required env vars:

- `TESSERA_TRUSTED_SOURCE`
- `TESSERA_CONSUMED_GENERIS_ROOT`

Example:

```bash
cd tessera-solidity
export TESSERA_TRUSTED_SOURCE=0xYourTrustedSource
export TESSERA_CONSUMED_GENERIS_ROOT=0x0000000000000000000000000000000000000000000000000000000000000000

forge script script/pending-deposit/Deploy.s.sol \
  --rpc-url http://localhost:8545 \
  --private-key <OPERATOR_PRIVATE_KEY> \
  --broadcast
```

## Testing

```bash
cd tessera-solidity
forge test
```

Current Solidity tests cover the new flow (`recordDeposit`, `withdraw`, `consume`) with mock verifiers.
