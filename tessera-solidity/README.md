# pending-deposit (tessera-solidity)

`DepositsRollupBridge` is the on-chain bridge for note deposits consumed into Tessera.

Current lifecycle:
- `Available`: note was recorded and can be consumed
- `Consumed`: note was included in a finalized consume batch

There is no on-chain consume-request queue anymore. Consume requests are pushed to the sequencer API.

## Current Bridge Model

- Deposits are keyed by `noteCommitment`:
  - `mapping(bytes32 => Deposit) deposits`
  - `mapping(bytes32 => bool) noteExists`
- Deposit value is inferred from ERC20 balance delta on the bridge:
  - `value = balanceOf(bridge) - lastMonitoredBalance`
- `recordDeposit(bytes32)` is callable only by `trustedSource`
- Batch consumption is finalized by operator through:
  - `finalizeConsumeBatch(bytes32 newConsumedRoot, bytes32[] noteCommitments, Proof proof)`

## Core API

| Function | Access | Description |
|---|---|---|
| `recordDeposit(bytes32 noteCommitment)` | `trustedSource` | Records `Available` deposit with balance-delta value |
| `finalizeConsumeBatch(bytes32 newConsumedRoot, bytes32[] noteCommitments, Proof proof)` | `operator` | Verifies proof, marks notes `Consumed`, updates `consumedRoot` |
| `getDeposit(bytes32 noteCommitment)` | view | Returns deposit data |
| `getDepositStatus(bytes32 noteCommitment)` | view | Returns note status |

## Admin API

| Function | Access | Description |
|---|---|---|
| `setOperator(address)` | operator | Transfer operator role |
| `setTrustedSource(address)` | operator | Update trusted source |
| `setPaused(bool)` | operator | Pause/unpause state-changing operations |

## Deposit Types

```solidity
enum DepositStatus { Available, Consumed }

struct Deposit {
    uint256 value;
    address recipient;
    DepositStatus status;
}
```

## Events

- `DepositAvailable(noteCommitment, value, recipient)`
- `DepositConsumed(noteCommitment)`
- `ConsumeBatchFinalized(batchSize, oldRoot, newRoot)`
- `OperatorChanged(oldOp, newOp)`
- `TrustedSourceChanged(oldSource, newSource)`
- `PausedChanged(isPaused)`

## Consume Proof Commitment

`finalizeConsumeBatch` verifies a Groth16 proof whose public commitment is:

`SHA256(consumedRoot_old || consumedRoot_new || noteCommitments_bytes)`

where `noteCommitments_bytes` is the packed concatenation of all 32-byte notes in batch order.

## Deployment

Deploy script: `script/pending-deposit/Deploy.s.sol`

Required env vars:
- `TESSERA_TRUSTED_SOURCE`
- `TESSERA_CONSUMED_GENERIS_ROOT`
- `TESSERA_CONSUME_BATCH_SIZE`
- `TESSERA_MONITORED_TOKEN`

Example:

```bash
cd tessera-solidity
export TESSERA_TRUSTED_SOURCE=0xYourTrustedSource
export TESSERA_CONSUMED_GENERIS_ROOT=0x0000000000000000000000000000000000000000000000000000000000000000
export TESSERA_CONSUME_BATCH_SIZE=128
export TESSERA_MONITORED_TOKEN=0xYourERC20

forge script script/pending-deposit/Deploy.s.sol \
  --rpc-url http://localhost:8545 \
  --private-key <OPERATOR_PRIVATE_KEY> \
  --broadcast
```

## Local Testing Contracts

- `ToyUSDT.sol`: toy ERC20 for local balance-delta deposit testing
- `ToyTrustedSource.sol`: helper that atomically:
  1. pulls tokens from user into bridge (`transferFrom`)
  2. calls `bridge.recordDeposit(noteCommitment)`

## Testing

```bash
cd tessera-solidity
forge test
```
