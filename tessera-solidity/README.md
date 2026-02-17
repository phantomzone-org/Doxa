# tessera-solidity

Solidity contracts for Tessera's pending-deposit bridge and ZK-verified tree updates.

The main contract is `DepositsRollupBridge` in `src/TesseraRollup.sol`.

## Roles

- `operator`
  - can update config (`setOperator`, `setPaused`)
  - is the only address allowed to verify and record proofs on-chain

## Deposit Lifecycle

Each deposit is keyed by a unique `noteCommitment` (`bytes32`) and has a status:

- `Pending`: escrowed and can be validated or withdrawn
- `Validated`: included in a finalized validation batch
- `Withdrawn`: withdrawn by recipient while pending

## Core Deposit API

| Function | Access | Purpose |
|---|---|---|
| `depositAndRegister(note, maxAmount)` | anyone | Pull ERC20 via `transferFrom`, store `Pending` deposit |
| `depositAndRegisterFor(note, payer, maxAmount)` | anyone | Delegated deposit creation for `payer` (requires payer allowance to bridge) |
| `withdrawPendingDeposit(note)` | recipient | Withdraw escrow while still `Pending` |

Notes:
- `noteCommitment` is one-time-use: duplicates revert.
- The stored deposit `value` is measured by in-call balance delta, not `maxAmount`.

## Deposit Validation (Single-Phase, Recommended)

Validation is an append-style proven transition that:
- marks each note in the batch as `Validated`
- advances `notesCommitmentRoot`

Primary flow:

1. `recordNotesCommitmentTreeUpdate(newRoot, notes, proof)` (operator-only)
   - verifies Groth16 proof
   - for bridge-tracked notes: requires each note is still `Pending`
   - for notes not tracked by this bridge: allows them as external/network-native leaves
   - marks tracked notes as `Validated`
   - updates `notesCommitmentRoot`

Proof commitment:

`SHA256(notesCommitmentRoot_old || notesCommitmentRoot_new || noteCommitments_bytes)`

where `noteCommitments_bytes` is the packed concatenation of all 32-byte notes in batch order.

## Legacy Validation APIs

The following APIs remain available for compatibility and tests:
- `validateDepositBatch(newRoot, notes, proof)` (legacy single-phase with aggregated-input placeholder)

External note behavior:
- If a note exists in bridge storage, it must be `Pending`.
- If a note does not exist in bridge storage, it is allowed for tree/root progression but does not create/update a deposit record.

## Other Tree Update APIs

These are separate proven root updates gated by different verifiers/circuits:

| Function | Access | Description |
|---|---|---|
| `recordNotesNullifierTreeUpdate(newRoot, leaves, proof)` | operator | Updates `notesNullifierRoot` |
| `recordAccountsCommitmentTreeUpdate(newRoot, leaves, proof)` | operator | Updates `accountsCommitmentRoot` |
| `recordAccountsNullifierTreeUpdate(newRoot, leaves, proof)` | operator | Updates `accountsNullifierRoot` |

## Local Testing

```bash
cd tessera-solidity
forge test
```
