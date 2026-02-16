# tessera-solidity

Solidity contracts for Tessera's pending-deposit bridge and ZK-verified tree updates.

The main contract is `DepositsRollupBridge` in `src/TesseraRollup.sol`.

## Roles

- `operator`
  - can update config (`setOperator`, `setTrustedSource`, `setPaused`)
  - is the only address allowed to verify and load proofs on-chain
- `trustedSource`
  - can create deposits on behalf of users via `depositAndRegisterFor`
  - typically an adapter contract that improves UX (e.g., permit flows)

## Deposit Lifecycle

Each deposit is keyed by a unique `noteCommitment` (`bytes32`) and has a status:

- `Pending`: escrowed and can be validated or withdrawn
- `Validated`: included in a finalized validation batch
- `Withdrawn`: withdrawn by recipient while pending

## Core Deposit API

| Function | Access | Purpose |
|---|---|---|
| `depositAndRegister(note, maxAmount)` | anyone | Pull ERC20 via `transferFrom`, store `Pending` deposit |
| `depositAndRegisterFor(note, payer, maxAmount)` | `trustedSource` | Delegated deposit creation for `payer` |
| `withdrawPendingDeposit(note)` | recipient | Withdraw escrow while still `Pending` |

Notes:
- `noteCommitment` is one-time-use: duplicates revert.
- The stored deposit `value` is measured by in-call balance delta, not `maxAmount`.

## Deposit Validation (Two-Phase, Recommended)

Validation is an append-style proven transition that:
- marks each note in the batch as `Validated`
- advances `notesCommitmentRoot`

Two-phase flow:

1. `loadValidateDepositBatch(newRoot, notes, proof)` (operator-only)
   - verifies Groth16 proof
   - stores a loaded batch keyed by `actionHash`
   - does not change deposits or `notesCommitmentRoot`

2. `executeValidateDepositBatch(newRoot, notes)` (permissionless)
   - requires a matching loaded batch for the current `notesCommitmentRoot`
   - for bridge-tracked notes: re-checks each note is still `Pending` (users may withdraw after load)
   - for notes not tracked by this bridge: allows them as external/network-native leaves
   - applies state changes for tracked deposits and deletes the loaded entry

Why two phases:
- better liveness: if the operator loads a batch and goes offline, anyone can still execute it
- safer retries: loading can be retried; execution is protected by the on-chain keying

Proof commitment:

`SHA256(notesCommitmentRoot_old || notesCommitmentRoot_new || noteCommitments_bytes)`

where `noteCommitments_bytes` is the packed concatenation of all 32-byte notes in batch order.

## Legacy Single-Phase Validation

`validateDepositBatch(newRoot, notes, proof)` (operator-only) verifies and applies in one transaction.

It is kept for compatibility and tests, but the two-phase flow is preferred operationally.

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
