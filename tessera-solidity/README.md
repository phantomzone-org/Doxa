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
- supports partial calldata batches (`0 < len <= noteBatchSize`) with deterministic on-chain dummy reconstruction

Primary flow:

1. `recordNotesCommitmentTreeUpdate(newRoot, notes, treeProof, inputsProof)` (operator-only)
   - verifies Groth16 proof
   - for bridge-tracked notes: requires each note is still `Pending`
   - for notes not tracked by this bridge: allows them as external/network-native leaves
   - marks tracked notes as `Validated`
   - updates `notesCommitmentRoot`

Proof commitment:

`SHA256(notesCommitmentRoot_old || notesCommitmentRoot_new || noteCommitments_bytes)`

where `noteCommitments_bytes` is the packed concatenation of all 32-byte notes in batch order.
If fewer than `noteBatchSize` notes are provided, the contract deterministically fills the remainder with dummies before hashing.

External note behavior:
- If a note exists in bridge storage, it must be `Pending`.
- If a note does not exist in bridge storage, it is allowed for tree/root progression but does not create/update a deposit record.

## Other Tree Update APIs

These are separate proven root updates gated by different verifiers/circuits:

| Function | Access | Description |
|---|---|---|
| `recordNotesNullifierTreeUpdate(newRoot, leaves, treeProof, inputsProof)` | operator | Updates `notesNullifierRoot` (partial batches allowed; dummies re-derived on-chain) |
| `recordAccountsCommitmentTreeUpdate(newRoot, leaves, treeProof, inputsProof)` | operator | Updates `accountsCommitmentRoot` (partial batches allowed; dummies re-derived on-chain) |
| `recordAccountsNullifierTreeUpdate(newRoot, leaves, treeProof, inputsProof)` | operator | Updates `accountsNullifierRoot` (partial batches allowed; dummies re-derived on-chain) |

## Local Testing

```bash
cd tessera-solidity
forge test
```
