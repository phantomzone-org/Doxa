# Code Review

## Findings

### High: Spend finalization is not atomic, so outputs can be lost after inputs are already consumed

File: [tessera-subpool-operator/src/spend_txs.rs](/home/pro7ech/gausslabs/Tessera/tessera-subpool-operator/src/spend_txs.rs#L245)

The operator marks input notes as consumed, marks the spend request approved, and updates the account before it guarantees that all outputs were delivered.

- Inputs are marked consumed at [spend_txs.rs](/home/pro7ech/gausslabs/Tessera/tessera-subpool-operator/src/spend_txs.rs#L245).
- The spend request is marked approved at [spend_txs.rs](/home/pro7ech/gausslabs/Tessera/tessera-subpool-operator/src/spend_txs.rs#L256).
- The account state is updated at [spend_txs.rs](/home/pro7ech/gausslabs/Tessera/tessera-subpool-operator/src/spend_txs.rs#L259).
- Remote output delivery failures are only logged, not retried or surfaced as fatal, at [spend_txs.rs](/home/pro7ech/gausslabs/Tessera/tessera-subpool-operator/src/spend_txs.rs#L312).

Impact:

- A transient sequencer/network failure while forwarding a cross-subpool output can permanently drop that output.
- The sender side still treats the spend as settled, so the lost note is hard to recover.

### High: Deposit processing can leave the account credited but the spendable note missing

File: [tessera-subpool-operator/src/deposits.rs](/home/pro7ech/gausslabs/Tessera/tessera-subpool-operator/src/deposits.rs#L230)

The deposit flow marks the deposit request approved and updates the account before inserting the pending input note.

- Deposit request approved at [deposits.rs](/home/pro7ech/gausslabs/Tessera/tessera-subpool-operator/src/deposits.rs#L230).
- Account updated at [deposits.rs](/home/pro7ech/gausslabs/Tessera/tessera-subpool-operator/src/deposits.rs#L233).
- Pending input note inserted later at [deposits.rs](/home/pro7ech/gausslabs/Tessera/tessera-subpool-operator/src/deposits.rs#L248).

Impact:

- If input-note insertion fails, the recipient AST balance is already incremented.
- The deposit request will no longer retry because it is already approved.
- The user can end up with credited account state but no corresponding spendable note.

### High: Fresh-account processing marks requests approved before the account row exists

File: [tessera-subpool-operator/src/operator.rs](/home/pro7ech/gausslabs/Tessera/tessera-subpool-operator/src/operator.rs#L167)

The fresh-account flow updates `freshacc_requests.status = APPROVED` before inserting the `accounts` row.

- Request approved at [operator.rs](/home/pro7ech/gausslabs/Tessera/tessera-subpool-operator/src/operator.rs#L167).
- Account inserted later at [operator.rs](/home/pro7ech/gausslabs/Tessera/tessera-subpool-operator/src/operator.rs#L185).

Impact:

- If the account insert fails, the request is no longer pending and will not be retried.
- The system records the account as approved even though the local account does not exist.

### Medium: Cross-subpool note relay is at-most-once and can lose notes on receiver-side failures

Files:

- [tessera-subpool-operator/src/spend_txs.rs](/home/pro7ech/gausslabs/Tessera/tessera-subpool-operator/src/spend_txs.rs#L376)
- [tessera-demo/src/sequencer/handlers.rs](/home/pro7ech/gausslabs/Tessera/tessera-demo/src/sequencer/handlers.rs#L281)

The receiver polls forwarded notes via `GET /pending_notes/{subpool_id}`. The demo sequencer removes the queued notes immediately when that endpoint is called.

- Receiver poll starts at [spend_txs.rs](/home/pro7ech/gausslabs/Tessera/tessera-subpool-operator/src/spend_txs.rs#L376).
- Sequencer drains and removes the queue at [handlers.rs](/home/pro7ech/gausslabs/Tessera/tessera-demo/src/sequencer/handlers.rs#L281).

Impact:

- If the receiver crashes or fails after reading the response but before local insertion completes, those forwarded notes are gone from the relay queue.
- There is no ack/retry protocol to recover them.

## Assumptions

- This review is based on the current workspace state, including recent operator, database, and demo sequencer changes.
- Findings are prioritized for correctness, recovery, and data-loss risk rather than style.

## Summary

The main architectural risk in `tessera-subpool-operator` is partial completion across multi-step workflows. Several paths perform an irreversible external or DB-visible state transition before all dependent local writes and downstream deliveries are guaranteed to succeed. The biggest reliability improvement would be to make these workflows idempotent and resumable, or to move approval/settled status transitions to the final successful step.
