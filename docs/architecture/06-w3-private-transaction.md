# W3: Private Transaction (Multi-Tree Fan-Out)

## Overview

A client submits a full private transaction containing input notes (to nullify), output notes (to commit), and account state changes. The sequencer validates the transaction proof and fans out individual leaves to all four independent tree pipelines.

## Sequence Diagram

```mermaid
sequenceDiagram
    participant C as Client
    participant API as Sequencer API
    participant SQ as Sequencer Loop

    C->>API: POST /private-tx<br/>{input_notes[], output_notes[],<br/>input_account, output_account, tx_proof}
    API->>API: validate tx_proof (dummy: 0x01)

    par Fan-out to 4 tree channels
        API->>SQ: notes_nullifier_tx ← each input_note
        API->>SQ: notes_commitment_tx ← each output_note
        API->>SQ: accounts_nullifier_tx ← input_account
        API->>SQ: accounts_commitment_tx ← output_account
    end

    Note over SQ: Each tree processes independently

    SQ->>SQ: Notes Nullifier pipeline<br/>(validate → batch → prove → finalize)
    SQ->>SQ: Notes Commitment pipeline<br/>(validate → batch → prove → finalize)
    SQ->>SQ: Accounts Nullifier pipeline<br/>(validate → batch → prove → finalize)
    SQ->>SQ: Accounts Commitment pipeline<br/>(validate → batch → prove → finalize)

    Note over SQ: Batch priority: NotesCommitment > NotesNullifier<br/>> AccountsCommitment > AccountsNullifier<br/>Only ONE batch in-flight at a time; partial pools flush on timeout with deterministic dummy padding
```

## Request Body

```json
{
  "input_notes": ["0x...", "0x..."],
  "output_notes": ["0x...", "0x..."],
  "input_account_commitment": "0x...",
  "output_account_commitment": "0x...",
  "tx_proof": "0x01",
  "tx_id": "optional-tracking-id"
}
```

## Fan-Out Logic

The handler decomposes a single private TX into individual leaf submissions across 4 channels:

| Field | Channel | Tree | Validation at Sequencer Loop |
|---|---|---|---|
| Each `input_notes[i]` | `notes_nullifier_tx` | Notes Nullifier | Not already in tree; note must be Validated on-chain |
| Each `output_notes[i]` | `notes_commitment_tx` | Notes Commitment | Note must be Pending on-chain |
| `input_account_commitment` | `accounts_nullifier_tx` | Accounts Nullifier | Not already in tree; must exist in commitment tree |
| `output_account_commitment` | `accounts_commitment_tx` | Accounts Commitment | Direct insertion (no on-chain status check) |

## Concurrency

- All 4 channel sends happen in sequence within the handler (not parallel), but the receiving loops process them independently via `tokio::select!`
- Only **one batch** can be in-flight at any time across all trees
- Batch priority determines which tree gets to prove next
- Under high private-TX throughput, accounts trees may starve behind notes trees

## Traceability

| Edge | File | Function |
|---|---|---|
| `POST /private-tx` | `tessera-server/src/sequencer/api.rs` | `private_tx_notes_handler()` |
| `notes_nullifier_tx` send | `tessera-server/src/sequencer/api.rs` | per `input_note` in loop |
| `notes_commitment_tx` send | `tessera-server/src/sequencer/api.rs` | per `output_note` in loop |
| `accounts_nullifier_tx` send | `tessera-server/src/sequencer/api.rs` | single `input_account_commitment` |
| `accounts_commitment_tx` send | `tessera-server/src/sequencer/api.rs` | single `output_account_commitment` |
| Batch priority | `tessera-server/src/sequencer/pipeline.rs` | `maybe_start_next_batch()` |

## Notes

- The `tx_proof` is currently validated by a dummy verifier (accepts `0x01`). This is a Phase A stub.
- The `tx_id` field is optional and used for tracking/logging only.
- Individual leaves from a single private TX may end up in different batches if the trees have different fill levels.
