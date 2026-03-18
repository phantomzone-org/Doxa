# Server Pipeline

Source: `tessera-server/src/`

---

## Purpose

The server is the operator node. It exposes an HTTP API for clients, accumulates private transactions and deposits into fixed-size batches, submits those batches to the contract (phase 1), dispatches proving work to the prover (possibly remote), and finalises each batch on-chain once a Groth16 proof is returned (phase 2).

---

## Module Map

| Module | Role |
|--------|------|
| `sequencer/mod.rs` | Core state: confirmed root, pending batches, batch builders |
| `sequencer/api.rs` | HTTP handlers — validates client submissions |
| `sequencer/batch.rs` | Slot types, `BatchBuilder`, `FinalizedBatch` |
| `sequencer/pipeline.rs` | `flush_batch`, `handle_prove_outcome` — on-chain interactions |
| `sequencer/recovery.rs` | Restart-safe recovery of in-flight batches |
| `contract.rs` | Ethers bindings: type conversion & on-chain calls |
| `prover_v2.rs` | Local `ProverRuntimeV2`; HTTP relay for remote provers |

---

## Sequencer State

```rust
confirmed_root: HashOutput           // current on-chain IMT root
confirmed_root_history: Set<HashOutput> // all ever-confirmed roots (replay guard)
pending_batches: Map<BatchId, TxBatchV2> // submitted but not yet proven
batch_builder: BatchBuilder          // accumulates TX slots
consume_batch_builder: BatchBuilder  // accumulates deposit slots
next_batch_id: u64                   // monotonic local counter
```

The `confirmed_root` is fetched from the contract at startup and updated on each successful `proveTransactionBatch` / `proveDepositBatch`.

---

## HTTP API

### `POST /private-tx` — Submit a private transaction

Client sends:
```json
{
  "tx_proof": "<base64-encoded PrivTx plonky2 proof>",
  "tx_id": "<optional idempotency key>"
}
```

Handler (`api.rs`):
1. Deserialises and verifies `tx_proof` against the inner PrivTx circuit verifier (85 PI elements; checks `not_fake_tx = 1`).
2. Extracts the four tree-leaf fields from the proof's public inputs using the PI layout from [`priv-tx-circuit.md`](priv-tx-circuit.md):
   - `AN` → `PI[5..9]`
   - `AC` → `PI[9..13]`
   - `NN[0..8]` → `PI[13..45]`
   - `NC[0..8]` → `PI[45..77]`
3. Checks the `AN` and each `NN[i]` against the local nullifier cache; rejects duplicates.
4. Appends a `BatchSlot::PrivateTx` to `batch_builder`.

### `POST /notes/commitment` — Deposit entry point

Client sends:
```json
{
  "note_commitment": "<hex bytes32>",
  "amount": "<uint256>",
  "depositor": "<address>"
}
```

Handler:
1. Calls `depositAndRegister(noteCommitment, amount)` on-chain (pulls ERC20 from depositor).
2. On success, appends a `BatchSlot::Deposit` with the note commitment to `consume_batch_builder`.

---

## Batch Slots

```rust
enum BatchSlot {
    PrivateTx {
        ac:    HashOutput,         // AccOut commitment
        an:    HashOutput,         // AccIn nullifier
        nc:    [HashOutput; 8],    // output note commitments
        nn:    [HashOutput; 8],    // input note nullifiers
        proof: Vec<u8>,            // raw PrivTx proof bytes
    },
    Deposit {
        nc:    [HashOutput; 8],    // note commitments (trailing slots may be dummy)
        // AC / AN / NN are dummies (not_fake_tx = 0)
    },
    Empty,                         // pure padding
}
```

A batch holds `account_batch_size` slots (default 16). Each slot contributes 8 NC and 8 NN leaves, giving 128 leaves per batch.

---

## Batch Formation (`BatchBuilder`)

The `BatchBuilder` fills slots in arrival order and finalises either when full or on a configurable timeout (≈ 5 s).

`BatchBuilder::finalize() → FinalizedBatch`:

```
FinalizedBatch {
    ac_leaves:        [HashOutput; BATCH_SIZE],     // arrival order
    an_leaves:        [HashOutput; BATCH_SIZE],     // arrival order
    an_sorted:        [HashOutput; BATCH_SIZE],     // sorted for cross-slot dedup
    an_permutation:   [usize; BATCH_SIZE],          // arrival → sorted index map
    nc_leaves:        [HashOutput; 128],            // arrival order (8 per slot)
    nn_leaves:        [HashOutput; 128],            // arrival order
    nn_sorted:        [HashOutput; 128],            // sorted for on-chain nullifier check
    nn_permutation:   [usize; 128],
    batch_poseidon_root: HashOutput,                // Poseidon(nc_leaves[0..128])
    tx_proofs:        HashMap<usize, Vec<u8>>,      // slot_idx → proof bytes (real TX only)
}
```

Dummy and deposit slots contribute zero hashes for their AN, or the actual NC notes for deposit slots. Sorting is applied to the NN array so the contract can check nullifier absence efficiently.

---

## Pipeline

### Phase 1 — On-Chain Submission

`flush_batch()` in `pipeline.rs`:

```
finalized = batch_builder.finalize()

batch = TransactionBatch {
    acRoot:            confirmed_root,
    ncRoot:            confirmed_root,
    mainPoolConfigRoot: chain(poolConfigRoot),
    batchPoseidonRoot: finalized.batch_poseidon_root,
    accountCommitment: finalized.ac_leaves[0],
    accountNullifier:  finalized.an_sorted[0],
    noteCommitments:   finalized.nc_leaves (LE-packed),
    noteNullifiers:    finalized.nn_sorted (LE-packed),
}

receipt = rollup.submitTransactionBatch(batch)
pi_commitment = extract(receipt, TransactionBatchSubmitted.piCommitment)

batch_id = next_batch_id++
pending_batches[batch_id] = TxBatchV2 { pi_commitment, nn_sorted, batch_poseidon_root }
```

### Phase 2 — Prove Dispatch

After submission the server sends a `ProveRequestV2` to the prover (local or remote HTTP):

```rust
ProveRequestV2 {
    batch_id:          BatchId,
    nc_leaves:         [HashOutput; 128],
    ac_root:           HashOutput,       // = confirmed_root at submit time
    nc_root:           HashOutput,       // = confirmed_root at submit time
    main_pool_cfg_root: HashOutput,
    tx_proofs_by_slot: HashMap<usize, Vec<u8>>,
}
```

### Phase 3 — Proof Reception & Finalisation

`handle_prove_outcome(ProveOutcomeV2::Success { ... })` in `pipeline.rs`:

```
rollup.proveTransactionBatch(pi_commitment, solidity_proof)
→ contract verifies Groth16, locks nullifiers, appends batchPoseidonRoot

new_root = extract(receipt, TransactionBatchProven.newTreeRoot)
confirmed_root = new_root
confirmed_root_history.insert(new_root)
pending_batches.remove(batch_id)
```

On failure (`ProveOutcomeV2::Failure`) the server logs the error and may re-enqueue or alert.

---

## Deposit Batch Pipeline

Mirrors the TX batch pipeline with `consume_batch_builder`:

```
submitDepositBatch(batch) → pi_commitment   [operator-only]
ConsumeProveRequest → prover
proveDepositBatch(pi_commitment, proof)     [permissionless]
→ deposits marked Validated
→ IMT root updated
```

---

## Field Encoding (`contract.rs`)

Goldilocks `HashOutput` ↔ Solidity `uint256` (little-endian across four 64-bit limbs):

```rust
// HashOutput → U256
fn hash_to_u256(h: HashOutput) -> U256 {
    U256::from(h[0]) | (U256::from(h[1]) << 64) | (U256::from(h[2]) << 128) | (U256::from(h[3]) << 192)
}
```

Each limb is validated to be < Goldilocks prime (`0xFFFFFFFF00000001`).

`HashOutput` ↔ `bytes32`: the four u64 limbs are written big-endian (8 bytes each).

---

## Recovery (`recovery.rs`)

On startup the server re-reads `pending_batches` (persisted to disk or re-derived from contract events) and re-dispatches any batch that was submitted but never proven. This ensures exactly-once delivery even across crashes.

---

## Key Constants

| Constant | Value | Source |
|----------|-------|--------|
| `ACCOUNT_BATCH_SIZE` | 16 | `sequencer/mod.rs` |
| `NOTE_BATCH` | 8 | `tessera-client/src/lib.rs` |
| Total NC leaves per batch | 128 (= 16 × 8) | derived |
| Batch flush timeout | ≈ 5 s | `sequencer/batch.rs` |
| `TX_LEAF_PI_SIZE` | 77 | `tessera-trees/src/proof_aggregation/super_aggregator_v2.rs` |
| `IS_REAL_OFFSET` | 4 | same |
| `TX_DATA_OFFSET` | 5 | same |
