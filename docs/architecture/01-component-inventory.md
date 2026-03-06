# Component Inventory

| Component | Type | Entry Points | Interfaces | Depends On | Source Files |
|---|---|---|---|---|---|
| **Sequencer** | Long-running server | `src/bin/sequencer.rs` → `main()` | HTTP API (axum) on `:8081` | Prover, Bridge Contract, RPC Node | `tessera-server/src/sequencer/mod.rs`, `tessera-server/src/sequencer/api.rs`, `tessera-server/src/sequencer/pipeline.rs`, `tessera-server/src/sequencer/recovery.rs` |
| **Prover** | Long-running server | `src/bin/prover.rs` → `main()` | HTTP API (axum) on `:8091`, `POST /prove` | tessera-trees, gnark FFI | `tessera-server/src/prover.rs`, `tessera-server/src/bin/prover.rs` |
| **DepositsRollupBridge** | Solidity smart contract | Constructor (deployment) | `registerTransactionBatchUpdate()`, `confirmTreeUpdate()`, 4x `recordTree*Update()`, `depositAndRegister()`, `withdrawPendingDeposit()` | VerifierNotesCommitment, VerifierNotesNullifier, VerifierAccountsCommitment, VerifierAccountsNullifier, VerifierAggregator, ERC20 Token | `tessera-solidity/src/TesseraRollup.sol` |
| **VerifierNotesCommitment** | Solidity smart contract | — | `verifyProof()` (IGroth16Verifier) | — | `tessera-solidity/src/VerifierNotesCommitment.sol` |
| **VerifierNotesNullifier** | Solidity smart contract | — | `verifyProof()` (IGroth16Verifier) | — | `tessera-solidity/src/VerifierNotesNullifier.sol` |
| **VerifierAccountsCommitment** | Solidity smart contract | — | `verifyProof()` (IGroth16Verifier) | — | `tessera-solidity/src/VerifierAccountsCommitment.sol` |
| **VerifierAccountsNullifier** | Solidity smart contract | — | `verifyProof()` (IGroth16Verifier) | — | `tessera-solidity/src/VerifierAccountsNullifier.sol` |
| **DummyVerifier** | Solidity smart contract (dev) | — | `verifyProof()` (IGroth16Verifier) | — | `tessera-solidity/src/DummyVerifier.sol` |
| **ToyUser** | Solidity adapter (dev) | — | `depositAndRecord()`, `depositAndRecordWithPermit()` | Bridge, ERC20 Token | `tessera-solidity/src/ToyUser.sol` |
| **ToyUSDT** | ERC20 token (dev) | — | Standard ERC20 + `mint()` + EIP-2612 `permit()` | — | `tessera-solidity/src/ToyUSDT.sol` |
| **tessera-trees** | Rust library | `lib.rs` | `CommitmentTree`, `NullifierTree`, `Groth16Wrapper`, `BN128Wrapper` | plonky2, gnark (Go FFI) | `tessera-trees/src/tree/`, `tessera-trees/src/groth/` |
| **TreeStore** | Persistence layer | — | `load_or_init()`, `commit_batch()`, `replay_wal()`, `force_checkpoint()` | Filesystem (WAL + Snapshots) | `tessera-server/src/tree_store/mod.rs` |

## Sequencer API Endpoints

All routes are `POST`:

| Route | Handler | Body | Channel | Description |
|---|---|---|---|---|
| `/consume-request`, `/notes/commitment` | `consume_request_handler()` | `{ note_commitment, input_proof }` | `notes_commitment_tx` | Submit a note for deposit-only commitment tree inclusion |
| `/private-tx`, `/private-tx/notes` | `private_tx_notes_handler()` | `{ input_notes[], output_notes[], input_account_commitment, output_account_commitment, tx_proof, tx_id }` | `private_tx_tx` | Submit a full private transaction via optimistic two-phase register+confirm |
| `/notes/nullifier` | `notes_nullifier_handler()` | `{ leaf }` | `notes_nullifier_tx` | Submit a nullifier leaf |
| `/accounts/commitment` | `accounts_commitment_handler()` | `{ leaf }` | `accounts_commitment_tx` | Submit an account commitment leaf |
| `/accounts/nullifier` | `accounts_nullifier_handler()` | `{ leaf }` | `accounts_nullifier_tx` | Submit an account nullifier leaf |

## Prover API Endpoints

| Route | Handler | Body | Response | Description |
|---|---|---|---|---|
| `POST /prove` | `prove_handler()` | `ProveRequest` (Commitment or Nullifier) | `ProveOutcome` (Success or Failure) | Generate a Groth16 proof |

## Configuration (Environment Variables)

### Sequencer

| Variable | Default | Description |
|---|---|---|
| `TESSERA_RPC_URL` | *required* | Ethereum JSON-RPC endpoint |
| `TESSERA_OPERATOR_KEY` | *required* | Operator private key (hex) |
| `TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS` | *required* | Bridge contract address |
| `TESSERA_CHAIN_ID` | *required* | Chain ID |
| `TESSERA_NOTES_COMMITMENT_ARTIFACTS_PATH` | *required* | Path to notes-commitment tree prover artifacts |
| `TESSERA_ACCOUNTS_COMMITMENT_ARTIFACTS_PATH` | *required* | Path to accounts-commitment tree prover artifacts |
| `TESSERA_NOTES_NULLIFIER_ARTIFACTS_PATH` | *required* | Path to notes-nullifier tree prover artifacts |
| `TESSERA_ACCOUNTS_NULLIFIER_ARTIFACTS_PATH` | *required* | Path to accounts-nullifier tree prover artifacts |
| `TESSERA_POLL_INTERVAL_SECS` | `12` | On-chain polling interval |
| `TESSERA_BATCH_TIMEOUT_SECS` | `12` | Max wait before flushing a partial batch (sequencer pads with deterministic dummies) |
| `TESSERA_SEQUENCER_API_ADDR` | `127.0.0.1:8081` | Sequencer HTTP bind address |
| `TESSERA_TREE_STORE_PATH` | `tessera-server/data/trees` | Persistent tree storage directory |
| `TESSERA_TREE_SNAPSHOT_EVERY_BATCHES` | `1` | Snapshot frequency (in batches) |
| `TESSERA_PROVER_API_URL` | `http://127.0.0.1:8091` | Prover service URL |
| `TESSERA_PROVER_API_TIMEOUT_SECS` | `1800` | Prover HTTP timeout (30 min) |

### Prover

| Variable | Default | Description |
|---|---|---|
| `TESSERA_NOTES_COMMITMENT_ARTIFACTS_PATH` | *required* | Path to notes-commitment tree artifacts |
| `TESSERA_ACCOUNTS_COMMITMENT_ARTIFACTS_PATH` | *required* | Path to accounts-commitment tree artifacts |
| `TESSERA_NOTES_NULLIFIER_ARTIFACTS_PATH` | *required* | Path to notes-nullifier tree artifacts |
| `TESSERA_ACCOUNTS_NULLIFIER_ARTIFACTS_PATH` | *required* | Path to accounts-nullifier tree artifacts |
| `TESSERA_NOTE_BATCH_SIZE` | `128` | Note-tree batch size (must match circuit) |
| `TESSERA_ACCOUNT_BATCH_SIZE` | `16` | Account-tree batch size (must equal `NOTE_BATCH_SIZE / 8`) |
| `TESSERA_PROVER_API_ADDR` | `127.0.0.1:8091` | Prover HTTP bind address |
