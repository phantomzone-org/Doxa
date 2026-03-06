# Tessera Client: Note/Account Derivation, Dummy Padding & Account Registration

## Progress Tracker

| # | Step | Status |
|---|------|--------|
| 1 | `account_artifacts` binary (8-PI circuit) | [x] |
| 2 | Server-side account proof verification | [x] |
| 3 | Client `register-account` subcommand | [x] |
| 4 | Client `private-tx` — derivation & padding | [x] |
| 5 | Update scripts and README | [x] |

---

## Context

The `private-tx` client command currently requires manually specifying output notes,
output accounts, and has no dummy-padding for unused note slots. In practice:

- **Output notes** are derived from input notes with a second key, not supplied independently.
- **Fewer than 8 input notes** must be padded to exactly 8 with deterministic dummies.
- **Accounts** need a registration step (insert commitment into AC tree) before a
  private-tx can nullify them.
- The client must always send **exactly 8 input nullifiers + 8 output commitments**
  to the sequencer (real + dummy).

### Cryptographic Primitives

All client-side derivations use **Poseidon hash** (`PoseidonHash::hash_no_pad` from plonky2)
over Goldilocks field elements. Each `bytes32` value is interpreted as 4 big-endian `u64`
Goldilocks field elements.

### Files Involved

| File | Action |
|------|--------|
| `tessera-server/src/bin/account_artifacts.rs` | **New** — 8-PI circuit artifact generator |
| `tessera-server/Cargo.toml` | Add `[[bin]]` entry |
| `tessera-server/src/config.rs` | Add `TESSERA_ACCOUNT_ARTIFACTS_PATH` |
| `tessera-server/src/sequencer/api.rs` | Add proof verification to `/accounts/commitment` |
| `tessera-server/src/sequencer/mod.rs` | Wire up `account_proof_verifier` |
| `tessera-server/src/bin/client.rs` | New subcommand + derivation + padding |
| `scripts/local_env.sh` | Add env var |
| `scripts/README.md` | Update examples |

---

## Step 1: `account_artifacts` binary

**Goal**: Create a trivial 8-PI Plonky2 circuit for account registration proofs.

### Circuit Layout

```
PI[0..4] = account commitment   (4 Goldilocks fields)
PI[4..8] = nullifier key        (4 Goldilocks fields)
```

### New File: `tessera-server/src/bin/account_artifacts.rs`

Follows the exact pattern of `tessera-server/src/bin/consume_artifacts.rs`:

1. Build a circuit with 8 virtual targets registered as public inputs.
2. Serialize to three files in `tessera-server/artifacts/account/`:
   - `leaf_common.bin` — `CommonCircuitData` (used by sequencer verifier)
   - `leaf_verifier.bin` — `VerifierOnlyCircuitData` (used by sequencer verifier)
   - `leaf_prover.bin` — full `CircuitData` (used by client prover)

### Cargo.toml Addition

```toml
[[bin]]
name = "account_artifacts"
path = "src/bin/account_artifacts.rs"
```

### Build Command

```bash
cargo run --bin account_artifacts --release --manifest-path tessera-server/Cargo.toml
```

---

## Step 2: Server-side account proof verification

**Goal**: The `/accounts/commitment` endpoint should verify a Plonky2 proof (like
`/consume-request` does), not accept bare leaves.

### 2a. `tessera-server/src/config.rs`

Add to `SequencerConfig`:

```rust
/// Optional path to pre-built account-circuit artifacts.
/// When set, the API layer validates /accounts/commitment proof bytes.
/// Set via `TESSERA_ACCOUNT_ARTIFACTS_PATH`.
pub account_artifacts_path: Option<PathBuf>,
```

Load from env in `SequencerConfig::from_env()`:

```rust
let account_artifacts_path = std::env::var("TESSERA_ACCOUNT_ARTIFACTS_PATH")
    .ok()
    .map(PathBuf::from);
```

### 2b. `tessera-server/src/sequencer/api.rs`

1. Add field to `ApiState`:
   ```rust
   pub(super) account_proof_verifier: Option<Arc<LeafProofVerifier>>,
   ```

2. Change request body for `accounts_commitment_handler` from `LeafBody` to a new type
   (or reuse `ConsumeRequestBody` pattern):
   ```rust
   #[derive(Debug, Deserialize)]
   struct AccountRegisterBody {
       leaf: String,
       input_proof: String,
   }
   ```

3. Add proof verification in `accounts_commitment_handler` before accepting the leaf.
   Follow the same pattern as `consume_request_handler` (lines 128-175):
   - Parse `input_proof` hex -> bytes
   - Call `verify_associated_tx_proof(&proof, state.account_proof_verifier.as_deref())`
   - Reject with reason on failure

### 2c. `tessera-server/src/sequencer/mod.rs`

Wire up `account_proof_verifier` from config, same pattern as `consume_proof_verifier`
(lines 405-410):

```rust
let account_proof_verifier = self
    .config
    .account_artifacts_path
    .as_deref()
    .map(|path| api::LeafProofVerifier::from_artifacts(path).map(Arc::new))
    .transpose()
    .context("failed to load account proof verifier")?;
```

Pass into `ApiState`.

---

## Step 3: Client `register-account` subcommand

**Goal**: New CLI command to register an account commitment on the sequencer.

### CLI Definition

```
RegisterAccount {
    --private-key    String   (required, bytes32 hex)
    --balance        u64      (default 0)
    --nonce          u64      (default 0)
}
```

### Derivation

```
account_commitment = Poseidon(pk_fields[0..4] || balance || nonce)
                   -> 6-field preimage -> 4-field HashOut

nullifier_key      = Poseidon(pk_fields[0..4])
                   -> 4-field preimage -> 4-field HashOut
```

Both are encoded back to `B256` using the standard big-endian u64 per limb convention.

### Flow

1. Parse private key via existing `resolve_private_key(Some(hex))`.
2. Call `derive_account_commitment(pk, balance, nonce) -> B256`.
3. Call `derive_nullifier_key(pk) -> B256`.
4. Load 8-PI circuit from `TESSERA_ACCOUNT_ARTIFACTS_PATH / leaf_prover.bin`.
5. Set PI[0..4] = commitment fields, PI[4..8] = nullifier key fields.
6. Prove circuit.
7. POST to `{TESSERA_SEQUENCER_API_URL}/accounts/commitment`:
   ```json
   { "leaf": "0x<commitment>", "input_proof": "0x<proof_hex>" }
   ```
8. Print commitment and nullifier key for user reference.

### New Helper Functions

```rust
/// Poseidon(pk_fields || balance || nonce) -> B256
fn derive_account_commitment(pk: &B256, balance: u64, nonce: u64) -> B256

/// Poseidon(pk_fields) -> B256
fn derive_nullifier_key(pk: &B256) -> B256
```

---

## Step 4: Client `private-tx` -- derivation & padding

**Goal**: Remove manual output specification; derive everything from input notes + private key.

### 4a. CLI Changes

**Remove**: `--output-notes`, `--output-account`

**Add**: `--account-commitment` (bytes32 hex -- the current account commitment to nullify)

**Keep**: `--input-notes` (1-8), `--private-key`, `--tx-id`

### 4b. Output Key Derivation

```
output_key = Poseidon(pk_fields[0..4])  // same as nullifier_key
```

This is deterministic from the private key.

### 4c. Per-Note Derivation

For each real input note `input_note[i]`:

```
input_nullifier[i]    = Poseidon(pk_fields || input_note_fields[i])     // 8-field preimage
output_commitment[i]  = Poseidon(output_key_fields || input_note_fields[i])  // 8-field preimage
```

### 4d. Dummy Padding to 8

When N < 8 real input notes, derive dummy notes for indices N..8:

```
DS_DUMMY_NOTE: u64 = 0x44554d4d59    // "DUMMY" ASCII domain separator

real_concat = [real_note[0]_fields || real_note[1]_fields || ... || real_note[N-1]_fields]
            -> N*4 Goldilocks field elements

For i in N..8:
    dummy_note[i] = Poseidon(DS_DUMMY_NOTE || i_as_u64 || real_concat)
    input_nullifier[i]   = Poseidon(pk || dummy_note[i])
    output_commitment[i] = Poseidon(output_key || dummy_note[i])
```

`PoseidonHash::hash_no_pad` handles arbitrary-length input (up to 34 fields for 8 real notes).

### 4e. Account Derivation

```
input_account_nullifier    = Poseidon(pk || account_commitment)
output_account_commitment  = Poseidon(output_key || account_commitment)
```

### 4f. PI Array (73 fields, layout unchanged)

```
[0]      = 1  (is_real)
[1..33]  = 8 input note nullifiers    (real[0..N] + dummy[N..8], 4 fields each)
[33..65] = 8 output note commitments  (real[0..N] + dummy[N..8], 4 fields each)
[65..69] = input account nullifier    (derived)
[69..73] = output account commitment  (derived)
```

### 4g. JSON Body

All values are derived -- no raw user values in the body:

```json
{
  "input_notes":                [ "0x<nullifier_0>", ..., "0x<nullifier_7>" ],
  "output_notes":               [ "0x<commitment_0>", ..., "0x<commitment_7>" ],
  "input_account_commitment":   "0x<account_nullifier>",
  "output_account_commitment":  "0x<output_account>",
  "tx_proof":                   "0x<proof_hex>",
  "tx_id":                      "..."
}
```

### New Helper Functions

```rust
/// Poseidon(output_key_fields || note_fields) -> B256
fn derive_output_commitment(output_key: &B256, note: &B256) -> B256

/// Pad real input notes to 8 with deterministic Poseidon-derived dummies.
/// Returns exactly 8 B256 values (real notes first, then dummies).
fn pad_dummy_notes(real_notes: &[B256]) -> Vec<B256>
```

---

## Step 5: Update scripts and README

### `scripts/local_env.sh`

Add:
```bash
export TESSERA_ACCOUNT_ARTIFACTS_PATH="${SCRIPT_DIR}/../tessera-server/artifacts/account"
```

### `scripts/README.md`

Update client usage examples:

```bash
# Generate account artifacts (one-time)
cargo run --bin account_artifacts --release --manifest-path tessera-server/Cargo.toml

# Register an account
cargo run --bin client --release --manifest-path tessera-server/Cargo.toml -- \
  register-account \
  --private-key 0xdeadbeef \
  --balance 0 \
  --nonce 0

# Submit a private transaction (2 real notes, padded to 8)
cargo run --bin client --release --manifest-path tessera-server/Cargo.toml -- \
  private-tx \
  --input-notes 0x01,0x02 \
  --account-commitment 0x<commitment-from-register> \
  --private-key 0xdeadbeef
```

---

## Verification

```bash
# 1. Build account artifacts
cargo run --bin account_artifacts --release --manifest-path tessera-server/Cargo.toml

# 2. Source env
source scripts/local_env.sh

# 3. Compile checks
cargo fmt
cargo clippy -p tessera-server

# 4. With sequencer running:
#    Register account
cargo run --bin client --release --manifest-path tessera-server/Cargo.toml -- \
  register-account --private-key 0xdeadbeef --balance 0 --nonce 0

# 5. Submit private-tx (2 notes, auto-padded to 8)
cargo run --bin client --release --manifest-path tessera-server/Cargo.toml -- \
  private-tx \
  --input-notes 0x01,0x02 \
  --account-commitment 0x<commitment-from-step-4> \
  --private-key 0xdeadbeef

# Expected: both commands succeed, sequencer logs show accepted requests
```
