# Tessera Codebase Reference

**Purpose:** Quick-reference for codebase structure, types, and APIs. Avoids re-exploring the
repo from scratch. Cross-reference with the four `e2e-report-*.md` docs for end-to-end flows.

---

## Repository Layout

```
tessera-client/   — Rust: ZK proof circuits, account/note types, Merkle trees, Schnorr signatures
tessera-server/   — Rust: sequencer, prover_v2, contract bindings, HTTP API
tessera-trees/    — Rust: Poseidon IMT, CommitmentTree, proof aggregation circuits (GenericAggregator, SubtreeRootCircuit, SuperAggregatorV2)
tessera-solidity/ — Solidity: TesseraRollupV2, verifiers, ToyUser, ToyUSDT
scripts/          — Shell: deployment and test-flow helpers
docs/             — Architecture and E2E reports
```

---

## Crate: tessera-client

### Constants (`src/lib.rs`)

```rust
pub const NOTE_BATCH: usize = 8;         // notes per account slot
pub const ACT_DEPTH: usize  = 32;        // account commitment tree depth
pub const NCT_DEPTH: usize  = 32;        // note commitment tree depth  (== ACT_DEPTH in V2)
pub const ANT_DEPTH: usize  = 32;
pub const NNT_DEPTH: usize  = 32;
pub const ACC_AST_DEPTH: usize = 10;     // per-account asset state tree depth
pub const SUBPOOL_CONFIG_DEPTH: usize = 2;
pub const MAIN_POOL_CONFIG_DEPTH: usize = 20;

pub const AST_DEFAULT_ROOT: [u64; 4] = [...]; // root of empty ACC_AST_DEPTH=10 Poseidon tree
pub const DEFAULT_SPEND_AUTH_PK: [u64; 5] = [...]; // placeholder spend key
pub const DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER: [u64; 5] = [1u64; 5];
```

### Public re-exports (`src/lib.rs`)

```rust
pub use account::*;
pub use note::*;
pub use plonky2_gadgets::priv_tx::{
    FakeTxInputs, FreshAccInputs, PrivTxInputs, PrivTxTargets, RejectTxInputs, SpendTxInputs,
    build_circuit_and_dummy_proof, build_circuit_and_real_proof,
    build_priv_tx_circuit, prove_dummy_priv_tx, prove_real_priv_tx, prove_real_priv_tx_seeded,
};
pub use TesseraGateSerializer;
```

### Domain Types

#### Account (`src/account.rs`)

```rust
pub struct PrivateIdentifier(pub [F; 2]);   // random 2-element secret
pub struct PublicIdentifier(pub HashOutput); // Poseidon(DS_PUBLIC_IDENTIFIER || priv_id)
pub struct SubpoolId(pub F);
pub struct Nonce(pub F);
pub struct NullifierKey(pub [F; 4]);         // Poseidon(DS_NULLIFIER_KEY || priv_id)
pub struct AccountCommitment(pub HashOutput);
pub struct AccountNullifier(pub HashOutput);
pub struct AssetId(pub(crate) F);

pub struct SpendAuth {
    pub spend_pk: Option<CompressedPublicKey<F>>,
}
pub struct ConsumeAuth {
    pub config: bool,                         // true = self-custody consume
    pub pk: Option<CompressedPublicKey<F>>,
}

pub struct AccountStateTree {  // depth-10 per-account asset Merkle tree
    // ...
}
impl AccountStateTree {
    pub fn new() -> Self
    pub fn root(&self) -> HashOutput
    pub fn insert_asset(&mut self, asset_id: AssetId, amount: U256) -> Result<(), String>
    pub fn update_asset(&mut self, asset_id: AssetId, amount: U256) -> Result<U256, String>
    pub fn insert_or_update_asset(&mut self, asset_id: AssetId, amount: U256) -> Option<U256>
    pub fn amount_for(&self, asset_id: AssetId) -> Option<(usize, U256)>
}

pub struct StandardAccount {
    pub private_identifier: PrivateIdentifier,
    pub subpool_id: SubpoolId,
    pub balance: U256,
    pub nonce: Nonce,
    pub spend_auth: SpendAuth,
    pub consume_auth: ConsumeAuth,
    pub ast: AccountStateTree,
}
impl StandardAccount {
    pub fn sample<R: CryptoRng + Rng>(rng: &mut R, subpool_id: SubpoolId) -> Self
    pub fn new_with(private_identifier: PrivateIdentifier, subpool_id: SubpoolId) -> Self
    pub fn public_id(&self) -> PublicIdentifier
    pub fn nk(&self) -> NullifierKey
    pub fn commitment(&self) -> AccountCommitment
    pub fn nullifier(&self, pos: Option<u64>) -> AccountNullifier
        // pos = None  → fresh_acc_nullifier (nonce==0, no keys, empty AST)
        // pos = Some(leaf_pos) → old_acc_nullifier (requires IMT position)
    pub fn is_fresh(&self) -> bool   // true when nonce=0, no keys, empty AST
}

pub struct AccountAddress {
    pub subpool_id: SubpoolId,
    pub(crate) public_id: PublicIdentifier,
}
impl AccountAddress {
    pub fn from_acc(acc: &StandardAccount) -> Self
}
```

**Commitment preimage** (19 F elements):
```
private_identifier[2] || subpool_id[1] || ast.root()[4] || nonce[1]
|| spend_pk_or_default[5] || consume_config[1] || consume_pk_or_placeholder[5]
```

**Nullifier (fresh)** = `Poseidon(commitment[4] || nk[4])`
**Nullifier (old, pos)** = `Poseidon(commitment[4] || nk[4] || pos[1])`

#### Notes (`src/note.rs`)

```rust
pub struct DepositNoteCommitment(pub HashOutput);

pub struct DepositNote {
    pub identifier: [F; 2],
    pub recipient:  AccountAddress,
    pub amount:     U256,
    pub asset_id:   AssetId,
}
impl DepositNote {
    pub fn commitment(&self) -> DepositNoteCommitment
    // preimage: identifier[2] || subpool_id[1] || public_id[4]
    //           || amount[8 u32 LE limbs] || asset_id[1]  (16 elements total)
}

pub struct NoteCommitment(pub HashOutput);
pub struct NoteNullifier(pub HashOutput);

pub struct StandardNote {
    pub(crate) identifier: NodeIdentifier,  // [F; 2]
    pub(crate) asset_id:   AssetId,
    pub(crate) amt:        U256,
    pub(crate) recipient:  AccountAddress,
    pub(crate) sender:     AccountAddress,
}
impl StandardNote {
    pub fn commitment(&self) -> NoteCommitment
    // preimage: identifier[2] || amt[8 LE u32 limbs] || asset_id[1]
    //           || recipient.subpool_id[1] || recipient.public_id[4]
    //           || sender.subpool_id[1] || sender.public_id[4]  (21 elements)
}

pub struct PositionedStandardNode {  // note with its IMT leaf position
    note: StandardNote,
    position: F,
}
impl PositionedStandardNode {
    pub fn from_note(n: StandardNote, position: F) -> Self
    pub fn nullifier(&self, nk: &NullifierKey) -> NoteNullifier
    // NoteNullifier = Poseidon(commitment[4] || position[1] || nk[4])
}
```

> **Note:** `StandardNote` is `pub(crate)` in some fields; use `sample_with` in tests:
> ```rust
> StandardNote::sample_with(recipient, sender, amount, asset_id)  // only in #[cfg(test)]
> ```

#### Tx hashes (`src/account.rs`)

```rust
pub fn derive_priv_tx_hash(
    accin_null: AccountNullifier,
    accout_comm: AccountCommitment,
    inotes_null: [NoteNullifier; NOTE_BATCH],
    onotes_comm: [NoteCommitment; NOTE_BATCH],
) -> [F; 4]
// = Poseidon(accin_null[4] || accout_comm[4] || inotes_null[8×4] || onotes_comm[8×4])

pub fn derive_deposit_tx_hash(
    accin_null: AccountNullifier,
    accout_comm: AccountCommitment,
    deposit_note_comm: DepositNoteCommitment,
    eth_adrs: H160,
) -> HashOutput

pub fn derive_withdraw_tx_hash(...) -> HashOutput
```

### Pool Config (`src/pool_config.rs`)

```rust
pub type CompPubKey = CompressedPublicKey<F>;   // ecgfp5 compressed point, 5×F

pub struct SubpoolConfigTree {          // depth-2 tree: [approval_key, rejection_key, consume_key, empty]
    pub approval_key: CompPubKey,
    pub rejection_key: CompPubKey,
    pub consume_key: CompPubKey,
}
impl SubpoolConfigTree {
    pub fn new(approval: CompPubKey, rejection: CompPubKey, consume: CompPubKey) -> Self
    pub fn root(&self) -> HashOutput
}

pub struct MainPoolConfigTree {         // depth-20 tree mapping subpool_id → SubpoolConfigRoot
}
impl MainPoolConfigTree {
    pub fn new() -> Self
    pub fn set_subpool(&mut self, index: usize, id: SubpoolId, subpool_root: HashOutput)
    pub fn root(&self) -> HashOutput
    pub fn merkle_proof_at(&self, index: usize) -> ...
}
```

The `main_pool.root()` **must match** the `poolConfigRoot` stored in the deployed contract.

### Merkle Tree (`src/tree.rs`)

```rust
pub struct CommitmentTreeMerkleProof<const DEPTH: usize> {
    pub(crate) leaf:       HashOutput,
    pub(crate) path:       Vec<HashOutput>,  // length == DEPTH
    pub(crate) num_leaves: usize,
    pub(crate) pos:        usize,
}
impl<const DEPTH: usize> CommitmentTreeMerkleProof<DEPTH> {
    pub(crate) fn new(leaf, path, pos, num_leaves) -> Self
    pub(crate) fn extract_siblings_bits(&self) -> ([[F; 4]; DEPTH], [bool; DEPTH])
    pub(crate) fn verify(&self, root: HashOutput) -> bool
}
```

The on-chain `CommitmentTree` (unified Poseidon IMT) is mirrored via `tessera_trees::tree::CommitmentTree`.

### Schnorr Signatures (`src/schnorr.rs`)

```rust
pub(crate) struct Scalar([u64; 5]);   // ecgfp5 scalar
impl Scalar {
    pub fn sample<R: Rng>(rng: &mut R) -> Self
    pub const fn from_raw(limbs: [u64; 5]) -> Self
}

pub struct PrivateKey { ... }
impl PrivateKey {
    pub fn new(s: Scalar) -> Self
    pub fn public_key<F: RichField>(&self) -> PublicKey<F>
}

pub struct Signature { ... }  // (R, s) over ecgfp5

pub fn schnorr_sign(sk: &PrivateKey, msg: &[F; 4], k: Scalar) -> Signature
```

**In tests**, use a fixed `k = Scalar::from_raw([1u64; 5])` (deterministic nonce).
**In production**, `k` must be drawn randomly or derived via RFC 6979.

### PrivTx Circuit Inputs (`src/plonky2_gadgets/priv_tx/inputs.rs`)

```rust
pub struct FreshAccInputs {
    pub accin:            StandardAccount,   // nonce=0, no keys, empty AST
    pub new_spend_auth:   SpendAuth,
    pub new_consume_auth: ConsumeAuth,
    pub root:             HashOutput,        // current on-chain IMT root (bound in super-agg)
    pub approval_key:     CompPubKey,
    pub rejection_key:    CompPubKey,
    pub consume_key:      CompPubKey,
    pub subpool_id:       SubpoolId,
    pub main_pool:        MainPoolConfigTree,
    pub approval_sig:     Signature,
    pub dinotes:          [[F; 4]; NOTE_BATCH],  // random dummy note preimages
    pub donotes:          [[F; 4]; NOTE_BATCH],
}

pub struct SpendTxInputs {
    pub accin:              StandardAccount,    // existing account (nonce > 0)
    pub root:               HashOutput,         // V2: used for both ACT + NCT proofs
    pub accin_merkle_proof: CommitmentTreeMerkleProof<ACT_DEPTH>,
    pub inotes:             Vec<StandardNote>,  // PositionedStandardNode actually (see spend.rs)
    pub inotes_nct_proofs:  Vec<CommitmentTreeMerkleProof<NCT_DEPTH>>,
    pub onotes:             Vec<StandardNote>,
    pub dinotes:            [[F; 4]; NOTE_BATCH],
    pub donotes:            [[F; 4]; NOTE_BATCH],
    pub approval_key:       CompPubKey,
    pub rejection_key:      CompPubKey,
    pub consume_key:        CompPubKey,
    pub subpool_id:         SubpoolId,
    pub main_pool:          MainPoolConfigTree,
    pub spend_sig:          Option<Signature>,  // None → fake sig (no active output notes)
    pub consume_sig:        Option<Signature>,
    pub approval_sig:       Signature,
}

pub struct RejectTxInputs {
    pub accin:                  StandardAccount,
    pub accin_act_merkle_proof: CommitmentTreeMerkleProof<ACT_DEPTH>,
    pub root:                   HashOutput,
    pub inotes:                 Vec<StandardNote>,
    pub inotes_nct_proofs:      Vec<CommitmentTreeMerkleProof<NCT_DEPTH>>,
    pub onotes:                 Vec<StandardNote>,
    pub dinotes:                [[F; 4]; NOTE_BATCH],
    pub donotes:                [[F; 4]; NOTE_BATCH],
    pub approval_key:           CompPubKey,
    pub rejection_key:          CompPubKey,
    pub consume_key:            CompPubKey,
    pub subpool_id:             SubpoolId,
    pub main_pool:              MainPoolConfigTree,
    pub consume_sig:            Signature,
    pub approval_sig:           Signature,
}

pub struct FakeTxInputs {
    pub root:                HashOutput,
    pub mainpool_config_root: HashOutput,
    pub override_an:         [F; 4],
    pub override_ac:         [F; 4],
    pub override_nn:         [[F; 4]; NOTE_BATCH],
    pub override_nc:         [[F; 4]; NOTE_BATCH],
}

pub enum PrivTxInputs { FreshAcc(FreshAccInputs), Spend(SpendTxInputs), Reject(RejectTxInputs), Fake(FakeTxInputs) }
```

### PrivTx Circuit API

```rust
// Build once (slow, ~1–2 min in --release). Cache and reuse.
pub fn build_priv_tx_circuit() -> (CircuitDataNative, PrivTxTargets<D>)

// Prove a real transaction (FreshAcc / Spend / Reject).
pub fn prove_real_priv_tx(
    circuit:  &CircuitDataNative,
    targets:  &PrivTxTargets<D>,
    inputs:   PrivTxInputs,
) -> ProofWithPublicInputsNative

// Prove a dummy/padding transaction (not_fake_tx = 0).
pub fn prove_dummy_priv_tx(
    circuit:      &CircuitDataNative,
    targets:      &PrivTxTargets<D>,
    override_an:  [F; 4],
    override_nn:  [[F; 4]; 8],
    override_ac:  [F; 4],
    override_nc:  [[F; 4]; 8],
) -> ProofWithPublicInputsNative

// Convenience: build + prove with RNG seed (for tests).
pub fn prove_real_priv_tx_seeded(seed: u64) -> (CircuitDataNative, ProofWithPublicInputsNative)
pub fn build_circuit_and_real_proof(inputs: PrivTxInputs) -> (CircuitDataNative, ProofWithPublicInputsNative)
pub fn build_circuit_and_dummy_proof() -> (CircuitDataNative, ProofWithPublicInputsNative)
```

### PrivTx Public Input Layout (85 F elements)

```
Index   Field
[0]     subpool_id_in   (auto-registered)
[1]     subpool_id_out
[2]     subpool_id_in   (explicit)
[3]     subpool_id_out  (explicit)
[4]     not_fake_tx     (IS_REAL_OFFSET = 4)
[5-8]   AN              AccountNullifier, 4×F    (TX_DATA_OFFSET = 5)
[9-12]  AC              AccountCommitment, 4×F
[13-44] NN[0..8]        NoteNullifier×8, each 4×F
[45-76] NC[0..8]        NoteCommitment×8, each 4×F
[77-80] root            on-chain Poseidon IMT root (V2: same value as [81-84])
[81-84] root            on-chain Poseidon IMT root (legacy duplicate slot)
```

**Extract leaf values from PIs:**
```rust
fn goldilocks_4_to_bytes32(elems: &[F]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, e) in elems[..4].iter().enumerate() {
        out[i*8..(i+1)*8].copy_from_slice(&e.to_canonical_u64().to_le_bytes());
    }
    out
}
let an = goldilocks_4_to_bytes32(&proof.public_inputs[5..]);   // AN
let ac = goldilocks_4_to_bytes32(&proof.public_inputs[9..]);   // AC
let nn: Vec<[u8;32]> = (0..8).map(|i| goldilocks_4_to_bytes32(&proof.public_inputs[13+i*4..])).collect();
let nc: Vec<[u8;32]> = (0..8).map(|i| goldilocks_4_to_bytes32(&proof.public_inputs[45+i*4..])).collect();
```

**Serialize proof for sequencer:**
```rust
use plonky2::util::serialization::Write;
let mut buf = Vec::new();
proof.write(&mut buf).unwrap();
let proof_bytes: Vec<u8> = buf;
```

---

## Crate: tessera-server

### `SequencerHandle` (`src/sequencer/handle.rs`)

```rust
// Production API
pub async fn submit_deposit(
    &self,
    note: [u8; 32],           // bytes32 LE-packed note commitment
    consume_proof: Option<Vec<u8>>,  // None for simple deposit flow
) -> anyhow::Result<()>

pub async fn submit_private_tx(
    &self,
    tx_id:               Option<String>,
    input_account_leaf:  [u8; 32],    // AN LE-packed
    output_account_leaf: [u8; 32],    // AC LE-packed
    input_notes:         Vec<[u8; 32]>, // NN LE-packed, up to 8
    output_notes:        Vec<[u8; 32]>, // NC LE-packed, up to 8
    tx_proof:            Vec<u8>,
) -> anyhow::Result<()>

// Test-only (TESSERA_TESTING=1)
pub async fn test_submit_deposit(&self, note: [u8; 32]) -> anyhow::Result<()>
pub async fn test_submit_tx(&self, an: [u8;32], ac: [u8;32], nn: [[u8;32];8], nc: [[u8;32];8]) -> anyhow::Result<()>
pub async fn test_validate_deposits(&self) -> anyhow::Result<()>  // blocks until on-chain confirmed
pub async fn test_validate_txs(&self) -> anyhow::Result<()>        // blocks until on-chain confirmed
```

### Prover Types (`src/types.rs`)

```rust
pub struct ProveRequestV2 {
    pub batch_id:          u64,
    pub nc_leaves:         Vec<[u8; 32]>,         // all NC leaves (batch_size × 8)
    pub root:              HashOutput,             // on-chain root at flush time
    pub main_pool_cfg_root: [u8; 32],
    pub tx_proofs_by_slot: HashMap<usize, Vec<u8>>, // slot_index → Plonky2 proof bytes
}

pub enum ProveOutcomeV2 {
    Success { batch_id, batch_poseidon_root: HashOutput, solidity_proof: Box<SolidityProof>, super_pi_commitment: [u8; 32] },
    Failure { batch_id, error: String },
}

pub struct ConsumeProveRequest {
    pub batch_id:              u64,
    pub nc_leaves:             Vec<[u8; 32]>,
    pub root:                  HashOutput,
    pub main_pool_cfg_root:    [u8; 32],
    pub consume_proofs_by_slot: HashMap<usize, Vec<u8>>,
}

pub enum ConsumeOutcome {
    Success { batch_id, batch_poseidon_root: HashOutput, solidity_proof: Box<SolidityProof>, super_pi_commitment: [u8; 32] },
    Failure { batch_id, error: String },
}

pub struct SolidityProof {
    pub proof:          [U256; 8],
    pub commitments:    [U256; 2],
    pub commitment_pok: [U256; 2],
}
```

### Sequencer Environment Variables

```bash
TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=<rollup contract>
TESSERA_MONITORED_TOKEN=<token contract>
TESSERA_ACCOUNT_BATCH_SIZE=2      # slots per batch (2 for fast tests)
TESSERA_BATCH_TIMEOUT_SECS=5      # flush after N seconds
TESSERA_PROVER_API_URL=http://127.0.0.1:8091
TESSERA_PROVER_API_TIMEOUT_SECS=1800
TESSERA_RPC_URL=<node rpc>
TESSERA_WS_URL=<node ws>
TESSERA_OPERATOR_KEY=<hex private key>
TESSERA_TESTING=1                 # enables /test/* endpoints
TESSERA_TEST_API_ADDR=127.0.0.1:8081
```

---

## Crate: tessera-trees

### CommitmentTree

```rust
use tessera_trees::tree::CommitmentTree;

let mut tree = CommitmentTree::<HashOutput>::new(DEPTH);
// DEPTH must be a const known at compile time OR passed dynamically

tree.insert(leaf: HashOutput) -> Option<LeafInfo>   // LeafInfo { path: usize, ... }
tree.get_root() -> HashOutput
tree.num_leaves() -> usize
tree.merkle_path(pos: usize, from_level: usize, depth: usize) -> Option<Vec<HashOutput>>
```

**Critical ordering rule:** All leaves must be inserted BEFORE generating any Merkle paths.
The circuit uses a single `root` wire; all proofs must be consistent with the FINAL tree root.

### Proof Aggregation Constants

```rust
// tessera-trees::proof_aggregation
pub const IS_REAL_OFFSET: usize = 4;   // PI index of not_fake_tx
pub const TX_DATA_OFFSET: usize = 5;   // PI index of AN start
```

---

## Crate: tessera-solidity

### TesseraRollupV2 Key Functions

```solidity
// Deposit lifecycle
function depositAndRegister(bytes32 noteCommitment, uint256 maxAmount) external returns (bytes32)
function depositAndRegisterFor(bytes32 noteCommitment, address payer, uint256 maxAmount) external returns (bytes32)
function withdrawPendingDeposit(bytes32 noteCommitment) external

function submitDepositBatch(DepositBatch calldata batch) external onlyOperator
function proveDepositBatch(bytes32 piCommitment, Proof calldata proof) external

// Transaction lifecycle
function submitTransactionBatch(TransactionBatch calldata batch) external onlyOperator
function proveTransactionBatch(bytes32 piCommitment, Proof calldata proof) external

// Query
function currentRoot() external view returns (uint256)
function isConfirmedRoot(uint256 root) external view returns (bool)
function getDeposit(bytes32 nc) external view returns (DepositInfo)
    // DepositInfo: (value, recipient, status)  status: 0=None, 1=Pending, 2=Validated, 3=Withdrawn
function isNullifierUsed(uint256 nullifier) external view returns (bool)
function poolConfigRoot() external view returns (bytes32)
```

### Deploy Script (`tessera-solidity/script/Deploy.s.sol`)

Deployment deploys `VerifierSuperAggregatorV2` for both TX and deposit verifiers (same circuit).
For testing, replace both with `AcceptAllVerifier` (accepts any proof including all-zero).

```bash
# Deploy with real verifier
forge script tessera-solidity/script/Deploy.s.sol --broadcast \
  --rpc-url $RPC_URL --private-key $DEPLOYER_KEY

# Deploy with AcceptAllVerifier for testing
TESSERA_TX_VERIFIER=<AcceptAllVerifier> TESSERA_DEPOSIT_VERIFIER=<AcceptAllVerifier> \
forge script tessera-solidity/script/Deploy.s.sol --broadcast ...
```

### AcceptAllVerifier (`tessera-solidity/src/AcceptAllVerifier.sol`)

Accepts any proof including all-zero. Deploy as both `txVerifier` and `depositVerifier` for
test-mode E2E that skips the Groth16 proving step.

---

## Key Invariants and Gotchas

### Merkle Proof Generation Order

In any test that uses a unified `CommitmentTree` for both account and note memberships:

```rust
// 1. INSERT ALL commitments first
let acc_pos  = tree.insert(acc.commitment().0).unwrap().path;
let note_pos = tree.insert(note.commitment().0).unwrap().path;

// 2. THEN generate all Merkle proofs against the FINAL root
let acc_proof  = CommitmentTreeMerkleProof::new(acc.commitment().0,  tree.merkle_path(acc_pos, 0, ACT_DEPTH).unwrap(), acc_pos, tree.num_leaves());
let note_proof = CommitmentTreeMerkleProof::new(note.commitment().0, tree.merkle_path(note_pos, 0, NCT_DEPTH).unwrap(), note_pos, tree.num_leaves());

// 3. Use tree.get_root() as the `root` field in SpendTxInputs / RejectTxInputs
```

Generating a proof before all inserts produces a stale root → "partition set twice" panic.

### LE Packing (bytes32 ↔ HashOutput)

```rust
// HashOutput([F; 4]) → [u8; 32]  (LE: e0 at bytes[0..8], e3 at bytes[24..32])
fn pack_to_bytes(h: HashOutput) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, e) in h.0.iter().enumerate() {
        out[i*8..(i+1)*8].copy_from_slice(&e.to_canonical_u64().to_le_bytes());
    }
    out
}

// [u8; 32] → HashOutput
fn unpack_from_bytes(b: [u8; 32]) -> HashOutput {
    let mut out = [0u64; 4];
    for i in 0..4 { out[i] = u64::from_le_bytes(b[i*8..(i+1)*8].try_into().unwrap()); }
    HashOutput(out.map(F::from_canonical_u64))
}
```

### poolConfigRoot Must Match Contract

The `main_pool.root()` used in every proof must equal the `poolConfigRoot` stored on-chain.
Set it once at deployment time; never change it mid-session.

### V2 Single IMT (act_root == nct_root)

Both PI[77-80] and PI[81-84] carry the same `root` value. The circuit retains two separate
wire targets (`act_root`, `nct_root`) as a V1 artifact; `set_common_tx_witness` sets both.
Always pass the same `root` to `FreshAccInputs`, `SpendTxInputs`, and `RejectTxInputs`.

### Account Nullifier: Fresh vs. Positioned

- `is_fresh() == true` (nonce=0, no keys, empty AST) → `nullifier(None)` — no IMT position needed
- After first FreshAcc TX, `nonce=1` → `nullifier(Some(pos))` where `pos` = leaf index in IMT

### Note Position (PositionedStandardNode)

`PositionedStandardNode::nullifier(nk)` depends on the leaf's absolute position in the IMT.
The sequencer allocates positions during batch construction. The client must know the on-chain
leaf index to compute the correct nullifier for a Spend TX.

### Batch Parameters

- `TESSERA_ACCOUNT_BATCH_SIZE` = N slots per batch (typically 2 for tests)
- Each slot holds up to `NOTE_BATCH=8` notes
- Total NC leaves per batch = `N × 8`
- Batch flushes when either `is_full()` OR `batch_timeout_secs` elapsed

### Running Tests

```bash
# Always use --release (non-release proving too slow)
cargo test -p tessera-client --release
cargo test -p tessera-trees --release
cargo test -p tessera-server --release

# After any code change:
cargo fmt
cargo clippy -p tessera-trees -p tessera-server -p tessera-client
```

---

## State That Must Be Tracked Client-Side

For a real E2E client (non-test-mode), the following state must be maintained in sync with the chain:

| State | Source of truth | Client-side mirror |
|-------|-----------------|--------------------|
| `currentRoot` | `rollup.currentRoot()` | queried before each batch / after each `DepositBatchProven` / `TransactionBatchProven` event |
| IMT leaf positions | on-chain events (leaf append order) | local `CommitmentTree<HashOutput>` built by replaying `DepositBatchProven` + `TransactionBatchProven` events |
| Account state | internal | `StandardAccount` struct — updated after each TX |
| Note positions | on-chain leaf index from event | needed to build `PositionedStandardNode` for Spend inputs |
| poolConfigRoot | `rollup.poolConfigRoot()` | queried once at startup |

---

## Existing Tests

| File | Description |
|------|-------------|
| `tessera-server/tests/e2e_v2.rs` | Full-stack with Anvil, `AcceptAllVerifier`, contract bindings — no real Plonky2 proofs |
| `tessera-client/src/plonky2_gadgets/priv_tx/freshacc.rs` | Unit test: real FreshAcc proof |
| `tessera-client/src/plonky2_gadgets/priv_tx/spend.rs` | Unit test: real Spend proof (unified tree) |
| `tessera-client/src/plonky2_gadgets/priv_tx/reject.rs` | Unit test: real Reject proof (unified tree) |
| `scripts/local_test_flow.sh` | Shell E2E via HTTP test API (TESSERA_TESTING=1) |
