use std::{collections::HashMap, hash::Hash, marker::PhantomData};

use plonky2::{hash::poseidon::PoseidonHash, plonk::config::Hasher};
use plonky2_field::types::{Field, Field64, PrimeField64};
use primitive_types::{H160, U256};
use rand::{CryptoRng, Rng, RngExt};
use serde::{Deserialize, Serialize};
use tessera_trees::{MerkleProof, MerkleTree};
use tessera_utils::{
	F, HASH_SIZE,
	hasher::{HashOutput, MerkleHash},
};

use crate::{
	ACC_AST_DEPTH, AST_DEFAULT_LEAF, DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER,
	DEFAULT_SPEND_AUTH_PK, DS_ACC_AST_LEAF, DS_NULLIFIER_KEY, DS_PUBLIC_IDENTIFIER,
	DepositNoteCommitment, NOTE_BATCH, NoteCommitment, NoteNullifier,
	ecgfp5::CompressedPoint,
	schnorr::CompressedPublicKey,
	utils::map_h160_to_f,
};

/// Pedersen-like commitment to an account state.
///
/// Computed as `H(private_identifier || subpool_id || ast_root || nonce
///              || spend_pk || consume_auth.config || consume_auth.pk)`.
/// The commitment is inserted into the Account Commitment Tree (ACT) and
/// serves as the public handle for an account without revealing its secrets.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct AccountCommitment(pub HashOutput);

/// Spend-once tag for an account, derived from its commitment and nullifier key.
///
/// Computed as `H(account_commitment || nk)`.  Publishing a nullifier proves
/// an account has been consumed/updated without revealing which account it was.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct AccountNullifier(pub HashOutput);

/// Secret key used to derive note and account nullifiers.
///
/// Derived from the account's `private_identifier`:
/// `nk = H(DS_NULLIFIER_KEY || private_identifier)`.
/// Keeping `nk` secret prevents linking nullifiers back to the owner.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct NullifierKey(pub [F; 4]);

/// Secret 2-field-element identifier that seeds all account-specific values.
///
/// Never leaves the client.  The public identifier, nullifier key, and account
/// commitment are all derived from it.
#[derive(Hash, PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PrivateIdentifier(pub [F; 2]);

impl PrivateIdentifier {
	/// Sample a fresh random private identifier from `rng`.
	fn sample<R: CryptoRng + Rng>(rng: &mut R) -> PrivateIdentifier {
		let arr = core::array::from_fn(|_| F::from_canonical_u64(rng.random_range(0..F::ORDER)));
		PrivateIdentifier(arr)
	}
}

/// The public, on-chain-visible identifier for an account.
///
/// Derived as `H(DS_PUBLIC_IDENTIFIER || private_identifier)`.
/// Embedded in notes as the recipient/sender condition so that the note
/// can only be spent by the holder of the matching private identifier.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct PublicIdentifier(pub HashOutput);

impl PublicIdentifier {
	pub(crate) const ZERO: Self = Self(HashOutput([F::ZERO; 4]));
}

/// Identifies which subpool an account belongs to.
///
/// Every account is scoped to exactly one subpool; the subpool's authority
/// keys (approval, rejection, consume) govern all transactions for that account.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SubpoolId(pub F);

impl SubpoolId {
	pub(crate) const ZERO: Self = Self(F::ZERO);
}

/// Monotonically-increasing counter included in every account commitment.
///
/// Each valid account transition increments the nonce by exactly 1, preventing
/// replay attacks and ensuring commitments are unique across updates.
#[derive(Debug, Clone, Copy)]
pub struct Nonce(pub F);

impl Nonce {
	/// Return a new `Nonce` with value `self + 1`.
	pub(crate) fn incremented(self) -> Self {
		Self(F::from_canonical_u64(self.0.to_canonical_u64() + 1))
	}
}

/// Authorization data for *spending* notes out of an account.
///
/// When `spend_pk` is `Some`, the holder of the corresponding private key
/// must sign the transaction hash.  `None` means no spend key is set yet
/// (pre-FreshAcc state), and [`DEFAULT_SPEND_AUTH_PK`] is used as a placeholder
/// in the account commitment.
#[derive(Debug, Clone, Default)]
pub struct SpendAuth {
	pub spend_pk: Option<CompressedPublicKey<F>>,
}

/// Authorization data for *consuming* (depositing into) an account.
#[derive(Debug, Clone, Default)]
pub struct ConsumeAuth {
	/// If `false`, consume is delegated to the subpool owner's key.
	/// If `true`, consume requires a signature from `self.pk`.
	pub config: bool,
	/// The account's own consume public key.
	/// `None` only when `config == false` (delegation mode).
	pub pk: Option<CompressedPublicKey<F>>,
}

/// A field-element identifier for a fungible asset type.
///
/// Must satisfy `0 <= value < F::ORDER` (Goldilocks field order).
/// Used as the key in the Account State Tree to track per-asset balances.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct AssetId(pub F);

impl AssetId {
	pub(crate) const ZERO: Self = Self(F::ZERO);

	/// Construct an `AssetId` from a `u64`, returning an error if the value
	/// exceeds the Goldilocks field order.
	pub fn from_u64(v: u64) -> anyhow::Result<Self> {
		anyhow::ensure!(
			v < F::ORDER,
			"AssetId value {v} is out of Goldilocks field range"
		);
		Ok(Self(F::from_canonical_u64(v)))
	}

	pub fn to_u64(&self) -> u64 {
		self.0.to_canonical_u64()
	}
}

/// A single leaf in the Account State Tree (AST), recording an asset balance.
///
/// Hashed as `H(DS_ACC_AST_LEAF || asset_id || amount_limbs[8])` where the
/// eight limbs are the u32 little-endian decomposition of the U256 amount.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct AccountStateTreeLeaf {
	pub asset_id: AssetId,
	pub amount: U256,
}

impl AccountStateTreeLeaf {
	/// Hash the leaf into a Merkle tree node.
	///
	/// Input layout (10 field elements):
	/// ```text
	/// [DS_ACC_AST_LEAF, asset_id, lo(word0), hi(word0), ..., lo(word3), hi(word3)]
	/// ```
	/// where each `U256` word is split into its low and high u32 halves
	/// (little-endian word order, matching `U256.0: [u64; 4]`).
	pub fn commitment<H>(&self) -> H::Digest
	where
		H: MerkleHash<Digest = HashOutput>,
	{
		// input = [DS_ACC_AST, asset_id, limb0, limb1, ..., limb7]
		// limb_i is the i-th 32-bit limb of `amount`, least-significant first.
		// U256.0 is [u64; 4] in little-endian word order.
		let mut input = [F::ZERO; 1 + 1 + 8];
		input[0] = F::from_canonical_u64(DS_ACC_AST_LEAF);
		input[1] = self.asset_id.0;
		for (i, word) in self.amount.0.iter().enumerate() {
			input[2 + i * 2] = F::from_canonical_u32(*word as u32);
			input[2 + i * 2 + 1] = F::from_canonical_u32((*word >> 32) as u32);
		}
		HashOutput(<PoseidonHash as Hasher<F>>::hash_no_pad(&input).elements)
	}
}

/// Per-account asset-balance Merkle tree with O(1) balance lookup.
///
/// Wraps a [`MerkleTree`] of depth [`ACC_AST_DEPTH`] (1024 leaves) and mirrors
/// the leaf contents in a `HashMap` so that balance queries and updates do not
/// require a tree scan.
///
/// Each occupied leaf stores one `(asset_id, amount)` pair.  New assets are
/// appended at the next free position; existing assets are updated in-place.
// TODO: handle the case when asset limit is reached
#[derive(Clone, Debug)]
pub struct AccountStateTree<H: MerkleHash> {
	pub(crate) tree: MerkleTree<H>,
	/// AssetId → (leaf_index, current_amount)
	pub assets: HashMap<AssetId, (usize, U256)>,
}

impl<H> Default for AccountStateTree<H>
where
	H: MerkleHash<Digest = HashOutput>,
{
	fn default() -> Self {
		Self::new()
	}
}

impl<H> AccountStateTree<H>
where
	H: MerkleHash<Digest = HashOutput>,
{
	/// Create an empty AST.  All leaves are initialised to [`AST_DEFAULT_LEAF`].
	pub fn new() -> Self {
		Self {
			tree: MerkleTree::new(ACC_AST_DEPTH),
			assets: HashMap::new(),
		}
	}

	/// Reconstruct an AST from a saved asset map.
	///
	/// Entries are inserted in `leaf_index` order. Returns `Err` if the
	/// leaf indices are not contiguous starting from 0.
	pub fn new_from_asset_map(map: HashMap<AssetId, (usize, U256)>) -> anyhow::Result<Self> {
		let mut entries: Vec<(AssetId, usize, U256)> = map
			.into_iter()
			.map(|(asset_id, (leaf_index, amount))| (asset_id, leaf_index, amount))
			.collect();
		entries.sort_by_key(|&(_, leaf_index, _)| leaf_index);

		for (expected, &(_, leaf_index, _)) in entries.iter().enumerate() {
			anyhow::ensure!(
				leaf_index == expected,
				"leaf_index sequence is not contiguous: expected {expected}, got {leaf_index}"
			);
		}

		let mut ast = Self::new();
		for (asset_id, _, amount) in entries {
			ast.insert_asset(asset_id, amount)
				.map_err(|e| anyhow::anyhow!(e))?;
		}
		Ok(ast)
	}

	/// Current Merkle root of the AST.
	pub fn root(&self) -> H::Digest {
		self.tree.root()
	}

	/// Number of occupied (non-default) leaves.
	pub fn size(&self) -> usize {
		self.tree.num_leaves()
	}

	/// Insert a new asset. Returns `Err` if `asset_id` is already tracked.
	pub fn insert_asset(&mut self, asset_id: AssetId, amount: U256) -> Result<(), String> {
		if self.assets.contains_key(&asset_id) {
			return Err(format!("asset {:?} already exists", asset_id));
		}
		let index = self.tree.num_leaves();
		let leaf = AccountStateTreeLeaf {
			asset_id,
			amount,
		};
		self.tree
			.insert(leaf.commitment::<H>())
			.map_err(|e| e.to_string())?;
		self.assets.insert(asset_id, (index, amount));
		Ok(())
	}

	/// Update an existing asset's amount. Returns `Ok(previous_amount)` or `Err` if not found.
	pub fn update_asset(&mut self, asset_id: AssetId, amount: U256) -> Result<U256, String> {
		let &(index, prev_amount) = self
			.assets
			.get(&asset_id)
			.ok_or_else(|| format!("asset {:?} not found", asset_id))?;
		let leaf = AccountStateTreeLeaf {
			asset_id,
			amount,
		};
		self.tree
			.update_leaf(index, leaf.commitment::<H>())
			.map_err(|e| e.to_string())?;
		self.assets.insert(asset_id, (index, amount));
		Ok(prev_amount)
	}

	/// Insert if new, update if existing.
	/// Returns `None` if newly inserted, `Some(previous_amount)` if updated.
	pub fn insert_or_update_asset(&mut self, asset_id: AssetId, amount: U256) -> Option<U256> {
		if self.assets.contains_key(&asset_id) {
			Some(self.update_asset(asset_id, amount).unwrap())
		} else {
			self.insert_asset(asset_id, amount).unwrap();
			None
		}
	}

	/// Generate a Merkle proof for the leaf at `index`.
	///
	/// Used to supply the witness for AST membership / update checks in circuits.
	pub fn merkle_proof_at(&self, index: usize) -> MerkleProof<H> {
		self.tree
			.merkle_proof(index)
			.expect("merkle proof generation failed")
	}

	/// Returns `(leaf_index, amount)` for the given asset, or `None` if never set.
	pub fn amount_for(&self, asset_id: AssetId) -> Option<(usize, U256)> {
		self.assets.get(&asset_id).copied()
	}

	/// Index at which the next new asset would be inserted.
	pub fn next_index(&self) -> usize {
		self.tree.num_leaves()
	}
}

/// A fully-materialised Tessera account held by a client.
///
/// Contains all secret and public fields needed to compute commitments,
/// nullifiers, and Merkle proofs.  The account is never transmitted; only
/// derived values (commitments, nullifiers, proofs) appear on-chain.
///
/// # State lifecycle
/// 1. **Pre-activation** — `nonce=0`, no `spend_pk`, no `consume_pk` set. Represented in the ACT by
///    a fresh commitment.
/// 2. **Active** — after a FreshAcc transaction sets the auth keys. Nonce ≥ 1 from this point
///    forward.
/// 3. **Each transaction** clones the account, increments the nonce, and optionally updates
///    balances or auth keys, producing a new commitment.
#[derive(Clone, Debug)]
pub struct StandardAccount {
	pub private_identifier: PrivateIdentifier,
	pub subpool_id: SubpoolId,
	pub nonce: Nonce,
	// TODO: make spend_auth generic over Field
	pub spend_auth: SpendAuth,
	pub consume_auth: ConsumeAuth,
	/// Per-asset balance Merkle tree.
	pub ast: AccountStateTree<HashOutput>,
}

impl StandardAccount {
	// TODO: why is this here?
	pub fn fake() -> Self {
		Self::new_with(
			crate::PrivateIdentifier([F::from_canonical_u64(1), F::from_noncanonical_u64(2)]),
			SubpoolId(F::ZERO),
		)
	}

	/// Sample a fresh account with a random private identifier and zero balances.
	/// The returned account is in the pre-activation state (`nonce=0`).
	pub fn sample<R: CryptoRng + Rng>(rng: &mut R, subpool_id: SubpoolId) -> Self {
		let private_identifier = PrivateIdentifier::sample(rng);
		StandardAccount {
			private_identifier,
			subpool_id,
			nonce: Nonce(F::ZERO),
			spend_auth: SpendAuth::default(),
			consume_auth: ConsumeAuth::default(),
			ast: AccountStateTree::new(),
		}
	}

	/// Create a fresh account with an explicit private identifier and zero balances.
	pub fn new_with(private_identifier: PrivateIdentifier, subpool_id: SubpoolId) -> Self {
		StandardAccount {
			private_identifier,
			subpool_id,
			nonce: Nonce(F::ZERO),
			spend_auth: SpendAuth::default(),
			consume_auth: ConsumeAuth::default(),
			ast: AccountStateTree::new(),
		}
	}

	/// Clone this account with the nonce incremented by one.
	///
	/// Used to derive the post-transaction account state (`accout`) from
	/// the pre-transaction state (`accin`) before modifying other fields.
	pub fn clone_with_incremented_nonce(&self) -> Self {
		let mut next = self.clone();
		next.nonce = self.nonce.incremented();
		next
	}

	/// Return the consume public key, falling back to the default placeholder if unset.
	pub fn consume_pk_or_default(&self) -> CompressedPublicKey<F> {
		self.consume_auth.pk.unwrap_or_else(|| {
			CompressedPublicKey(CompressedPoint::from(DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER))
		})
	}

	/// Return the shareable [`AccountAddress`] (subpool_id + public_id).
	pub fn address(&self) -> AccountAddress {
		AccountAddress::from_acc(self)
	}

	/// Derive the public identifier for this account.
	///
	/// `public_id = H(DS_PUBLIC_IDENTIFIER || private_identifier)`
	///
	/// The public identifier is embedded in notes as the spend/reject condition
	/// and is safe to share — it does not reveal the private identifier.
	pub fn public_id(&self) -> PublicIdentifier {
		let mut input = [F::ZERO; 3];
		input[0] = F::from_canonical_u64(DS_PUBLIC_IDENTIFIER);
		input[1..].copy_from_slice(self.private_identifier.0.as_slice());
		let pubid = <PoseidonHash as Hasher<F>>::hash_no_pad(input.as_slice()).elements;
		PublicIdentifier(pubid.into())
	}

	/// Derive the nullifier key for this account.
	///
	/// `nk = H(DS_NULLIFIER_KEY || private_identifier)`
	///
	/// The nullifier key is used to derive note and account nullifiers.
	/// It must stay secret — exposing it allows linking all nullifiers to
	/// this account.
	pub fn nk(&self) -> NullifierKey {
		let mut input = [F::ZERO; 3];
		input[0] = F::from_canonical_u64(DS_NULLIFIER_KEY);
		input[1..].copy_from_slice(self.private_identifier.0.as_slice());
		let nk = <PoseidonHash as Hasher<F>>::hash_no_pad(input.as_ref()).elements;
		NullifierKey(nk)
	}

	/// Compute the Poseidon commitment to this account's full state.
	///
	/// Hash input (19 field elements):
	/// ```text
	/// private_identifier[2] || subpool_id[1] || ast_root[4] || nonce[1]
	/// || spend_pk[5] || consume_auth.config[1] || consume_auth.pk[5]
	/// ```
	/// Placeholder values ([`DEFAULT_SPEND_AUTH_PK`] /
	/// [`DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER`]) are used when the
	/// respective keys are not yet set.
	pub fn commitment(&self) -> AccountCommitment {
		let mut inp = Vec::with_capacity(19);
		inp.extend_from_slice(&self.private_identifier.0);
		inp.push(self.subpool_id.0);
		inp.extend_from_slice(&self.ast.root().0);
		inp.push(self.nonce.0);

		if let Some(spend_pk) = self.spend_auth.spend_pk {
			inp.extend_from_slice(&spend_pk.0.w.0);
		} else {
			inp.extend_from_slice(&DEFAULT_SPEND_AUTH_PK.map(F::from_canonical_u64));
		}

		if self.consume_auth.config {
			inp.push(F::ONE);
			inp.extend(self.consume_auth.pk.unwrap().0.w.0);
		} else {
			inp.push(F::ZERO);
			inp.extend(DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER.map(F::from_canonical_u64));
		};

		AccountCommitment(HashOutput(
			<PoseidonHash as Hasher<F>>::hash_no_pad(&inp).elements,
		))
	}

	pub fn nullifier(&self) -> AccountNullifier {
		let mut inp = Vec::with_capacity(4 + 4);
		inp.extend(self.commitment().0.0);
		inp.extend(self.nk().0);

		AccountNullifier(HashOutput(
			<PoseidonHash as Hasher<F>>::hash_no_pad(&inp).elements,
		))
	}

	/// Return `true` if the account is in the pre-activation (fresh) state.
	///
	/// An account is fresh iff:
	/// - `nonce == 0`
	/// - no spend key has been set
	/// - consume auth is not self-delegated (`config == false`)
	/// - no assets have been recorded in the AST
	///
	/// The circuit uses this to gate FreshAcc-specific invariants.
	pub fn is_fresh(&self) -> bool {
		self.nonce.0 == F::ZERO
			&& self.spend_auth.spend_pk.is_none()
			&& !self.consume_auth.config
			&& self.consume_auth.pk.is_none()
			&& self.ast.size() == 0
	}
}

/// The public address shared with counterparties so they can target notes.
///
/// Contains only public fields (`subpool_id` + `public_id`); the private
/// identifier is never included.  Encoded as an 80-character hex string for
/// transport.
#[derive(Debug, Clone, Copy)]
pub struct AccountAddress {
	pub subpool_id: SubpoolId,
	pub(crate) public_id: PublicIdentifier,
}

impl AccountAddress {
	pub(crate) const ZERO: Self = Self {
		subpool_id: SubpoolId::ZERO,
		public_id: PublicIdentifier::ZERO,
	};

	/// Construct an address from its components.
	pub fn new(subpool_id: SubpoolId, public_id: PublicIdentifier) -> Self {
		Self {
			subpool_id,
			public_id,
		}
	}

	/// Derive the address from an account.
	pub fn from_acc(acc: &StandardAccount) -> Self {
		Self {
			subpool_id: acc.subpool_id,
			public_id: acc.public_id(),
		}
	}

	/// Serialize to a 40-byte little-endian representation.
	///
	/// Layout:
	/// - bytes `[0..8]`  → `subpool_id` (u64 LE)
	/// - bytes `[8..40]` → `public_id`  (4 × u64 LE)
	pub fn to_bytes(&self) -> [u8; 40] {
		let mut bytes = [0u8; 40];
		bytes[..8].copy_from_slice(&self.subpool_id.0.to_canonical_u64().to_le_bytes());
		for (i, f) in self.public_id.0.0.iter().enumerate() {
			bytes[8 + i * 8..8 + (i + 1) * 8].copy_from_slice(&f.to_canonical_u64().to_le_bytes());
		}
		bytes
	}

	/// Deserialize from the 40-byte representation produced by [`Self::to_bytes`].
	pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
		anyhow::ensure!(bytes.len() == 40, "expected 40 bytes, got {}", bytes.len());
		let subpool_raw = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
		let mut pub_id = [F::ZERO; 4];
		for i in 0..4 {
			pub_id[i] = F::from_canonical_u64(u64::from_le_bytes(
				bytes[8 + i * 8..16 + i * 8].try_into().unwrap(),
			));
		}
		Ok(Self {
			subpool_id: SubpoolId(F::from_canonical_u64(subpool_raw)),
			public_id: PublicIdentifier(HashOutput(pub_id)),
		})
	}

	/// Encode as an 80-character lowercase hex string.
	///
	/// Layout: `subpool_id (16 hex) || public_id (64 hex)`.
	pub fn to_hex(&self) -> String {
		hex::encode(self.to_bytes())
	}

	/// Decode from the 80-hex-char encoding produced by [`Self::to_hex`].
	pub fn from_hex(s: &str) -> anyhow::Result<Self> {
		anyhow::ensure!(s.len() == 80, "expected 80 hex chars, got {}", s.len());
		Self::from_bytes(&hex::decode(s)?)
	}
}

/// Compute the native (non-circuit) transaction hash for a private transaction.
///
/// `tx_hash = H(accin_null[4] || accout_comm[4]
///             || inotes_null[NOTE_BATCH×4] || onotes_comm[NOTE_BATCH×4])`
///
/// This is the message signed by the spend, consume, and approval keys.
/// The circuit independently derives the same hash and verifies the signatures.
pub fn derive_priv_tx_hash(
	accin_null: AccountNullifier,
	accout_comm: AccountCommitment,
	inotes_null: [NoteNullifier; NOTE_BATCH],
	onotes_comm: [NoteCommitment; NOTE_BATCH],
) -> HashOutput {
	use plonky2::plonk::config::Hasher;
	let mut inp = Vec::with_capacity(4 + 4 + 4 * crate::NOTE_BATCH + 4 * crate::NOTE_BATCH);
	inp.extend_from_slice(&accin_null.0.0);
	inp.extend_from_slice(&accout_comm.0.0);
	for n in &inotes_null {
		inp.extend(n.0.0);
	}
	for c in &onotes_comm {
		inp.extend(c.0.0);
	}

	HashOutput(<PoseidonHash as Hasher<F>>::hash_no_pad(&inp).elements)
}

/// Compute the native transaction hash for a deposit transaction.
///
/// `tx_hash = H(accin_null[4] || accout_comm[4] || deposit_note_comm[4] || eth_address[5])`
///
/// Signed by the consume key (owner or subpool-delegated) and the approval key.
pub fn derive_deposit_tx_hash(
	accin_null: AccountNullifier,
	accout_comm: AccountCommitment,
	deposit_note_comm: DepositNoteCommitment,
	eth_adrs: H160,
) -> HashOutput {
	let mut tx_hash_inp: Vec<F> = Vec::with_capacity(17);
	tx_hash_inp.extend_from_slice(&accin_null.0.0);
	tx_hash_inp.extend_from_slice(&accout_comm.0.0);
	tx_hash_inp.extend_from_slice(&deposit_note_comm.0.0);
	tx_hash_inp.extend_from_slice(&map_h160_to_f(eth_adrs));
	HashOutput(<PoseidonHash as Hasher<F>>::hash_no_pad(&tx_hash_inp).elements)
}

/// Compute the native transaction hash for a withdrawal transaction.
///
/// Hash input layout:
/// ```text
/// accin_null[4] || accout_comm[4] || asset_ids[NOTE_BATCH]
/// || amounts_f[8×NOTE_BATCH]   (each U256 as 8 u32 field elements, LE)
/// || w_acc_addr[5]             (Ethereum address as 5 u32 field elements)
/// ```
///
/// Signed by the approval key.  The `amounts` array must match the
/// `withdrawal_amts` used to fill the circuit witness.
pub fn derive_withdraw_tx_hash(
	accin_null: AccountNullifier,
	accout_comm: AccountCommitment,
	asset_ids: [AssetId; NOTE_BATCH],
	amounts: [U256; NOTE_BATCH],
	w_acc_addr: H160,
) -> HashOutput {
	// inp = accin_null[4] || accout_comm[4] || asset_ids[NOTE_BATCH]
	//     || amounts_f[8*NOTE_BATCH] (each U256 as 8 u32 F limbs) || w_acc_addr[5]
	let mut inp: Vec<F> = Vec::new();
	inp.extend_from_slice(&accin_null.0.0);
	inp.extend_from_slice(&accout_comm.0.0);
	for id in &asset_ids {
		inp.push(id.0);
	}
	for amt in &amounts {
		// U256 stores 4 u64 limbs (little-endian); split each into 2 u32 limbs
		for limb64 in amt.0.iter() {
			inp.push(F::from_canonical_u32(*limb64 as u32));
			inp.push(F::from_canonical_u32((*limb64 >> 32) as u32));
		}
	}
	inp.extend_from_slice(&map_h160_to_f(w_acc_addr));
	HashOutput(<PoseidonHash as Hasher<F>>::hash_no_pad(&inp).elements)
}

/// Compute the actual root of the default empty Account State Tree (depth `ACC_AST_DEPTH`,
/// all leaves = `AST_DEFAULT_LEAF`)
pub(crate) fn ast_default_root() -> HashOutput {
	use plonky2::{
		hash::{hash_types::HashOut, poseidon::PoseidonHash},
		plonk::config::Hasher,
	};
	use plonky2_field::types::Field;

	let mut cur: [F; HASH_SIZE] = AST_DEFAULT_LEAF.map(F::from_canonical_u64);
	for _ in 0..ACC_AST_DEPTH {
		let r = <PoseidonHash as Hasher<F>>::two_to_one(
			HashOut {
				elements: cur,
			},
			HashOut {
				elements: cur,
			},
		);
		cur = r.elements;
	}
	cur.into()
}

#[cfg(test)]
mod tests {}
