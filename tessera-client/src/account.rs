use std::{collections::HashMap, hash::Hash, marker::PhantomData};

use plonky2::{hash::poseidon::PoseidonHash, plonk::config::Hasher};
use plonky2_field::types::{Field, Field64, PrimeField64};
use primitive_types::{H160, U256};
use rand::{CryptoRng, Rng, RngExt};
use serde::{Deserialize, Serialize};
use tessera_utils::{F, HASH_SIZE, hasher::HashOutput};

use crate::{
	ACC_AST_DEPTH, AST_DEFAULT_LEAF, DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER,
	DEFAULT_SPEND_AUTH_PK, DS_ACC_AST_LEAF, DS_NULLIFIER_KEY, DS_PUBLIC_IDENTIFIER,
	DepositNoteCommitment, NOTE_BATCH, NoteCommitment, NoteNullifier,
	schnorr::CompressedPublicKey,
	tree::{GenericNode, Leaf, MerkleProof, MerkleTree},
	utils::map_h160_to_f,
};

#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct AccountCommitment(pub HashOutput);

#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct AccountNullifier(pub HashOutput);

#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct NullifierKey(pub [F; 4]);

#[derive(Hash, PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PrivateIdentifier(pub [F; 2]);

impl PrivateIdentifier {
	fn sample<R: CryptoRng + Rng>(rng: &mut R) -> PrivateIdentifier {
		let arr = core::array::from_fn(|_| F::from_canonical_u64(rng.random_range(0..F::ORDER)));
		PrivateIdentifier(arr)
	}
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct PublicIdentifier(pub HashOutput);

impl PublicIdentifier {
	pub(crate) const ZERO: Self = Self(HashOutput([F::ZERO; 4]));
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SubpoolId(pub F);

#[derive(Debug, Clone, Copy)]
pub struct Nonce(pub F);

impl Nonce {
	pub(crate) fn incremented(self) -> Self {
		Self(F::from_canonical_u64(self.0.to_canonical_u64() + 1))
	}
}

#[derive(Debug, Clone, Default)]
pub struct SpendAuth {
	pub spend_pk: Option<CompressedPublicKey<F>>,
}

#[derive(Debug, Clone, Default)]
pub struct ConsumeAuth {
	/// If false, consume is delegated to subpool owner
	/// If true, consume requires signature from self.pk
	pub config: bool,
	/// None only when self.config == 1.
	pub pk: Option<CompressedPublicKey<F>>,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct AssetId(pub(crate) F);

impl AssetId {
	pub fn from_u64(v: u64) -> anyhow::Result<Self> {
		anyhow::ensure!(v < F::ORDER, "AssetId value {v} is out of Goldilocks field range");
		Ok(Self(F::from_canonical_u64(v)))
	}
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct AccountStateTreeLeaf {
	pub asset_id: AssetId,
	pub amount: U256,
}

impl Leaf for AccountStateTreeLeaf {
	type Node = GenericNode<Self>;

	fn empty() -> Self::Node {
		GenericNode {
			inner: HashOutput(AST_DEFAULT_LEAF.map(F::from_canonical_u64)),
			_phantom: PhantomData,
		}
	}
}

impl From<AccountStateTreeLeaf> for GenericNode<AccountStateTreeLeaf> {
	fn from(value: AccountStateTreeLeaf) -> Self {
		// input = [DS_ACC_AST, asset_id, limb0, limb1, ..., limb7]
		// limb_i is the i-th 32-bit limb of `amount`, least-significant first.
		// U256.0 is [u64; 4] in little-endian word order.
		let mut input = [F::ZERO; 1 + 1 + 8];
		input[0] = F::from_canonical_u64(DS_ACC_AST_LEAF);
		input[1] = value.asset_id.0;
		for (i, word) in value.amount.0.iter().enumerate() {
			input[2 + i * 2] = F::from_canonical_u32(*word as u32);
			input[2 + i * 2 + 1] = F::from_canonical_u32((*word >> 32) as u32);
		}
		Self::from(HashOutput(
			<PoseidonHash as Hasher<F>>::hash_no_pad(&input).elements,
		))
	}
}

/// Wraps the per-account asset Merkle tree with an O(1) amount lookup map.
// TODO: handle the case when asset limit is reached
#[derive(Clone, Debug)]
pub struct AccountStateTree {
	pub(crate) tree: MerkleTree<ACC_AST_DEPTH, GenericNode<AccountStateTreeLeaf>>,
	/// AssetId → (leaf_index, current_amount)
	assets: HashMap<AssetId, (usize, U256)>,
}

impl Default for AccountStateTree {
	fn default() -> Self {
		Self::new()
	}
}

impl AccountStateTree {
	pub fn new() -> Self {
		Self {
			tree: MerkleTree::new(),
			assets: HashMap::new(),
		}
	}

	pub fn root(&self) -> HashOutput {
		self.tree.root()
	}

	pub fn size(&self) -> usize {
		self.tree.size()
	}

	/// Insert a new asset. Returns `Err` if `asset_id` is already tracked.
	pub fn insert_asset(&mut self, asset_id: AssetId, amount: U256) -> Result<(), String> {
		if self.assets.contains_key(&asset_id) {
			return Err(format!("asset {:?} already exists", asset_id));
		}
		let index = self.tree.next_index();
		self.tree.insert(AccountStateTreeLeaf {
			asset_id,
			amount,
		});
		self.assets.insert(asset_id, (index, amount));
		Ok(())
	}

	/// Update an existing asset's amount. Returns `Ok(previous_amount)` or `Err` if not found.
	pub fn update_asset(&mut self, asset_id: AssetId, amount: U256) -> Result<U256, String> {
		let &(index, prev_amount) = self
			.assets
			.get(&asset_id)
			.ok_or_else(|| format!("asset {:?} not found", asset_id))?;
		self.tree.set_leaf(
			index,
			AccountStateTreeLeaf {
				asset_id,
				amount,
			},
		);
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

	pub fn merkle_proof_at(
		&self,
		index: usize,
	) -> MerkleProof<GenericNode<AccountStateTreeLeaf>, ACC_AST_DEPTH> {
		self.tree.merkle_proof_at(index)
	}

	/// Returns `(leaf_index, amount)` for the given asset, or `None` if never set.
	pub fn amount_for(&self, asset_id: AssetId) -> Option<(usize, U256)> {
		self.assets.get(&asset_id).copied()
	}

	/// Next free leaf index.
	pub fn next_index(&self) -> usize {
		self.tree.next_index()
	}
}

#[derive(Clone, Debug)]
pub struct StandardAccount {
	pub private_identifier: PrivateIdentifier,
	pub subpool_id: SubpoolId,
	pub balance: U256,
	pub nonce: Nonce,
	// TODO: make spend_auth generic over Field
	pub spend_auth: SpendAuth,
	pub consume_auth: ConsumeAuth,
	pub ast: AccountStateTree,
}

impl StandardAccount {
	pub fn sample<R: CryptoRng + Rng>(rng: &mut R, subpool_id: SubpoolId) -> Self {
		let private_identifier = PrivateIdentifier::sample(rng);
		StandardAccount {
			private_identifier,
			subpool_id,
			balance: U256::zero(),
			nonce: Nonce(F::ZERO),
			spend_auth: SpendAuth::default(),
			consume_auth: ConsumeAuth::default(),
			ast: AccountStateTree::new(),
		}
	}

	pub fn new_with(private_identifier: PrivateIdentifier, subpool_id: SubpoolId) -> Self {
		StandardAccount {
			private_identifier,
			subpool_id,
			balance: U256::zero(),
			nonce: Nonce(F::ZERO),
			spend_auth: SpendAuth::default(),
			consume_auth: ConsumeAuth::default(),
			ast: AccountStateTree::new(),
		}
	}

	pub fn clone_with_incremented_nonce(&self) -> Self {
		let mut next = self.clone();
		next.nonce = self.nonce.incremented();
		next
	}

	pub fn address(&self) -> AccountAddress {
		AccountAddress::from_acc(self)
	}

	pub fn public_id(&self) -> PublicIdentifier {
		let mut input = [F::ZERO; 3];
		input[0] = F::from_canonical_u64(DS_PUBLIC_IDENTIFIER);
		input[1..].copy_from_slice(self.private_identifier.0.as_slice());
		let pubid = <PoseidonHash as Hasher<F>>::hash_no_pad(input.as_slice()).elements;
		PublicIdentifier(pubid.into())
	}

	pub fn nk(&self) -> NullifierKey {
		let mut input = [F::ZERO; 3];
		input[0] = F::from_canonical_u64(DS_NULLIFIER_KEY);
		input[1..].copy_from_slice(self.private_identifier.0.as_slice());
		let nk = <PoseidonHash as Hasher<F>>::hash_no_pad(input.as_ref()).elements;
		NullifierKey(nk)
	}

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

	pub fn nullifier(&self, pos: Option<u64>) -> AccountNullifier {
		if self.is_fresh() {
			self.fresh_acc_nullifier()
		} else {
			assert!(pos.is_some());
			self.old_acc_nullifier(pos.unwrap())
		}
	}

	pub fn is_fresh(&self) -> bool {
		self.nonce.0 == F::ZERO
			&& self.spend_auth.spend_pk.is_none()
			&& !self.consume_auth.config
			&& self.consume_auth.pk.is_none()
			&& self.ast.size() == 0
	}

	fn fresh_acc_nullifier(&self) -> AccountNullifier {
		let mut inp = Vec::with_capacity(4 + 4);
		inp.extend(self.commitment().0.0);
		inp.extend(self.nk().0);

		AccountNullifier(HashOutput(
			<PoseidonHash as Hasher<F>>::hash_no_pad(&inp).elements,
		))
	}

	fn old_acc_nullifier(&self, pos: u64) -> AccountNullifier {
		let pos = F::from_canonical_u64(pos);

		let mut inp = Vec::with_capacity(4 + 1 + 4);
		inp.extend(self.commitment().0.0);
		inp.extend(self.nk().0);
		inp.push(pos);

		AccountNullifier(HashOutput(
			<PoseidonHash as Hasher<F>>::hash_no_pad(&inp).elements,
		))
	}
}

#[derive(Clone, Copy)]
pub struct AccountAddress {
	pub subpool_id: SubpoolId,
	pub(crate) public_id: PublicIdentifier,
}

impl AccountAddress {
	pub fn from_acc(acc: &StandardAccount) -> Self {
		Self {
			subpool_id: acc.subpool_id,
			public_id: acc.public_id(),
		}
	}

	pub(crate) fn zero() -> Self {
		Self {
			subpool_id: SubpoolId(F::ZERO),
			public_id: PublicIdentifier::ZERO,
		}
	}

	/// Encode as `hex(subpool_id) | hex(public_id)`.
	/// - `subpool_id`: 8 bytes (u64 little-endian) → 16 hex chars
	/// - `public_id`:  32 bytes (4 × u64 LE)       → 64 hex chars
	/// Decode from the 80-hex-char encoding produced by `to_hex`.
	pub fn from_hex(s: &str) -> anyhow::Result<Self> {
		anyhow::ensure!(s.len() == 80, "expected 80 hex chars, got {}", s.len());
		let bytes = hex::decode(s)?;
		let subpool_raw = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
		let mut pub_id = [F::ZERO; 4];
		for i in 0..4 {
			pub_id[i] = F::from_canonical_u64(
				u64::from_le_bytes(bytes[8 + i * 8..16 + i * 8].try_into().unwrap()),
			);
		}
		Ok(Self {
			subpool_id: SubpoolId(F::from_canonical_u64(subpool_raw)),
			public_id: PublicIdentifier(HashOutput(pub_id)),
		})
	}

	pub fn to_hex(&self) -> String {
		let mut bytes = [0u8; 40];
		bytes[..8].copy_from_slice(&self.subpool_id.0.to_canonical_u64().to_le_bytes());
		for (i, f) in self.public_id.0.0.iter().enumerate() {
			bytes[8 + i * 8..8 + (i + 1) * 8].copy_from_slice(&f.to_canonical_u64().to_le_bytes());
		}
		bytes.iter().map(|b| format!("{b:02x}")).collect()
	}
}

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
	tx_hash_inp.extend_from_slice(&map_h160_to_f(&eth_adrs));
	HashOutput(<PoseidonHash as Hasher<F>>::hash_no_pad(&tx_hash_inp).elements)
}

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
	inp.extend_from_slice(&map_h160_to_f(&w_acc_addr));
	HashOutput(<PoseidonHash as Hasher<F>>::hash_no_pad(&inp).elements)
}

/// Compute the actual root of the default empty Account State Tree (depth `ACC_AST_DEPTH`,
/// all leaves = `AST_DEFAULT_LEAF`)
pub(crate) fn ast_default_root() -> [u64; HASH_SIZE] {
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
	cur.map(|f| f.to_canonical_u64())
}

#[cfg(test)]
mod tests {}
