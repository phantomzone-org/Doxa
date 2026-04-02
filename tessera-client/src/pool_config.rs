use std::{
	collections::{BTreeMap, HashMap},
	hash::Hash,
};

use plonky2::{
	hash::{hash_types::HashOut, poseidon::PoseidonHash},
	plonk::config::Hasher,
};
use plonky2_field::types::{Field, PrimeField64};
use tessera_trees::{MerkleProof, MerkleTree, error::MerkleTreeResult};
use tessera_utils::{
	F, HASH_SIZE,
	hasher::{HashOutput, MerkleHash},
};

use crate::{
	MAIN_POOL_CONFIG_DEPTH, SUBPOOL_CONFIG_DEPTH, SubpoolId, ecgfp5::CompressedPoint,
	plonky2_gadgets::witness::fake_authority_key, schnorr::CompressedPublicKey,
};

// ── CompressedPublicKey ───────────────────────────────────────────────────────

pub type CompPubKey = CompressedPublicKey<F>;

impl CompPubKey {
	pub fn commit<H>(&self) -> H::Digest
	where
		H: MerkleHash<Digest = HashOutput>,
	{
		let hash = <PoseidonHash as Hasher<F>>::hash_no_pad(&self.0.w.0).elements;
		HashOutput(hash)
	}
}

const APPROVAL_KEY_INDEX: usize = 0;
const REJECTION_KEY_INDEX: usize = 1;
const CONSUME_KEY_INDEX: usize = 2;

/// A depth-2 Merkle tree holding the three authority public keys for a subpool.
///
/// Layout:
/// ```text
///                   SubpoolConfigRoot
///       node0                           node1
/// H(approval)  H(rejection)     H(consume)  H(zero×5)
/// ```
pub struct SubpoolConfigTree<H: MerkleHash> {
	pub approval_key: CompPubKey,
	pub rejection_key: CompPubKey,
	pub consume_key: CompPubKey,
	inner: MerkleTree<H>,
}

impl<H> SubpoolConfigTree<H>
where
	H: MerkleHash<Digest = HashOutput>,
{
	/// Build the tree from the three authority keys.
	/// Keys are inserted at fixed positions 0, 1, 2 via `insert` (in order).
	/// Position 3 remains the default empty leaf.
	pub fn new(approval: CompPubKey, rejection: CompPubKey, consume: CompPubKey) -> Self {
		let mut inner = MerkleTree::new(SUBPOOL_CONFIG_DEPTH);
		inner.insert(approval.commit::<H>()).unwrap();
		inner.insert(rejection.commit::<H>()).unwrap();
		inner.insert(consume.commit::<H>()).unwrap();
		Self {
			approval_key: approval,
			rejection_key: rejection,
			consume_key: consume,
			inner,
		}
	}

	pub fn root(&self) -> H::Digest {
		self.inner.root()
	}

	pub fn approval_key_proof(&self) -> MerkleTreeResult<MerkleProof<H>> {
		self.inner.merkle_proof(APPROVAL_KEY_INDEX)
	}

	pub fn rejection_key_proof(&self) -> MerkleTreeResult<MerkleProof<H>> {
		self.inner.merkle_proof(REJECTION_KEY_INDEX)
	}

	pub fn consume_key_proof(&self) -> MerkleTreeResult<MerkleProof<H>> {
		self.inner.merkle_proof(CONSUME_KEY_INDEX)
	}
}

impl SubpoolConfigTree<HashOutput> {
	pub fn fake_instance() -> (SubpoolConfigTree<HashOutput>, SubpoolFullProof<HashOutput>) {
		let key = fake_authority_key();
		let mut main_pool = MainPoolConfigTree::<HashOutput>::new();
		let subpool = SubpoolConfigTree::new(key, key, key);
		main_pool
			.insert_subpool(SubpoolId::ZERO, subpool.root())
			.unwrap();
		let subpool_proof = main_pool
			.full_subpool_proof(&subpool, SubpoolId::ZERO)
			.unwrap();
		(subpool, subpool_proof)
	}
}

// ── MainPoolConfigTree ────────────────────────────────────────────────────────

/// A leaf in the MainPoolConfigTree storing the raw subpool root and subpool id as field elements.
///
/// `Hash` is implemented by converting each `F` to its canonical `u64` representation —
/// no Poseidon involved. Poseidon is only used in `From<MainPoolConfigLeaf> for Node`
/// to compute the on-tree node value `H(subpool_root || subpool_id)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MainPoolConfigLeaf<H: MerkleHash> {
	pub subpool_root: H::Digest,
	pub subpool_id: SubpoolId,
}

impl<H: MerkleHash> MainPoolConfigLeaf<H> {
	pub fn new(subpool_root: H::Digest, subpool_id: SubpoolId) -> Self where {
		Self {
			subpool_root,
			subpool_id,
		}
	}
}

impl<H> MainPoolConfigLeaf<H>
where
	H: MerkleHash<Digest = HashOutput>,
{
	pub fn commit(&self) -> H::Digest {
		let mut input = [F::ZERO; HASH_SIZE + 1];
		input[..HASH_SIZE].copy_from_slice(&self.subpool_root.0);
		input[HASH_SIZE] = self.subpool_id.0;
		let hash = <PoseidonHash as Hasher<F>>::hash_no_pad(&input).elements;
		HashOutput(hash)
	}
}

/// A depth-20 Merkle tree where position `subpool_id` holds
/// TODO: swap the order below
/// `H(SubpoolConfigRoot || subpool_id)`.
#[derive(Clone)]
pub struct MainPoolConfigTree<H: MerkleHash> {
	inner: MerkleTree<H>,
	leaf_index_map: BTreeMap<H::Digest, usize>,
}

impl<H> MainPoolConfigTree<H>
where
	H: MerkleHash<Digest = HashOutput>,
{
	pub fn new() -> Self {
		Self {
			inner: MerkleTree::new(MAIN_POOL_CONFIG_DEPTH),
			leaf_index_map: BTreeMap::new(),
		}
	}

	pub fn root(&self) -> H::Digest {
		self.inner.root()
	}

	/// Insert or update the entry for `subpool_id` at the given `index` in the tree.
	pub fn insert_subpool(
		&mut self,
		subpool_id: SubpoolId,
		subpool_root: HashOutput,
	) -> MerkleTreeResult<()> {
		let leaf = MainPoolConfigLeaf::<H>::new(subpool_root, subpool_id);
		let digest = leaf.commit();
		let index = self.inner.insert(digest)?;
		self.leaf_index_map.insert(digest, index);
		Ok(())
	}

	/// Return the Merkle proof for a subpool inside this tree.
	pub fn subpool_proof(
		&self,
		subpool_id: SubpoolId,
		subpool_root: H::Digest,
	) -> MerkleTreeResult<MerkleProof<H>> {
		let leaf = MainPoolConfigLeaf::<H>::new(subpool_root, subpool_id);
		let digest = leaf.commit();
		let index = *self
			.leaf_index_map
			.get(&digest)
			.ok_or_else(|| anyhow::anyhow!("subpool leaf not found in index map"))?;
		self.inner.merkle_proof(index)
	}

	/// Return proofs for all three authority keys in `subpool` plus the subpool's
	/// own proof inside this main pool tree.
	pub fn full_subpool_proof(
		&self,
		subpool: &SubpoolConfigTree<H>,
		subpool_id: SubpoolId,
	) -> MerkleTreeResult<SubpoolFullProof<H>> {
		let main_pool_proof = self.subpool_proof(subpool_id, subpool.root())?;
		let approval_proof = subpool.approval_key_proof()?;
		let rejection_proof = subpool.rejection_key_proof()?;
		let consume_proof = subpool.consume_key_proof()?;
		Ok(SubpoolFullProof {
			approval_proof,
			rejection_proof,
			consume_proof,
			main_pool_proof,
		})
	}
}

// ── Combined proof ────────────────────────────────────────────────────────────

/// All three subpool authority-key proofs (relative to the SubpoolConfigRoot)
/// together with the subpool's proof inside the MainPoolConfigTree.
pub struct SubpoolFullProof<H: MerkleHash> {
	pub approval_proof: MerkleProof<H>,
	pub rejection_proof: MerkleProof<H>,
	pub consume_proof: MerkleProof<H>,
	pub main_pool_proof: MerkleProof<H>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use super::*;
	use crate::schnorr::{PrivateKey, PublicKey, Scalar};

	fn dummy_key(seed: u64) -> CompPubKey {
		let scalar = Scalar::from_raw([seed, seed + 1, seed + 2, seed + 3, seed & 0x7F]);
		let privkey = PrivateKey::new(scalar);
		let pubkey: PublicKey<F> = privkey.public_key();
		pubkey.into()
	}

	#[test]
	fn test_full_subpool_proof() {
		let approval = dummy_key(1);
		let rejection = dummy_key(2);
		let consume = dummy_key(3);

		let subpool = SubpoolConfigTree::<HashOutput>::new(approval, rejection, consume);

		let mut main_tree = MainPoolConfigTree::new();
		let subpool_id = SubpoolId(F::from_canonical_u64(5));
		main_tree
			.insert_subpool(subpool_id, subpool.root())
			.unwrap();

		let proof = main_tree
			.full_subpool_proof(&subpool, subpool_id)
			.expect("proof must be Some");

		assert!(proof.approval_proof.verify(), "approval proof invalid");
		assert!(proof.rejection_proof.verify(), "rejection proof invalid");
		assert!(proof.consume_proof.verify(), "consume proof invalid");
		assert!(proof.main_pool_proof.verify(), "main pool proof invalid");
	}
}
