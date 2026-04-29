use std::{
	collections::{BTreeMap, HashMap},
	hash::Hash,
	marker::PhantomData,
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
	schnorr::CompressedPublicKey,
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
pub struct SubpoolConfig<H: MerkleHash<Digest = HashOutput>> {
	approval_key: CompPubKey,
	_phantom: PhantomData<H>,
}

impl<H: MerkleHash<Digest = HashOutput>> SubpoolConfig<H> {
	/// Build the tree from the three authority keys.
	/// Keys are inserted at fixed positions 0, 1, 2 via `insert` (in order).
	/// Position 3 remains the default empty leaf.
	pub fn new(approval_key: CompPubKey) -> Self {
		Self {
			approval_key,
			_phantom: PhantomData,
		}
	}

	/// Get the approval key for this subpool.
	pub fn approval_key(&self) -> CompPubKey {
		self.approval_key
	}

	pub fn commitment(&self) -> H::Digest {
		self.approval_key.commit::<H>()
	}
}

// ── MainPoolConfigTree ────────────────────────────────────────────────────────

/// A leaf in the MainPoolConfigTree storing the raw subpool root and subpool id as field elements.
///
/// `Hash` is implemented by converting each `F` to its canonical `u64` representation —
/// no Poseidon involved. Poseidon is only used in `From<MainPoolConfigLeaf> for Node`
/// to compute the on-tree node value `H(subpool_config_comm|| subpool_id)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MainPoolConfigLeaf<H: MerkleHash> {
	pub subpool_config_comm: H::Digest,
	pub subpool_id: SubpoolId,
}

impl<H: MerkleHash> MainPoolConfigLeaf<H> {
	pub fn new(subpool_root: H::Digest, subpool_id: SubpoolId) -> Self where {
		Self {
			subpool_config_comm: subpool_root,
			subpool_id,
		}
	}
}

impl<H> MainPoolConfigLeaf<H>
where
	H: MerkleHash<Digest = HashOutput>,
{
	pub fn commit(&self) -> H::Digest {
		let mut left = HashOut::default();
		left.elements[0] = self.subpool_id.0;
		let right = self.subpool_config_comm.as_hash_out();
		let hash = <PoseidonHash as Hasher<F>>::two_to_one(left, right);
		HashOutput(hash.elements)
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

	/// Insert the entry for `subpool_id` at position `subpool_id` in the tree.
	///
	/// The leaf is placed at index `subpool_id.0` (matching the on-chain convention
	/// where `updateSubpoolRoot` navigates the binary tree using the bits of
	/// `subpoolId`).  Zero leaves are pre-filled at positions `0..subpool_id` so
	/// that the underlying append-only [`MerkleTree`] can update the target slot.
	///
	/// # Errors
	/// Returns an error if `subpool_id == 0` (reserved) or if the underlying tree
	/// operation fails.
	pub fn insert_subpool_at_position(
		&mut self,
		subpool_id: SubpoolId,
		subpool_root: HashOutput,
	) -> MerkleTreeResult<()> {
		let id = subpool_id.0.to_canonical_u64() as usize;
		anyhow::ensure!(id > 0, "subpool_id 0 is reserved and cannot be used");

		let leaf = MainPoolConfigLeaf::<H>::new(subpool_root, subpool_id);
		let digest = leaf.commit();

		// Pre-fill with zero leaves so the target index is within bounds for update_leaf.
		while self.inner.num_leaves() <= id {
			self.inner.insert(H::ZERO)?;
		}
		self.inner.update_leaf(id, digest)?;
		self.leaf_index_map.insert(digest, id);
		Ok(())
	}

	/// Return the Merkle proof for a subpool inside this tree.
	pub fn subpool_proof(
		&self,
		subpool_id: SubpoolId,
		subpool_config_comm: H::Digest,
	) -> MerkleTreeResult<MerkleProof<H>> {
		let leaf = MainPoolConfigLeaf::<H>::new(subpool_config_comm, subpool_id);
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
		subpool: &SubpoolConfig<H>,
		subpool_id: SubpoolId,
	) -> MerkleTreeResult<SubpoolFullProof<H>> {
		let main_pool_proof = self.subpool_proof(subpool_id, subpool.commitment())?;
		Ok(SubpoolFullProof {
			main_pool_proof,
		})
	}
}

// ── Combined proof ────────────────────────────────────────────────────────────

/// All three subpool authority-key proofs (relative to the SubpoolConfigRoot)
/// together with the subpool's proof inside the MainPoolConfigTree.
pub struct SubpoolFullProof<H: MerkleHash> {
	pub main_pool_proof: MerkleProof<H>,
}

impl<H: MerkleHash> Default for SubpoolFullProof<H> {
	fn default() -> Self {
		Self {
			main_pool_proof: MerkleProof {
				leaf: H::ZERO,
				siblings: vec![H::ZERO; MAIN_POOL_CONFIG_DEPTH],
				path: vec![false; MAIN_POOL_CONFIG_DEPTH],
				pos: 0,
				num_leaves: 0,
				root: H::ZERO,
			},
		}
	}
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
	use rand::SeedableRng;
	use rand_chacha::ChaCha8Rng;

	use super::*;
	use crate::schnorr::{PrivateKey, PublicKey, Scalar};

	#[test]
	fn test_full_subpool_proof() {
		let mut rng = ChaCha8Rng::seed_from_u64(42);
		let approval = PrivateKey::sample(&mut rng).public_key().into();

		let subpool = SubpoolConfig::<HashOutput>::new(approval);

		let mut main_tree = MainPoolConfigTree::new();
		let subpool_id = SubpoolId(F::from_canonical_u64(5));
		main_tree
			.insert_subpool_at_position(subpool_id, subpool.commitment())
			.unwrap();

		let proof = main_tree
			.full_subpool_proof(&subpool, subpool_id)
			.expect("proof must be Some");

		assert!(proof.main_pool_proof.verify(), "main pool proof invalid");
	}
}
