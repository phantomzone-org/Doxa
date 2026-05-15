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
use doxa_trees::{MerkleProof, MerkleTree, error::MerkleTreeResult};
use doxa_utils::{
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

/// Public key of the authority key of the subpool
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

	/// Insert a subpool at the leaf position `subpool_id` in the config tree,
	/// matching the on-chain convention used by `updateSubpoolRoot`.
	///
	/// Subpools must be inserted **sequentially**: 1, 2, 3, … with no gaps.
	///
	/// * `subpool_id = 1` — always allowed.  Position 0 is permanently reserved (zero leaf); it is
	///   seeded automatically on the first call.
	/// * `subpool_id = N > 1` — only allowed if `subpool_id = N − 1` has already been inserted
	///   (i.e. the tree has exactly `N` leaves at the time of the call, meaning positions 0 … N−1
	///   are all occupied).
	///
	/// # Errors
	/// * `subpool_id == 0` — reserved, always rejected.
	/// * `subpool_id > 1` and the previous subpool has not been inserted yet.
	/// * Any underlying [`MerkleTree`] error.
	pub fn insert_subpool_at_position(
		&mut self,
		subpool_id: SubpoolId,
		subpool_root: HashOutput,
	) -> MerkleTreeResult<()> {
		let id = subpool_id.0.to_canonical_u64() as usize;
		anyhow::ensure!(id > 0, "subpool_id 0 is reserved and cannot be used");

		if id == 1 {
			// Seed the permanently-reserved position 0 on first use.
			if self.inner.num_leaves() == 0 {
				self.inner.insert(H::ZERO)?; // position 0: reserved zero
			}
			// After seeding, inner.num_leaves() == 1; next insert → position 1.
		} else {
			// Enforce sequential insertion: position id−1 must already exist.
			anyhow::ensure!(
				self.inner.num_leaves() == id,
				"cannot insert subpool_id={id}: subpool_id={} must be inserted first \
				 (tree has {} leaves, expected {id})",
				id - 1,
				self.inner.num_leaves(),
			);
		}

		let digest = if subpool_root == H::ZERO {
			H::ZERO // uninitialized subpool: spec says leaf = H::ZERO, not Poseidon(id, 0)
		} else {
			MainPoolConfigLeaf::<H>::new(subpool_root, subpool_id).commit()
		};
		let inserted_at = self.inner.insert(digest)?;
		debug_assert_eq!(inserted_at, id, "inserted at wrong position");
		// Only add to leaf_index_map when digest is non-zero (zero is the default/sentinel value)
		if digest != H::ZERO {
			self.leaf_index_map.insert(digest, id);
		}
		Ok(())
	}

	/// Return the Merkle proof for a subpool inside this tree.
	pub fn subpool_proof(
		&self,
		subpool_id: SubpoolId,
		subpool_config_comm: H::Digest,
	) -> MerkleTreeResult<MerkleProof<H>> {
		if subpool_config_comm == H::ZERO {
			// Zero-root subpool: leaf = H::ZERO stored at position subpool_id
			let id = subpool_id.0.to_canonical_u64() as usize;
			return self.inner.merkle_proof(id);
		}
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
			subpool_config: SubpoolConfig::new(subpool.approval_key()),
			subpool_id,
		})
	}
}

// ── Combined proof ────────────────────────────────────────────────────────────

/// All three subpool authority-key proofs (relative to the SubpoolConfigRoot)
/// together with the subpool's proof inside the MainPoolConfigTree.
pub struct SubpoolFullProof<H: MerkleHash<Digest = HashOutput>> {
	pub main_pool_proof: MerkleProof<H>,
	pub subpool_config: SubpoolConfig<H>,
	pub subpool_id: SubpoolId,
}

impl<H: MerkleHash<Digest = HashOutput>> Default for SubpoolFullProof<H> {
	fn default() -> Self {
		// Same key as fake_approval_key() in plonky2_gadgets/priv_tx/utils.rs
		// Note: should be a valid public key
		let dummy_key = CompressedPublicKey(
			[
				7613690455422068269u64,
				12930951591626745075,
				16103143792840800039,
				4657200339622395349,
				3857357297380158342,
			]
			.into(),
		);
		Self {
			main_pool_proof: MerkleProof {
				leaf: H::ZERO,
				siblings: vec![H::ZERO; MAIN_POOL_CONFIG_DEPTH],
				path: vec![false; MAIN_POOL_CONFIG_DEPTH],
				pos: 0,
				num_leaves: 0,
				root: H::ZERO,
			},
			subpool_config: SubpoolConfig::new(dummy_key),
			subpool_id: SubpoolId(F::ZERO),
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
		// Insert subpools 1-4 as sequential prerequisites (zero roots = uninitialized)
		for i in 1u64..5 {
			main_tree
				.insert_subpool_at_position(SubpoolId(F::from_canonical_u64(i)), HashOutput::ZERO)
				.unwrap();
		}
		let subpool_id = SubpoolId(F::from_canonical_u64(5));
		main_tree
			.insert_subpool_at_position(subpool_id, subpool.commitment())
			.unwrap();

		let proof = main_tree
			.full_subpool_proof(&subpool, subpool_id)
			.expect("proof must be Some");

		assert!(proof.main_pool_proof.verify(), "main pool proof invalid");
	}

	#[test]
	fn test_zero_root_subpool_proof() {
		let mut main_tree = MainPoolConfigTree::<HashOutput>::new();

		// Insert subpool 1 with a non-zero root
		let non_zero_root = HashOutput([F::from_canonical_u64(42), F::ZERO, F::ZERO, F::ZERO]);
		let subpool_id_1 = SubpoolId(F::from_canonical_u64(1));
		main_tree
			.insert_subpool_at_position(subpool_id_1, non_zero_root)
			.unwrap();

		// Insert subpool 2 with a zero root (uninitialized)
		let subpool_id_2 = SubpoolId(F::from_canonical_u64(2));
		main_tree
			.insert_subpool_at_position(subpool_id_2, HashOutput::ZERO)
			.unwrap();

		// Requesting proof for the zero-root subpool should succeed
		let proof = main_tree
			.subpool_proof(subpool_id_2, HashOutput::ZERO)
			.expect("proof must be Ok for zero-root subpool");

		assert_eq!(
			proof.leaf,
			HashOutput::ZERO,
			"leaf should be H::ZERO for zero-root subpool"
		);
		assert!(
			proof.verify(),
			"Merkle proof for zero-root subpool should be valid"
		);
	}
}
