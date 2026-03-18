use std::hash::Hash;

use plonky2::{hash::poseidon::PoseidonHash, plonk::config::Hasher};
use plonky2_field::types::{Field, PrimeField64};
use tessera_trees::{
	F,
	tree::{HASH_SIZE, hasher::HashOutput},
};

use crate::{
	MAIN_POOL_CONFIG_DEPTH, SubpoolId,
	schnorr::CompressedPublicKey,
	tree::{GenericNode, Leaf, MerkleProof, MerkleTree},
};

// ── CompressedPublicKey ───────────────────────────────────────────────────────

pub type CompPubKey = CompressedPublicKey<F>;

// ── SubpoolConfigTree ─────────────────────────────────────────────────────────

/// A leaf in the SubpoolConfigTree: a compressed public key, or empty (the 4th slot).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SubpoolConfigLeaf(pub Option<CompPubKey>);

impl Hash for SubpoolConfigLeaf {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		match &self.0 {
			Some(cpk) => {
				1u8.hash(state);
				for f in &cpk.0.w.0 {
					f.to_canonical_u64().hash(state);
				}
			},
			None => 0u8.hash(state),
		}
	}
}

impl Leaf for SubpoolConfigLeaf {
	type Node = GenericNode<SubpoolConfigLeaf>;

	fn empty() -> Self::Node {
		SubpoolConfigLeaf(None).into()
	}
}

impl From<SubpoolConfigLeaf> for GenericNode<SubpoolConfigLeaf> {
	fn from(leaf: SubpoolConfigLeaf) -> Self {
		let inputs: [F; 5] = match leaf.0 {
			Some(cpk) => cpk.0.w.0,
			None => [F::ZERO; 5],
		};
		let hash = <PoseidonHash as Hasher<F>>::hash_no_pad(&inputs).elements;
		Self::from(HashOutput(hash))
	}
}

pub type SubpoolConfigNode = GenericNode<SubpoolConfigLeaf>;

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
pub struct SubpoolConfigTree {
	pub approval_key: CompPubKey,
	pub rejection_key: CompPubKey,
	pub consume_key: CompPubKey,
	inner: MerkleTree<2, SubpoolConfigNode>,
}

impl SubpoolConfigTree {
	/// Build the tree from the three authority keys.
	/// Keys are inserted at fixed positions 0, 1, 2 via `insert` (in order).
	/// Position 3 remains the default empty leaf.
	pub fn new(approval: CompPubKey, rejection: CompPubKey, consume: CompPubKey) -> Self {
		let mut inner = MerkleTree::new();
		inner.insert(SubpoolConfigLeaf(Some(approval)));
		inner.insert(SubpoolConfigLeaf(Some(rejection)));
		inner.insert(SubpoolConfigLeaf(Some(consume)));
		Self {
			approval_key: approval,
			rejection_key: rejection,
			consume_key: consume,
			inner,
		}
	}

	pub fn root(&self) -> HashOutput {
		self.inner.root()
	}

	pub fn approval_key_proof(&self) -> MerkleProof<SubpoolConfigNode, 2> {
		self.inner
			.merkle_proof(SubpoolConfigLeaf(Some(self.approval_key)))
			.expect("approval key must be in tree")
	}

	pub fn rejection_key_proof(&self) -> MerkleProof<SubpoolConfigNode, 2> {
		self.inner
			.merkle_proof(SubpoolConfigLeaf(Some(self.rejection_key)))
			.expect("rejection key must be in tree")
	}

	pub fn consume_key_proof(&self) -> MerkleProof<SubpoolConfigNode, 2> {
		self.inner
			.merkle_proof(SubpoolConfigLeaf(Some(self.consume_key)))
			.expect("consume key must be in tree")
	}
}

// ── MainPoolConfigTree ────────────────────────────────────────────────────────

/// A leaf in the MainPoolConfigTree storing the raw subpool root and subpool id as field elements.
///
/// `Hash` is implemented by converting each `F` to its canonical `u64` representation —
/// no Poseidon involved. Poseidon is only used in `From<MainPoolConfigLeaf> for Node`
/// to compute the on-tree node value `H(subpool_root || subpool_id)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MainPoolConfigLeaf {
	pub subpool_root: HashOutput,
	pub subpool_id: SubpoolId,
}

impl std::hash::Hash for MainPoolConfigLeaf {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		for f in &self.subpool_root.0 {
			f.to_canonical_u64().hash(state);
		}
		self.subpool_id.0.to_canonical_u64().hash(state);
	}
}

impl MainPoolConfigLeaf {
	pub fn new(subpool_root: HashOutput, subpool_id: SubpoolId) -> Self {
		Self {
			subpool_root,
			subpool_id,
		}
	}
}

impl Leaf for MainPoolConfigLeaf {
	type Node = GenericNode<MainPoolConfigLeaf>;

	fn empty() -> Self::Node {
		// TODO: any reason to change from [0;4] to default inon-zero value?
		MainPoolConfigLeaf {
			subpool_root: HashOutput([F::ZERO; HASH_SIZE]),
			subpool_id: SubpoolId(F::ZERO),
		}
		.into()
	}
}

impl From<MainPoolConfigLeaf> for GenericNode<MainPoolConfigLeaf> {
	fn from(leaf: MainPoolConfigLeaf) -> Self {
		let mut input = [F::ZERO; HASH_SIZE + 1];
		input[..HASH_SIZE].copy_from_slice(&leaf.subpool_root.0);
		input[HASH_SIZE] = leaf.subpool_id.0;
		let hash = <PoseidonHash as Hasher<F>>::hash_no_pad(&input).elements;
		Self::from(HashOutput(hash))
	}
}

pub type MainPoolConfigNode = GenericNode<MainPoolConfigLeaf>;

/// A depth-20 Merkle tree where position `subpool_id` holds
/// TODO: swap the order below
/// `H(SubpoolConfigRoot || subpool_id)`.
pub struct MainPoolConfigTree {
	inner: MerkleTree<MAIN_POOL_CONFIG_DEPTH, MainPoolConfigNode>,
}

impl MainPoolConfigTree {
	pub fn new() -> Self {
		Self {
			inner: MerkleTree::new(),
		}
	}

	pub fn root(&self) -> HashOutput {
		self.inner.root()
	}

	/// Insert or update the entry for `subpool_id` at the given `index` in the tree.
	pub fn set_subpool(&mut self, index: usize, subpool_id: SubpoolId, subpool_root: HashOutput) {
		let leaf = MainPoolConfigLeaf::new(subpool_root, subpool_id);
		self.inner.set_leaf(index, leaf);
	}

	/// Return the Merkle proof for a subpool inside this tree.
	pub fn subpool_proof(
		&self,
		subpool_id: SubpoolId,
		subpool_root: HashOutput,
	) -> Option<MerkleProof<MainPoolConfigNode, MAIN_POOL_CONFIG_DEPTH>> {
		let leaf = MainPoolConfigLeaf::new(subpool_root, subpool_id);
		self.inner.merkle_proof(leaf)
	}

	/// Return proofs for all three authority keys in `subpool` plus the subpool's
	/// own proof inside this main pool tree.
	pub fn full_subpool_proof(
		&self,
		subpool: &SubpoolConfigTree,
		subpool_id: SubpoolId,
	) -> Option<SubpoolFullProof> {
		let main_pool_proof = self.subpool_proof(subpool_id, subpool.root())?;
		Some(SubpoolFullProof {
			approval_proof: subpool.approval_key_proof(),
			rejection_proof: subpool.rejection_key_proof(),
			consume_proof: subpool.consume_key_proof(),
			main_pool_proof,
		})
	}
}

// ── Combined proof ────────────────────────────────────────────────────────────

/// All three subpool authority-key proofs (relative to the SubpoolConfigRoot)
/// together with the subpool's proof inside the MainPoolConfigTree.
pub struct SubpoolFullProof {
	pub approval_proof: MerkleProof<SubpoolConfigNode, 2>,
	pub rejection_proof: MerkleProof<SubpoolConfigNode, 2>,
	pub consume_proof: MerkleProof<SubpoolConfigNode, 2>,
	pub main_pool_proof: MerkleProof<MainPoolConfigNode, MAIN_POOL_CONFIG_DEPTH>,
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

		let subpool = SubpoolConfigTree::new(approval, rejection, consume);

		let mut main_tree = MainPoolConfigTree::new();
		let index = 7_usize;
		let subpool_id = SubpoolId(F::from_canonical_u64(5));
		main_tree.set_subpool(index, subpool_id, subpool.root());

		let proof = main_tree
			.full_subpool_proof(&subpool, subpool_id)
			.expect("proof must be Some");

		assert!(proof.approval_proof.verify(), "approval proof invalid");
		assert!(proof.rejection_proof.verify(), "rejection proof invalid");
		assert!(proof.consume_proof.verify(), "consume proof invalid");
		assert!(proof.main_pool_proof.verify(), "main pool proof invalid");
	}
}
