use tessera_utils::{
	F, HASH_SIZE,
	hasher::{HashOutput, MerkleHash},
};

use crate::{MerkleTree, error::MerkleTreeResult};

impl<H: MerkleHash> MerkleTree<H> {
	pub fn merkle_proof(&self, index: usize) -> MerkleTreeResult<MerkleProof<H>> {
		let siblings = self.merkle_path(index, 0, self.depth())?;
		let leaf = if index < self.num_leaves() {
			self.leaves[index]
		} else {
			H::ZERO
		};
		let path = (0..self.depth()).map(|j| (index >> j) & 1 == 1).collect();
		let root = self.root();
		Ok(MerkleProof {
			leaf,
			siblings,
			path,
			pos: index,
			num_leaves: self.num_leaves(),
			root,
		})
	}
}

pub struct MerkleProof<H: MerkleHash> {
	pub leaf: H::Digest,
	pub siblings: Vec<H::Digest>,
	pub path: Vec<bool>,
	pub pos: usize,
	pub num_leaves: usize,
	pub root: H::Digest,
}

impl MerkleProof<HashOutput> {
	pub fn extract_siblings_bits(&self) -> (Vec<[F; HASH_SIZE]>, &[bool]) {
		let siblings = self.siblings.iter().map(|h| h.0).collect();
		(siblings, &self.path)
	}
}

impl<H: MerkleHash> MerkleProof<H> {
	pub fn verify(&self) -> bool {
		let mut current = self.leaf;
		for (bit, sibling) in self.path.iter().zip(self.siblings.iter()) {
			current = H::hash_2_to_1_swapped(&current, sibling, *bit);
		}
		current == self.root
	}
}
