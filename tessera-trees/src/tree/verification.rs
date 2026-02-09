use anyhow::anyhow;

use crate::tree::{
	MerkleTree,
	error::{MerkleTreeError, MerkleTreeResult},
	hasher::MerkleHash,
};

impl<H: MerkleHash> MerkleTree<H> {
	pub fn verify(&self) -> MerkleTreeResult<()> {
		self.verify_layers()?;
		self.verify_root()?;
		Ok(())
	}

	fn verify_layers(&self) -> MerkleTreeResult<()> {
		let mut prev_hashes: Vec<H::Digest> = self.leaves.iter().map(|n| *n).collect();

		for (level, layer) in self.layers.iter().enumerate() {
			let mut expected_layer = Vec::with_capacity(layer.len());

			let mut i = 0;
			while i < prev_hashes.len() {
				let left = &prev_hashes[i];
				let right = if i + 1 < prev_hashes.len() {
					&prev_hashes[i + 1]
				} else {
					&self.default_siblings[level]
				};

				expected_layer.push(H::hash_2_to_1(left, right, false));
				i += 2;
			}

			if &expected_layer != layer {
				return Err(anyhow!(MerkleTreeError::LayerMismatch(level)));
			}

			prev_hashes = expected_layer;
		}

		Ok(())
	}

	fn verify_root(&self) -> MerkleTreeResult<()> {
		let recomputed_root = self.recompute_root();
		let stored_root = self.get_root();

		if recomputed_root != stored_root {
			return Err(anyhow!(MerkleTreeError::RootMismatch));
		}

		Ok(())
	}

	fn recompute_root(&self) -> H::Digest {
		let mut current: Vec<H::Digest> = self.leaves.iter().map(|n| *n).collect();

		for level in 0..self.depth() {
			let mut next = Vec::with_capacity((current.len() + 1) / 2);

			let mut i = 0;
			while i < current.len() {
				let left = &current[i];
				let right = if i + 1 < current.len() {
					&current[i + 1]
				} else {
					&self.default_siblings[level]
				};

				next.push(H::hash_2_to_1(left, right, false));
				i += 2;
			}

			current = next;
		}

		debug_assert_eq!(current.len(), 1);
		current[0]
	}
}
