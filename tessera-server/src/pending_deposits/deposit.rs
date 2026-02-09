use serde::{Deserialize, Serialize};
use tessera_trees::{
	tree::hasher::{Hash, MerkleHash},
	F,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDeposit {
	note_commitment: Hash,
	address: [F; 3],
	amount: F,
}

impl PendingDeposit {
	pub fn new(note_commitment: Hash, address: [F; 3], amount: F) -> Self {
		Self {
			note_commitment,
			address,
			amount,
		}
	}

	pub fn note_commitment(&self) -> Hash {
		self.note_commitment
	}

	pub fn address(&self) -> [F; 3] {
		self.address
	}

	pub fn amount(&self) -> F {
		self.amount
	}

	pub fn hash(&self) -> Hash {
		// Hash the note commitment, address, and amount together to get a unique hash for this
		// pending deposit
		let tmp: Hash = Hash::new([
			self.address[0],
			self.address[1],
			self.address[2],
			self.amount,
		]);
		Hash::hash_2_to_1(&self.note_commitment, &tmp, false)
	}
}
