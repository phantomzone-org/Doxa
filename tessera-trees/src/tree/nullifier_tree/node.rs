use std::{fmt::Display, marker::PhantomData};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
	bound(
		serialize = "H::Digest: Serialize",
		deserialize = "H::Digest: Deserialize<'de>"
	)
)]
pub struct Node<H: MerkleHash> {
	pub next_index: usize,
	pub value: H::Digest,
	pub next_value: H::Digest,
	pub(crate) _phantom: PhantomData<H>,
}

impl<H: MerkleHash> Display for Node<H> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		writeln!(f, "	hash      : {}", self.compute_hash())?;
		writeln!(f, "	next_index: {}", self.next_index)?;
		writeln!(f, "	value     : {}", self.value)?;
		writeln!(f, "	next_value: {}", self.next_value)
	}
}

impl<H: MerkleHash> Node<H> {
	pub(crate) fn first() -> Self {
		Self::new(H::HEAD, 0, H::TAIL)
	}

	pub fn new(value: H::Digest, next_index: usize, next_value: H::Digest) -> Self {
		Self {
			next_index,
			value,
			next_value,
			_phantom: PhantomData,
		}
	}
}

impl<H: MerkleHash> Node<H> {
	pub fn compute_hash(&self) -> H::Digest {
		H::commit_node(&self.value, self.next_index, &self.next_value)
	}

	/// Determines if the node is active.
	pub fn is_active(&self) -> bool {
		self.value != H::HEAD
	}
}

#[cfg(test)]
use rand::Rng;

use crate::tree::hasher::MerkleHash;
#[cfg(test)]
use crate::tree::hasher::NewRandom;

#[cfg(test)]
impl<H: MerkleHash> Node<H>
where
	H::Digest: NewRandom,
{
	/// Creates a random node for testing purposes.
	/// Uses index 0 and TAIL as next_value, with a random value.
	pub fn new_random<R: Rng + ?Sized>(rng: &mut R) -> Self {
		let value = H::Digest::new_random(rng);
		Self::new(value, 0, H::TAIL)
	}
}
