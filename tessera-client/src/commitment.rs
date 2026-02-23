use digest::{Digest, Output};
use plonky2_field::types::{Field, PrimeField64};

use serde::{Deserialize, Serialize};
use tessera_trees::{F, tree::{HASH_SIZE, hasher::Hash}};


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment(pub [u8; 32]);

impl AsRef<[u8]> for Commitment{
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl Commitment{

	pub fn new_from_field_elements(elems: [F; HASH_SIZE]) -> Self{
		let mut out = [0u8; 32];
		for (i, f) in elems.into_iter().enumerate() {
			let bytes = f.to_canonical_u64().to_le_bytes();
			out[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
		}
		Self(out)
	}

	pub fn new_from_bytes(bytes: [u8; 32]) -> Self {
		let mut elems = [F::ZERO; HASH_SIZE];
		for i in 0..HASH_SIZE {
			let chunk = u64::from_be_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
			elems[i] = F::from_canonical_u64(chunk & 0x7FFF_FFFF_FFFF_FFFF);
		}
		Self::new_from_field_elements(elems)
	}

	pub fn hash_inplace<H: Digest>(&self, out: &mut Output<H>) {
		let mut hasher = H::new();
		hasher.update(self.as_ref());
		*out = hasher.finalize();
	}

	pub fn hash<H: Digest>(&self) -> Output<H> {
		let mut out = Output::<H>::default();
		self.hash_inplace::<H>(&mut out);
		out
	}

	pub fn as_field_elems(&self) -> [F; HASH_SIZE]{
		let mut elems = [F::ZERO; HASH_SIZE];
		for (i, chunk) in self.0.chunks_exact(8).take(HASH_SIZE).enumerate() {
			let bytes: [u8; 8] = chunk.try_into().unwrap();
			elems[i] = F::from_canonical_u64(u64::from_le_bytes(bytes));
		}
		elems
	}

	pub fn as_field_hash(&self) -> Hash {
		Hash(self.as_field_elems())
	}
}