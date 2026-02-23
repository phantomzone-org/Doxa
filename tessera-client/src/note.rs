use digest::{Digest, Output};
use itertools::Itertools;
use plonky2::{hash::poseidon::PoseidonHash, plonk::config::Hasher};
use plonky2_field::types::{Field, Field64, PrimeField64};
use primitive_types::U256;
use rand::{
	CryptoRng, Rng, RngExt,
	distr::{Uniform},
};
use serde::{Deserialize, Serialize};
use tessera_trees::{F, tree::{HASH_SIZE, hasher::Hash}};

use crate::account::{NullifierKey, PublicIdentifier, StandardAccount, SubpoolId};

#[derive(Clone, Copy)]
pub struct NodeIdentifier([F; 2]);

impl NodeIdentifier {
	pub fn from_rng<R: CryptoRng + Rng>(rng: &mut R) -> Self {
		Self(
			rng.sample_iter(Uniform::new(0, F::ORDER).unwrap())
				.take(2)
				.map(F::from_canonical_u64)
				.collect_array()
				.unwrap(),
		)
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteCommitment(pub [u8; 32]);

impl AsRef<[u8]> for NoteCommitment{
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl NoteCommitment {

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteNullifier(pub [u8; 32]);

impl AsRef<[u8]> for NoteNullifier{
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl NoteNullifier{

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

#[derive(Clone, Copy)]
pub struct RecipientCond {
	pub subpool_id: SubpoolId,
	public_id: PublicIdentifier,
}

impl RecipientCond {
	pub fn from_acc(acc: &StandardAccount) -> Self {
		Self {
			subpool_id: acc.subpool_id,
			public_id: acc.public_id(),
		}
	}
}

#[derive(Clone, Copy)]
pub struct SenderCond {
	subpool_id: SubpoolId,
	public_id: PublicIdentifier,
}

impl SenderCond {
	pub fn from_acc(acc: &StandardAccount) -> Self {
		Self {
			subpool_id: acc.subpool_id,
			public_id: acc.public_id(),
		}
	}
}

#[derive(Clone, Copy)]
pub struct StandardNote {
	identifier: NodeIdentifier,
	amt: U256,
	recipient: RecipientCond,
	sender: SenderCond,
}

impl StandardNote {
	pub fn commitment(&self) -> NoteCommitment {
		let mut input = [F::ZERO; 20];
		input[..2].copy_from_slice(self.identifier.0.as_slice());
		// TODO: add amount here
		// recipient condition
		input[10] = self.recipient.subpool_id.0;
		input[11..15].copy_from_slice(self.recipient.public_id.0.0.as_slice());
		// sender condition
		input[15] = self.sender.subpool_id.0;
		input[16..20].copy_from_slice(self.sender.public_id.0.0.as_slice());
		let note_comm = <PoseidonHash as Hasher<F>>::hash_no_pad(input.as_ref()).elements;
		NoteCommitment::new_from_field_elements(note_comm)
	}
}

#[derive(Clone)]
/// Note with its position in Note Commitment tree
pub struct PositionedStandardNode {
	note: StandardNote,
	position: F,
}

impl PositionedStandardNode {
	pub fn from_note(n: StandardNote, position: F) -> Self {
		Self {
			note: n,
			position,
		}
	}

	pub fn nullifier(&self, nk: &NullifierKey) -> NoteNullifier {
		let mut input = [F::ZERO; 9];
		input[..4].copy_from_slice(&self.note.commitment().as_field_elems());
		input[4..8].copy_from_slice(nk.0.as_slice());
		input[8] = self.position;
		let nullifier = <PoseidonHash as Hasher<F>>::hash_no_pad(input.as_ref()).elements;
		NoteNullifier::new_from_field_elements(nullifier)
	}
}

#[cfg(test)]
mod tests {
	use rand::rng;

	use super::*;

	impl StandardNote {
		pub fn sample_with(recipient: RecipientCond, sender: SenderCond, amt: U256) -> Self {
			let mut rng = rng();
			StandardNote {
				identifier: NodeIdentifier::from_rng(&mut rng),
				amt,
				recipient,
				sender,
			}
		}
	}
}
