use itertools::Itertools;
use plonky2::{hash::poseidon::PoseidonHash, plonk::config::Hasher};
use plonky2_field::types::{Field, Field64};
use primitive_types::U256;
use rand::{CryptoRng, Rng, RngExt, distr::Uniform};
use tessera_trees::F;

use crate::{
	account::{NullifierKey, PublicIdentifier, StandardAccount, SubpoolId},
	commitment::Commitment,
};

pub type NoteCommitment = Commitment;
pub type NoteNullifier = Commitment;

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
