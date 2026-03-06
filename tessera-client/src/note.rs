use itertools::Itertools;
use plonky2::{hash::poseidon::PoseidonHash, plonk::config::Hasher};
use plonky2_field::types::{Field, Field64};
use primitive_types::U256;
use rand::{CryptoRng, Rng, RngExt, distr::Uniform};
use tessera_trees::{F, tree::hasher::HashOutput};

use crate::{
	account::{NullifierKey, PublicIdentifier, StandardAccount, SubpoolId},
	commitment::Commitment,
};

pub struct NoteCommitment(pub HashOutput);
pub struct NoteNullifier(pub HashOutput);

#[derive(Clone, Copy)]
pub struct NodeIdentifier(pub(crate) [F; 2]);

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
	pub(crate) public_id: PublicIdentifier,
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
	pub(crate) subpool_id: SubpoolId,
	pub(crate) public_id: PublicIdentifier,
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
pub struct AssetId(pub(crate) F);

#[derive(Clone, Copy)]
pub struct StandardNote {
	pub(crate) identifier: NodeIdentifier,
	pub(crate) asset_id: AssetId,
	pub(crate) amt: U256,
	pub(crate) recipient: RecipientCond,
	pub(crate) sender: SenderCond,
}

impl StandardNote {
	pub fn commitment(&self) -> NoteCommitment {
		let mut input = [F::ZERO; 20];
		input[..2].copy_from_slice(self.identifier.0.as_slice());
		// amount: U256.0 is [u64; 4] little-endian words, split into lo/hi u32 limbs
		for (i, word) in self.amt.0.iter().enumerate() {
			input[2 + i * 2] = F::from_canonical_u32(*word as u32);
			input[2 + i * 2 + 1] = F::from_canonical_u32((*word >> 32) as u32);
		}
		// recipient condition
		input[10] = self.recipient.subpool_id.0;
		input[11..15].copy_from_slice(self.recipient.public_id.0.0.as_slice());
		// sender condition
		input[15] = self.sender.subpool_id.0;
		input[16..20].copy_from_slice(self.sender.public_id.0.0.as_slice());

		NoteCommitment(HashOutput(
			<PoseidonHash as Hasher<F>>::hash_no_pad(input.as_ref()).elements,
		))
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
		input[..4].copy_from_slice(&self.note.commitment().0.0);
		input[4] = self.position;
		input[5..9].copy_from_slice(nk.0.as_slice());

		NoteNullifier(HashOutput(
			<PoseidonHash as Hasher<F>>::hash_no_pad(input.as_ref()).elements,
		))
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
				asset_id: AssetId(F::ZERO),
				amt,
				recipient,
				sender,
			}
		}
	}
}
