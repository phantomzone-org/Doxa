use itertools::Itertools;
use plonky2::{hash::poseidon::PoseidonHash, plonk::config::Hasher};
use plonky2_field::{
	goldilocks_field::GoldilocksField,
	types::{Field, Field64},
};
use primitive_types::U256;
use rand::{
	CryptoRng, Rng, RngExt,
	distr::{StandardUniform, Uniform},
};
use tessera_trees::{F, tree::hasher::Hash};

use crate::account::{NullifierKey, PublicIdentifier, StandardAccount, SubpoolId};

#[derive(Clone, Copy)]
pub(crate) struct NodeIdentifier([F; 2]);

impl NodeIdentifier {
	pub(crate) fn from_rng<R: CryptoRng + Rng>(rng: &mut R) -> Self {
		Self(
			rng.sample_iter(Uniform::new(0, F::ORDER).unwrap())
				.take(2)
				.map(F::from_canonical_u64)
				.collect_array()
				.unwrap(),
		)
	}
}

#[derive(PartialEq, Eq, Clone)]
pub(crate) struct NoteCommitment(pub(crate) Hash);

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct NoteNullifier(pub(crate) Hash);

// TODO: these names are not good, change them
#[derive(Clone, Copy)]
pub(crate) struct SpendCond {
	pub(crate) rcvsbpool_id: SubpoolId,
	rcvpblic_id: PublicIdentifier,
}

impl SpendCond {
	pub(crate) fn from_acc(acc: &StandardAccount) -> Self {
		Self {
			rcvsbpool_id: acc.subpool_id,
			rcvpblic_id: acc.public_id(),
		}
	}
}

#[derive(Clone, Copy)]
pub(crate) struct RejectCond {
	sndsbpool_id: SubpoolId,
	sndpblic_id: PublicIdentifier,
}

impl RejectCond {
	pub(crate) fn from_acc(acc: &StandardAccount) -> Self {
		Self {
			sndsbpool_id: acc.subpool_id,
			sndpblic_id: acc.public_id(),
		}
	}
}

#[derive(Clone, Copy)]
pub(crate) struct StandardNote {
	identifier: NodeIdentifier,
	amt: U256,
	spnd_cond: SpendCond,
	rjct_cond: RejectCond,
}

impl StandardNote {
	pub(crate) fn commitment(&self) -> NoteCommitment {
		let mut input = [F::ZERO; 20];
		input[..2].copy_from_slice(self.identifier.0.as_slice());
		// TODO: add amount here
		// spnd_cond
		input[10] = self.spnd_cond.rcvsbpool_id.0;
		input[11..15].copy_from_slice(self.spnd_cond.rcvpblic_id.0.0.as_slice());
		// rjct codn
		input[15] = self.rjct_cond.sndsbpool_id.0;
		input[16..20].copy_from_slice(self.rjct_cond.sndpblic_id.0.0.as_slice());
		let note_comm = <PoseidonHash as Hasher<F>>::hash_no_pad(input.as_ref()).elements;
		NoteCommitment(note_comm.into())
	}
}

#[derive(Clone)]
/// Note with its position in Note Commitment tree
pub(crate) struct PositionedStandardNode {
	note: StandardNote,
	position: F,
}

impl PositionedStandardNode {
	pub(crate) fn from_note(n: StandardNote, position: F) -> Self {
		Self {
			note: n,
			position,
		}
	}

	pub(crate) fn nullifier(&self, nk: &NullifierKey) -> NoteNullifier {
		let mut input = [F::ZERO; 9];
		input[..4].copy_from_slice(self.note.commitment().0.0.as_slice());
		input[4..8].copy_from_slice(nk.0.as_slice());
		input[8] = self.position;
		let nullifier = <PoseidonHash as Hasher<F>>::hash_no_pad(input.as_ref()).elements;
		NoteNullifier(nullifier.into())
	}
}

#[cfg(test)]
mod tests {
	use rand::rng;

	use super::*;

	impl StandardNote {
		pub(crate) fn sample_with(spnd_cond: SpendCond, rjct_cond: RejectCond, amt: U256) -> Self {
			let mut rng = rng();
			StandardNote {
				identifier: NodeIdentifier::from_rng(&mut rng),
				amt,
				spnd_cond,
				rjct_cond,
			}
		}
	}
}
