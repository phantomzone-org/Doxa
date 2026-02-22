use plonky2::{
	hash::{
		hashing::{hash_n_to_hash_no_pad, hash_n_to_m_no_pad},
		poseidon::PoseidonHash,
	},
	plonk::config::Hasher,
};
use plonky2_field::types::{Field, Field64};
use primitive_types::U256;
use rand::{CryptoRng, Rng, RngExt};
use tessera_trees::{F, tree::hasher::Hash};

use crate::{DS_NULLIFIER_KEY, DS_PUBLIC_IDENTIFIER, schnorr::PublicKey};

#[derive(PartialEq, Eq, Clone, Debug)]
pub(crate) struct NullifierKey(pub(crate) [F; 4]);

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub(crate) struct PrivateIdentifier([F; 2]);

impl PrivateIdentifier {
	fn sample<R: CryptoRng + Rng>(rng: &mut R) -> PrivateIdentifier {
		let arr = core::array::from_fn(|_| F::from_canonical_u64(rng.random_range(0..F::ORDER)));
		PrivateIdentifier(arr)
	}
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub(crate) struct PublicIdentifier(pub(crate) Hash);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct SubpoolId(pub(crate) F);

#[derive(Debug, Clone)]
pub(crate) struct Nonce(pub(crate) F);

#[derive(Debug, Clone, Default)]
pub(crate) struct Auth {
	pub(crate) nspend_pk: Option<PublicKey<F>>,
}

#[derive(Clone, Debug)]
pub(crate) struct StandardAccount {
	pub(crate) private_identifier: PrivateIdentifier,
	pub(crate) subpool_id: SubpoolId,
	pub(crate) balance: U256,
	pub(crate) nonce: Nonce,
	pub(crate) auth: Auth,
}

impl StandardAccount {
	pub(crate) fn sample<R: CryptoRng + Rng>(rng: &mut R, subpool_id: SubpoolId) -> Self {
		let private_identifier = PrivateIdentifier::sample(rng);
		StandardAccount {
			private_identifier,
			subpool_id,
			balance: U256::zero(),
			nonce: Nonce(F::ZERO),
			auth: Auth::default(),
		}
	}

	pub(crate) fn public_id(&self) -> PublicIdentifier {
		let mut input = [F::ZERO; 3];
		input[0] = F::from_canonical_u64(DS_PUBLIC_IDENTIFIER);
		input[1..].copy_from_slice(self.private_identifier.0.as_slice());
		let pubid = <PoseidonHash as Hasher<F>>::hash_no_pad(input.as_slice()).elements;
		PublicIdentifier(pubid.into())
	}

	pub(crate) fn nk(&self) -> NullifierKey {
		let mut input = [F::ZERO; 3];
		input[0] = F::from_canonical_u64(DS_NULLIFIER_KEY);
		input[1..].copy_from_slice(self.private_identifier.0.as_slice());
		let nk = <PoseidonHash as Hasher<F>>::hash_no_pad(input.as_ref()).elements;
		NullifierKey(nk.into())
	}
}

#[cfg(test)]
mod tests {
	use std::array;

	use rand::rng;
	use tessera_trees::tree::CommitmentTree;

	use super::*;
	use crate::{
		NOTE_BATCH,
		note::{PositionedStandardNode, RejectCond, SpendCond, StandardNote},
	};

	impl StandardAccount {
		fn set_auth(&mut self, auth: Auth) {
			self.auth = auth;
		}
	}

	#[test]
	fn testtest() {
		let mut tree = CommitmentTree::<Hash>::new(32);

		let mut rng = rng();
		let sbpoolid = SubpoolId(F::ONE);
		let [acc0, acc1] = array::from_fn(|_| StandardAccount::sample(&mut rng, sbpoolid));
		let notes: [StandardNote; NOTE_BATCH] = array::from_fn(|i| {
			StandardNote::sample_with(
				SpendCond::from_acc(&acc0),
				RejectCond::from_acc(&acc1),
				U256::from(i),
			)
		});
		let ncs = notes.map(|n| n.commitment());
		let pnotes = ncs.iter().enumerate().map(|(i, nc)| {
			tree.insert(nc.0).unwrap();
			PositionedStandardNode::from_note(notes[i], F::from_canonical_usize(i))
		});

		// let mrklpaths = pnotes.map(|pn| tree.)
	}
}
