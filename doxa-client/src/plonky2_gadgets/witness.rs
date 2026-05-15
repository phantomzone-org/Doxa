use plonky2::{
	hash::hash_types::HashOutTarget,
	iop::{
		target::Target,
		witness::{PartialWitness, WitnessWrite},
	},
};
use plonky2_field::{
	extension::Extendable,
	types::{Field, PrimeField64},
};
use doxa_utils::{
	F,
	hasher::{HashOutput, ToHashOut},
};

use crate::{
	DEFAULT_SPEND_AUTH_PK, SubpoolId,
	ecgfp5::{CompressedPoint, Legendre, PointEw},
	plonky2_gadgets::{
		priv_tx::targets::SubpoolFullProofTargets,
		signature::{PubkeyTarget, SchnorrTargets, set_schnorr_witness},
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolFullProof},
	schnorr::{CompressedPublicKey, Scalar, Signature, schnorr_challenge},
};

impl SchnorrTargets {
	pub(crate) fn set(
		&self,
		pw: &mut PartialWitness<F>,
		pk: CompPubKey,
		tx_hash: HashOutput,
		signature: &Signature,
	) {
		let cr = signature.r.encode();
		let e = schnorr_challenge(&cr, &pk.0, &tx_hash.0);
		// let e = Scalar::ONE;
		set_schnorr_witness(pw, self, PointEw::decode(pk.0).unwrap(), cr, e, signature.s);
	}

	pub(crate) fn set_dummy(&self, pw: &mut PartialWitness<F>, pk: CompPubKey) {
		let q = PointEw::decode(pk.0).unwrap();
		let e = Scalar::ONE;
		let s = Scalar::ONE;
		let r = PointEw::generator().scalar_mul(&s).add(&q.scalar_mul(&e));
		set_schnorr_witness(pw, self, q, r.encode(), e, s);
	}
}

pub(crate) fn set_hash_blocks<const N: usize>(
	pw: &mut PartialWitness<F>,
	targets: &[HashOutTarget; N],
	values: &[[F; 4]; N],
) {
	for (row_targets, row_values) in targets.iter().zip(values.iter()) {
		for (&target, &value) in row_targets.elements.iter().zip(row_values.iter()) {
			pw.set_target(target, value).unwrap();
		}
	}
}
