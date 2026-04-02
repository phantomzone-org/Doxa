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
use tessera_utils::{
	F,
	hasher::{HashOutput, ToHashOut},
};

use crate::{
	SubpoolId,
	ecgfp5::{Legendre, PointEw},
	plonky2_gadgets::{
		priv_tx::targets::SubpoolFullProofTargets,
		signature::{PubkeyTarget, SchnorrTargets, set_schnorr_witness},
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree, SubpoolFullProof},
	schnorr::{CompressedPublicKey, Scalar, Signature, schnorr_challenge},
};

pub(crate) fn fake_authority_key<F>() -> CompressedPublicKey<F>
where
	F: PrimeField64 + Extendable<5> + Legendre,
{
	CompressedPublicKey(PointEw::generator().encode())
}

pub(crate) fn set_authority_keys(
	pw: &mut PartialWitness<F>,
	approval_target: PubkeyTarget,
	rejection_target: PubkeyTarget,
	consume_target: PubkeyTarget,
	approval_key: CompPubKey,
	rejection_key: CompPubKey,
	consume_key: CompPubKey,
) {
	approval_target.set_witness(pw, approval_key);
	rejection_target.set_witness(pw, rejection_key);
	consume_target.set_witness(pw, consume_key);
}

pub(crate) fn set_subpool_full_proof(
	pw: &mut PartialWitness<F>,
	targets: &SubpoolFullProofTargets,
	subpool_proof: SubpoolFullProof<HashOutput>,
	subpool_root: HashOutput,
	subpool_id: SubpoolId,
	approval_key: CompPubKey,
	rejection_key: CompPubKey,
	consume_key: CompPubKey,
) {
	targets
		.approval_proof
		.set_witness(pw, &subpool_proof.approval_proof);
	targets
		.rejection_proof
		.set_witness(pw, &subpool_proof.rejection_proof);
	targets
		.consume_proof
		.set_witness(pw, &subpool_proof.consume_proof);
	targets
		.main_pool_proof
		.set_witness(pw, &subpool_proof.main_pool_proof);
	pw.set_hash_target(targets.subpool_config_root.0, subpool_root.to_hash_out())
		.unwrap();
}

impl SchnorrTargets {
	pub(crate) fn set(
		&self,
		pw: &mut PartialWitness<F>,
		pk: CompPubKey,
		tx_hash: HashOutput,
		signature: Signature,
	) {
		let cr = signature.r.encode();
		let e = schnorr_challenge(&cr, &pk.0, &tx_hash.0);
		set_schnorr_witness(pw, self, PointEw::decode(pk.0).unwrap(), cr, e, signature.s);
	}

	pub(crate) fn set_fake(&self, pw: &mut PartialWitness<F>, pk: CompPubKey) {
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
