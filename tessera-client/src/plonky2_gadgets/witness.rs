use plonky2::iop::{
	target::Target,
	witness::{PartialWitness, WitnessWrite},
};
use tessera_trees::F;

use crate::{
	SubpoolId,
	ecgfp5::PointEw,
	plonky2_gadgets::{
		merkle::SetMerklePathOfWitness,
		priv_tx::targets::SubpoolFullProofTargets,
		signature::{PubkeyTarget, SchnorrTargets, set_schnorr_witness},
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
	schnorr::{CompressedPublicKey, Scalar, Signature, schnorr_challenge},
};

pub(crate) fn set_authority_keys(
	pw: &mut PartialWitness<F>,
	approval_target: &PubkeyTarget,
	rejection_target: &PubkeyTarget,
	consume_target: &PubkeyTarget,
	approval_key: &CompPubKey,
	rejection_key: &CompPubKey,
	consume_key: &CompPubKey,
) {
	approval_target.set_witness(pw, approval_key);
	rejection_target.set_witness(pw, rejection_key);
	consume_target.set_witness(pw, consume_key);
}

pub(crate) fn set_subpool_full_proof(
	pw: &mut PartialWitness<F>,
	targets: &SubpoolFullProofTargets,
	main_pool: &MainPoolConfigTree,
	approval_key: &CompPubKey,
	rejection_key: &CompPubKey,
	consume_key: &CompPubKey,
	subpool_id: SubpoolId,
) {
	let subpool = SubpoolConfigTree::new(*approval_key, *rejection_key, *consume_key);
	let full_proof = main_pool
		.full_subpool_proof(&subpool, subpool_id)
		.expect("subpool not registered in main_pool at the given subpool_id");

	targets
		.approval_proof
		.set_witness(pw, &full_proof.approval_proof);
	targets
		.rejection_proof
		.set_witness(pw, &full_proof.rejection_proof);
	targets
		.consume_proof
		.set_witness(pw, &full_proof.consume_proof);
	targets
		.main_pool_proof
		.set_witness(pw, &full_proof.main_pool_proof);
	pw.set_target_arr(&targets.subpool_config_root.0.elements, &subpool.root().0)
		.unwrap();
}

pub(crate) fn fake_authority_keys() -> (CompPubKey, CompPubKey, CompPubKey) {
	let approval = PointEw::generator().scalar_mul(&Scalar::from_raw([1, 2, 3, 4, 5]));
	let rejection = PointEw::generator().scalar_mul(&Scalar::from_raw([6, 7, 8, 9, 0]));
	let consume = PointEw::generator().scalar_mul(&Scalar::from_raw([11, 12, 13, 14, 0]));
	(
		CompressedPublicKey(approval.encode()),
		CompressedPublicKey(rejection.encode()),
		CompressedPublicKey(consume.encode()),
	)
}

pub(crate) fn set_real_schnorr_signature(
	pw: &mut PartialWitness<F>,
	targets: &SchnorrTargets,
	public_key: CompPubKey,
	tx_hash: &[F],
	signature: Signature,
) {
	let cr = signature.r.encode();
	let e = schnorr_challenge(&cr, &public_key.0, tx_hash);
	set_schnorr_witness(
		pw,
		targets,
		PointEw::decode(public_key.0).unwrap(),
		cr,
		e,
		signature.s,
	);
}

pub(crate) fn set_fake_schnorr_signature(
	pw: &mut PartialWitness<F>,
	targets: &SchnorrTargets,
	public_key: CompPubKey,
	e: [u64; 5],
	s: [u64; 5],
) {
	let q = PointEw::decode(public_key.0).unwrap();
	let e = Scalar::from_raw(e);
	let s = Scalar::from_raw(s);
	let r = PointEw::generator().scalar_mul(&s).add(&q.scalar_mul(&e));
	set_schnorr_witness(pw, targets, q, r.encode(), e, s);
}

pub(crate) fn set_hash_blocks<const N: usize>(
	pw: &mut PartialWitness<F>,
	targets: &[[Target; 4]; N],
	values: &[[F; 4]; N],
) {
	for (row_targets, row_values) in targets.iter().zip(values.iter()) {
		for (&target, &value) in row_targets.iter().zip(row_values.iter()) {
			pw.set_target(target, value).unwrap();
		}
	}
}
