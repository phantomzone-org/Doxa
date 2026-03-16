use std::array;

use plonky2::{
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::config::Hasher,
};
use plonky2_field::types::Field;
use rand::Rng;
use tessera_trees::{F, tree::hasher::HashOutput};

use super::{double_hash_native, targets::TxCircuitTargets};
use crate::{
	ACT_DEPTH, AccountAddress, AssetId, ConsumeAuth, DEFAULT_SPEND_AUTH_PK, MAIN_POOL_CONFIG_DEPTH,
	NCT_DEPTH, NOTE_BATCH, Nonce, NoteCommitment, NoteNullifier, SUBPOOL_CONFIG_DEPTH, SpendAuth,
	StandardAccount, SubpoolId,
	account::PublicIdentifier,
	derive_priv_tx_hash,
	ecgfp5::{CompressedPoint, PointEw},
	note::{NodeIdentifier, StandardNote},
	plonky2_gadgets::{
		merkle::{SetDummyMerklePathOfWitness, SetMerklePathOfWitness},
		set_hash, set_u256_zero,
		signature::set_schnorr_witness,
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
	schnorr::{Scalar, Signature, schnorr_challenge},
};

/// Fill `pw` with a complete FreshAcc transaction witness.
///
/// `accout` is derived internally by cloning `accin` and applying
/// `new_spend_auth`, `new_consume_auth`, and incrementing the nonce to 1.
///
/// The subpool config tree is reconstructed internally from the three keys.
/// `main_pool` must already contain an entry for `subpool_id`; the function
/// panics otherwise.
/// Sample `NOTE_BATCH` random dummy input-note and output-note hashes.
///
/// Each hash is 4 Goldilocks field elements drawn uniformly at random.
/// The returned arrays are suitable as `dinotes` / `donotes` inputs to
/// [`set_freshacc_tx_witness`].
///
/// `nct_root` and `act_root` are [F::ZERO; 4] for a normal FreshAcc (no notes,
/// account not yet in ACT).
pub(crate) fn set_freshacc_tx_witness(
	pw: &mut PartialWitness<F>,
	t: &TxCircuitTargets,
	accin: &StandardAccount,
	new_spend_auth: SpendAuth,
	new_consume_auth: ConsumeAuth,
	act_root: HashOutput,
	nct_root: HashOutput,
	approval_key: CompPubKey,
	rejection_key: CompPubKey,
	consume_key: CompPubKey,
	subpool_id: SubpoolId,
	main_pool: &MainPoolConfigTree,
	approval_sig: Signature,
	dinotes: [[F; 4]; NOTE_BATCH],
	donotes: [[F; 4]; NOTE_BATCH],
) {
	// ── Build accout ──────────────────────────────────────────────────────────
	let mut accout = accin.clone();
	accout.nonce = Nonce(F::ONE);
	accout.spend_auth = new_spend_auth;
	accout.consume_auth = new_consume_auth;

	// ── Dummy notes (needed for tx_hash) ──────────────────────────────────────
	let dinote_nulls = array::from_fn(|i| NoteNullifier(double_hash_native(dinotes[i]).into()));
	let donote_comms = array::from_fn(|i| NoteCommitment(double_hash_native(donotes[i]).into()));

	// ── Tx hash ───────────────────────────────────────────────────────────────
	let tx_hash = derive_priv_tx_hash(
		accin.nullifier(None),
		accout.commitment(),
		dinote_nulls,
		donote_comms,
	);

	// ── Tx kind flags ─────────────────────────────────────────────────────────
	pw.set_bool_target(t.is_rjct, false).unwrap();
	pw.set_bool_target(t.is_fresh_acc, true).unwrap();
	pw.set_bool_target(t.is_update_auth, false).unwrap();
	pw.set_bool_target(t.is_priv_tx, false).unwrap();

	pw.set_bool_target(t.not_fake_tx, true).unwrap();

	// ── Tree roots ────────────────────────────────────────────────────────────
	set_hash(pw, t.mainpool_config_root.0, main_pool.root().0);
	set_hash(pw, t.act_root.0, act_root.0);
	set_hash(pw, t.nct_root.0, nct_root.0);

	// ── Authority keys ────────────────────────────────────────────────────────
	t.approval_key.set_witness(pw, &approval_key);
	t.rejection_key.set_witness(pw, &rejection_key);
	t.subpool_consume_key.set_witness(pw, &consume_key);

	// ── Accounts ──────────────────────────────────────────────────────────────
	t.accin.set_witness(pw, accin);
	t.accout.set_witness(pw, &accout);
	for tgt in t.d_accin.0 { pw.set_target(tgt, F::ZERO).unwrap(); }
	for tgt in t.d_accout.0 { pw.set_target(tgt, F::ZERO).unwrap(); }

	// ── Asset / amounts (all zeros for FreshAcc) ──────────────────────────────
	pw.set_target(t.asset_id.0, F::ZERO).unwrap();
	set_u256_zero(pw, &t.accin_amt);
	set_u256_zero(pw, &t.accout_amt);
	pw.set_bool_target(t.asset_exists_in_accin, false).unwrap();
	pw.set_bool_target(t.asset_exists_in_accout, false).unwrap();
	pw.set_target(t.accin_pos, F::ZERO).unwrap();

	// ── Merkle proofs ─────────────────────────────────────────────────────────

	// ACT: not enforced for FreshAcc
	t.accin_act_merkle.set_dummy_witness(pw, ACT_DEPTH);

	// accin AST at index 0 (asset not in tree → Empty leaf)
	t.accin_ast_merkle
		.set_witness(pw, &accin.ast.merkle_proof_at(0));
	// accout_ast_merkle is auto-filled via connect_array in the circuit

	// ── Input notes (all inactive) ────────────────────────────────────────────
	let zero_addr = AccountAddress {
		subpool_id: SubpoolId(F::ZERO),
		public_id: PublicIdentifier(HashOutput([F::ZERO; 4])),
	};
	let inote = StandardNote {
		identifier: NodeIdentifier([F::ZERO; 2]),
		asset_id: AssetId(F::ZERO),
		amt: primitive_types::U256::zero(),
		recipient: AccountAddress::from_acc(accin),
		sender: zero_addr,
	};
	for i in 0..NOTE_BATCH {
		t.inotes[i].set_witness(pw, &inote);
		pw.set_target(t.inotes_pos[i], F::ZERO).unwrap();
		pw.set_bool_target(t.inotes_isactive[i], false).unwrap();
		// NCT: not enforced (selector = false)
		t.inotes_nct_merkle[i].set_dummy_witness(pw, NCT_DEPTH);
	}

	// ── Output notes (all inactive) ───────────────────────────────────────────
	let onote = StandardNote {
		identifier: NodeIdentifier([F::ZERO; 2]),
		asset_id: AssetId(F::ZERO),
		amt: primitive_types::U256::zero(),
		recipient: zero_addr,
		sender: zero_addr,
	};
	for i in 0..NOTE_BATCH {
		t.onotes[i].set_witness(pw, &onote);
		pw.set_bool_target(t.onotes_isactive[i], false).unwrap();
	}

	// ── Dummy note hashes ─────────────────────────────────────────────────────
	for i in 0..NOTE_BATCH {
		for j in 0..4 {
			pw.set_target(t.dinotes[i].0[j], dinotes[i][j]).unwrap();
			pw.set_target(t.donotes[i].0[j], donotes[i][j]).unwrap();
		}
	}

	// ── Subpool full proof ────────────────────────────────────────────────────
	let subpool = SubpoolConfigTree::new(approval_key, rejection_key, consume_key);
	let full_proof = main_pool
		.full_subpool_proof(&subpool, subpool_id)
		.expect("subpool not registered in main_pool at the given subpool_id");

	t.subpool_proof_targets
		.approval_proof
		.set_witness(pw, &full_proof.approval_proof);
	t.subpool_proof_targets
		.rejection_proof
		.set_witness(pw, &full_proof.rejection_proof);
	t.subpool_proof_targets
		.consume_proof
		.set_witness(pw, &full_proof.consume_proof);
	t.subpool_proof_targets
		.main_pool_proof
		.set_witness(pw, &full_proof.main_pool_proof);

	pw.set_target_arr(
		&t.subpool_proof_targets.subpool_config_root.0.elements,
		&subpool.root().0,
	)
	.unwrap();

	// ── Signatures ────────────────────────────────────────────────────────────

	// Spend (fake): is_spend_req = false → apply_check = false.
	let spend_q: PointEw<F> =
		PointEw::decode(CompressedPoint::from(DEFAULT_SPEND_AUTH_PK)).unwrap();
	let spend_e = Scalar::from_raw([42, 8, 2, 5, 1]);
	let spend_s = Scalar::from_raw([7, 12, 13, 14, 14]);
	let spend_r = PointEw::generator()
		.scalar_mul(&spend_s)
		.add(&spend_q.scalar_mul(&spend_e));
	set_schnorr_witness(
		pw,
		&t.sig_targets.spend,
		spend_q,
		spend_r.encode(),
		spend_e,
		spend_s,
	);

	// Consume (fake): consume_auth.config = false → circuit uses subpool_consume_key.
	let consume_q: PointEw<F> = PointEw::decode(consume_key.0).unwrap();
	let consume_e = Scalar::from_raw([13, 13, 5, 6, 7]);
	let consume_s = Scalar::from_raw([17, 19, 12, 13, 16]);
	let consume_r = PointEw::generator()
		.scalar_mul(&consume_s)
		.add(&consume_q.scalar_mul(&consume_e));
	set_schnorr_witness(
		pw,
		&t.sig_targets.consume,
		consume_q,
		consume_r.encode(),
		consume_e,
		consume_s,
	);

	// Approval (real): always enforced for FreshAcc.
	let approval_q: PointEw<F> = PointEw::decode(approval_key.0).unwrap();
	let approval_cr = approval_sig.r.encode();
	let approval_cq = approval_q.encode();
	let approval_e = schnorr_challenge(&approval_cr, &approval_cq, &tx_hash);
	set_schnorr_witness(
		pw,
		&t.sig_targets.approval,
		approval_q,
		approval_cr,
		approval_e,
		approval_sig.s,
	);
}

#[cfg(test)]
mod tests {
	use std::array;

	use plonky2::{
		iop::witness::PartialWitness,
		plonk::{
			circuit_builder::CircuitBuilder,
			circuit_data::CircuitConfig,
			config::{GenericConfig, PoseidonGoldilocksConfig},
		},
	};
	use plonky2_field::types::Field;
	use rand::{SeedableRng, rand_core::Rng};
	use rand_chacha::ChaCha8Rng;
	use tessera_trees::tree::hasher::HashOutput;

	use super::*;
	use crate::{
		Nonce, NoteCommitment, NoteNullifier, SpendAuth, StandardAccount, SubpoolId,
		derive_priv_tx_hash,
		plonky2_gadgets::priv_tx::{double_hash_native, priv_tx_circuit, sample_dummy_notes},
		pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
		schnorr::{CompressedPublicKey, PrivateKey, Scalar, schnorr_sign},
	};

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = <C as GenericConfig<D>>::F;

	fn sample_sk(rng: &mut impl Rng) -> PrivateKey {
		PrivateKey::from_raw(array::from_fn(|_| rng.next_u64()))
	}

	#[test]
	fn test_prove_fresh_acc_tx() {
		let mut rng = ChaCha8Rng::seed_from_u64(42);

		// ── Keys for one subpool ──────────────────────────────────────────────
		let approval_sk = sample_sk(&mut rng);
		let approval_cpk: CompPubKey = approval_sk.public_key::<F>().into();

		let rejection_sk = sample_sk(&mut rng);
		let rejection_cpk: CompPubKey = rejection_sk.public_key::<F>().into();

		let consume_sk = sample_sk(&mut rng);
		let consume_cpk: CompPubKey = consume_sk.public_key::<F>().into();

		let subpool = SubpoolConfigTree::new(approval_cpk, rejection_cpk, consume_cpk);
		let subpool_id = SubpoolId(F::ONE);

		let mut main_pool = MainPoolConfigTree::new();
		main_pool.set_subpool(0, subpool_id, subpool.root());

		// ── Accounts ─────────────────────────────────────────────────────────
		let accin = StandardAccount::sample(&mut rng, subpool_id);

		let nspend_sk = sample_sk(&mut rng);
		let spend_cpk: CompressedPublicKey<F> = nspend_sk.public_key().into();
		let new_spend_auth = SpendAuth {
			spend_pk: Some(spend_cpk),
		};
		let new_consume_auth = accin.consume_auth.clone();

		// ── Compute tx_hash to produce the approval signature ─────────────────
		// Mirrors the dummy-note encoding inside set_freshacc_tx_witness.
		let mut accout = accin.clone();
		accout.nonce = Nonce(F::ONE);
		accout.spend_auth = new_spend_auth.clone();
		accout.consume_auth = new_consume_auth.clone();

		let (dinotes, donotes) = sample_dummy_notes(&mut rng);
		let dinote_nulls = array::from_fn(|i| NoteNullifier(double_hash_native(dinotes[i]).into()));
		let donote_comms =
			array::from_fn(|i| NoteCommitment(double_hash_native(donotes[i]).into()));
		let tx_hash = derive_priv_tx_hash(
			accin.nullifier(None),
			accout.commitment(),
			dinote_nulls,
			donote_comms,
		);

		// TODO: sample randomly and reduce mod n
		let k = Scalar::from_raw(array::from_fn(|_| 1));
		let approval_sig = schnorr_sign(&approval_sk, &tx_hash, k);

		// ── Build circuit ─────────────────────────────────────────────────────
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let t = priv_tx_circuit::<HashOutput, _, _>(&mut builder);
		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		// ── Fill witness ──────────────────────────────────────────────────────
		super::set_freshacc_tx_witness(
			&mut pw,
			&t,
			&accin,
			new_spend_auth,
			new_consume_auth,
			HashOutput([F::ZERO; 4]), // act_root: not in ACT yet
			HashOutput([F::ZERO; 4]), // nct_root: no notes for FreshAcc
			approval_cpk,
			rejection_cpk,
			consume_cpk,
			subpool_id,
			&main_pool,
			approval_sig,
			dinotes,
			donotes,
		);

		// ── Prove & verify ────────────────────────────────────────────────────
		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}
}
