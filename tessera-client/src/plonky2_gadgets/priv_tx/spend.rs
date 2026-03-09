use std::array;

use plonky2::{
	hash::{hash_types::HashOut, hashing::hash_n_to_m_no_pad, poseidon::PoseidonHash},
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::config::Hasher,
};
use plonky2_field::types::{Field, PrimeField64};
use primitive_types::U256;
use tessera_trees::{
	F,
	tree::{CommitmentInsertProof, hasher::HashOutput},
};

use super::{double_hash_native, targets::TxCircuitTargets};
use crate::{
	ACC_AST_DEPTH, ACT_DEPTH, AccountAddress, AssetId, DEFAULT_SPEND_AUTH_PK,
	MAIN_POOL_CONFIG_DEPTH, NCT_DEPTH, NOTE_BATCH, Nonce, NoteCommitment, NoteNullifier,
	PrivateIdentifier, SUBPOOL_CONFIG_DEPTH, StandardAccount, SubpoolId,
	account::{AccountStateTreeLeaf, PublicIdentifier},
	derive_priv_tx_hash,
	ecgfp5::{CompressedPoint, PointEw},
	note::{NodeIdentifier, PositionedStandardNode, StandardNote},
	plonky2_gadgets::{
		merkle::{MerkleSiblingsBits, set_merkle_siblings_and_bits},
		set_hash, set_u256_zero,
		signature::set_schnorr_witness,
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
	schnorr::{CompressedPublicKey, Scalar, Signature},
};

/// Compute circuit-compatible Merkle root using `two_to_one` at every level.
/// `CommitmentTree::hash_root` uses a different formula at the top level, so
/// use this helper instead when constructing the root to pass to the circuit.
fn circuit_merkle_root<const DEPTH: usize>(
	leaf: [F; 4],
	siblings: &[[F; 4]; DEPTH],
	bits: [bool; DEPTH],
) -> [F; 4] {
	let mut cur = leaf;
	for level in 0..DEPTH {
		let sib = siblings[level];
		let result = if bits[level] {
			<PoseidonHash as Hasher<F>>::two_to_one(
				HashOut {
					elements: sib,
				},
				HashOut {
					elements: cur,
				},
			)
		} else {
			<PoseidonHash as Hasher<F>>::two_to_one(
				HashOut {
					elements: cur,
				},
				HashOut {
					elements: sib,
				},
			)
		};
		cur = result.elements;
	}
	cur
}

/// Fill `pw` with a complete PrivTx (spend) transaction witness.
///
/// `accout` is derived internally: cloned from `accin`, nonce incremented by
/// one, and the AST updated with the net balance change for the transacted asset.
/// Amounts and `asset_exists` flags are derived from `accin.ast` and the
/// computed `accout`.
///
/// The ACT/NCT circuit-compatible roots are computed from the supplied proofs.
pub(crate) fn set_spend_tx_witness(
	pw: &mut PartialWitness<F>,
	t: &TxCircuitTargets,
	accin: &StandardAccount,
	// Position of Comm(accin) in the ACT.
	accin_act_pos: usize,
	// Siblings from act.merkle_path(accin_act_pos, 0, ACT_DEPTH).unwrap().
	accin_act_siblings: &[HashOutput],
	inotes: &[StandardNote],
	// Position of inote commitments in NCT tree (same order)
	inotes_pos: &[usize],
	// Merkle path of inotes in NCT tree
	inotes_nct_proofs: &[Vec<HashOutput>],
	onotes: &[StandardNote],
	dinotes: [[F; 4]; NOTE_BATCH],
	donotes: [[F; 4]; NOTE_BATCH],
	approval_key: &CompPubKey,
	rejection_key: &CompPubKey,
	consume_key: &CompPubKey,
	subpool_id: SubpoolId,
	main_pool: &MainPoolConfigTree,
	// Some(sig) if there are active output notes requiring spend auth; None → fake.
	spend_sig: Option<Signature>,
	// Some(sig) if there are active input notes and not active output notes requiring consume
	// auth; None → fake.
	consume_sig: Option<Signature>,
	approval_sig: Signature,
) {
	assert!(inotes.len() <= NOTE_BATCH);
	assert!(onotes.len() <= NOTE_BATCH);
	assert_eq!(inotes.len(), inotes_nct_proofs.len());
	assert_eq!(inotes.len(), inotes_pos.len());

	// ── Derive asset_id ───────────────────────────────────────────────────────
	let asset_id = inotes
		.first()
		.or(onotes.first())
		.map(|n| n.asset_id)
		.expect("at least one active note is required for a spend tx");

	// ── Derive accout ─────────────────────────────────────────────────────────
	let (ast_index, old_bal) = accin
		.ast
		.amount_for(asset_id)
		.unwrap_or_else(|| (accin.ast.next_index(), U256::zero()));
	let delta_in: U256 = inotes
		.iter()
		.map(|n| n.amt)
		.fold(U256::zero(), |a, b| a + b);
	let delta_out: U256 = onotes
		.iter()
		.map(|n| n.amt)
		.fold(U256::zero(), |a, b| a + b);
	let new_bal = old_bal + delta_in - delta_out;

	let mut accout = accin.clone();
	accout.nonce = Nonce(F::from_canonical_u64(accin.nonce.0.to_canonical_u64() + 1));
	accout.ast.set_leaf(
		ast_index,
		AccountStateTreeLeaf {
			asset_id,
			amount: new_bal,
		},
	);

	// ── Derive amounts and asset_exists flags ─────────────────────────────────
	let (_, accin_amt) = accin.ast.amount_for(asset_id).unwrap_or((0, U256::zero()));
	let (_, accout_amt) = accout.ast.amount_for(asset_id).unwrap_or((0, U256::zero()));
	let asset_exists_in_accin = accin.ast.amount_for(asset_id).is_some();
	let asset_exists_in_accout = accout.ast.amount_for(asset_id).is_some();

	// ── ACT position, siblings, circuit-compatible root ───────────────────────
	let accin_pos = accin_act_pos;
	let act_sibs: [[F; 4]; ACT_DEPTH] = array::from_fn(|i| accin_act_siblings[i].0);
	let act_bits: [bool; ACT_DEPTH] = array::from_fn(|i| (accin_pos >> i) & 1 == 1);
	let act_root = HashOutput(circuit_merkle_root(
		accin.commitment().0.0,
		&act_sibs,
		act_bits,
	));

	// ── NCT circuit-compatible root (from first active note's proof) ──────────
	let nct_root = if !inotes.is_empty() {
		let sibs_0: [[F; 4]; NCT_DEPTH] = array::from_fn(|j| inotes_nct_proofs[0][j].0);
		let bits_0: [bool; NCT_DEPTH] = array::from_fn(|j| (inotes_pos[0] >> j) & 1 == 1);
		HashOutput(circuit_merkle_root(
			inotes[0].commitment().0.0,
			&sibs_0,
			bits_0,
		))
	} else {
		HashOutput([F::ZERO; 4])
	};

	// ── tx_hash ───────────────────────────────────────────────────────────────
	let nk = accin.nk();
	let tx_inote_nulls: [NoteNullifier; NOTE_BATCH] = array::from_fn(|i| {
		if i < inotes.len() {
			let pos_f = F::from_canonical_usize(inotes_pos[i]);
			NoteNullifier(
				PositionedStandardNode::from_note(inotes[i].clone(), pos_f)
					.nullifier(&nk)
					.0,
			)
		} else {
			NoteNullifier(HashOutput(double_hash_native(dinotes[i])))
		}
	});
	let tx_onote_comms: [NoteCommitment; NOTE_BATCH] = array::from_fn(|i| {
		if i < onotes.len() {
			onotes[i].commitment()
		} else {
			NoteCommitment(HashOutput(double_hash_native(donotes[i])))
		}
	});
	let accin_null = accin.nullifier(Some(accin_pos as u64));
	let tx_hash = derive_priv_tx_hash(
		accin_null,
		accout.commitment(),
		tx_inote_nulls,
		tx_onote_comms,
	);

	// ── Tx kind flags ─────────────────────────────────────────────────────────
	pw.set_bool_target(t.is_rjct, false).unwrap();
	pw.set_bool_target(t.is_fresh_acc, false).unwrap();
	pw.set_bool_target(t.is_update_auth, false).unwrap();
	pw.set_bool_target(t.is_priv_tx, true).unwrap();

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

	// ── Asset / amounts ───────────────────────────────────────────────────────
	pw.set_target(t.asset_id.0, asset_id.0).unwrap();
	t.accin_amt.set_witness(pw, accin_amt);
	t.accout_amt.set_witness(pw, accout_amt);

	pw.set_bool_target(t.asset_exists_in_accin, asset_exists_in_accin)
		.unwrap();
	pw.set_bool_target(t.asset_exists_in_accout, asset_exists_in_accout)
		.unwrap();
	pw.set_target(t.accin_pos, F::from_canonical_usize(accin_pos))
		.unwrap();

	// ── ACT Merkle proof ──────────────────────────────────────────────────────
	set_merkle_siblings_and_bits(pw, &t.accin_act_merkle.0, act_sibs, act_bits);

	// ── AST Merkle proof ──────────────────────────────────────────────────────
	let ast_proof = accin.ast.merkle_proof_at(ast_index);
	t.accin_ast_merkle.0.set_witness(pw, &ast_proof);

	// ── Input notes ───────────────────────────────────────────────────────────
	let zero_addr = AccountAddress {
		subpool_id: SubpoolId(F::ZERO),
		public_id: PublicIdentifier(HashOutput([F::ZERO; 4])),
	};
	let inactive_inote = StandardNote {
		identifier: NodeIdentifier([F::ZERO; 2]),
		asset_id,
		amt: U256::zero(),
		recipient: AccountAddress::from_acc(accin),
		sender: zero_addr,
	};

	for i in 0..NOTE_BATCH {
		if i < inotes.len() {
			let pos_i = inotes_pos[i];
			let sibs_i: [[F; 4]; NCT_DEPTH] = array::from_fn(|j| inotes_nct_proofs[i][j].0);
			let bits_i: [bool; NCT_DEPTH] = array::from_fn(|j| (pos_i >> j) & 1 == 1);
			t.inotes[i].set_witness(pw, &inotes[i]);
			pw.set_target(t.inotes_pos[i], F::from_canonical_usize(pos_i))
				.unwrap();
			pw.set_bool_target(t.inotes_isactive[i], true).unwrap();
			set_merkle_siblings_and_bits(pw, &t.inotes_nct_merkle[i], sibs_i, bits_i);
		} else {
			t.inotes[i].set_witness(pw, &inactive_inote);
			pw.set_target(t.inotes_pos[i], F::ZERO).unwrap();
			pw.set_bool_target(t.inotes_isactive[i], false).unwrap();
			set_merkle_siblings_and_bits(
				pw,
				&t.inotes_nct_merkle[i],
				[[F::ZERO; 4]; NCT_DEPTH],
				[false; NCT_DEPTH],
			);
		}
	}

	// ── Output notes ──────────────────────────────────────────────────────────
	let inactive_onote = StandardNote {
		identifier: NodeIdentifier([F::ZERO; 2]),
		asset_id,
		amt: U256::zero(),
		recipient: zero_addr,
		sender: zero_addr,
	};

	for i in 0..NOTE_BATCH {
		if i < onotes.len() {
			t.onotes[i].set_witness(pw, &onotes[i]);
			pw.set_bool_target(t.onotes_isactive[i], true).unwrap();
		} else {
			t.onotes[i].set_witness(pw, &inactive_onote);
			pw.set_bool_target(t.onotes_isactive[i], false).unwrap();
		}
	}

	// ── Dummy note hashes ─────────────────────────────────────────────────────
	for i in 0..NOTE_BATCH {
		for j in 0..4 {
			pw.set_target(t.dinotes[i].0[j], dinotes[i][j]).unwrap();
			pw.set_target(t.donotes[i].0[j], donotes[i][j]).unwrap();
		}
	}

	// ── Subpool full proof ────────────────────────────────────────────────────
	let subpool = SubpoolConfigTree::new(*approval_key, *rejection_key, *consume_key);
	let full_proof = main_pool
		.full_subpool_proof(&subpool, subpool_id)
		.expect("subpool not registered in main_pool at the given subpool_id");

	t.subpool_proof_targets.approval_proof.set_witness(pw, &full_proof.approval_proof);
	t.subpool_proof_targets.rejection_proof.set_witness(pw, &full_proof.rejection_proof);
	t.subpool_proof_targets.consume_proof.set_witness(pw, &full_proof.consume_proof);
	t.subpool_proof_targets.main_pool_proof.set_witness(pw, &full_proof.main_pool_proof);

	pw.set_target_arr(
		&t.subpool_proof_targets.subpool_config_root.0.elements,
		&subpool.root().0,
	)
	.unwrap();

	// ── Signatures ────────────────────────────────────────────────────────────

	// Helper: given sig.r and the signer's decoded public key, compute the
	// challenge scalar e = H(R_enc || Q_enc || tx_hash).
	let compute_e = |cr: &CompressedPoint<F>, cq: &CompressedPoint<F>| -> Scalar {
		let mut h: Vec<F> = cr.w.0.to_vec();
		h.extend_from_slice(&cq.w.0);
		h.extend_from_slice(&tx_hash);
		let h_out = hash_n_to_m_no_pad::<F, <PoseidonHash as Hasher<F>>::Permutation>(&h, 5);
		Scalar::from_hash(array::from_fn(|i| h_out[i]))
	};

	// Spend signature
	{
		if let Some(sig) = spend_sig {
			let cq = accin.spend_auth.spend_pk.unwrap().0;
			let cr = sig.r.encode();
			let e = compute_e(&cr, &cq);
			set_schnorr_witness(
				pw,
				&t.sig_targets.spend,
				PointEw::decode(cq).unwrap(),
				cr,
				e,
				sig.s,
			);
		} else {
			// Fake: spend is not enforced when there are no active output notes.
			let q = PointEw::decode(
				accin
					.spend_auth
					.spend_pk
					.expect("accin must have a spend_pk for spend tx")
					.0,
			)
			.unwrap();
			let e = Scalar::from_raw([11, 22, 33, 44, 55]);
			let s = Scalar::from_raw([9, 8, 7, 6, 5]);
			let r = PointEw::generator().scalar_mul(&s).add(&q.scalar_mul(&e));
			set_schnorr_witness(pw, &t.sig_targets.spend, q, r.encode(), e, s);
		}
	}

	// Consume signature
	{
		let cq = if accin.consume_auth.config {
			accin.consume_auth.pk.unwrap().0
		} else {
			consume_key.0
		};
		if let Some(sig) = consume_sig {
			let cr = sig.r.encode();
			let e = compute_e(&cr, &cq);
			set_schnorr_witness(
				pw,
				&t.sig_targets.consume,
				PointEw::decode(cq).unwrap(),
				cr,
				e,
				sig.s,
			);
		} else {
			// Fake: consume is not enforced when there are no active input notes.
			let q = PointEw::decode(cq).unwrap();
			let e = Scalar::from_raw([13, 13, 13, 13, 13]);
			let s = Scalar::from_raw([14, 15, 16, 17, 18]);
			let r = PointEw::generator().scalar_mul(&s).add(&q.scalar_mul(&e));
			set_schnorr_witness(pw, &t.sig_targets.consume, q, r.encode(), e, s);
		}
	}

	// Approval signature (always real)
	{
		let cq = approval_key.0;
		let cr = approval_sig.r.encode();
		let e = compute_e(&cr, &cq);
		set_schnorr_witness(
			pw,
			&t.sig_targets.approval,
			PointEw::decode(cq).unwrap(),
			cr,
			e,
			approval_sig.s,
		);
	}
}

/// Fill `pw` with a fully fake transaction witness (`not_fake_tx = false`).
///
/// `accout` is derived from `accin` with the nonce incremented by one.
/// All tx-kind flags are `false`.
///
/// The three authority keys are derived from fixed scalars; their subpool-internal
/// Merkle proofs are real (the SubpoolConfigTree is reconstructed from those
/// keys), but the main-pool inclusion proof is zeroed out.
///
/// All notes are inactive and all signatures are fake constants. The circuit will not
/// enforce any of these because `not_fake_tx = false`.
pub(crate) fn set_fake_tx_witness(
	pw: &mut PartialWitness<F>,
	t: &TxCircuitTargets,
	nct_root: HashOutput,
	act_root: HashOutput,
	mainpool_config_root: HashOutput,
) {
	// ── Sample accin ────────────────────────────────────────────────────────--
	let accin = StandardAccount::new_with(
		PrivateIdentifier([F::from_canonical_u64(1), F::from_noncanonical_u64(2)]),
		SubpoolId(F::ZERO),
	);

	// ── Derive accout ─────────────────────────────────────────────────────────
	let mut accout = accin.clone();
	accout.nonce = Nonce(F::from_canonical_u64(accin.nonce.0.to_canonical_u64() + 1));

	// ── Tx kind flags (all false, not_fake_tx = false) ────────────────────────
	pw.set_bool_target(t.not_fake_tx, false).unwrap();
	pw.set_bool_target(t.is_rjct, false).unwrap();
	pw.set_bool_target(t.is_fresh_acc, false).unwrap();
	pw.set_bool_target(t.is_update_auth, false).unwrap();
	pw.set_bool_target(t.is_priv_tx, false).unwrap();

	// ── Tree roots (all zero) ─────────────────────────────────────────────────
	set_hash(pw, t.mainpool_config_root.0, mainpool_config_root.0);
	set_hash(pw, t.act_root.0, act_root.0);
	set_hash(pw, t.nct_root.0, nct_root.0);

	// ── Authority keys (derived from fixed scalars) ───────────────────────────
	let fake_approval_q = PointEw::generator().scalar_mul(&Scalar::from_raw([1, 2, 3, 4, 5]));
	let fake_rejection_q = PointEw::generator().scalar_mul(&Scalar::from_raw([6, 7, 8, 9, 0]));
	let fake_consume_q = PointEw::generator().scalar_mul(&Scalar::from_raw([11, 12, 13, 14, 0]));
	let fake_approval_cpk = CompressedPublicKey(fake_approval_q.encode());
	let fake_rejection_cpk = CompressedPublicKey(fake_rejection_q.encode());
	let fake_consume_cpk = CompressedPublicKey(fake_consume_q.encode());
	t.approval_key.set_witness(pw, &fake_approval_cpk);
	t.rejection_key.set_witness(pw, &fake_rejection_cpk);
	t.subpool_consume_key.set_witness(pw, &fake_consume_cpk);

	// ── Accounts ──────────────────────────────────────────────────────────────
	t.accin.set_witness(pw, &accin);
	t.accout.set_witness(pw, &accout);

	// ── Asset / amounts (all zeros) ───────────────────────────────────────────
	pw.set_target(t.asset_id.0, F::ZERO).unwrap();
	set_u256_zero(pw, &t.accin_amt);
	set_u256_zero(pw, &t.accout_amt);
	pw.set_bool_target(t.asset_exists_in_accin, false).unwrap();
	pw.set_bool_target(t.asset_exists_in_accout, false).unwrap();
	pw.set_target(t.accin_pos, F::ZERO).unwrap();

	// ── ACT Merkle proof (all zeros) ──────────────────────────────────────────
	set_merkle_siblings_and_bits(
		pw,
		&t.accin_act_merkle.0,
		[[F::ZERO; 4]; ACT_DEPTH],
		[false; ACT_DEPTH],
	);

	// ── AST Merkle proof (real path of default leaf at index 0) ──────────────
	let ast_proof = accin.ast.merkle_proof_at(0);
	t.accin_ast_merkle.0.set_witness(pw, &ast_proof);

	// ── Input notes (all inactive) ────────────────────────────────────────────
	let zero_addr = AccountAddress {
		subpool_id: SubpoolId(F::ZERO),
		public_id: PublicIdentifier(HashOutput([F::ZERO; 4])),
	};
	let inactive_inote = StandardNote {
		identifier: NodeIdentifier([F::ZERO; 2]),
		asset_id: AssetId(F::ZERO),
		amt: U256::zero(),
		recipient: AccountAddress::from_acc(&accin),
		sender: zero_addr,
	};
	for i in 0..NOTE_BATCH {
		t.inotes[i].set_witness(pw, &inactive_inote);
		pw.set_target(t.inotes_pos[i], F::ZERO).unwrap();
		pw.set_bool_target(t.inotes_isactive[i], false).unwrap();
		set_merkle_siblings_and_bits(
			pw,
			&t.inotes_nct_merkle[i],
			[[F::ZERO; 4]; NCT_DEPTH],
			[false; NCT_DEPTH],
		);
	}

	// ── Output notes (all inactive) ───────────────────────────────────────────
	let inactive_onote = StandardNote {
		identifier: NodeIdentifier([F::ZERO; 2]),
		asset_id: AssetId(F::ZERO),
		amt: U256::zero(),
		recipient: zero_addr,
		sender: zero_addr,
	};
	for i in 0..NOTE_BATCH {
		t.onotes[i].set_witness(pw, &inactive_onote);
		pw.set_bool_target(t.onotes_isactive[i], false).unwrap();
	}

	// ── Dummy note hashes (all zeros) ─────────────────────────────────────────
	for i in 0..NOTE_BATCH {
		for j in 0..4 {
			pw.set_target(t.dinotes[i].0[j], F::ZERO).unwrap();
			pw.set_target(t.donotes[i].0[j], F::ZERO).unwrap();
		}
	}

	// ── Subpool proof ─────────────────────────────────────────────────────────
	// The three key-membership proofs are real (reconstructed from the fake keys).
	// Only the main-pool inclusion proof is zeroed — it is not enforced when
	// not_fake_tx = false.
	let fake_subpool =
		SubpoolConfigTree::new(fake_approval_cpk, fake_rejection_cpk, fake_consume_cpk);

	t.subpool_proof_targets.approval_proof.set_witness(pw, &fake_subpool.approval_key_proof());
	t.subpool_proof_targets.rejection_proof.set_witness(pw, &fake_subpool.rejection_key_proof());
	t.subpool_proof_targets.consume_proof.set_witness(pw, &fake_subpool.consume_key_proof());

	set_merkle_siblings_and_bits(
		pw,
		&t.subpool_proof_targets.main_pool_proof,
		[[F::ZERO; 4]; MAIN_POOL_CONFIG_DEPTH],
		[false; MAIN_POOL_CONFIG_DEPTH],
	);
	pw.set_target_arr(
		&t.subpool_proof_targets.subpool_config_root.0.elements,
		&fake_subpool.root().0,
	)
	.unwrap();

	// ── Signatures (all fake) ─────────────────────────────────────────────────

	// Spend (fake)
	let spend_q = PointEw::decode(CompressedPoint::from(DEFAULT_SPEND_AUTH_PK)).unwrap();
	let spend_e = Scalar::from_raw([11, 22, 33, 44, 55]);
	let spend_s = Scalar::from_raw([9, 8, 7, 6, 5]);
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

	// Consume (fake)
	let consume_e = Scalar::from_raw([13, 13, 13, 13, 13]);
	let consume_s = Scalar::from_raw([14, 15, 16, 17, 18]);
	let consume_r = PointEw::generator()
		.scalar_mul(&consume_s)
		.add(&fake_consume_q.scalar_mul(&consume_e));
	set_schnorr_witness(
		pw,
		&t.sig_targets.consume,
		fake_consume_q,
		consume_r.encode(),
		consume_e,
		consume_s,
	);

	// Approval (fake)
	let approval_e = Scalar::from_raw([21, 22, 23, 24, 25]);
	let approval_s = Scalar::from_raw([31, 32, 33, 34, 35]);
	let approval_r = PointEw::generator()
		.scalar_mul(&approval_s)
		.add(&fake_approval_q.scalar_mul(&approval_e));
	set_schnorr_witness(
		pw,
		&t.sig_targets.approval,
		fake_approval_q,
		approval_r.encode(),
		approval_e,
		approval_s,
	);
}

#[cfg(test)]
mod tests {
	use itertools::Itertools;
	use plonky2::plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::CircuitConfig,
		config::{GenericConfig, PoseidonGoldilocksConfig},
	};
	use rand::SeedableRng;
	use rand_chacha::ChaCha8Rng;
	use tessera_trees::tree::CommitmentTree;

	use super::*;
	use crate::{
		SpendAuth,
		plonky2_gadgets::priv_tx::priv_tx_circuit,
		schnorr::{CompressedPublicKey, PrivateKey, schnorr_sign},
	};

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = <C as GenericConfig<D>>::F;

	fn double_hash_native(elems: [F; 4]) -> [F; 4] {
		let h0 = <PoseidonHash as Hasher<F>>::hash_no_pad(&elems).elements;
		<PoseidonHash as Hasher<F>>::hash_no_pad(&h0).elements
	}

	#[test]
	fn test_prove_priv_tx() {
		// ── Keys for subpool ──────────────────────────────────────────────────
		let approval_sk = PrivateKey::from_raw([2, 3, 4, 5, 6]);
		let approval_cpk: CompPubKey = approval_sk.public_key::<F>().into();

		let rejection_sk = PrivateKey::from_raw([5, 6, 7, 8, 0]);
		let rejection_cpk: CompPubKey = rejection_sk.public_key::<F>().into();

		let consume_sk = PrivateKey::from_raw([9, 10, 11, 12, 0]);
		let consume_cpk: CompPubKey = consume_sk.public_key::<F>().into();

		let subpool = SubpoolConfigTree::new(approval_cpk, rejection_cpk, consume_cpk);
		let subpool_id = SubpoolId(F::ONE);

		let mut main_pool = MainPoolConfigTree::new();
		main_pool.set_subpool(0, subpool_id, subpool.root());

		// ── Create commitment trees ───────────────────────────────────────────
		let mut act = CommitmentTree::<HashOutput>::new(crate::ACT_DEPTH);
		let mut nct = CommitmentTree::<HashOutput>::new(crate::NCT_DEPTH);

		// ── Sample accounts ───────────────────────────────────────────────────
		let mut rng = ChaCha8Rng::seed_from_u64(1);
		let mut acc0 = StandardAccount::sample(&mut rng, subpool_id);
		let acc1 = StandardAccount::sample(&mut rng, SubpoolId(F::from_canonical_u64(2)));

		// ── Simulate FreshAcc for acc0 ────────────────────────────────────────
		// Advance acc0 to post-FreshAcc state (nonce=1, spend_auth set, consume_auth unchanged)
		let spend_sk = PrivateKey::from_raw([999, 1000, 1001, 1002, 0]);
		let spend_cpk = CompressedPublicKey::from(spend_sk.public_key::<F>());
		acc0.nonce = Nonce(F::ONE);
		acc0.spend_auth = SpendAuth {
			spend_pk: Some(spend_cpk),
		};

		// Insert acc0 commitment into ACT
		let acc0_pos = act.insert(acc0.commitment().0).unwrap().path; // = 0
		let acc0_act_siblings = act.merkle_path(acc0_pos, 0, crate::ACT_DEPTH).unwrap();

		// ── Create notes N0, N1 ───────────────────────────────────────────────
		let asset_id_val = crate::AssetId(F::ONE);
		let n0 = StandardNote {
			identifier: NodeIdentifier::from_rng(&mut rng),
			asset_id: asset_id_val,
			amt: U256::from(100u64),
			recipient: crate::AccountAddress::from_acc(&acc0),
			sender: crate::AccountAddress::from_acc(&acc1),
		};
		let n1 = StandardNote {
			identifier: NodeIdentifier::from_rng(&mut rng),
			asset_id: asset_id_val,
			amt: U256::from(50u64),
			recipient: crate::AccountAddress::from_acc(&acc0),
			sender: crate::AccountAddress::from_acc(&acc1),
		};

		// ── Build accout (post-consume state) ─────────────────────────────────
		let mut accout = acc0.clone();
		accout.nonce = Nonce(F::from_canonical_u64(2));
		// spend_auth and consume_auth are immutable in PrivTx — kept from acc0
		// Update AST: position 0 gets asset_id=1 with amount=150
		accout.ast.set_leaf(
			0,
			AccountStateTreeLeaf {
				asset_id: asset_id_val,
				amount: U256::from(150u64),
			},
		);

		// Insert note commitments into NCT
		let n0_nct_proof = nct.insert(n0.commitment().0).unwrap();
		let n1_nct_proof = nct.insert(n1.commitment().0).unwrap();
		let n0_pos = n0_nct_proof.path;
		let n1_pos = n1_nct_proof.path;

		// Dummy notes (same pattern as freshacc)
		let dinotes: [[F; 4]; NOTE_BATCH] = array::from_fn(|i| [F::from_canonical_usize(i); 4]);
		let donotes: [[F; 4]; NOTE_BATCH] =
			array::from_fn(|i| [F::from_canonical_usize(i + NOTE_BATCH); 4]);

		// ── Compute note nullifiers and tx_hash ───────────────────────────────
		let nk0 = acc0.nk();
		// After Part 1 fix, native order matches circuit: commitment || position || nk
		let n0_null_arr: [F; 4] =
			PositionedStandardNode::from_note(n0, F::from_canonical_usize(n0_pos))
				.nullifier(&nk0)
				.0
				.0;
		let n1_null_arr: [F; 4] =
			PositionedStandardNode::from_note(n1, F::from_canonical_usize(n1_pos))
				.nullifier(&nk0)
				.0
				.0;

		// tx_hash: real nullifiers for active notes (0, 1), dummy for rest
		let tx_inote_nulls: [NoteNullifier; NOTE_BATCH] = array::from_fn(|i| {
			let arr: [F; 4] = match i {
				0 => n0_null_arr,
				1 => n1_null_arr,
				_ => double_hash_native(dinotes[i]),
			};
			NoteNullifier(HashOutput(arr))
		});
		let tx_onote_comms: [NoteCommitment; NOTE_BATCH] =
			array::from_fn(|i| NoteCommitment(HashOutput(double_hash_native(donotes[i]))));

		let accin_null = acc0.nullifier(Some(acc0_pos as u64));
		let tx_hash = derive_priv_tx_hash(
			accin_null,
			accout.commitment(),
			tx_inote_nulls,
			tx_onote_comms,
		);

		// ── Build circuit ──────────────────────────────────────────────────────
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let t = priv_tx_circuit(&mut builder);
		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		let inotes = vec![n0, n1];
		let inotes_pos = vec![n0_pos, n1_pos];
		let inotes_nct_proofs = inotes_pos
			.iter()
			.map(|i| nct.merkle_path(*i, 0, crate::NCT_DEPTH).unwrap())
			.collect_vec();

		// ── Signatures ────────────────────────────────────────────────────────

		// Consume (REAL): is_consume_req = true (N0+N1 active, no onotes)
		// consume_auth.config = false → circuit uses subpool consume key (consume_cpk)
		let consume_sig = {
			let k_c = Scalar::from_raw([7, 8, 9, 10, 11]);
			schnorr_sign(&consume_sk, &tx_hash, k_c)
		};

		// Approval (REAL): always required
		let approval_sig = {
			let k = Scalar::from_raw([1, 2, 3, 4, 5]);
			schnorr_sign(&approval_sk, &tx_hash, k)
		};

		// --- Set Witness -------------------------------------------------------

		set_spend_tx_witness(
			&mut pw,
			&t,
			&acc0,
			acc0_pos,
			&acc0_act_siblings,
			&inotes,
			&inotes_pos,
			&inotes_nct_proofs,
			&vec![],
			dinotes,
			donotes,
			&approval_cpk,
			&rejection_cpk,
			&consume_cpk,
			subpool_id,
			&main_pool,
			None,
			Some(consume_sig),
			approval_sig,
		);

		// ── Prove & verify ─────────────────────────────────────────────────────
		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}

	#[test]
	fn test_fake_tx() {
		// ── Build circuit ──────────────────────────────────────────────────────
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let t = priv_tx_circuit(&mut builder);
		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		let zerohash = HashOutput([F::ZERO; 4]);
		set_fake_tx_witness(&mut pw, &t, zerohash, zerohash, zerohash);

		// ── Prove & verify ─────────────────────────────────────────────────────
		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}
}
