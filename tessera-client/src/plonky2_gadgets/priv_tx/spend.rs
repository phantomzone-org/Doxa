use std::array;

use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2_field::types::{Field, PrimeField64};
use primitive_types::U256;
use tessera_utils::{
	F,
	hasher::{HashOutput, MerkleHashCircuit},
};

use super::{
	double_hash_native,
	targets::TxCircuitTargets,
	witness::{TxKindFlags, set_common_tx_witness, set_tx_kind_flags},
};
use crate::{
	ACT_DEPTH, AccountAddress, AssetId, DEFAULT_SPEND_AUTH_PK, MAIN_POOL_CONFIG_DEPTH, NCT_DEPTH,
	NOTE_BATCH, Nonce, NoteCommitment, NoteNullifier, PrivateIdentifier, SpendAuth,
	StandardAccount, SubpoolId,
	account::{AccountStateTreeLeaf, PublicIdentifier},
	derive_priv_tx_hash,
	ecgfp5::CompressedPoint,
	note::{NodeIdentifier, PositionedStandardNode, StandardNote},
	plonky2_gadgets::{
		merkle::{SetDummyMerklePathOfWitness, SetMerklePathOfWitness},
		set_hash, set_u256_zero,
		witness::{
			fake_authority_keys, set_authority_keys, set_fake_schnorr_signature, set_hash_blocks,
			set_real_schnorr_signature, set_subpool_full_proof,
		},
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
	schnorr::{CompressedPublicKey, PrivateKey, Signature},
	tree::CommitmentTreeMerkleProof,
};

/// Fill `pw` with a complete PrivTx (spend) transaction witness.
///
/// `accout` is derived internally: cloned from `accin`, nonce incremented by
/// one, and the AST updated with the net balance change for the transacted asset.
/// Amounts and `asset_exists` flags are derived from `accin.ast` and the
/// computed `accout`.
///
/// The root is the on-chain Poseidon IMT root used for both the account
/// commitment (ACT) and input-note commitment (NCT) Merkle proofs.
#[allow(clippy::too_many_arguments)]
pub fn set_spend_tx_witness(
	pw: &mut PartialWitness<F>,
	t: &TxCircuitTargets,
	accin: &StandardAccount,
	root: HashOutput,
	// MerkleProof of commitment of AccIn in the on-chain IMT
	accin_merkle_proof: CommitmentTreeMerkleProof<ACT_DEPTH>,
	inotes: &[StandardNote],
	// MerkleProof of commitments of inotes in NCT
	inotes_nct_proofs: &[CommitmentTreeMerkleProof<NCT_DEPTH>],
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

	let mut accout = accin.clone_with_incremented_nonce();
	accout.ast.insert_or_update_asset(asset_id, new_bal);

	// ── Derive amounts and asset_exists flags ─────────────────────────────────
	let (_, accin_amt) = accin.ast.amount_for(asset_id).unwrap_or((0, U256::zero()));
	let (_, accout_amt) = accout.ast.amount_for(asset_id).unwrap_or((0, U256::zero()));
	let asset_exists_in_accin = accin.ast.amount_for(asset_id).is_some();
	let asset_exists_in_accout = accout.ast.amount_for(asset_id).is_some();

	// ── tx_hash ───────────────────────────────────────────────────────────────
	let nk = accin.nk();
	let tx_inote_nulls: [NoteNullifier; NOTE_BATCH] = array::from_fn(|i| {
		if i < inotes.len() {
			let pos_f = F::from_canonical_usize(inotes_nct_proofs[i].pos);
			NoteNullifier(
				PositionedStandardNode::from_note(inotes[i], pos_f)
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
	let accin_null = accin.nullifier(Some(accin_merkle_proof.pos as u64));
	let tx_hash = derive_priv_tx_hash(
		accin_null,
		accout.commitment(),
		tx_inote_nulls,
		tx_onote_comms,
	);

	// ── Tx kind flags ─────────────────────────────────────────────────────────
	set_tx_kind_flags(
		pw,
		t,
		TxKindFlags {
			is_rjct: false,
			is_fresh_acc: false,
			is_update_auth: false,
			is_priv_tx: true,
			not_fake_tx: true,
		},
	);

	// ── Tree roots ────────────────────────────────────────────────────────────
	set_common_tx_witness(
		pw,
		t,
		main_pool.root(),
		root,
		approval_key,
		rejection_key,
		consume_key,
		accin,
		&accout,
	);
	set_hash(pw, t.accin_null.0, accin_null.0.0);
	set_hash(pw, t.accout_comm.0, accout.commitment().0.0);

	// ── Asset / amounts ───────────────────────────────────────────────────────
	pw.set_target(t.asset_id.0, asset_id.0).unwrap();
	t.accin_amt.set_witness(pw, accin_amt);
	t.accout_amt.set_witness(pw, accout_amt);

	pw.set_bool_target(t.asset_exists_in_accin, asset_exists_in_accin)
		.unwrap();
	pw.set_bool_target(t.asset_exists_in_accout, asset_exists_in_accout)
		.unwrap();
	pw.set_target(t.accin_pos, F::from_canonical_usize(accin_merkle_proof.pos))
		.unwrap();

	// ── ACT Merkle proof ──────────────────────────────────────────────────────
	t.accin_act_merkle.set_witness(pw, &accin_merkle_proof);

	// ── AST Merkle proof ──────────────────────────────────────────────────────
	t.accin_ast_merkle
		.set_witness(pw, &accin.ast.merkle_proof_at(ast_index));

	// ── Input notes ───────────────────────────────────────────────────────────
	let zero_addr = AccountAddress::zero();
	let inactive_inote = StandardNote {
		identifier: NodeIdentifier::ZERO,
		asset_id,
		amt: U256::zero(),
		recipient: AccountAddress::from_acc(accin),
		sender: zero_addr,
	};

	for i in 0..NOTE_BATCH {
		if i < inotes.len() {
			t.inotes[i].set_witness(pw, &inotes[i]);
			pw.set_target(
				t.inotes_pos[i],
				F::from_canonical_usize(inotes_nct_proofs[i].pos),
			)
			.unwrap();
			pw.set_bool_target(t.inotes_isactive[i], true).unwrap();
			t.inotes_nct_merkle[i].set_witness(pw, &inotes_nct_proofs[i]);
		} else {
			t.inotes[i].set_witness(pw, &inactive_inote);
			pw.set_target(t.inotes_pos[i], F::ZERO).unwrap();
			pw.set_bool_target(t.inotes_isactive[i], false).unwrap();
			t.inotes_nct_merkle[i].set_dummy_witness(pw, NCT_DEPTH);
		}
	}

	// ── Output notes ──────────────────────────────────────────────────────────
	let inactive_onote = StandardNote {
		identifier: NodeIdentifier::ZERO,
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
	set_hash_blocks(pw, &t.dinotes.map(|note| note.0), &dinotes);
	set_hash_blocks(pw, &t.donotes.map(|note| note.0), &donotes);

	// ── Subpool full proof ────────────────────────────────────────────────────
	set_subpool_full_proof(
		pw,
		&t.subpool_proof_targets,
		main_pool,
		approval_key,
		rejection_key,
		consume_key,
		subpool_id,
	);

	// ── Signatures ────────────────────────────────────────────────────────────

	// Spend signature
	{
		if let Some(sig) = spend_sig {
			set_real_schnorr_signature(
				pw,
				&t.sig_targets.spend,
				accin.spend_auth.spend_pk.unwrap(),
				&tx_hash.0,
				sig,
			);
		} else {
			set_fake_schnorr_signature(
				pw,
				&t.sig_targets.spend,
				accin
					.spend_auth
					.spend_pk
					.expect("accin must have a spend_pk for spend tx"),
				[11, 22, 33, 44, 55],
				[9, 8, 7, 6, 5],
			);
		}
	}

	// Consume signature
	{
		let consume_public_key = if accin.consume_auth.config {
			accin.consume_auth.pk.unwrap()
		} else {
			*consume_key
		};
		if let Some(sig) = consume_sig {
			set_real_schnorr_signature(
				pw,
				&t.sig_targets.consume,
				consume_public_key,
				&tx_hash.0,
				sig,
			);
		} else {
			set_fake_schnorr_signature(
				pw,
				&t.sig_targets.consume,
				consume_public_key,
				[13, 13, 13, 13, 13],
				[14, 15, 16, 17, 18],
			);
		}
	}

	// Approval signature (always real)
	set_real_schnorr_signature(
		pw,
		&t.sig_targets.approval,
		*approval_key,
		&tx_hash.0,
		approval_sig,
	);
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
#[allow(clippy::too_many_arguments)]
pub fn set_fake_tx_witness(
	pw: &mut PartialWitness<F>,
	t: &TxCircuitTargets,
	root: HashOutput,
	mainpool_config_root: HashOutput,
	accin_null_override: [F; 4],
	accout_comm_override: [F; 4],
	override_nc: [[F; 4]; crate::NOTE_BATCH],
) {
	// ── Sample accin ────────────────────────────────────────────────────────--
	let accin = StandardAccount::new_with(
		PrivateIdentifier([F::from_canonical_u64(1), F::from_noncanonical_u64(2)]),
		SubpoolId(F::ZERO),
	);

	// ── Derive accout ─────────────────────────────────────────────────────────
	let accout = accin.clone_with_incremented_nonce();

	// ── Tx kind flags (all false, not_fake_tx = false) ────────────────────────
	set_tx_kind_flags(
		pw,
		t,
		TxKindFlags {
			is_rjct: false,
			is_fresh_acc: false,
			is_update_auth: false,
			is_priv_tx: false,
			not_fake_tx: false,
		},
	);

	// ── Tree roots ─────────────────────────────────────────────────-----------
	let (fake_approval_cpk, fake_rejection_cpk, fake_consume_cpk) = fake_authority_keys();
	set_common_tx_witness(
		pw,
		t,
		mainpool_config_root,
		root,
		&fake_approval_cpk,
		&fake_rejection_cpk,
		&fake_consume_cpk,
		&accin,
		&accout,
	);
	set_hash(pw, t.accin_null.0, accin_null_override);
	set_hash(pw, t.accout_comm.0, accout_comm_override);

	// ── Asset / amounts (all zeros) ───────────────────────────────────────────
	pw.set_target(t.asset_id.0, F::ZERO).unwrap();
	set_u256_zero(pw, &t.accin_amt);
	set_u256_zero(pw, &t.accout_amt);
	pw.set_bool_target(t.asset_exists_in_accin, false).unwrap();
	pw.set_bool_target(t.asset_exists_in_accout, false).unwrap();
	pw.set_target(t.accin_pos, F::ZERO).unwrap();

	// ── ACT Merkle proof (all zeros) ──────────────────────────────────────────
	t.accin_act_merkle.set_dummy_witness(pw, ACT_DEPTH);

	// ── AST Merkle proof (real path of default leaf at index 0) ──────────────
	t.accin_ast_merkle
		.set_witness(pw, &accin.ast.merkle_proof_at(0));

	// ── Input notes (all inactive) ────────────────────────────────────────────
	let zero_addr = AccountAddress::zero();
	let inactive_inote = StandardNote {
		identifier: NodeIdentifier::ZERO,
		asset_id: AssetId(F::ZERO),
		amt: U256::zero(),
		recipient: AccountAddress::from_acc(&accin),
		sender: zero_addr,
	};
	for i in 0..NOTE_BATCH {
		t.inotes[i].set_witness(pw, &inactive_inote);
		pw.set_target(t.inotes_pos[i], F::ZERO).unwrap();
		pw.set_bool_target(t.inotes_isactive[i], false).unwrap();
		t.inotes_nct_merkle[i].set_dummy_witness(pw, NCT_DEPTH);
	}

	// ── Output notes (all inactive) ───────────────────────────────────────────
	let inactive_onote = StandardNote {
		identifier: NodeIdentifier::ZERO,
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
	set_hash_blocks(
		pw,
		&t.dinotes.map(|note| note.0),
		&[[F::ZERO; 4]; NOTE_BATCH],
	);
	set_hash_blocks(
		pw,
		&t.donotes.map(|note| note.0),
		&[[F::ZERO; 4]; NOTE_BATCH],
	);

	// ── Subpool proof ─────────────────────────────────────────────────────────
	// The three key-membership proofs are real (reconstructed from the fake keys).
	// Only the main-pool inclusion proof is zeroed — it is not enforced when
	// not_fake_tx = false.
	let fake_subpool =
		SubpoolConfigTree::new(fake_approval_cpk, fake_rejection_cpk, fake_consume_cpk);

	t.subpool_proof_targets
		.approval_proof
		.set_witness(pw, &fake_subpool.approval_key_proof());
	t.subpool_proof_targets
		.rejection_proof
		.set_witness(pw, &fake_subpool.rejection_key_proof());
	t.subpool_proof_targets
		.consume_proof
		.set_witness(pw, &fake_subpool.consume_key_proof());
	t.subpool_proof_targets
		.main_pool_proof
		.set_dummy_witness(pw, MAIN_POOL_CONFIG_DEPTH);

	pw.set_target_arr(
		&t.subpool_proof_targets.subpool_config_root.0.elements,
		&fake_subpool.root().0,
	)
	.unwrap();

	// ── Signatures (all fake) ─────────────────────────────────────────────────

	// Spend (fake)
	set_fake_schnorr_signature(
		pw,
		&t.sig_targets.spend,
		CompressedPublicKey(CompressedPoint::from(DEFAULT_SPEND_AUTH_PK)),
		[11, 22, 33, 44, 55],
		[9, 8, 7, 6, 5],
	);

	// Consume (fake)
	set_fake_schnorr_signature(
		pw,
		&t.sig_targets.consume,
		fake_consume_cpk,
		[13, 13, 13, 13, 13],
		[14, 15, 16, 17, 18],
	);

	// Approval (fake)
	set_fake_schnorr_signature(
		pw,
		&t.sig_targets.approval,
		fake_approval_cpk,
		[21, 22, 23, 24, 25],
		[31, 32, 33, 34, 35],
	);
}

#[cfg(test)]
mod tests {
	use itertools::Itertools;
	use plonky2::{
		hash::poseidon::PoseidonHash,
		plonk::{
			circuit_builder::CircuitBuilder,
			circuit_data::CircuitConfig,
			config::{GenericConfig, Hasher, PoseidonGoldilocksConfig},
		},
		timed,
	};
	use rand::SeedableRng;
	use rand_chacha::ChaCha8Rng;
	use tessera_trees::CommitmentTree;

	use super::*;
	use crate::{
		SpendAuth,
		plonky2_gadgets::{priv_tx::priv_tx_circuit, tests::print_common_data},
		schnorr::{CompressedPublicKey, PrivateKey, Scalar, schnorr_sign},
		time,
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

		// ── Single unified IMT (V2: accounts and notes share one on-chain tree) ─
		// Insert all commitments first, then generate all proofs against the final root.
		let mut tree = CommitmentTree::<HashOutput>::new(crate::ACT_DEPTH);

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
		accout
			.ast
			.insert_or_update_asset(asset_id_val, U256::from(150u64));

		// Insert all commitments into the unified tree before generating proofs
		let acc0_pos = tree.insert(acc0.commitment().0).unwrap().path;
		let n0_pos = tree.insert(n0.commitment().0).unwrap().path;
		let n1_pos = tree.insert(n1.commitment().0).unwrap().path;

		// Generate all Merkle proofs against the FINAL tree root
		let acc0_act_proof = CommitmentTreeMerkleProof::new(
			acc0.commitment().0,
			tree.merkle_path(acc0_pos, 0, ACT_DEPTH).unwrap(),
			acc0_pos,
			tree.num_leaves(),
		);
		assert!(acc0_act_proof.verify(tree.get_root()));

		let inotes = [n0, n1];
		let inotes_nct_proofs = [
			CommitmentTreeMerkleProof::new(
				inotes[0].commitment().0,
				tree.merkle_path(n0_pos, 0, NCT_DEPTH).unwrap(),
				n0_pos,
				tree.num_leaves(),
			),
			CommitmentTreeMerkleProof::new(
				inotes[1].commitment().0,
				tree.merkle_path(n1_pos, 0, NCT_DEPTH).unwrap(),
				n1_pos,
				tree.num_leaves(),
			),
		];

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

		// ── Signatures ────────────────────────────────────────────────────────

		// Consume (REAL): is_consume_req = true (N0+N1 active, no onotes)
		// consume_auth.config = false → circuit uses subpool consume key (consume_cpk)
		let consume_sig = {
			let k_c = Scalar::from_raw([7, 8, 9, 10, 11]);
			schnorr_sign(&consume_sk, &tx_hash.0, k_c)
		};

		// Approval (REAL): always required
		let approval_sig = {
			let k = Scalar::from_raw([1, 2, 3, 4, 5]);
			schnorr_sign(&approval_sk, &tx_hash.0, k)
		};

		// ── Build circuit ──────────────────────────────────────────────────────
		let config = CircuitConfig::standard_recursion_zk_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let ctx = HashOutput::register_luts(&mut builder);
		let t = priv_tx_circuit::<HashOutput, _, _>(&mut builder, &ctx);
		let inner_data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		// --- Set Witness -------------------------------------------------------

		set_spend_tx_witness(
			&mut pw,
			&t,
			&acc0,
			tree.get_root(),
			acc0_act_proof,
			&inotes,
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

		// Inner prove and verify
		print_common_data(&inner_data.common, "inner common data");
		let inner_proof = time!(
			"inner prove",
			inner_data.prove(pw).expect("inner proof generation failed")
		);
		time!(
			"inner verify",
			inner_data
				.verify(inner_proof.clone())
				.expect("inner verification failed")
		);

		// --- Recursive prove & verify ------------------------------------------

		// Build the outer (recursive) circuit that verifies the inner proof.
		let mut rec_builder =
			CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
		let proof_target = rec_builder.add_virtual_proof_with_pis(&inner_data.common);
		let verifier_target =
			rec_builder.add_virtual_verifier_data(inner_data.common.config.fri_config.cap_height);
		rec_builder.verify_proof::<C>(&proof_target, &verifier_target, &inner_data.common);
		let rec_data = time!("rec build", rec_builder.build::<C>());
		print_common_data(&rec_data.common, "rec common data");

		// Set the recursive witness.
		let mut rec_pw = PartialWitness::new();
		rec_pw
			.set_proof_with_pis_target(&proof_target, &inner_proof)
			.unwrap();
		rec_pw
			.set_cap_target(
				&verifier_target.constants_sigmas_cap,
				&inner_data.verifier_only.constants_sigmas_cap,
			)
			.unwrap();
		rec_pw
			.set_hash_target(
				verifier_target.circuit_digest,
				inner_data.verifier_only.circuit_digest,
			)
			.unwrap();

		let rec_proof = time!(
			"rec prove",
			rec_data.prove(rec_pw).expect("recursive proof failed")
		);
		time!(
			"rec verify",
			rec_data.verify(rec_proof).expect("recursive verify failed")
		);
	}

	#[test]
	fn test_fake_tx() {
		// ── Build circuit ──────────────────────────────────────────────────────
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let ctx = HashOutput::register_luts(&mut builder);
		let t = priv_tx_circuit::<HashOutput, _, _>(&mut builder, &ctx);
		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		let zerohash = HashOutput([F::ZERO; 4]);
		set_fake_tx_witness(
			&mut pw,
			&t,
			zerohash,
			zerohash,
			[F::ZERO; 4],
			[F::ZERO; 4],
			[[F::ZERO; 4]; NOTE_BATCH],
		);

		// ── Prove & verify ─────────────────────────────────────────────────────
		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}
}
