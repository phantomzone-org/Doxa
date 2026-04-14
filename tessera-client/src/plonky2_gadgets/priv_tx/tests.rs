use std::array;

use itertools::Itertools;
use plonky2::{
	hash::poseidon::PoseidonHash,
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::CircuitConfig,
		config::{GenericConfig, Hasher, PoseidonGoldilocksConfig},
	},
	timed,
};
use plonky2_field::types::{Field, PrimeField64};
use primitive_types::U256;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use tessera_trees::{MerkleProof, MerkleTree};
use tessera_utils::{ConfigNative, D, F, hasher::HashOutput};

use super::*;
use crate::{
	AccountAddress, AssetId, DS_PUBLIC_IDENTIFIER, NOTE_BATCH, Nonce, NoteCommitment,
	NoteIdentifier, NoteNullifier, PIHelper, PublicIdentifier, STATE_TREE_DEPTH, SpendAuth,
	StandardAccount, StandardNote, SubpoolId, derive_priv_tx_hash,
	plonky2_gadgets::{
		priv_tx::{
			fake_tx::set_fake_tx_witness, freshacc_tx::set_freshacc_tx_witness, priv_tx_circuit,
			reject_tx::set_reject_tx_witness, spend_tx::set_spend_tx_witness, targets::TxKindFlags,
		},
		tests::print_common_data,
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfig},
	schnorr::{CompressedPublicKey, PrivateKey, Scalar, schnorr_sign},
	time,
};

fn double_hash_native(elems: [F; 4]) -> [F; 4] {
	let h0 = <PoseidonHash as Hasher<F>>::hash_no_pad(&elems).elements;
	<PoseidonHash as Hasher<F>>::hash_no_pad(&h0).elements
}

fn sample_sk(rng: &mut impl Rng) -> PrivateKey {
	PrivateKey::from_raw(array::from_fn(|_| rng.next_u64()))
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

	let subpool = SubpoolConfig::<HashOutput>::new(approval_cpk);
	let subpool_id = SubpoolId(F::ONE);

	let mut main_pool = MainPoolConfigTree::new();
	main_pool
		.insert_subpool(subpool_id, subpool.commitment())
		.unwrap();

	// ── Single unified IMT (V2: accounts and notes share one on-chain tree) ─
	// Insert all commitments first, then generate all proofs against the final root.
	let mut tree = MerkleTree::<HashOutput>::new(crate::STATE_TREE_DEPTH);

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
		identifier: NoteIdentifier::from_rng(&mut rng),
		asset_id: asset_id_val,
		amt: U256::from(100u64),
		recipient: crate::AccountAddress::from_acc(&acc0),
		sender: crate::AccountAddress::from_acc(&acc1),
		memo: [0u8; 512],
	};
	let n1 = StandardNote {
		identifier: NoteIdentifier::from_rng(&mut rng),
		asset_id: asset_id_val,
		amt: U256::from(50u64),
		recipient: crate::AccountAddress::from_acc(&acc0),
		sender: crate::AccountAddress::from_acc(&acc1),
		memo: [0u8; 512],
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
	let acc0_pos = tree.insert(acc0.commitment().0).unwrap();
	let n0_pos = tree.insert(n0.commitment().0).unwrap();
	let n1_pos = tree.insert(n1.commitment().0).unwrap();

	// Generate all Merkle proofs against the FINAL tree root
	let acc0_act_proof = tree.merkle_proof(acc0_pos).unwrap();
	assert!(acc0_act_proof.verify());

	let inotes = [n0, n1];
	let inotes_nct_proofs = [
		tree.merkle_proof(n0_pos).unwrap(),
		tree.merkle_proof(n1_pos).unwrap(),
	];

	// Dummy notes (same pattern as freshacc)
	let dinotes: [[F; 4]; NOTE_BATCH] = array::from_fn(|i| [F::from_canonical_usize(i); 4]);
	let donotes: [[F; 4]; NOTE_BATCH] =
		array::from_fn(|i| [F::from_canonical_usize(i + NOTE_BATCH); 4]);

	// ── Compute note nullifiers and tx_hash ───────────────────────────────
	let nk0 = acc0.nk();
	// After Part 1 fix, native order matches circuit: commitment || position || nk
	let n0_null_arr: [F; 4] = n0.nullifier(n0_pos, &nk0).unwrap().0.0;
	let n1_null_arr: [F; 4] = n1.nullifier(n1_pos, &nk0).unwrap().0.0;

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

	let accin_null = acc0.nullifier();
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
	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, D>::new(config);
	let t = priv_tx_circuit::<HashOutput, _, _>(&mut builder);
	let inner_data = builder.build::<ConfigNative>();
	let mut pw = PartialWitness::new();

	// --- Set Witness -------------------------------------------------------
	t.set_tx_kind_flags(&mut pw, TxKindFlags::SPEND);

	set_spend_tx_witness(
		&mut pw,
		&t,
		&acc0,
		tree.root(),
		acc0_act_proof,
		&inotes,
		&inotes_nct_proofs,
		&vec![],
		dinotes,
		donotes,
		approval_cpk,
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

	// ── PI accessor checks ─────────────────────────────────────────────────
	let tp = crate::PrivateTransactionProof(inner_proof.clone());
	assert_eq!(tp.act_root(), tree.root(), "act_root mismatch");
	assert_eq!(
		tp.mainpool_config_root(),
		main_pool.root(),
		"mainpool_config_root mismatch"
	);
	assert_eq!(
		tp.not_fake_tx().to_canonical_u64(),
		1,
		"not_fake_tx should be 1"
	);
	assert_eq!(
		tp.accin_nullifier(),
		accin_null.0,
		"accin_nullifier mismatch"
	);
	assert_eq!(
		tp.accout_commitment(),
		accout.commitment().0,
		"accout_commitment mismatch"
	);

	let inote_nulls = tp.input_note_nullifiers();
	assert_eq!(
		inote_nulls[0],
		HashOutput(n0_null_arr),
		"inote_null[0] mismatch"
	);
	assert_eq!(
		inote_nulls[1],
		HashOutput(n1_null_arr),
		"inote_null[1] mismatch"
	);

	let onote_comms = tp.output_note_commitments();
	for i in 0..NOTE_BATCH {
		assert_eq!(
			onote_comms[i],
			HashOutput(double_hash_native(donotes[i])),
			"onote_comm[{i}] mismatch"
		);
	}

	// --- Recursive prove & verify ------------------------------------------

	// Build the outer (recursive) circuit that verifies the inner proof.
	let mut rec_builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
	let proof_target = rec_builder.add_virtual_proof_with_pis(&inner_data.common);
	let verifier_target =
		rec_builder.add_virtual_verifier_data(inner_data.common.config.fri_config.cap_height);
	rec_builder.verify_proof::<ConfigNative>(&proof_target, &verifier_target, &inner_data.common);
	let rec_data = time!("rec build", rec_builder.build::<ConfigNative>());
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
	let t = priv_tx_circuit::<HashOutput, _, _>(&mut builder);
	let data = builder.build::<ConfigNative>();
	let mut pw = PartialWitness::new();

	let zerohash = HashOutput([F::ZERO; 4]);
	t.set_tx_kind_flags(&mut pw, TxKindFlags::FAKE);
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

#[test]
fn test_prove_fresh_acc_tx() {
	let mut rng = ChaCha8Rng::seed_from_u64(42);

	// ── Keys for one subpool ──────────────────────────────────────────────
	let approval_sk = sample_sk(&mut rng);
	let approval_cpk: CompPubKey = approval_sk.public_key::<F>().into();

	let subpool = SubpoolConfig::<HashOutput>::new(approval_cpk);
	let subpool_id = SubpoolId(F::ONE);

	let mut main_pool = MainPoolConfigTree::new();
	main_pool
		.insert_subpool(subpool_id, subpool.commitment())
		.unwrap();

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
	let donote_comms = array::from_fn(|i| NoteCommitment(double_hash_native(donotes[i]).into()));
	let tx_hash = derive_priv_tx_hash(
		accin.nullifier(),
		accout.commitment(),
		dinote_nulls,
		donote_comms,
	);

	// TODO: sample randomly and reduce mod n
	let k = Scalar::from_raw(array::from_fn(|_| 1));
	let approval_sig = schnorr_sign(&approval_sk, &tx_hash.0, k);

	// ── Build circuit ─────────────────────────────────────────────────────
	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, D>::new(config);
	let t = priv_tx_circuit::<HashOutput, _, _>(&mut builder);
	let data = builder.build::<ConfigNative>();
	let mut pw = PartialWitness::new();

	// ── Fill witness ──────────────────────────────────────────────────────
	t.set_tx_kind_flags(&mut pw, TxKindFlags::FRESH_ACC);
	set_freshacc_tx_witness(
		&mut pw,
		&t,
		&accin,
		new_spend_auth,
		new_consume_auth,
		HashOutput([F::ZERO; 4]), // root: not in IMT yet; no notes for FreshAcc
		approval_cpk,
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

/// Dummy proofs must have PI[IS_REAL_OFFSET] (not_fake_tx) = 0.
/// Regression: set_freshacc_tx_witness sets is_fresh_acc=true, which
/// has a circuit constraint is_fresh_acc → not_fake_tx, forcing is_real=1.
/// Fix: dummy proofs use set_fake_tx_witness (is_fresh_acc=false).
#[test]
fn dummy_proof_has_not_fake_tx_zero() {
	const IS_REAL_OFFSET: usize = 8; // PI[8] = not_fake_tx

	let (circuit, targets) = build_priv_tx_circuit();
	let proof = prove_dummy_priv_tx(
		&circuit,
		&targets,
		[F::ZERO; 4],
		[[F::ZERO; 4]; NOTE_BATCH],
		[F::ZERO; 4],
		[[F::ZERO; 4]; NOTE_BATCH],
	);
	assert_eq!(
		proof.public_inputs[IS_REAL_OFFSET].to_canonical_u64(),
		0,
		"prove_dummy_priv_tx PI[IS_REAL_OFFSET] should be 0 (not_fake_tx=false)"
	);

	let (_circuit2, proof2) = build_circuit_and_dummy_proof();
	assert_eq!(
		proof2.public_inputs[IS_REAL_OFFSET].to_canonical_u64(),
		0,
		"build_circuit_and_dummy_proof PI[IS_REAL_OFFSET] should be 0 (not_fake_tx=false)"
	);
}

/// Dummy proofs' AN PIs must equal override_an at TX_DATA_OFFSET.
#[test]
fn dummy_proof_an_override_matches_pi() {
	// PI layout: [0]=not_fake [1-4]=root [5-8]=mpct_root [9-12]=AN ...
	const TX_DATA_OFFSET: usize = 9; // PI[9..13] = accin_null (AN)

	let (circuit, targets) = build_priv_tx_circuit();
	let override_an = [
		F::from_canonical_u64(111),
		F::from_canonical_u64(222),
		F::from_canonical_u64(333),
		F::from_canonical_u64(444),
	];
	let proof = prove_dummy_priv_tx(
		&circuit,
		&targets,
		override_an,
		[[F::ZERO; 4]; NOTE_BATCH],
		[F::ZERO; 4],
		[[F::ZERO; 4]; NOTE_BATCH],
	);
	let pis = &proof.public_inputs;
	for k in 0..4 {
		assert_eq!(
			pis[TX_DATA_OFFSET + k].to_canonical_u64(),
			override_an[k].to_canonical_u64(),
			"dummy proof AN PI[{}] mismatch: got {} expected {}",
			TX_DATA_OFFSET + k,
			pis[TX_DATA_OFFSET + k].to_canonical_u64(),
			override_an[k].to_canonical_u64(),
		);
	}
}

#[test]
fn test_prove_reject_tx() {
	// ── Keys for subpool ──────────────────────────────────────────────────
	let approval_sk = PrivateKey::from_raw([2, 3, 4, 5, 6]);
	let approval_cpk: CompPubKey = approval_sk.public_key::<F>().into();

	let subpool = SubpoolConfig::<HashOutput>::new(approval_cpk);
	let subpool_id = SubpoolId(F::ONE);

	let mut main_pool = MainPoolConfigTree::new();
	main_pool
		.insert_subpool(subpool_id, subpool.commitment())
		.unwrap();

	// ── Account (simulate post-FreshAcc) ──────────────────────────────────
	let mut rng = ChaCha8Rng::seed_from_u64(99);
	let spend_sk = PrivateKey::from_raw([999, 1000, 1001, 1002, 0]);
	let spend_cpk = CompressedPublicKey::from(spend_sk.public_key::<F>());
	let mut acc = StandardAccount::sample(&mut rng, subpool_id);
	acc.nonce = Nonce(F::ONE);
	acc.spend_auth = SpendAuth {
		spend_pk: Some(spend_cpk),
	};

	// ── Single unified IMT (V2: accounts and notes share one on-chain tree) ─
	// Insert all commitments first, then generate all proofs against the final root.
	let mut state_tree = MerkleTree::<HashOutput>::new(STATE_TREE_DEPTH);
	let acc_pos = state_tree.insert(acc.commitment().0).unwrap();

	// ── Sender address ────────────────────────────────────────────────────
	let sender_priv = [F::from_canonical_u64(77), F::from_canonical_u64(88)];
	let sender_pubid = PublicIdentifier(HashOutput(
		<PoseidonHash as Hasher<F>>::hash_no_pad(&[
			F::from_canonical_u64(DS_PUBLIC_IDENTIFIER),
			sender_priv[0],
			sender_priv[1],
		])
		.elements,
	));
	let sender_addr = AccountAddress {
		subpool_id: SubpoolId(F::from_canonical_u64(2)),
		public_id: sender_pubid,
	};

	// ── Two input notes addressed to acc, sent from sender ────────────────
	let asset_id_val = AssetId(F::ONE);
	let note0 = StandardNote {
		identifier: NoteIdentifier::from_rng(&mut rng),
		asset_id: asset_id_val,
		amt: U256::from(100u64),
		recipient: AccountAddress::from_acc(&acc),
		sender: sender_addr,
		memo: [0u8; 512],
	};
	let note1 = StandardNote {
		identifier: NoteIdentifier::from_rng(&mut rng),
		asset_id: asset_id_val,
		amt: U256::from(50u64),
		recipient: AccountAddress::from_acc(&acc),
		sender: sender_addr,
		memo: [0u8; 512],
	};

	// Insert notes into the same unified tree, then generate all proofs against final root
	let n0_pos = state_tree.insert(note0.commitment().0).unwrap();
	let n1_pos = state_tree.insert(note1.commitment().0).unwrap();

	let acc_act_proof = state_tree.merkle_proof(acc_pos).unwrap();
	assert!(acc_act_proof.verify());

	let inotes_nct_proofs = [
		state_tree.merkle_proof(n0_pos).unwrap(),
		state_tree.merkle_proof(n1_pos).unwrap(),
	];

	// ── Output notes (reject — send back to sender) ───────────────────────
	let onote0 = StandardNote {
		identifier: note0.identifier,
		asset_id: note0.asset_id,
		amt: note0.amt,
		recipient: sender_addr,
		sender: sender_addr,
		memo: [0u8; 512],
	};
	let onote1 = StandardNote {
		identifier: note1.identifier,
		asset_id: note1.asset_id,
		amt: note1.amt,
		recipient: sender_addr,
		sender: sender_addr,
		memo: [0u8; 512],
	};

	// ── Dummy notes ───────────────────────────────────────────────────────
	let (dinotes, donotes) = sample_dummy_notes(&mut rng);

	// ── Compute tx_hash natively ──────────────────────────────────────────
	let nk = acc.nk();
	let accin_null = acc.nullifier();
	let mut accout = acc.clone();
	accout.nonce = Nonce(F::from_canonical_u64(2));

	let tx_inote_nulls: [NoteNullifier; NOTE_BATCH] = core::array::from_fn(|i| match i {
		0 => NoteNullifier(note0.nullifier(n0_pos, &nk).unwrap().0),
		1 => NoteNullifier(note1.nullifier(n1_pos, &nk).unwrap().0),
		_ => NoteNullifier(HashOutput(double_hash_native(dinotes[i]))),
	});
	let tx_onote_comms: [NoteCommitment; NOTE_BATCH] = core::array::from_fn(|i| match i {
		0 => onote0.commitment(),
		1 => onote1.commitment(),
		_ => NoteCommitment(HashOutput(double_hash_native(donotes[i]))),
	});
	let tx_hash = crate::derive_priv_tx_hash(
		accin_null,
		accout.commitment(),
		tx_inote_nulls,
		tx_onote_comms,
	);

	// ── Signatures ────────────────────────────────────────────────────────
	let approval_sig = schnorr_sign(&approval_sk, &tx_hash.0, Scalar::from_raw([1, 2, 3, 4, 5]));

	// ── Build circuit ──────────────────────────────────────────────────────
	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, D>::new(config);
	let t = priv_tx_circuit::<HashOutput, _, _>(&mut builder);
	let data = builder.build::<ConfigNative>();
	let mut pw = PartialWitness::new();

	// ── Fill witness ──────────────────────────────────────────────────────
	t.set_tx_kind_flags(&mut pw, TxKindFlags::REJECT);
	set_reject_tx_witness(
		&mut pw,
		&t,
		&acc,
		acc_act_proof,
		state_tree.root(),
		&[note0, note1],
		&inotes_nct_proofs,
		&[onote0, onote1],
		dinotes,
		donotes,
		approval_cpk,
		subpool_id,
		&main_pool,
		None,
		approval_sig,
	);

	// ── Prove & verify ─────────────────────────────────────────────────────
	let proof = data.prove(pw).expect("prove failed");
	data.verify(proof).expect("verify failed");
}
