use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2_field::types::{Field, PrimeField64};
use primitive_types::U256;
use tessera_trees::MerkleProof;
use tessera_utils::{F, hasher::HashOutput};

use super::{
	double_hash_native,
	targets::TxCircuitTargets,
	witness::{TxKindFlags, set_common_tx_witness, set_tx_kind_flags},
};
use crate::{
	AccountAddress, AssetId, COM_TREE_DEPTH, NOTE_BATCH, Nonce, NoteCommitment, NoteNullifier,
	StandardAccount, SubpoolId,
	account::PublicIdentifier,
	derive_priv_tx_hash,
	note::{NodeIdentifier, PositionedStandardNode, StandardNote},
	plonky2_gadgets::{
		set_hash,
		witness::{set_hash_blocks, set_real_schnorr_signature, set_subpool_full_proof},
	},
	pool_config::{CompPubKey, MainPoolConfigTree},
	schnorr::Signature,
};

/// Fill `pw` with a complete reject transaction witness.
///
/// `accout` is derived internally by cloning `accin` and incrementing the nonce.
/// The tx_hash uses the real `accin` nullifier (position-based) and `accout` commitment —
/// no dummy accounts. `d_accin`/`d_accout` circuit targets are zeroed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn set_reject_tx_witness(
	pw: &mut PartialWitness<F>,
	t: &TxCircuitTargets,
	accin: &StandardAccount,
	accin_act_merkle_proof: MerkleProof<HashOutput>,
	root: HashOutput,
	inotes: &[StandardNote],
	inotes_nct_proofs: &[MerkleProof<HashOutput>],
	onotes: &[StandardNote],
	dinotes: [[F; 4]; NOTE_BATCH],
	donotes: [[F; 4]; NOTE_BATCH],
	approval_key: &CompPubKey,
	rejection_key: &CompPubKey,
	consume_key: &CompPubKey,
	subpool_id: SubpoolId,
	main_pool: &MainPoolConfigTree<HashOutput>,
	consume_sig: Signature,
	approval_sig: Signature,
) {
	assert!(inotes.len() <= NOTE_BATCH);
	assert_eq!(inotes.len(), onotes.len());
	assert_eq!(inotes.len(), inotes_nct_proofs.len());

	// ── Build accout ──────────────────────────────────────────────────────────
	let accout = accin.clone_with_incremented_nonce();

	// ── Tx hash ───────────────────────────────────────────────────────────────
	let nk = accin.nk();
	let accin_null = accin.nullifier();

	let tx_inote_nulls: [NoteNullifier; NOTE_BATCH] = core::array::from_fn(|i| {
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
	let tx_onote_comms: [NoteCommitment; NOTE_BATCH] = core::array::from_fn(|i| {
		if i < onotes.len() {
			onotes[i].commitment()
		} else {
			NoteCommitment(HashOutput(double_hash_native(donotes[i])))
		}
	});
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
			is_rjct: true,
			is_fresh_acc: false,
			is_update_auth: false,
			is_priv_tx: false,
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
	// Use the asset_id from active inotes (all notes must share the same asset_id in the circuit)
	let asset_id = inotes
		.first()
		.map(|n| n.asset_id)
		.unwrap_or(AssetId(F::ZERO));
	pw.set_target(t.asset_id.0, asset_id.0).unwrap();

	let (ast_index, accin_amt) = accin
		.ast
		.amount_for(asset_id)
		.unwrap_or_else(|| (accin.ast.next_index(), U256::zero()));
	let asset_exists = accin.ast.amount_for(asset_id).is_some();
	// Reject tx does not modify the AST, so accout amounts mirror accin
	t.accin_amt.set_witness(pw, accin_amt);
	t.accout_amt.set_witness(pw, accin_amt);
	pw.set_bool_target(t.asset_exists_in_accin, asset_exists)
		.unwrap();
	pw.set_bool_target(t.asset_exists_in_accout, asset_exists)
		.unwrap();
	pw.set_target(
		t.accin_pos,
		F::from_canonical_usize(accin_act_merkle_proof.pos),
	)
	.unwrap();

	// ── ACT Merkle proof ──────────────────────────────────────────────────────
	t.accin_act_merkle.set_witness(pw, &accin_act_merkle_proof);

	// ── AST Merkle proof ──────────────────────────────────────────────────────
	// Use asset's leaf index if present, else next free default-leaf path
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
		memo: [0u8; 512],
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
			t.inotes_nct_merkle[i].set_dummy_witness(pw);
		}
	}

	// ── Output notes ──────────────────────────────────────────────────────────
	let inactive_onote = StandardNote {
		identifier: NodeIdentifier::ZERO,
		asset_id,
		amt: U256::zero(),
		recipient: zero_addr,
		sender: zero_addr,
		memo: [0u8; 512],
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

	// Spend (fake — disabled for reject by not_is_rjct, but Q must match accin.spend_auth)
	crate::plonky2_gadgets::witness::set_fake_schnorr_signature(
		pw,
		&t.sig_targets.spend,
		accin
			.spend_auth
			.spend_pk
			.expect("accin must have a spend_pk"),
		[42, 8, 2, 5, 1],
		[7, 12, 13, 14, 14],
	);

	// Consume (real — is_consume_req = has_inotes AND not_is_spend_req = true)
	set_real_schnorr_signature(
		pw,
		&t.sig_targets.consume,
		*consume_key,
		&tx_hash.0,
		consume_sig,
	);

	// Approval (real — always required)
	set_real_schnorr_signature(
		pw,
		&t.sig_targets.approval,
		*approval_key,
		&tx_hash.0,
		approval_sig,
	);
}

#[cfg(test)]
mod tests {
	use plonky2::{
		hash::poseidon::PoseidonHash,
		iop::witness::PartialWitness,
		plonk::{
			circuit_builder::CircuitBuilder,
			circuit_data::CircuitConfig,
			config::{GenericConfig, Hasher, PoseidonGoldilocksConfig},
		},
	};
	use plonky2_field::types::Field;
	use primitive_types::U256;
	use rand::SeedableRng;
	use rand_chacha::ChaCha8Rng;
	use tessera_trees::{MerkleProof, MerkleTree};
	use tessera_utils::hasher::{HashOutput, MerkleHashCircuit};

	use super::*;
	use crate::{
		AssetId, COM_TREE_DEPTH, DS_PUBLIC_IDENTIFIER, NOTE_BATCH, Nonce, SpendAuth,
		StandardAccount, SubpoolId,
		account::{AccountAddress, PublicIdentifier},
		note::{NodeIdentifier, PositionedStandardNode, StandardNote},
		plonky2_gadgets::priv_tx::{priv_tx_circuit, sample_dummy_notes},
		pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
		schnorr::{CompressedPublicKey, PrivateKey, Scalar, schnorr_sign},
	};

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = <C as GenericConfig<D>>::F;

	fn double_hash_native(elems: [F; 4]) -> [F; 4] {
		let h0 = <PoseidonHash as Hasher<F>>::hash_no_pad(&elems).elements;
		<PoseidonHash as Hasher<F>>::hash_no_pad(&h0).elements
	}

	#[test]
	fn test_prove_reject_tx() {
		// ── Keys for subpool ──────────────────────────────────────────────────
		let approval_sk = PrivateKey::from_raw([2, 3, 4, 5, 6]);
		let approval_cpk: CompPubKey = approval_sk.public_key::<F>().into();

		let rejection_sk = PrivateKey::from_raw([5, 6, 7, 8, 0]);
		let rejection_cpk: CompPubKey = rejection_sk.public_key::<F>().into();

		let consume_sk = PrivateKey::from_raw([9, 10, 11, 12, 0]);
		let consume_cpk: CompPubKey = consume_sk.public_key::<F>().into();

		let subpool =
			SubpoolConfigTree::<HashOutput>::new(approval_cpk, rejection_cpk, consume_cpk);
		let subpool_id = SubpoolId(F::ONE);

		let mut main_pool = MainPoolConfigTree::new();
		main_pool
			.insert_subpool(subpool_id, subpool.root())
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
		let mut tree = MerkleTree::<HashOutput>::new(COM_TREE_DEPTH);
		let acc_pos = tree.insert(acc.commitment().0).unwrap();

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
			identifier: NodeIdentifier::from_rng(&mut rng),
			asset_id: asset_id_val,
			amt: U256::from(100u64),
			recipient: AccountAddress::from_acc(&acc),
			sender: sender_addr,
			memo: [0u8; 512],
		};
		let note1 = StandardNote {
			identifier: NodeIdentifier::from_rng(&mut rng),
			asset_id: asset_id_val,
			amt: U256::from(50u64),
			recipient: AccountAddress::from_acc(&acc),
			sender: sender_addr,
			memo: [0u8; 512],
		};

		// Insert notes into the same unified tree, then generate all proofs against final root
		let n0_pos = tree.insert(note0.commitment().0).unwrap();
		let n1_pos = tree.insert(note1.commitment().0).unwrap();

		let acc_act_proof = tree.merkle_proof(acc_pos).unwrap();
		assert!(acc_act_proof.verify());

		let inotes_nct_proofs = [
			tree.merkle_proof(n0_pos).unwrap(),
			tree.merkle_proof(n1_pos).unwrap(),
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
			0 => NoteNullifier(
				PositionedStandardNode::from_note(note0.clone(), F::from_canonical_usize(n0_pos))
					.nullifier(&nk)
					.0,
			),
			1 => NoteNullifier(
				PositionedStandardNode::from_note(note1.clone(), F::from_canonical_usize(n1_pos))
					.nullifier(&nk)
					.0,
			),
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
		let consume_sig =
			schnorr_sign(&consume_sk, &tx_hash.0, Scalar::from_raw([7, 8, 9, 10, 11]));
		let approval_sig =
			schnorr_sign(&approval_sk, &tx_hash.0, Scalar::from_raw([1, 2, 3, 4, 5]));

		// ── Build circuit ──────────────────────────────────────────────────────
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let t = priv_tx_circuit::<HashOutput, _, _>(&mut builder);
		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		// ── Fill witness ──────────────────────────────────────────────────────
		set_reject_tx_witness(
			&mut pw,
			&t,
			&acc,
			acc_act_proof,
			tree.root(),
			&[note0, note1],
			&inotes_nct_proofs,
			&[onote0, onote1],
			dinotes,
			donotes,
			&approval_cpk,
			&rejection_cpk,
			&consume_cpk,
			subpool_id,
			&main_pool,
			consume_sig,
			approval_sig,
		);

		// ── Prove & verify ─────────────────────────────────────────────────────
		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}
}
