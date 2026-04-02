use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2_field::types::{Field, PrimeField64};
use primitive_types::U256;
use tessera_trees::MerkleProof;
use tessera_utils::{F, hasher::HashOutput};

use super::{double_hash_native, targets::TxCircuitTargets};
use crate::{
	AccountAddress, AssetId, COM_TREE_DEPTH, NOTE_BATCH, Nonce, NoteCommitment, NoteNullifier,
	StandardAccount, SubpoolId,
	account::PublicIdentifier,
	derive_priv_tx_hash,
	ecgfp5::PointEw,
	note::{NoteIdentifier, StandardNote},
	plonky2_gadgets::{
		set_hash,
		witness::{set_hash_blocks, set_subpool_full_proof},
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
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
	approval_key: CompPubKey,
	rejection_key: CompPubKey,
	consume_key: CompPubKey,
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
			StandardNote::nullifier(&inotes[i].commitment(), inotes_nct_proofs[i].pos, &nk)
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

	// ── Tree roots ────────────────────────────────────────────────────────────
	t.set_common_witnesses(
		pw,
		main_pool.root(),
		root,
		approval_key,
		rejection_key,
		consume_key,
		accin,
		&accout,
	);

	set_hash(pw, t.public.accin_null.0, accin_null.0.0);
	set_hash(pw, t.public.accout_comm.0, accout.commitment().0.0);

	// ── Asset / amounts ───────────────────────────────────────────────────────
	// Use the asset_id from active inotes (all notes must share the same asset_id in the circuit)
	let asset_id = inotes
		.first()
		.map(|n| n.asset_id)
		.unwrap_or(AssetId(F::ZERO));
	pw.set_target(t.public.asset_id.0, asset_id.0).unwrap();

	let (ast_index, accin_amt) = accin
		.ast
		.amount_for(asset_id)
		.unwrap_or_else(|| (accin.ast.next_index(), U256::zero()));
	let asset_exists = accin.ast.amount_for(asset_id).is_some();
	// Reject tx does not modify the AST, so accout amounts mirror accin
	t.private.accin_amt.set_witness(pw, accin_amt);
	t.private.accout_amt.set_witness(pw, accin_amt);
	pw.set_bool_target(t.private.asset_exists_in_accin, asset_exists)
		.unwrap();
	pw.set_bool_target(t.private.asset_exists_in_accout, asset_exists)
		.unwrap();
	pw.set_target(
		t.private.accin_pos,
		F::from_canonical_usize(accin_act_merkle_proof.pos),
	)
	.unwrap();

	// ── ACT Merkle proof ──────────────────────────────────────────────────────
	t.private
		.accin_act_merkle
		.set_witness(pw, &accin_act_merkle_proof);

	// ── AST Merkle proof ──────────────────────────────────────────────────────
	// Use asset's leaf index if present, else next free default-leaf path
	t.private
		.accin_ast_merkle
		.set_witness(pw, &accin.ast.merkle_proof_at(ast_index));

	// ── Input notes ───────────────────────────────────────────────────────────
	let zero_addr = AccountAddress::ZERO;
	let inactive_inote = StandardNote {
		identifier: NoteIdentifier::ZERO,
		asset_id,
		amt: U256::zero(),
		recipient: AccountAddress::from_acc(accin),
		sender: zero_addr,
		memo: [0u8; 512],
	};
	for i in 0..NOTE_BATCH {
		if i < inotes.len() {
			t.private.inotes[i].set_witness(pw, &inotes[i]);
			pw.set_target(
				t.private.inotes_pos[i],
				F::from_canonical_usize(inotes_nct_proofs[i].pos),
			)
			.unwrap();
			pw.set_bool_target(t.private.inotes_isactive[i], true)
				.unwrap();
			t.private.inotes_nct_merkle[i].set_witness(pw, &inotes_nct_proofs[i]);
		} else {
			t.private.inotes[i].set_witness(pw, &inactive_inote);
			pw.set_target(t.private.inotes_pos[i], F::ZERO).unwrap();
			pw.set_bool_target(t.private.inotes_isactive[i], false)
				.unwrap();
			t.private.inotes_nct_merkle[i].set_dummy_witness(pw);
		}
	}

	// ── Output notes ──────────────────────────────────────────────────────────
	let inactive_onote = StandardNote {
		identifier: NoteIdentifier::ZERO,
		asset_id,
		amt: U256::zero(),
		recipient: zero_addr,
		sender: zero_addr,
		memo: [0u8; 512],
	};
	for i in 0..NOTE_BATCH {
		if i < onotes.len() {
			t.private.onotes[i].set_witness(pw, &onotes[i]);
			pw.set_bool_target(t.private.onotes_isactive[i], true)
				.unwrap();
		} else {
			t.private.onotes[i].set_witness(pw, &inactive_onote);
			pw.set_bool_target(t.private.onotes_isactive[i], false)
				.unwrap();
		}
	}

	// ── Dummy note hashes ─────────────────────────────────────────────────────
	set_hash_blocks(pw, &t.private.dinotes.map(|note| note.0), &dinotes);
	set_hash_blocks(pw, &t.private.donotes.map(|note| note.0), &donotes);

	let subpool = SubpoolConfigTree::new(approval_key, rejection_key, consume_key);
	let subpool_proof = main_pool
		.full_subpool_proof(&subpool, subpool_id)
		.expect("subpool not registered in main_pool at the given subpool_id");

	// ── Subpool full proof ────────────────────────────────────────────────────
	set_subpool_full_proof(
		pw,
		&t.private.subpool_proof_targets,
		subpool_proof,
		subpool.root(),
		subpool_id,
		approval_key,
		rejection_key,
		consume_key,
	);

	// ── Signatures ────────────────────────────────────────────────────────────

	// Spend (fake — disabled for reject by not_is_rjct, but Q must match accin.spend_auth)
	let spend_pk = accin
		.spend_auth
		.spend_pk
		.expect("accin must have a spend_pk");
	t.private.sig_targets.spend.set_fake(pw, spend_pk);

	// Consume (real — is_consume_req = has_inotes AND not_is_spend_req = true)
	t.private
		.sig_targets
		.consume
		.set(pw, consume_key, tx_hash, consume_sig);

	// Approval (real — always required)
	t.private
		.sig_targets
		.approval
		.set(pw, approval_key, tx_hash, approval_sig);
}
