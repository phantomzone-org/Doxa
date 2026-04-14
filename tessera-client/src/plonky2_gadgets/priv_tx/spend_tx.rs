use std::array;

use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2_field::types::{Field, PrimeField64};
use primitive_types::U256;
use tessera_trees::MerkleProof;
use tessera_utils::{
	F,
	hasher::{HashOutput, MerkleHashCircuit},
};

use super::{double_hash_native, targets::TxCircuitTargets};
use crate::{
	AccountAddress, AssetId, DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER, DEFAULT_SPEND_AUTH_PK,
	MAIN_POOL_CONFIG_DEPTH, NOTE_BATCH, Nonce, NoteCommitment, NoteNullifier, PrivateIdentifier,
	STATE_TREE_DEPTH, SpendAuth, StandardAccount, SubpoolId,
	account::{AccountStateTreeLeaf, PublicIdentifier},
	derive_priv_tx_hash,
	ecgfp5::CompressedPoint,
	note::{NoteIdentifier, StandardNote},
	plonky2_gadgets::{
		set_hash, set_u256_zero,
		witness::{fake_authority_key, set_hash_blocks},
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfig},
	schnorr::{CompressedPublicKey, PrivateKey, Signature},
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
	accin_merkle_proof: MerkleProof<HashOutput>,
	inotes: &[StandardNote],
	// MerkleProof of commitments of inotes in NCT
	inotes_nct_proofs: &[MerkleProof<HashOutput>],
	onotes: &[StandardNote],
	dinotes: [[F; 4]; NOTE_BATCH],
	donotes: [[F; 4]; NOTE_BATCH],
	approval_key: CompPubKey,
	subpool_id: SubpoolId,
	main_pool: &MainPoolConfigTree<HashOutput>,
	// Some(sig) if there are active output notes requiring spend auth; None → fake.
	spend_sig: Option<Signature>,
	// Some(sig) if there are active input notes and no active output notes requiring consume
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
			inotes[i]
				.nullifier(inotes_nct_proofs[i].pos, &nk)
				.expect("note position must be < F::ORDER")
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
	let accin_null = accin.nullifier();
	let tx_hash = derive_priv_tx_hash(
		accin_null,
		accout.commitment(),
		tx_inote_nulls,
		tx_onote_comms,
	);

	// ── Tree roots ────────────────────────────────────────────────────────────
	t.set_common_witnesses(pw, main_pool.root(), root, approval_key, accin, &accout);

	set_hash(pw, t.public.accin_null.0, accin_null.0.0);
	set_hash(pw, t.public.accout_comm.0, accout.commitment().0.0);

	// ── Asset / amounts ───────────────────────────────────────────────────────
	pw.set_target(t.private.asset_id.0, asset_id.0).unwrap();
	t.private.accin_amt.set_witness(pw, accin_amt);
	t.private.accout_amt.set_witness(pw, accout_amt);

	pw.set_bool_target(t.private.asset_exists_in_accin, asset_exists_in_accin)
		.unwrap();
	pw.set_bool_target(t.private.asset_exists_in_accout, asset_exists_in_accout)
		.unwrap();

	// ── ACT Merkle proof ──────────────────────────────────────────────────────
	t.private
		.accin_act_merkle
		.set_witness(pw, &accin_merkle_proof);

	// ── AST Merkle proof ──────────────────────────────────────────────────────
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

	let subpool = SubpoolConfig::new(approval_key);
	let subpool_proof = main_pool
		.full_subpool_proof(&subpool, subpool_id)
		.expect("subpool not registered in main_pool at the given subpool_id");

	// ── Subpool full proof ────────────────────────────────────────────────────
	t.private.subpool_proof_targets.set_witness(
		pw,
		subpool_proof,
		subpool.commitment(),
		subpool_id,
	);

	// ── Signatures ────────────────────────────────────────────────────────────

	// Spend signature
	{
		// TODO: I think one should return an error here saying that spend_key must exist
		let spend_pk = accin
			.spend_auth
			.spend_pk
			.unwrap_or_else(|| CompressedPublicKey(CompressedPoint::from(DEFAULT_SPEND_AUTH_PK)));
		if let Some(sig) = spend_sig {
			t.private.sig_targets.spend.set(pw, spend_pk, tx_hash, sig);
		} else {
			t.private.sig_targets.spend.set_fake(pw, spend_pk);
		}
	}

	// Consume signature
	{
		// TODO: return an error if consume_auth.config == 1 and consume_auth.pk is None
		let consume_public_key = accin.consume_auth.pk.unwrap_or_else(|| {
			CompressedPublicKey(CompressedPoint::from(
				DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER,
			))
		});
		if let Some(sig) = consume_sig {
			t.private
				.sig_targets
				.consume
				.set(pw, consume_public_key, tx_hash, sig);
		} else {
			t.private
				.sig_targets
				.consume
				.set_fake(pw, consume_public_key);
		}
	}

	// Approval signature (always real)
	t.private
		.sig_targets
		.approval
		.set(pw, approval_key, tx_hash, approval_sig);
}
