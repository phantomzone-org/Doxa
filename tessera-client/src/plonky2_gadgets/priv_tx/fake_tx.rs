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
	AccountAddress, AssetId, COM_TREE_DEPTH, DEFAULT_SPEND_AUTH_PK, MAIN_POOL_CONFIG_DEPTH,
	NOTE_BATCH, Nonce, NoteCommitment, NoteNullifier, PrivateIdentifier, SpendAuth,
	StandardAccount, SubpoolId,
	account::{AccountStateTreeLeaf, PublicIdentifier},
	derive_priv_tx_hash,
	ecgfp5::CompressedPoint,
	note::{NoteIdentifier, StandardNote},
	plonky2_gadgets::{
		set_hash, set_u256_zero,
		witness::{
			fake_authority_key, set_authority_keys, set_hash_blocks, set_subpool_full_proof,
		},
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
	schnorr::{CompressedPublicKey, PrivateKey, Signature},
};

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

	// ── Tree roots ─────────────────────────────────────────────────-----------
	let key = fake_authority_key();
	t.set_common_witnesses(
		pw,
		mainpool_config_root,
		root,
		key,
		key,
		key,
		&accin,
		&accout,
	);
	set_hash(pw, t.public.accin_null.0, accin_null_override);
	set_hash(pw, t.public.accout_comm.0, accout_comm_override);

	// ── Asset / amounts (all zeros) ───────────────────────────────────────────
	pw.set_target(t.private.asset_id.0, F::ZERO).unwrap();
	set_u256_zero(pw, &t.private.accin_amt);
	set_u256_zero(pw, &t.private.accout_amt);
	pw.set_bool_target(t.private.asset_exists_in_accin, false)
		.unwrap();
	pw.set_bool_target(t.private.asset_exists_in_accout, false)
		.unwrap();
	pw.set_target(t.private.accin_pos, F::ZERO).unwrap();

	// ── ACT Merkle proof (all zeros) ──────────────────────────────────────────
	t.private.accin_act_merkle.set_dummy_witness(pw);

	// ── AST Merkle proof (real path of default leaf at index 0) ──────────────
	t.private
		.accin_ast_merkle
		.set_witness(pw, &accin.ast.merkle_proof_at(0));

	// ── Input notes (all inactive) ────────────────────────────────────────────
	let zero_addr = AccountAddress::ZERO;
	let inactive_inote = StandardNote {
		identifier: NoteIdentifier::ZERO,
		asset_id: AssetId(F::ZERO),
		amt: U256::zero(),
		recipient: AccountAddress::from_acc(&accin),
		sender: zero_addr,
		memo: [0u8; 512],
	};
	for i in 0..NOTE_BATCH {
		t.private.inotes[i].set_witness(pw, &inactive_inote);
		pw.set_target(t.private.inotes_pos[i], F::ZERO).unwrap();
		pw.set_bool_target(t.private.inotes_isactive[i], false)
			.unwrap();
		t.private.inotes_nct_merkle[i].set_dummy_witness(pw);
	}

	// ── Output notes (all inactive) ───────────────────────────────────────────
	let inactive_onote = StandardNote {
		identifier: NoteIdentifier::ZERO,
		asset_id: AssetId(F::ZERO),
		amt: U256::zero(),
		recipient: zero_addr,
		sender: zero_addr,
		memo: [0u8; 512],
	};
	for i in 0..NOTE_BATCH {
		t.private.onotes[i].set_witness(pw, &inactive_onote);
		pw.set_bool_target(t.private.onotes_isactive[i], false)
			.unwrap();
	}

	// ── Dummy note hashes (all zeros) ─────────────────────────────────────────
	set_hash_blocks(
		pw,
		&t.private.dinotes.map(|note| note.0),
		&[[F::ZERO; 4]; NOTE_BATCH],
	);
	set_hash_blocks(
		pw,
		&t.private.donotes.map(|note| note.0),
		&[[F::ZERO; 4]; NOTE_BATCH],
	);

	// ── Subpool proof ─────────────────────────────────────────────────────────
	// The three key-membership proofs are real (reconstructed from the fake keys).
	// Only the main-pool inclusion proof is zeroed — it is not enforced when
	// not_fake_tx = false.
	let fake_subpool = SubpoolConfigTree::new(key, key, key);

	let fake_subpool_approval_key_proof = fake_subpool.approval_key_proof().unwrap();
	let fake_subpool_rejection_key_proof = fake_subpool.rejection_key_proof().unwrap();
	let fake_subpool_consume_key_proof = fake_subpool.consume_key_proof().unwrap();

	t.private
		.subpool_proof_targets
		.approval_proof
		.set_witness(pw, &fake_subpool_approval_key_proof);
	t.private
		.subpool_proof_targets
		.rejection_proof
		.set_witness(pw, &fake_subpool_rejection_key_proof);
	t.private
		.subpool_proof_targets
		.consume_proof
		.set_witness(pw, &fake_subpool_consume_key_proof);
	t.private
		.subpool_proof_targets
		.main_pool_proof
		.set_dummy_witness(pw);

	pw.set_target_arr(
		&t.private
			.subpool_proof_targets
			.subpool_config_root
			.0
			.elements,
		&fake_subpool.root().0,
	)
	.unwrap();

	// ── Signatures (all fake) ─────────────────────────────────────────────────
	// The spend circuit gate uses accin.spend_auth as cq — must match what
	// accin.set_witness stored (DEFAULT_SPEND_AUTH_PK when no spend_pk is set).
	let default_spend_pk = CompressedPublicKey(CompressedPoint::from(DEFAULT_SPEND_AUTH_PK));

	// Spend (fake)
	t.private.sig_targets.spend.set_fake(pw, default_spend_pk);

	// Consume (fake) — circuit uses the subpool consume key (consume_auth.config=false)
	t.private.sig_targets.consume.set_fake(pw, key);

	// Approval (fake)
	t.private.sig_targets.approval.set_fake(pw, key);
}
