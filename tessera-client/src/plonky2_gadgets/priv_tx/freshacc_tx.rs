use std::array;

use plonky2::{
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::config::Hasher,
};
use plonky2_field::types::Field;
use rand::Rng;
use tessera_utils::{F, hasher::HashOutput};

use super::{double_hash_native, targets::TxCircuitTargets};
use crate::{
	AccountAddress, AssetId, ConsumeAuth, DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER,
	DEFAULT_SPEND_AUTH_PK, MAIN_POOL_CONFIG_DEPTH, NOTE_BATCH, Nonce, NoteCommitment,
	NoteNullifier, STATE_TREE_DEPTH, SUBPOOL_CONFIG_DEPTH, SpendAuth, StandardAccount, SubpoolId,
	account::PublicIdentifier,
	derive_priv_tx_hash,
	ecgfp5::{CompressedPoint, PointEw},
	note::{NoteIdentifier, StandardNote},
	plonky2_gadgets::{set_hash, set_u256_zero, witness::set_hash_blocks},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfig},
	schnorr::{CompressedPublicKey, Signature},
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
/// `root` is `HashOutput([F::ZERO; 4])` for a normal FreshAcc (account not yet
/// in the on-chain IMT; no notes to prove membership for).
#[allow(clippy::too_many_arguments)]
pub(crate) fn set_freshacc_tx_witness(
	pw: &mut PartialWitness<F>,
	t: &TxCircuitTargets,
	accin: &StandardAccount,
	new_spend_auth: SpendAuth,
	new_consume_auth: ConsumeAuth,
	root: HashOutput,
	approval_key: CompPubKey,
	subpool_id: SubpoolId,
	main_pool: &MainPoolConfigTree<HashOutput>,
	approval_sig: Signature,
	dinotes: [[F; 4]; NOTE_BATCH],
	donotes: [[F; 4]; NOTE_BATCH],
) {
	// ── Build accout ──────────────────────────────────────────────────────────
	let mut accout = accin.clone_with_incremented_nonce();
	accout.spend_auth = new_spend_auth;
	accout.consume_auth = new_consume_auth;

	// ── Dummy notes (needed for tx_hash) ──────────────────────────────────────
	let dinote_nulls = array::from_fn(|i| NoteNullifier(double_hash_native(dinotes[i]).into()));
	let donote_comms = array::from_fn(|i| NoteCommitment(double_hash_native(donotes[i]).into()));

	// ── Tx hash ───────────────────────────────────────────────────────────────
	let tx_hash = derive_priv_tx_hash(
		accin.nullifier(),
		accout.commitment(),
		dinote_nulls,
		donote_comms,
	);

	// ── Tree roots ────────────────────────────────────────────────────────────
	t.set_common_witnesses(pw, main_pool.root(), root, approval_key, accin, &accout);

	// ── Asset / amounts (all zeros for FreshAcc) ──────────────────────────────
	pw.set_target(t.private.asset_id.0, F::ZERO).unwrap();
	set_u256_zero(pw, &t.private.accin_amt);
	set_u256_zero(pw, &t.private.accout_amt);
	pw.set_bool_target(t.private.asset_exists_in_accin, false)
		.unwrap();
	pw.set_bool_target(t.private.asset_exists_in_accout, false)
		.unwrap();

	// ── Merkle proofs ─────────────────────────────────────────────────────────

	// ACT: not enforced for FreshAcc
	t.private.accin_act_merkle.set_dummy_witness(pw);

	// accin AST at index 0 (asset not in tree → Empty leaf)
	t.private
		.accin_ast_merkle
		.set_witness(pw, &accin.ast.merkle_proof_at(0));
	// accout_ast_merkle is auto-filled via connect_array in the circuit

	// ── Input notes (all inactive) ────────────────────────────────────────────
	let zero_addr = AccountAddress::ZERO;
	let inote = StandardNote {
		identifier: NoteIdentifier::ZERO,
		asset_id: AssetId(F::ZERO),
		amt: primitive_types::U256::zero(),
		recipient: AccountAddress::from_acc(accin),
		sender: zero_addr,
		memo: [0u8; 512],
	};
	for i in 0..NOTE_BATCH {
		t.private.inotes[i].set_witness(pw, &inote);
		pw.set_target(t.private.inotes_pos[i], F::ZERO).unwrap();
		pw.set_bool_target(t.private.inotes_isactive[i], false)
			.unwrap();
		// NCT: not enforced (selector = false)
		t.private.inotes_nct_merkle[i].set_dummy_witness(pw);
	}

	// ── Output notes (all inactive) ───────────────────────────────────────────
	let onote = StandardNote {
		identifier: NoteIdentifier::ZERO,
		asset_id: AssetId(F::ZERO),
		amt: primitive_types::U256::zero(),
		recipient: zero_addr,
		sender: zero_addr,
		memo: [0u8; 512],
	};
	for i in 0..NOTE_BATCH {
		t.private.onotes[i].set_witness(pw, &onote);
		pw.set_bool_target(t.private.onotes_isactive[i], false)
			.unwrap();
	}

	// ── Dummy note hashes ─────────────────────────────────────────────────────
	set_hash_blocks(pw, &t.private.dinotes.map(|note| note.0), &dinotes);
	set_hash_blocks(pw, &t.private.donotes.map(|note| note.0), &donotes);

	// ── AN/AC/NN/NC override targets ─────────────────────────────────────────
	// For real TXs these equal the derived values (enforced by circuit).
	set_hash(pw, t.public.accin_null.0, accin.nullifier().0.0);
	set_hash(pw, t.public.accout_comm.0, accout.commitment().0.0);

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

	// Spend (fake)
	t.private.sig_targets.spend.set_fake(
		pw,
		CompressedPublicKey(CompressedPoint::from(DEFAULT_SPEND_AUTH_PK)),
	);

	// Consume (fake)
	t.private.sig_targets.consume.set_fake(
		pw,
		CompressedPublicKey(CompressedPoint::from(
			DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER,
		)),
	);

	// Approval (real): always enforced for FreshAcc.
	t.private
		.sig_targets
		.approval
		.set(pw, approval_key, tx_hash, approval_sig);
}
