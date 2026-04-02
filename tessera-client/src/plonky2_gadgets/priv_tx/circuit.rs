use itertools::Itertools;
use plonky2::{
	hash::{
		hash_types::{HashOutTarget, RichField},
		poseidon::Poseidon,
	},
	iop::target::{BoolTarget, Target},
	plonk::circuit_builder::CircuitBuilder,
};
use plonky2_field::extension::Extendable;
use tessera_utils::{
	HASH_SIZE,
	hasher::{HashOutput, MerkleHashCircuit, MerkleHashTarget},
};

use crate::{
	NOTE_BATCH,
	plonky2_gadgets::{
		priv_tx::{
			circuit_builder::PrivTxCircuitBuilder,
			targets::{
				AccountCommitmentTarget, AccountNullifierTarget, AssetIdTarget, DummyNoteTarget,
				MainPoolConfigRootTarget, NoteCommitmentTarget, NoteNullifierTarget, NoteTarget,
				RootTarget, SubpoolIdTarget, TxCircuitPrivateTargets, TxCircuitPublicTargets,
				TxCircuitTargets,
			},
		},
		u256::CircuitBuilderU256,
	},
};

/// Build the Plonky2 private transaction circuit.
///
/// A single circuit handles four transaction kinds selected by boolean flags:
///
/// | Kind          | `is_fresh_acc` | `is_rjct` | `is_update_auth` | `is_priv_tx` |
/// |---------------|:--------------:|:---------:|:----------------:|:------------:|
/// | FreshAcc      | 1              | 0         | 0                | 0            |
/// | Reject        | 0              | 1         | 0                | 0            |
/// | UpdateAuth    | 0              | 0         | 1                | 0            |
/// | Spend/transfer| 0              | 0         | 0                | 1            |
///
/// # Constraints enforced
/// 1. **Account commitment / nullifier** — derived from account witness; for real txs constrained
///    to match free PI targets `accin_null` / `accout_comm`.
/// 2. **FreshAcc check** — when `is_fresh_acc`, `accin` must be in the default state.
/// 3. **Account transition invariants** — per-kind rules for immutable fields.
/// 4. **ACT membership** — for non-fresh accounts gated on `not_fake_tx`.
/// 5. **AST update** — asset leaf updated at the same position in accin/accout ASTs.
/// 6. **Note processing** — NCT membership, spend-condition checks, reject mirroring.
/// 7. **Balance invariant** — conservation of assets across notes and accounts.
/// 8. **Subpool membership** — three key proofs + main pool proof.
/// 9. **Signatures** — spend / consume / approval Schnorr signatures.
///
/// # Public inputs (76 elements for NOTE_BATCH=7)
/// ```text
/// [0]     subpool_id_in
/// [1]     subpool_id_out
/// [2]     not_fake_tx
/// [3-6]   root (4 elements)
/// [7-10]  mainpool_config_root (4 elements)
/// [11-14] accin_null  (AN, 4 elements)
/// [15-18] accout_comm (AC, 4 elements)
/// [19-46] effective inote nullifiers (7×4)
/// [47-74] effective onote commitments (7×4, donote_comm when slot inactive)
/// [75]    asset_id
/// ```
pub fn priv_tx_circuit<
	H: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<4>>,
	F: RichField + Extendable<D> + Poseidon,
	const D: usize,
>(
	builder: &mut CircuitBuilder<F, D>,
) -> TxCircuitTargets
where
	HashOutput: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<4>>,
{
	// not_fake_tx = 1 for real transactions; 0 for dummy/padding proofs.
	// Gating on this flag allows all constraint checks to be bypassed for
	// dummy proofs while keeping the same compiled circuit.
	let not_fake_tx = builder.add_virtual_bool_target_safe();

	// Tx kinds
	let is_rjct = builder.add_virtual_bool_target_safe();
	let is_fresh_acc = builder.add_virtual_bool_target_safe();
	let is_update_auth = builder.add_virtual_bool_target_safe();
	let is_priv_tx = builder.add_virtual_bool_target_safe();

	let root = RootTarget(builder.add_virtual_hash());
	let mainpool_config_root = MainPoolConfigRootTarget(builder.add_virtual_hash());

	// Subpool authority keys
	let (approval_key, rejection_key, subpool_consume_key) = builder.add_virtual_authority_keys();

	let asset_id = AssetIdTarget(builder.add_virtual_target());
	let accin_amt = builder.add_virtual_u256_target();
	let asset_exists_in_accin = builder.add_virtual_bool_target_safe();
	let accout_amt = builder.add_virtual_u256_target();
	let asset_exists_in_accout = builder.add_virtual_bool_target_safe();

	let accin = builder.add_virtual_account_target();
	let accout = builder.add_virtual_account_target();
	let private_identifier = accin.private_identifier;
	let subpool_id = accin.subpool_id;
	let public_identifier = builder.derive_public_identifier(private_identifier);
	let nk = builder.derive_nullifier_key(accin.private_identifier);

	let accin_comm = builder.derive_account_commitment(accin);
	let derived_accout_comm = builder.derive_account_commitment(accout);
	// Step 1: AccOut commitment — free PI target.
	// For real txs (not_fake_tx=1) the circuit enforces accout_comm == derived_accout_comm.
	// For dummy proofs the prover may supply any value (constraints are bypassed).
	let accout_comm = AccountCommitmentTarget(builder.add_virtual_hash());
	builder.conditionally_assert_hash_equal(not_fake_tx, accout_comm.0, derived_accout_comm.0);

	// Step 2: FreshAcc check — when is_fresh_acc, accin must be in the default state
	// (nonce=0, default keys, empty AST).
	builder.assert_fresh_account(accin, is_fresh_acc);

	// Step 3: Account transition invariants (per-kind rules for immutable fields + nonce).
	// private_identifier and subpool_id are immutable for all tx kinds — enforced by sharing
	// the same wires in derive_account_commitment for both accin and accout.
	builder.assert_account_invariants(
		accin,
		accout,
		is_rjct,
		is_fresh_acc,
		is_update_auth,
		is_priv_tx,
	);

	// Step 4: ACT membership — verify accin's commitment is in the ACT.
	// Condition: only for non-fresh accounts and real transactions.
	let accin_pos = builder.add_virtual_target();
	let not_is_fresh_acc = builder.not(is_fresh_acc);
	let check_act = builder.and(not_is_fresh_acc, not_fake_tx);
	let accin_merkletrgts = builder
		.conditionally_assert_account_commitment_exists_in_act::<H>(accin_comm, root, check_act);

	// Step 5: AccIn nullifier — free PI target.
	// For real txs enforced == derived_null; for dummy proofs any value is accepted.
	let derived_null = builder.derive_account_nullifier(accin_comm, nk);
	let accin_null = AccountNullifierTarget(builder.add_virtual_hash());
	builder.conditionally_assert_hash_equal(not_fake_tx, accin_null.0, derived_null.0);

	// Step 6: AST update — prove accin and accout ASTs both contain the asset at the same
	// leaf position, with amounts differing by the transferred value.
	let accin_ast_merkle = builder.assert_ast_update(
		asset_id,
		accin_amt,
		accout_amt,
		accin.acc_ast_root,
		accout.acc_ast_root,
		asset_exists_in_accin,
		asset_exists_in_accout,
	);

	// Step 7: Allocate NOTE_BATCH input and output note slots.
	// Inactive slots are filled with dummy values; all are padded to NOTE_BATCH.
	let inotes: [NoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_note_target());
	let inotes_pos: [Target; NOTE_BATCH] = core::array::from_fn(|_| builder.add_virtual_target());
	let inotes_isactive: [BoolTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_bool_target_safe());
	let inotes_comm = core::array::from_fn(|i| builder.derive_note_commitment(inotes[i]));
	let inotes_null: [NoteNullifierTarget; NOTE_BATCH] =
		core::array::from_fn(|i| builder.derive_note_nullifier(inotes_comm[i], inotes_pos[i], nk));

	let onotes: [NoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_note_target());
	let onotes_isactive: [BoolTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_bool_target_safe());
	let onotes_comm = onotes.map(|n| builder.derive_note_commitment(n));

	// Dummy notes provide deterministic padding nullifiers / commitments for inactive slots.
	let dinotes: [DummyNoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_dummy_note_target());
	let dinotes_null: [NoteNullifierTarget; NOTE_BATCH] =
		core::array::from_fn(|i| builder.derive_dummy_note_nullifier(dinotes[i]));

	let donotes: [DummyNoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_dummy_note_target());
	let donotes_comm = donotes.map(|dn| builder.derive_dummy_note_commitment(dn));

	// Step 8: Reject check — when is_rjct, each onote is the mirror of the corresponding
	// inote with spend/reject conditions swapped (note returns to sender).
	builder.assert_is_reject(is_rjct, inotes, inotes_isactive, onotes, onotes_isactive);

	// All inotes and onotes must share the same asset_id as the transaction.
	for note in inotes.iter().chain(onotes.iter()) {
		builder.connect(note.asset_id.0, asset_id.0);
	}

	// Step 9: Input note validity — NCT membership + spend-condition check.
	let inotes_mrkltrgt = builder.assert_inotes_valid::<H>(
		inotes,
		inotes_isactive,
		inotes_comm,
		public_identifier,
		subpool_id,
		root,
	);

	// Step 10: Balance invariant — assets are conserved across accounts and notes.
	// accin_amt + Σ(active inote amounts) == accout_amt + Σ(active onote amounts)
	builder.assert_balance_invariant(
		accin_amt,
		accout_amt,
		inotes,
		onotes,
		inotes_isactive,
		onotes_isactive,
	);

	// Step 11: Derive tx hash.
	// For inactive inote slots use dummy nullifiers; for inactive onote slots use dummy comms.
	// This makes the tx hash deterministic even when fewer than NOTE_BATCH notes are used.
	let effective_inotes_null: [NoteNullifierTarget; NOTE_BATCH] = core::array::from_fn(|i| {
		NoteNullifierTarget(HashOutTarget {
			elements: core::array::from_fn(|j| {
				builder._if(
					inotes_isactive[i],
					inotes_null[i].0.elements[j],
					dinotes_null[i].0.elements[j],
				)
			}),
		})
	});
	// For real txs the circuit enforces onotes_comm matches the PI; dummy proofs get donote_comm.
	let derived_onotes_comm: [NoteCommitmentTarget; NOTE_BATCH] = core::array::from_fn(|i| {
		NoteCommitmentTarget(HashOutTarget {
			elements: core::array::from_fn(|j| {
				builder._if(
					onotes_isactive[i],
					onotes_comm[i].0.elements[j],
					donotes_comm[i].0.elements[j],
				)
			}),
		})
	});

	let tx_hash = builder.derive_tx_hash(
		effective_inotes_null,
		derived_onotes_comm,
		accin_null,
		accout_comm,
	);

	// Step 12: Subpool full proof — verify authority key memberships.
	// All checks gated by not_fake_tx so dummy proofs can use zero-filled paths.
	let subpool_proof_targets = builder.assert_subpool_full_proof(
		SubpoolIdTarget(accin.subpool_id.0),
		approval_key,
		rejection_key,
		subpool_consume_key,
		mainpool_config_root,
		not_fake_tx,
	);

	// Step 13: Signature verification.
	let not_is_rjct = builder.not(is_rjct);
	let sig_targets = builder.assert_tx_signatures(
		tx_hash,
		inotes_isactive,
		onotes_isactive,
		accin,
		subpool_consume_key,
		approval_key,
		not_is_rjct,
		not_fake_tx,
	);

	// Step 14: Register public inputs.
	let public_targets = TxCircuitPublicTargets {
		not_fake_tx,
		root,
		mainpool_config_root,
		accin_null,
		accout_comm,
		inotes_null: effective_inotes_null,
		onotes_comm: donotes_comm,
	};

	public_targets.register(builder);

	TxCircuitTargets {
		public: public_targets,
		private: TxCircuitPrivateTargets {
			is_rjct,
			is_fresh_acc,
			is_update_auth,
			is_priv_tx,
			approval_key,
			rejection_key,
			subpool_consume_key,
			accin,
			accout,
			accin_amt,
			accout_amt,
			asset_exists_in_accin,
			asset_exists_in_accout,
			accin_pos,
			accin_act_merkle: accin_merkletrgts,
			accin_ast_merkle,
			inotes,
			inotes_pos,
			inotes_isactive,
			onotes,
			onotes_isactive,
			dinotes,
			donotes,
			subpool_proof_targets,
			sig_targets,
			inotes_nct_merkle: inotes_mrkltrgt,
			accin_subpool_id: accin.subpool_id,
			accout_subpool_id: accout.subpool_id,
			asset_id,
		},
	}
}
