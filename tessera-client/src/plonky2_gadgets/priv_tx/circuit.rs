use itertools::Itertools;
use plonky2::{hash::{hash_types::{HashOutTarget, RichField}, poseidon::Poseidon}, iop::target::{BoolTarget, Target}, plonk::circuit_builder::CircuitBuilder};
use plonky2_field::extension::Extendable;
use tessera_utils::hasher::{MerkleHashCircuit, MerkleHashTarget};

use crate::{NOTE_BATCH, plonky2_gadgets::{priv_tx::{cb::PrivTxCircuitBuilder, targets::{AccountCommitmentTarget, AccountNullifierTarget, RootTarget, AssetIdTarget, DummyNoteTarget, MainPoolConfigRootTarget, NoteCommitmentTarget, NoteNullifierTarget, NoteTarget, SubpoolIdTarget, TxCircuitTargets}}, u256::CircuitBuilderU256}};



pub fn priv_tx_circuit<
	H: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<4>>,
	F: RichField + Extendable<D> + Poseidon,
	const D: usize,
>(
	builder: &mut CircuitBuilder<F, D>,
) -> TxCircuitTargets {
	// Mint constants
	// let ds_nullifier_key = builder.constant(F::from_canonical_u64(DS_NULLIFIER_KEY));

	// not_fake_tx is a PI and set to 1 for tx that are not fake. It may be se to 0 to produce a
	// dummy proof (used at proof aggregation stage)
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
	// Free virtual target — prover supplies the real or padding value.
	// When not_fake_tx=1, enforced to equal derived_accout_comm below.
	let accout_comm = AccountCommitmentTarget(builder.add_virtual_hash());
	for i in 0..4 {
		let diff = builder.sub(accout_comm.0.elements[i], derived_accout_comm.0.elements[i]);
		let gated = builder.mul(not_fake_tx.target, diff);
		builder.assert_zero(gated);
	}

	// Assert AccIn matches FreshAccount defaults when is_fresh_acc
	builder.assert_fresh_account(accin, is_fresh_acc);

	// AccIn → AccOut transition invariants
	// private_identifier, subpool_id are immutable for all tx kinds — enforced by sharing the
	// same wires in `derive_account_commitment` for both accin and accout.
	builder.assert_account_invariants(
		accin,
		accout,
		is_rjct,
		is_fresh_acc,
		is_update_auth,
		is_priv_tx,
	);

	// Check Comm(AccIn) in ACT iff !fresh && not_fake == 1
	let accin_pos = builder.add_virtual_target();
	let not_is_fresh_acc = builder.not(is_fresh_acc);
	let check_act = builder.and(not_is_fresh_acc, not_fake_tx);
	let accin_merkletrgts = builder.conditionally_assert_account_commitment_exists_in_act::<H>(
		accin_comm, root, check_act,
	);

	// AccIn nullifier — free virtual target; prover supplies the real or padding value.
	// When not_fake_tx=1, the circuit enforces accin_null == derived_null below.
	let derived_null = builder.derive_account_nullifier(accin_comm, nk);
	let accin_null = AccountNullifierTarget(builder.add_virtual_hash());
	for i in 0..4 {
		let diff = builder.sub(accin_null.0.elements[i], derived_null.0.elements[i]);
		let gated = builder.mul(not_fake_tx.target, diff);
		builder.assert_zero(gated);
	}

	// Verify asset/amt proofs in AccIn and AccOut ASTs; enforce same leaf position was updated
	let accin_ast_merkle = builder.assert_ast_update(
		asset_id,
		accin_amt,
		accout_amt,
		accin.acc_ast_root,
		accout.acc_ast_root,
		asset_exists_in_accin,
		asset_exists_in_accout,
	);

	// Input and Output notes //

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

	let dinotes: [DummyNoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_dummy_note_target());
	let dinotes_null: [NoteNullifierTarget; NOTE_BATCH] =
		core::array::from_fn(|i| builder.derive_dummy_note_nullifier(dinotes[i]));

	let donotes: [DummyNoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_dummy_note_target());
	let donotes_comm = donotes.map(|dn| builder.derive_dummy_note_commitment(dn));

	// check is_rjct
	builder.assert_is_reject(is_rjct, inotes, inotes_isactive, onotes, onotes_isactive);

	// All inotes and onotes share the same asset_id
	for note in inotes.iter().chain(onotes.iter()) {
		builder.connect(note.asset_id.0, asset_id.0);
	}

	// for each inote verify NCT membership, and check spend auth
	let inotes_mrkltrgt = builder.assert_inotes_valid::<H>(
		inotes,
		inotes_isactive,
		inotes_comm,
		public_identifier,
		subpool_id,
		root,
	);

	// Balance invariant: AccIn.amt + Sum([INote.amt]) == AccOut.amt + Sum([Onote.amt]) //
	builder.assert_balance_invariant(
		accin_amt,
		accout_amt,
		inotes,
		onotes,
		inotes_isactive,
		onotes_isactive,
	);

	// Derive tx hash //

	// select valid inote nullifiers, onote commitments as per respective isactive selector
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
	// Derived NC (for real TX enforcement).
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

	// Validate authorization //

	// Verify SubpoolFullProof: 3 authority key proofs (depth-2) + main pool proof (depth-20)
	// Skip subpoolProof verification if not_fake_tx = 0
	let subpool_proof_targets = builder.assert_subpool_full_proof(
		SubpoolIdTarget(accin.subpool_id.0),
		approval_key,
		rejection_key,
		subpool_consume_key,
		mainpool_config_root,
		not_fake_tx,
	);

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

	// Declare public inputs:
	//  - effective input note nullifiers
	//  - effective output note commitments
	//  - AIn Nullifier
	//  - AOut commitment
	//  - not_is_fake bool target
	//  - NCT root
	//  - ACT root
	// PI layout (77 total, NOTE_BATCH=7):
	//   [0-1]  = subpool_id_in/out auto-registered by add_virtual_account_target
	//   [2]    = subpool_id_in  (explicit, same wire as [0])
	//   [3]    = subpool_id_out (explicit, same wire as [1])
	//   [4]    = not_fake_tx    (IS_REAL_OFFSET)
	//   [5-8]  = AN             (TX_DATA_OFFSET)
	//   [9-12] = AC
	//   [13-40]= NN (7×4=28, NOTE_BATCH=7)
	//   [41-68]= NC (7×4=28)
	//   [69-72]= act_root
	//   [73-76]= nct_root
	builder.register_public_input(accin.subpool_id.0);
	builder.register_public_input(accout.subpool_id.0);
	builder.register_public_input(not_fake_tx.target);
	builder.register_public_inputs(&accin_null.0.elements);
	builder.register_public_inputs(&accout_comm.0.elements);
	builder.register_public_inputs(
		effective_inotes_null
			.iter()
			.flat_map(|v| v.0.elements.iter().copied())
			.collect_vec()
			.as_slice(),
	);
	builder.register_public_inputs(
		donotes_comm
			.iter()
			.flat_map(|v| v.0.elements.iter().copied())
			.collect_vec()
			.as_slice(),
	);
	builder.register_public_inputs(&root.0.elements);

	TxCircuitTargets {
		not_fake_tx,
		is_rjct,
		is_fresh_acc,
		is_update_auth,
		is_priv_tx,
		root,
		mainpool_config_root,
		approval_key,
		rejection_key,
		subpool_consume_key,
		accin,
		accout,
		accin_amt,
		accout_amt,
		asset_id,
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
		accin_null,
		accout_comm,
	}
}