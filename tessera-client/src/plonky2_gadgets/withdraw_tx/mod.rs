use itertools::Itertools;
use plonky2::{
	hash::{
		hash_types::{HashOutTarget, RichField},
		poseidon::Poseidon,
	},
	iop::{
		target::{BoolTarget, Target},
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::circuit_builder::CircuitBuilder,
};
use plonky2_field::{
	extension::Extendable,
	types::{Field, PrimeField64},
};
use primitive_types::{H160, U256};
use tessera_utils::{
	F,
	hasher::{HashOutput, MerkleHashCircuit, MerkleHashTarget},
	plonky2_gadgets::u32::add_u8_range_check_lookup_table,
};

use crate::{
	AssetId, COM_TREE_DEPTH, NOTE_BATCH, Nonce, StandardAccount, SubpoolId,
	account::AccountStateTreeLeaf,
	derive_withdraw_tx_hash,
	ecgfp5::PointEw,
	plonky2_gadgets::{
		merkle::{SetMerklePathOfWitness, conditional_merkle_verify_commitment_tree_gadget},
		priv_tx::{
			cb::PrivTxCircuitBuilder,
			targets::{
				AccountNullifierTarget, ActRootTarget, AssetIdTarget, MainPoolConfigRootTarget,
				SubpoolIdTarget,
			},
		},
		set_hash,
		signature::conditional_schnorr_verify_gadget,
		u256::CircuitBuilderU256,
		withdraw_tx::{cb::WithdrawTxCircuitBuilder, targets::WithdrawTxTargets},
		witness::{set_authority_keys, set_real_schnorr_signature, set_subpool_full_proof},
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
	schnorr::Signature,
	tree::CommitmentTreeMerkleProof,
	utils::map_h160_to_f,
};

pub(crate) mod cb;
pub(crate) mod targets;

pub fn withdraw_tx_circuit<
	H: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<4>>,
	F: RichField + Extendable<D> + Poseidon,
	const D: usize,
>(
	builder: &mut CircuitBuilder<F, D>,
	ctx: &H::CircuitContext,
) -> WithdrawTxTargets {
	// ── Tx flag ───────────────────────────────────────────────────────────────
	let not_fake_tx = builder.add_virtual_bool_target_safe();

	// ── Authority keys ────────────────────────────────────────────────────────
	let (approval_key, rejection_key, subpool_consume_key) = builder.add_virtual_authority_keys();

	// ── Tree roots ────────────────────────────────────────────────────────────
	let act_root = ActRootTarget(builder.add_virtual_hash());
	let mainpool_config_root = MainPoolConfigRootTarget(builder.add_virtual_hash());

	// ── Accounts ──────────────────────────────────────────────────────────────
	// subpool_id is automatically registered as a public input inside
	// add_virtual_account_target (via add_virtual_public_input).
	let accin = builder.add_virtual_account_target();
	let accout = builder.add_virtual_account_target();
	let accin_pos = builder.add_virtual_target();

	// ── Per-asset withdrawal fields ───────────────────────────────────────────
	let asset_ids: [AssetIdTarget; NOTE_BATCH] =
		core::array::from_fn(|_| AssetIdTarget(builder.add_virtual_target()));
	let withdrawal_amts = core::array::from_fn(|_| builder.add_virtual_u256_target());
	let accin_amts = core::array::from_fn(|_| builder.add_virtual_u256_target());
	let accout_amts = core::array::from_fn(|_| builder.add_virtual_u256_target());
	let asset_exists_in_accin: [BoolTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_bool_target_safe());
	let asset_exists_in_accout: [BoolTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_bool_target_safe());

	// ── Withdrawal destination ────────────────────────────────────────────────
	let w_acc_addr: [Target; 5] = builder.add_virtual_target_arr();

	// ── Commitment / nullifier / nullifier-key derivation ─────────────────────
	let nk = builder.derive_nullifier_key(accin.private_identifier);
	let accin_comm = builder.derive_account_commitment(accin);
	let accout_comm = builder.derive_account_commitment(accout);
	// Withdrawal always requires an existing account — position-based nullifier.
	let accin_null = AccountNullifierTarget(builder.derive_account_nullifier(accin_comm, nk).0);

	// ── ACT membership ───────────────────────────────────────────────────────
	let accin_act_merkle = conditional_merkle_verify_commitment_tree_gadget::<H, _, _, _>(
		builder,
		accin_comm.0,
		act_root.0,
		not_fake_tx,
		ctx,
	);

	// ── Account invariants ───────────────────────────────────────────────────
	// Enforces unconditionally: private_identifier, subpool_id, nonce+1,
	// spend_auth, and consume_auth are all immutable. AST root may change.
	builder.assert_account_invariants_simple(accin, accout);

	// ── Chained AST updates ───────────────────────────────────────────────────
	// We process NOTE_BATCH withdrawal slots in sequence.  Each slot updates
	// the account state tree by subtracting withdrawal_amts[i] from asset_ids[i].
	//
	// Intermediate roots: ast_roots[0..NOTE_BATCH-1] are virtual; the final
	// output root is connected to accout.acc_ast_root.
	//
	//   accin.acc_ast_root
	//     → (update 0) → ast_roots[0]
	//     → (update 1) → ast_roots[1]
	//     → ...
	//     → (update N-1) → accout.acc_ast_root
	let intermediate_roots: Vec<HashOutTarget> = (0..NOTE_BATCH - 1)
		.map(|_| builder.add_virtual_hash())
		.collect();

	let range_lut = add_u8_range_check_lookup_table(builder);

	let ast_merkles = core::array::from_fn(|i| {
		let prev_root = if i == 0 {
			accin.acc_ast_root
		} else {
			intermediate_roots[i - 1]
		};
		let curr_root = if i < NOTE_BATCH - 1 {
			intermediate_roots[i]
		} else {
			accout.acc_ast_root
		};

		// Enforce balance: accin_amts[i] == accout_amts[i] + withdrawal_amts[i]
		let rhs =
			builder.u256_addition_chain::<1>(&accout_amts[i], &[withdrawal_amts[i]], range_lut);
		builder.connect_u256(&accin_amts[i], &rhs);

		builder.assert_ast_update(
			asset_ids[i],
			accin_amts[i],
			accout_amts[i],
			prev_root,
			curr_root,
			asset_exists_in_accin[i],
			asset_exists_in_accout[i],
		)
	});

	// ── Tx hash ───────────────────────────────────────────────────────────────
	let tx_hash = builder.derive_withdraw_tx_hash(
		accin_null,
		accout_comm,
		asset_ids,
		withdrawal_amts,
		w_acc_addr,
	);

	// ── Subpool full proof ────────────────────────────────────────────────────
	let subpool_proof_targets = builder.assert_subpool_full_proof(
		SubpoolIdTarget(accin.subpool_id.0),
		approval_key,
		rejection_key,
		subpool_consume_key,
		mainpool_config_root,
		not_fake_tx,
	);

	// ── Approval signature ────────────────────────────────────────────────────
	let approval_sig =
		conditional_schnorr_verify_gadget(builder, tx_hash.0, approval_key, not_fake_tx);

	// ── Public inputs ─────────────────────────────────────────────────────────
	// Order: not_fake_tx | act_root | mpct_root | accin_null | accout_comm
	//      | asset_ids[NOTE_BATCH] | amounts_f[8*NOTE_BATCH] | w_acc_addr[5]
	// (subpool_id is auto-registered via add_virtual_account_target)
	builder.register_public_input(not_fake_tx.target);
	builder.register_public_inputs(&act_root.0.elements);
	builder.register_public_inputs(&mainpool_config_root.0.elements);
	builder.register_public_inputs(&accin_null.0.elements);
	builder.register_public_inputs(&accout_comm.0.elements);
	for id in &asset_ids {
		builder.register_public_input(id.0);
	}
	builder.register_public_inputs(
		withdrawal_amts
			.iter()
			.flat_map(|amt| amt.0.map(|u| u.0))
			.collect_vec()
			.as_slice(),
	);
	builder.register_public_inputs(&w_acc_addr);

	WithdrawTxTargets {
		not_fake_tx,
		act_root,
		mainpool_config_root,
		approval_key,
		rejection_key,
		subpool_consume_key,
		accin,
		accout,
		accin_pos,
		asset_ids,
		withdrawal_amts,
		accin_amts,
		accout_amts,
		asset_exists_in_accin,
		asset_exists_in_accout,
		w_acc_addr,
		accin_act_merkle,
		ast_merkles,
		subpool_proof_targets,
		approval_sig,
	}
}

/// Fill `pw` with a complete withdrawal transaction witness.
///
/// `accout` is derived internally by cloning `accin`, incrementing the nonce,
/// and applying all asset withdrawals to the AST.
///
/// `withdrawals` contains up to `NOTE_BATCH` `(asset_id, withdrawal_amount)` pairs.
/// Remaining slots are zero-padded automatically.
#[allow(clippy::too_many_arguments)]
pub(crate) fn set_withdraw_tx_witness(
	pw: &mut PartialWitness<F>,
	t: &WithdrawTxTargets,
	accin: &StandardAccount,
	accin_act_merkle_proof: CommitmentTreeMerkleProof<COM_TREE_DEPTH>,
	act_root: HashOutput,
	main_pool: &MainPoolConfigTree,
	withdrawals: &[(AssetId, U256)],
	w_acc_addr: H160,
	approval_key: &CompPubKey,
	rejection_key: &CompPubKey,
	consume_key: &CompPubKey,
	subpool_id: SubpoolId,
	approval_sig: Signature,
) {
	assert!(withdrawals.len() <= NOTE_BATCH, "too many withdrawal slots");

	// ── Build per-slot data ────────────────────────────────────────────────
	let mut current_ast = accin.ast.clone();

	let mut slot_asset_ids = [AssetId(F::ZERO); NOTE_BATCH];
	let mut slot_withdrawal_amts = [U256::zero(); NOTE_BATCH];
	let mut slot_accin_amts = [U256::zero(); NOTE_BATCH];
	let mut slot_accout_amts = [U256::zero(); NOTE_BATCH];
	let mut slot_exists_in = [false; NOTE_BATCH];
	let mut slot_exists_out = [false; NOTE_BATCH];
	let mut slot_proofs = Vec::with_capacity(NOTE_BATCH);

	for i in 0..NOTE_BATCH {
		if i < withdrawals.len() {
			let (asset_id, withdrawal_amt) = withdrawals[i];
			slot_asset_ids[i] = asset_id;
			slot_withdrawal_amts[i] = withdrawal_amt;
			// TODO: panic here
			let (ast_index, old_bal) = current_ast.amount_for(asset_id).unwrap();
			slot_accin_amts[i] = old_bal;
			slot_exists_in[i] = true;

			// Capture proof BEFORE the update so siblings reflect accin state.
			slot_proofs.push(current_ast.merkle_proof_at(ast_index));

			let new_bal = old_bal - withdrawal_amt;
			slot_accout_amts[i] = new_bal;
			slot_exists_out[i] = new_bal > U256::zero();

			current_ast
				.insert_or_update_asset(asset_id, new_bal)
				.unwrap();
		} else {
			// Padding slot: zero amounts, default-leaf proof at next free index.
			slot_proofs.push(current_ast.merkle_proof_at(current_ast.next_index()));
		}
	}

	// ── Build accout ──────────────────────────────────────────────────────
	let mut accout = accin.clone_with_incremented_nonce();
	accout.ast = current_ast.clone();

	// ── Native TxHash ─────────────────────────────────────────────────────
	let accin_null = accin.nullifier();
	let tx_hash = derive_withdraw_tx_hash(
		accin_null,
		accout.commitment(),
		slot_asset_ids,
		slot_withdrawal_amts,
		w_acc_addr,
	);

	// ── Tx flag ───────────────────────────────────────────────────────────
	pw.set_bool_target(t.not_fake_tx, true).unwrap();

	// ── Tree roots ────────────────────────────────────────────────────────
	set_hash(pw, t.act_root.0, act_root.0);
	set_hash(pw, t.mainpool_config_root.0, main_pool.root().0);

	// ── Authority keys ────────────────────────────────────────────────────
	set_authority_keys(
		pw,
		&t.approval_key,
		&t.rejection_key,
		&t.subpool_consume_key,
		approval_key,
		rejection_key,
		consume_key,
	);

	// ── Accounts ──────────────────────────────────────────────────────────
	t.accin.set_witness(pw, accin);
	t.accout.set_witness(pw, &accout);
	pw.set_target(
		t.accin_pos,
		F::from_canonical_usize(accin_act_merkle_proof.pos),
	)
	.unwrap();

	// ── Per-slot witnesses ─────────────────────────────────────────────────
	for i in 0..NOTE_BATCH {
		pw.set_target(t.asset_ids[i].0, slot_asset_ids[i].0)
			.unwrap();
		t.withdrawal_amts[i].set_witness(pw, slot_withdrawal_amts[i]);
		t.accin_amts[i].set_witness(pw, slot_accin_amts[i]);
		t.accout_amts[i].set_witness(pw, slot_accout_amts[i]);
		pw.set_bool_target(t.asset_exists_in_accin[i], slot_exists_in[i])
			.unwrap();
		pw.set_bool_target(t.asset_exists_in_accout[i], slot_exists_out[i])
			.unwrap();
		t.ast_merkles[i].set_witness(pw, &slot_proofs[i]);
	}

	// ── Withdrawal destination ─────────────────────────────────────────────
	pw.set_target_arr(&t.w_acc_addr, &map_h160_to_f(&w_acc_addr))
		.unwrap();

	// ── ACT Merkle proof ──────────────────────────────────────────────────
	t.accin_act_merkle.set_witness(pw, &accin_act_merkle_proof);

	// ── Subpool full proof ────────────────────────────────────────────────
	set_subpool_full_proof(
		pw,
		&t.subpool_proof_targets,
		main_pool,
		approval_key,
		rejection_key,
		consume_key,
		subpool_id,
	);

	// ── Approval signature ────────────────────────────────────────────────
	set_real_schnorr_signature(pw, &t.approval_sig, *approval_key, &tx_hash.0, approval_sig);
}

#[cfg(test)]
mod tests {
	use plonky2::{
		iop::witness::PartialWitness,
		plonk::{
			circuit_builder::CircuitBuilder,
			circuit_data::CircuitConfig,
			config::{GenericConfig, PoseidonGoldilocksConfig},
		},
	};
	use plonky2_field::types::Field;
	use primitive_types::{H160, U256};
	use rand::SeedableRng;
	use rand_chacha::ChaCha8Rng;
	use tessera_trees::CommitmentTree;
	use tessera_utils::hasher::HashOutput;

	use super::*;
	use crate::{
		AssetId, COM_TREE_DEPTH, Nonce, SpendAuth, StandardAccount, SubpoolId,
		account::AccountStateTreeLeaf,
		pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
		schnorr::{PrivateKey, Scalar, schnorr_sign},
		tree::CommitmentTreeMerkleProof,
	};

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = <C as GenericConfig<D>>::F;

	#[test]
	fn test_prove_withdraw_tx() {
		// ── Keys for subpool ──────────────────────────────────────────────
		let approval_sk = PrivateKey::from_raw([1, 2, 3, 4, 5]);
		let approval_cpk: CompPubKey = approval_sk.public_key::<F>().into();
		let rejection_sk = PrivateKey::from_raw([5, 6, 7, 8, 0]);
		let rejection_cpk: CompPubKey = rejection_sk.public_key::<F>().into();
		let consume_sk = PrivateKey::from_raw([9, 10, 11, 12, 0]);
		let consume_cpk: CompPubKey = consume_sk.public_key::<F>().into();

		let subpool_id = SubpoolId(F::ONE);
		let subpool = SubpoolConfigTree::new(approval_cpk, rejection_cpk, consume_cpk);
		let mut main_pool = MainPoolConfigTree::new();
		main_pool.set_subpool(0, subpool_id, subpool.root());

		// ── Sample accin ──────────────────────────────────────────────────
		let mut rng = ChaCha8Rng::seed_from_u64(2);
		let mut accin = StandardAccount::sample(&mut rng, subpool_id);

		// ── Simulate FreshAcc: nonce = 1, set spend_pk ────────────────────
		accin.nonce = Nonce(F::ONE);
		accin.spend_auth = SpendAuth {
			spend_pk: Some(PrivateKey::from_raw([8, 7, 6, 5, 4]).public_key().into()),
		};

		// ── Mutate AST: set balances (asset_id=1 → 100, 2 → 200, 3 → 300) ─
		accin
			.ast
			.insert_asset(AssetId(F::from_canonical_u64(1)), U256::from(100u64))
			.unwrap();
		accin
			.ast
			.insert_asset(AssetId(F::from_canonical_u64(2)), U256::from(200u64))
			.unwrap();
		accin
			.ast
			.insert_asset(AssetId(F::from_canonical_u64(3)), U256::from(300u64))
			.unwrap();

		// ── Insert accin into ACT ─────────────────────────────────────────
		let mut act = CommitmentTree::<HashOutput>::new(COM_TREE_DEPTH);
		let accin_insert = act.insert(accin.commitment().0).unwrap();
		let accin_act_proof = CommitmentTreeMerkleProof::new(
			accin.commitment().0,
			accin_insert.siblings_new,
			accin_insert.path,
			act.num_leaves(),
		);
		let act_root = act.get_root();
		assert!(accin_act_proof.verify(act_root));

		// ── Withdrawals: (asset_id=2, 50) and (asset_id=3, 50) ───────────
		let withdrawals = [
			(AssetId(F::from_canonical_u64(2)), U256::from(50u64)),
			(AssetId(F::from_canonical_u64(3)), U256::from(60u64)),
		];

		// ── Compute native TxHash and sign ────────────────────────────────
		// Build accout for native hash (mirrors set_withdraw_tx_witness internals)
		let mut slot_asset_ids = [AssetId(F::ZERO); crate::NOTE_BATCH];
		let mut slot_withdrawal_amts = [U256::zero(); crate::NOTE_BATCH];
		let mut current_ast = accin.ast.clone();
		for (i, &(asset_id, withdrawal_amt)) in withdrawals.iter().enumerate() {
			slot_asset_ids[i] = asset_id;
			slot_withdrawal_amts[i] = withdrawal_amt;
			let (_, old_bal) = current_ast.amount_for(asset_id).unwrap();
			let new_bal = old_bal - withdrawal_amt;
			current_ast
				.insert_or_update_asset(asset_id, new_bal)
				.unwrap();
		}
		let mut accout = accin.clone();
		accout.nonce = Nonce(F::from_canonical_u64(2));
		accout.ast = current_ast;

		let accin_null = accin.nullifier();
		let tx_hash = crate::derive_withdraw_tx_hash(
			accin_null,
			accout.commitment(),
			slot_asset_ids,
			slot_withdrawal_amts,
			H160::zero(),
		);

		let k = Scalar::from_raw([1, 2, 3, 4, 5]);
		let approval_sig = schnorr_sign(&approval_sk, &tx_hash.0, k);

		// ── Build circuit ─────────────────────────────────────────────────
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let ctx = HashOutput::register_luts(&mut builder);
		let t = withdraw_tx_circuit::<HashOutput, _, _>(&mut builder, &ctx);
		let data = builder.build::<C>();

		// ── Fill witness ──────────────────────────────────────────────────
		let mut pw = PartialWitness::new();
		set_withdraw_tx_witness(
			&mut pw,
			&t,
			&accin,
			accin_act_proof,
			act_root,
			&main_pool,
			&withdrawals,
			H160::zero(),
			&approval_cpk,
			&rejection_cpk,
			&consume_cpk,
			subpool_id,
			approval_sig,
		);

		// ── Prove & verify ────────────────────────────────────────────────
		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}
}
