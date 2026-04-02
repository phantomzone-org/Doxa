use plonky2::{
	hash::{hash_types::RichField, poseidon::Poseidon},
	iop::{
		target::{BoolTarget, Target},
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::circuit_builder::CircuitBuilder,
};
use plonky2_field::{extension::Extendable, types::Field};
use primitive_types::{H160, U256};
use tessera_trees::MerkleProof;
use tessera_utils::{
	F,
	hasher::{HashOutput, MerkleHash},
};

use crate::{
	AssetId, COM_TREE_DEPTH, NOTE_BATCH, StandardAccount, SubpoolId, derive_withdraw_tx_hash,
	plonky2_gadgets::{
		merkle::MerkleRootTarget,
		priv_tx::targets::{
			AccountCommitmentTarget, AccountNullifierTarget, AccountTarget, AssetIdTarget,
			MainPoolConfigRootTarget, RootTarget, SubpoolFullProofTargets, SubpoolIdTarget,
		},
		set_hash,
		signature::{PubkeyTarget, SchnorrTargets},
		u256::U256Target,
		witness::{fake_authority_key, set_authority_keys, set_subpool_full_proof},
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
	schnorr::Signature,
	utils::map_h160_to_f,
};

// ── Public targets ─────────────────────────────────────────────────────────────

/// Public input targets for the withdrawal transaction circuit.
pub(crate) struct WithdrawTxPublicTargets {
	/// PI[0..4]: Account Commitment Tree root.
	pub(crate) root: RootTarget,
	/// PI[4..8]: Main pool configuration tree root.
	pub(crate) mainpool_config_root: MainPoolConfigRootTarget,
	/// PI[8]: 1 for a real withdrawal, 0 for a dummy/padding proof.
	pub(crate) not_fake_tx: BoolTarget,
	/// PI[9..13]: Input account nullifier (derived from private `accin` witness).
	pub(crate) accin_null: AccountNullifierTarget,
	/// PI[13..17]: Output account commitment (derived from private `accout` witness).
	pub(crate) accout_comm: AccountCommitmentTarget,
	/// PI[17..24]: Asset IDs for each withdrawal slot (zero for padding slots).
	pub(crate) asset_ids: [AssetIdTarget; NOTE_BATCH],
	/// PI[24..80]: Withdrawal amounts per slot (8 limbs × NOTE_BATCH slots).
	pub(crate) withdrawal_amts: [U256Target; NOTE_BATCH],
	/// PI[80..85]: Ethereum destination address (5 × u32 field elements).
	pub(crate) w_acc_addr: [Target; 5],
}

impl WithdrawTxPublicTargets {
	/// Register all public inputs in PI order.
	pub(crate) fn register<F: RichField + Extendable<D> + Poseidon, const D: usize>(
		&self,
		builder: &mut CircuitBuilder<F, D>,
	) {

		builder.register_public_inputs(&self.root.0.elements);
		builder.register_public_inputs(&self.mainpool_config_root.0.elements);
		builder.register_public_input(self.not_fake_tx.target);
		builder.register_public_inputs(&self.accin_null.0.elements);
		builder.register_public_inputs(&self.accout_comm.0.elements);
		for id in &self.asset_ids {
			builder.register_public_input(id.0);
		}
		builder.register_public_inputs(
			&self
				.withdrawal_amts
				.iter()
				.flat_map(|amt| amt.0.map(|u| u.0))
				.collect::<Vec<_>>(),
		);
		builder.register_public_inputs(&self.w_acc_addr);
	}

	/// Fill all free public-input targets for a real withdrawal.
	///
	/// `accin_null` and `accout_comm` are **not** set here — they are derived
	/// in-circuit from the private `accin`/`accout` witnesses and propagated
	/// automatically by the prover.
	///
	/// `acc_in_subpool_id` and `acc_out_subpool_id` are set here (same wire as
	/// `private.accin.subpool_id` / `private.accout.subpool_id`); the private
	/// witness sets the same wire to a consistent value.
	pub(crate) fn set_real(
		&self,
		pw: &mut PartialWitness<F>,
		act_root: HashOutput,
		main_pool_root: HashOutput,
		slot_asset_ids: [AssetId; NOTE_BATCH],
		slot_withdrawal_amts: [U256; NOTE_BATCH],
		w_acc_addr: H160,
	) {
		pw.set_bool_target(self.not_fake_tx, true).unwrap();
		set_hash(pw, self.root.0, act_root.0);
		set_hash(pw, self.mainpool_config_root.0, main_pool_root.0);
		for (i, id) in slot_asset_ids.iter().enumerate() {
			pw.set_target(self.asset_ids[i].0, id.0).unwrap();
		}
		for (i, amt) in slot_withdrawal_amts.iter().enumerate() {
			self.withdrawal_amts[i].set_witness(pw, *amt);
		}
		pw.set_target_arr(&self.w_acc_addr, &map_h160_to_f(w_acc_addr))
			.unwrap();
	}

	/// Fill free public-input targets for a fake (dummy) withdrawal.
	///
	/// `acc_in_subpool_id`, `acc_out_subpool_id`, `accin_null`, and `accout_comm`
	/// are **not** set here — they are computed from the private witnesses in
	/// [`WithdrawTxPrivateTargets::set_fake`].
	pub(crate) fn set_fake(&self, pw: &mut PartialWitness<F>) {
		pw.set_bool_target(self.not_fake_tx, false).unwrap();
		set_hash(pw, self.root.0, HashOutput::ZERO.0);
		set_hash(pw, self.mainpool_config_root.0, HashOutput::ZERO.0);
		for i in 0..NOTE_BATCH {
			pw.set_target(self.asset_ids[i].0, F::ZERO).unwrap();
			self.withdrawal_amts[i].set_witness(pw, U256::zero());
		}
		pw.set_target_arr(&self.w_acc_addr, &map_h160_to_f(H160::zero()))
			.unwrap();
	}
}

// ── Private targets ────────────────────────────────────────────────────────────

/// Private (non-public-input) targets for the withdrawal transaction circuit.
pub(crate) struct WithdrawTxPrivateTargets {
	/// Input account subpool ID.
	pub(crate) acc_in_subpool_id: SubpoolIdTarget,
	/// Output account subpool ID.
	pub(crate) acc_out_subpool_id: SubpoolIdTarget,
	/// Subpool approval authority public key.
	pub(crate) approval_key: PubkeyTarget,
	/// Subpool rejection authority public key.
	pub(crate) rejection_key: PubkeyTarget,
	/// Subpool consume authority public key.
	pub(crate) subpool_consume_key: PubkeyTarget,
	/// Pre-withdrawal account state.
	pub(crate) accin: AccountTarget,
	/// Post-withdrawal account state (nonce+1, AST updated for each slot).
	pub(crate) accout: AccountTarget,
	/// AccIn leaf index in the ACT (prover-supplied for nullifier derivation).
	pub(crate) accin_pos: Target,
	/// AccIn asset balances per slot (before withdrawal).
	pub(crate) accin_amts: [U256Target; NOTE_BATCH],
	/// AccOut asset balances per slot (after withdrawal).
	pub(crate) accout_amts: [U256Target; NOTE_BATCH],
	/// Whether each asset exists in AccIn's AST (false for padding slots).
	pub(crate) asset_exists_in_accin: [BoolTarget; NOTE_BATCH],
	/// Whether each asset remains in AccOut's AST (false when balance hits zero).
	pub(crate) asset_exists_in_accout: [BoolTarget; NOTE_BATCH],
	/// ACT membership proof for AccIn.
	pub(crate) accin_act_merkle: MerkleRootTarget,
	/// Per-slot AST update proofs (chained: slot `i` output root feeds slot `i+1` input root).
	pub(crate) ast_merkles: [MerkleRootTarget; NOTE_BATCH],
	/// Authority key membership proofs for the subpool.
	pub(crate) subpool_proof_targets: SubpoolFullProofTargets,
	/// Approval Schnorr signature over the withdrawal tx hash.
	pub(crate) approval_sig: SchnorrTargets,
}

impl WithdrawTxPrivateTargets {
	/// Fill private targets from pre-computed slot data.
	///
	/// Called by [`WithdrawTxTargets::set_real`] after slot data has been
	/// derived from the raw withdrawal inputs.
	#[allow(clippy::too_many_arguments)]
	fn set_witnesses(
		&self,
		pw: &mut PartialWitness<F>,
		accin: &StandardAccount,
		accout: &StandardAccount,
		accin_act_merkle_proof: MerkleProof<HashOutput>,
		slot_asset_ids: [AssetId; NOTE_BATCH],
		slot_withdrawal_amts: [U256; NOTE_BATCH],
		slot_accin_amts: [U256; NOTE_BATCH],
		slot_accout_amts: [U256; NOTE_BATCH],
		slot_exists_in: [bool; NOTE_BATCH],
		slot_exists_out: [bool; NOTE_BATCH],
		slot_proofs: Vec<MerkleProof<HashOutput>>,
		w_acc_addr: H160,
		approval_key: CompPubKey,
		rejection_key: CompPubKey,
		consume_key: CompPubKey,
		subpool_id: SubpoolId,
		main_pool: &MainPoolConfigTree<HashOutput>,
		approval_sig: Signature,
	) {
		// ── Native tx hash ────────────────────────────────────────────────────────
		let accin_null = accin.nullifier();
		let tx_hash = derive_withdraw_tx_hash(
			accin_null,
			accout.commitment(),
			slot_asset_ids,
			slot_withdrawal_amts,
			w_acc_addr,
		);

		// ── Accounts ──────────────────────────────────────────────────────────────
		self.accin.set_witness(pw, accin);
		self.accout.set_witness(pw, accout);
		pw.set_target(
			self.accin_pos,
			F::from_canonical_usize(accin_act_merkle_proof.pos),
		)
		.unwrap();

		// ── Per-slot witnesses ────────────────────────────────────────────────────
		for i in 0..NOTE_BATCH {
			self.accin_amts[i].set_witness(pw, slot_accin_amts[i]);
			self.accout_amts[i].set_witness(pw, slot_accout_amts[i]);
			pw.set_bool_target(self.asset_exists_in_accin[i], slot_exists_in[i])
				.unwrap();
			pw.set_bool_target(self.asset_exists_in_accout[i], slot_exists_out[i])
				.unwrap();
			self.ast_merkles[i].set_witness(pw, &slot_proofs[i]);
		}

		// ── ACT Merkle proof ──────────────────────────────────────────────────────
		self.accin_act_merkle
			.set_witness(pw, &accin_act_merkle_proof);

		// ── Authority keys ────────────────────────────────────────────────────────
		set_authority_keys(
			pw,
			self.approval_key,
			self.rejection_key,
			self.subpool_consume_key,
			approval_key,
			rejection_key,
			consume_key,
		);

		// ── Subpool full proof ────────────────────────────────────────────────────
		let subpool = SubpoolConfigTree::new(approval_key, rejection_key, consume_key);
		let subpool_proof = main_pool
			.full_subpool_proof(&subpool, subpool_id)
			.expect("subpool not registered in main_pool at the given subpool_id");
		set_subpool_full_proof(
			pw,
			&self.subpool_proof_targets,
			subpool_proof,
			subpool.root(),
			subpool_id,
			approval_key,
			rejection_key,
			consume_key,
		);

		// ── Approval signature ────────────────────────────────────────────────────
		self.approval_sig
			.set(pw, approval_key, tx_hash, approval_sig);
	}

	/// Fill all private targets for a fake (dummy) withdrawal (`not_fake_tx = 0`).
	///
	/// Creates a minimal fake account, inserts it into a fresh ACT for a valid
	/// Merkle proof, and uses fake authority keys and a fake signature.
	/// All withdrawal slots are zero-padded (no balances change).
	pub(crate) fn set_fake(&self, pw: &mut PartialWitness<F>) {
		use tessera_trees::MerkleTree;

		let accin = StandardAccount::fake();
		let accout = accin.clone_with_incremented_nonce();

		let key = fake_authority_key();
		let (_, subpool_proof) = SubpoolConfigTree::fake_instance();

		// Build a minimal ACT containing only accin so the ACT proof is valid.
		let mut act = MerkleTree::<HashOutput>::new(COM_TREE_DEPTH);
		let accin_pos_idx = act.insert(accin.commitment().0).unwrap();
		let accin_act_merkle_proof = act.merkle_proof(accin_pos_idx).unwrap();

		// ── Accounts ──────────────────────────────────────────────────────────────
		self.accin.set_witness(pw, &accin);
		self.accout.set_witness(pw, &accout);
		pw.set_target(
			self.accin_pos,
			F::from_canonical_usize(accin_act_merkle_proof.pos),
		)
		.unwrap();

		// ── Per-slot witnesses (all zero, no withdrawals) ─────────────────────────
		// Each slot's AST proof uses index 0 (the default leaf in an empty AST).
		// With exists_in=false and exists_out=false, the AST root is unchanged
		// across all slots, which is consistent with accin.acc_ast_root == accout.acc_ast_root.
		for i in 0..NOTE_BATCH {
			self.accin_amts[i].set_witness(pw, U256::zero());
			self.accout_amts[i].set_witness(pw, U256::zero());
			pw.set_bool_target(self.asset_exists_in_accin[i], false)
				.unwrap();
			pw.set_bool_target(self.asset_exists_in_accout[i], false)
				.unwrap();
			self.ast_merkles[i].set_witness(pw, &accin.ast.merkle_proof_at(0));
		}

		// ── ACT Merkle proof ──────────────────────────────────────────────────────
		self.accin_act_merkle
			.set_witness(pw, &accin_act_merkle_proof);

		// ── Authority keys and subpool proof ──────────────────────────────────────
		set_authority_keys(
			pw,
			self.approval_key,
			self.rejection_key,
			self.subpool_consume_key,
			key,
			key,
			key,
		);
		set_subpool_full_proof(
			pw,
			&self.subpool_proof_targets,
			subpool_proof,
			HashOutput::ZERO,
			SubpoolId::ZERO,
			key,
			key,
			key,
		);

		// ── Approval signature (fake — not enforced when not_fake_tx = 0) ─────────
		self.approval_sig.set_fake(pw, key);
	}
}

// ── Top-level targets ──────────────────────────────────────────────────────────

/// All targets allocated by
/// [`withdraw_tx_circuit`](crate::plonky2_gadgets::withdraw_tx::circuit::withdraw_tx_circuit).
pub(crate) struct WithdrawTxTargets {
	pub(crate) public: WithdrawTxPublicTargets,
	pub(crate) private: WithdrawTxPrivateTargets,
}

impl WithdrawTxTargets {
	/// Fill the complete witness for a real withdrawal transaction.
	///
	/// Derives `accout`, per-slot balances, and AST proofs from `accin` and
	/// `withdrawals`; computes the native tx hash; then fills both public and
	/// private targets.
	#[allow(clippy::too_many_arguments)]
	pub(crate) fn set_real(
		&self,
		pw: &mut PartialWitness<F>,
		accin: &StandardAccount,
		accin_act_merkle_proof: MerkleProof<HashOutput>,
		act_root: HashOutput,
		main_pool: &MainPoolConfigTree<HashOutput>,
		withdrawals: &[(AssetId, U256)],
		w_acc_addr: H160,
		approval_key: CompPubKey,
		rejection_key: CompPubKey,
		consume_key: CompPubKey,
		subpool_id: SubpoolId,
		approval_sig: Signature,
	) {
		assert!(withdrawals.len() <= NOTE_BATCH, "too many withdrawal slots");

		let (
			slot_asset_ids,
			slot_withdrawal_amts,
			slot_accin_amts,
			slot_accout_amts,
			slot_exists_in,
			slot_exists_out,
			slot_proofs,
			accout,
		) = compute_withdrawal_slots(accin, withdrawals);

		self.public.set_real(
			pw,
			act_root,
			main_pool.root(),
			slot_asset_ids,
			slot_withdrawal_amts,
			w_acc_addr,
		);

		self.private.set_witnesses(
			pw,
			accin,
			&accout,
			accin_act_merkle_proof,
			slot_asset_ids,
			slot_withdrawal_amts,
			slot_accin_amts,
			slot_accout_amts,
			slot_exists_in,
			slot_exists_out,
			slot_proofs,
			w_acc_addr,
			approval_key,
			rejection_key,
			consume_key,
			subpool_id,
			main_pool,
			approval_sig,
		);
	}

	/// Fill the complete witness for a fake (dummy) withdrawal (`not_fake_tx = 0`).
	pub(crate) fn set_fake(&self, pw: &mut PartialWitness<F>) {
		self.public.set_fake(pw);
		self.private.set_fake(pw);
	}
}

// ── Slot computation helper ────────────────────────────────────────────────────

/// Derive per-slot withdrawal data from the raw inputs.
///
/// Returns `(slot_asset_ids, slot_withdrawal_amts, slot_accin_amts,
/// slot_accout_amts, slot_exists_in, slot_exists_out, slot_proofs, accout)`.
///
/// Padding slots (beyond `withdrawals.len()`) use zero values and an AST proof
/// at the next unused leaf index (no balance change, root is unchanged).
#[allow(clippy::type_complexity)]
pub(crate) fn compute_withdrawal_slots(
	accin: &StandardAccount,
	withdrawals: &[(AssetId, U256)],
) -> (
	[AssetId; NOTE_BATCH],
	[U256; NOTE_BATCH],
	[U256; NOTE_BATCH],
	[U256; NOTE_BATCH],
	[bool; NOTE_BATCH],
	[bool; NOTE_BATCH],
	Vec<MerkleProof<HashOutput>>,
	StandardAccount,
) {
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
			let (ast_index, old_bal) = current_ast.amount_for(asset_id).unwrap();
			slot_accin_amts[i] = old_bal;
			slot_exists_in[i] = true;
			// Capture proof BEFORE the update so siblings reflect the current state.
			slot_proofs.push(current_ast.merkle_proof_at(ast_index));
			let new_bal = old_bal - withdrawal_amt;
			slot_accout_amts[i] = new_bal;
			slot_exists_out[i] = new_bal > U256::zero();
			current_ast
				.insert_or_update_asset(asset_id, new_bal)
				.unwrap();
		} else {
			// Padding slot: proof at the next unused leaf (default leaf, no change).
			slot_proofs.push(current_ast.merkle_proof_at(current_ast.next_index()));
		}
	}

	let mut accout = accin.clone_with_incremented_nonce();
	accout.ast = current_ast;

	(
		slot_asset_ids,
		slot_withdrawal_amts,
		slot_accin_amts,
		slot_accout_amts,
		slot_exists_in,
		slot_exists_out,
		slot_proofs,
		accout,
	)
}
