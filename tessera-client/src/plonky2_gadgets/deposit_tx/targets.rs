use digest::typenum::Zero;
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
use plonky2_field::{extension::Extendable, packed::PackedField, types::Field};
use primitive_types::{H160, U256};
use tessera_trees::MerkleProof;
use tessera_utils::{
	D, F,
	hasher::{HashOutput, MerkleHash, ToHashOut},
};

use crate::{
	AccountCommitment, AccountNullifier, AssetId, COM_TREE_DEPTH, StandardAccount, SubpoolId,
	derive_deposit_tx_hash,
	note::DepositNote,
	plonky2_gadgets::{
		merkle::MerkleRootTarget,
		priv_tx::targets::{
			AccountCommitmentTarget, AccountNullifierTarget, AccountTarget, AssetIdTarget,
			MainPoolConfigRootTarget, PublicIdentifierTaregt, RootTarget, SubpoolFullProofTargets,
			SubpoolIdTarget,
		},
		set_hash,
		signature::{PubkeyTarget, SchnorrTargets},
		u256::U256Target,
		witness::{fake_authority_key, set_authority_keys, set_subpool_full_proof},
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree, SubpoolFullProof},
	schnorr::{CompressedPublicKey, Signature},
	utils::map_h160_to_f,
};

// ----- DepositNote targets -----

/// Circuit targets for a [`DepositNote`].
///
/// Mirrors the native `DepositNote` field-by-field; `set_witness` fills all
/// targets from a concrete note.
#[derive(Clone, Copy)]
pub(crate) struct DepositNoteTarget {
	/// Random 2-element note identifier.
	pub(crate) identifier: [Target; 2],
	pub(crate) recipient_subpool_id: SubpoolIdTarget,
	pub(crate) recipient_public_id: PublicIdentifierTaregt,
	pub(crate) amount: U256Target,
	pub(crate) asset_id: AssetIdTarget,
}

impl DepositNoteTarget {
	/// Fill all note targets from a concrete [`DepositNote`].
	pub(crate) fn set_witness(&self, pw: &mut PartialWitness<F>, note: DepositNote) {
		pw.set_target(self.identifier[0], note.identifier.0[0])
			.unwrap();
		pw.set_target(self.identifier[1], note.identifier.0[1])
			.unwrap();
		pw.set_target(self.recipient_subpool_id.0, note.recipient.subpool_id.0)
			.unwrap();
		pw.set_target_arr(
			&self.recipient_public_id.0.elements,
			&note.recipient.public_id.0.0,
		)
		.unwrap();

		self.amount.set_witness(pw, note.amount);
		pw.set_target(self.asset_id.0, note.asset_id.0).unwrap();
	}
}

/// Circuit target for the commitment to a deposit note.
///
/// Derived in-circuit by [`DepositTxCircuitBuilder::derive_deposit_note_comm`];
/// exposed as a public input so the on-chain verifier can match it to the
/// corresponding Ethereum event.
#[derive(Clone, Copy)]
pub(crate) struct DepositNoteCommitmentTarget(pub(crate) HashOutTarget);

// ----- Signature targets -----

/// Signature targets for the two authorizations required on a deposit.
///
/// - `consume`: signed by either the account's own consume key or the subpool consume key,
///   depending on `accin.consume_auth.config`.
/// - `approval`: always signed by the subpool approval key.
#[derive(Clone)]
pub(crate) struct DepositTxSignatureTargets {
	pub(crate) consume: SchnorrTargets,
	pub(crate) approval: SchnorrTargets,
}

// ----- Top-level DepositTxTargets -----

/// All circuit targets allocated by [`deposit_tx_circuit`].
///
/// Held by [`DepositTxCircuit`] and passed to the witness-filling functions
/// so the same compilation can generate many proofs without rebuilding.
pub(crate) struct DepositTxTargets {
	pub public_targets: DepositTxPublicTargets,
	pub private_targets: DepositTxPrivateTargets,
}

/// Fill `pw` with a complete DepositTx witness.
///
/// `accout` is derived internally: cloned from `accin`, nonce incremented by one,
/// AST updated with `deposit_note.amount` credited to `deposit_note.asset_id`.
#[allow(clippy::too_many_arguments)]
impl DepositTxTargets {
	pub(crate) fn set_real(
		&self,
		pw: &mut PartialWitness<F>,
		act_root: HashOutput,
		main_pool: MainPoolConfigTree<HashOutput>,
		accin: &StandardAccount,
		accout: &StandardAccount,
		accin_act_merkle_proof: MerkleProof<HashOutput>,
		deposit_note: DepositNote,
		eth_address: H160,
		approval_key: CompPubKey,
		rejection_key: CompPubKey,
		consume_key: CompPubKey,
		subpool_id: SubpoolId,
		consume_sig: Signature,
		approval_sig: Signature,
	) {
		self.public_targets.set_real(
			pw,
			accin.subpool_id,
			accout.subpool_id,
			true,
			main_pool.root(),
			act_root,
			accin.nullifier(),
			accout.commitment(),
			eth_address,
			subpool_id,
			deposit_note.amount,
			deposit_note.asset_id,
		);
		self.private_targets.set_real(
			pw,
			main_pool,
			accin,
			accin_act_merkle_proof,
			deposit_note,
			approval_key,
			rejection_key,
			consume_key,
			eth_address,
			subpool_id,
			consume_sig,
			approval_sig,
		);
	}

	pub(crate) fn set_fake(&self, pw: &mut PartialWitness<F>) {
		self.public_targets.set_fake(pw);
		self.private_targets.set_fake(pw);
	}
}

pub struct DepositTxPublicTargets {
	/// PI[0]: Input account subpool ID
	pub acc_in_subpool_id: SubpoolIdTarget,
	/// PI[1]: Output account subpool ID
	pub acc_out_subpool_id: SubpoolIdTarget,
	/// PI[2]: 1 for a real transaction, 0 for a dummy/padding proof.
	pub not_fake_tx: BoolTarget,
	/// PI[3..7]: Main pool configuration tree root.
	pub mainpool_config_root: MainPoolConfigRootTarget,
	/// PI[7..11]: Account Commitment Tree root.
	pub root: RootTarget,
	/// PI[11..15]: Input account nullifier.
	pub accin_null: AccountNullifierTarget,
	/// PI[15..19]: Output account commitment.
	pub accout_comm: AccountCommitmentTarget,
	/// PI[19..23]: Derived commitment to `deposit_note`.
	pub note_comm: DepositNoteCommitmentTarget,
	/// PI[23..28]: Ethereum address (5 × u32 LE limbs).
	pub eth_address: [Target; 5],
	/// PI[28..36]: Deposit amount.
	pub amount: U256Target,
	/// PI[36]: Asset being deposited.
	pub asset_id: AssetIdTarget,
}

impl DepositTxPublicTargets {
	pub fn register<F, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>)
	where
		F: RichField + Extendable<D> + Poseidon,
	{
		builder.register_public_input(self.acc_in_subpool_id.0);
		builder.register_public_input(self.acc_out_subpool_id.0);
		builder.register_public_input(self.not_fake_tx.target);
		builder.register_public_inputs(&self.mainpool_config_root.0.elements);
		builder.register_public_inputs(&self.root.0.elements);
		builder.register_public_inputs(&self.accin_null.0.elements);
		builder.register_public_inputs(&self.accout_comm.0.elements);
		builder.register_public_inputs(&self.note_comm.0.elements);
		builder.register_public_inputs(&self.eth_address);
		builder.register_public_inputs(&self.amount.0.map(|v| v.0));
		builder.register_public_input(self.asset_id.0);
	}
}

impl DepositTxPublicTargets {
	pub fn set_real(
		&self,
		pw: &mut PartialWitness<F>,
		acc_in_subpool_id: SubpoolId,
		acc_out_subpool_id: SubpoolId,
		not_fake_tx: bool,
		main_pool_root: HashOutput,
		act_root: HashOutput,
		accin_null: AccountNullifier,
		accout_comm: AccountCommitment,
		eth_address: H160,
		subpool_id: SubpoolId,
		amount: U256,
		asset_id: AssetId,
	) {
		self.set_witnesses(
			pw,
			acc_in_subpool_id.0,
			acc_out_subpool_id.0,
			not_fake_tx,
			main_pool_root,
			act_root,
			accin_null.0,
			accout_comm.0,
			eth_address,
			subpool_id.0,
			amount,
			asset_id.0,
		);
	}

	pub fn set_fake(&self, pw: &mut PartialWitness<F>) {
		// Only set truly free variables. Derived targets (accin_null, accout_comm,
		// deposit_note_comm) are computed automatically by circuit generators from
		// the private witness set in DepositTxPrivateTargets::set_fake, so they
		// must NOT be set here to avoid "wire set twice" conflicts.
		pw.set_bool_target(self.not_fake_tx, false).unwrap();
		pw.set_hash_target(self.mainpool_config_root.0, HashOutput::ZERO.to_hash_out())
			.unwrap();
		pw.set_hash_target(self.root.0, HashOutput::ZERO.to_hash_out())
			.unwrap();
		pw.set_target_arr(&self.eth_address, &map_h160_to_f(H160::zero()))
			.unwrap();
	}

	fn set_witnesses(
		&self,
		pw: &mut PartialWitness<F>,
		acc_in_subpool_id: F,
		acc_out_subpool_id: F,
		not_fake_tx: bool,
		main_pool_root: HashOutput,
		act_root: HashOutput,
		accin_null: HashOutput,
		accout_comm: HashOutput,
		eth_address: H160,
		subpool_id: F,
		amount: U256,
		asset_id: F,
	) {
		pw.set_target(self.acc_in_subpool_id.0, acc_in_subpool_id)
			.unwrap();
		pw.set_target(self.acc_out_subpool_id.0, acc_out_subpool_id)
			.unwrap();
		pw.set_bool_target(self.not_fake_tx, not_fake_tx).unwrap();
		pw.set_hash_target(self.mainpool_config_root.0, main_pool_root.to_hash_out())
			.unwrap();
		pw.set_hash_target(self.root.0, act_root.to_hash_out())
			.unwrap();
		pw.set_hash_target(self.accin_null.0, accin_null.to_hash_out())
			.unwrap();
		pw.set_hash_target(self.accout_comm.0, accout_comm.to_hash_out())
			.unwrap();
		pw.set_target_arr(&self.eth_address, &map_h160_to_f(eth_address))
			.unwrap();
		self.amount.set_witness(pw, amount);
		pw.set_target(self.asset_id.0, asset_id).unwrap();
	}
}

pub(crate) struct DepositTxPrivateTargets {
	/// The deposit note fields.
	pub(crate) deposit_note: DepositNoteTarget,
	/// Pre-transaction account state.
	pub(crate) accin: AccountTarget,
	/// Post-transaction account state (nonce+1, AST updated).
	pub(crate) accout: AccountTarget,
	/// Merkle proof that AccIn's commitment is in the ACT.
	pub(crate) accin_act_merkle: MerkleRootTarget,
	/// Merkle proof for the AST leaf update (accin → accout).
	pub(crate) accin_ast_merkle: MerkleRootTarget,
	/// AccIn balance for `asset_id` before the deposit.
	pub(crate) accin_amt: U256Target,
	/// AccOut balance for `asset_id` after the deposit.
	pub(crate) accout_amt: U256Target,
	/// AccIn leaf index in the ACT (supplied by the prover for nullifier derivation).
	pub(crate) accin_pos: Target,
	/// Whether `asset_id` already exists in AccIn's AST.
	pub(crate) asset_exists_in_accin: BoolTarget,
	/// Whether `asset_id` exists in AccOut's AST (always true after deposit).
	pub(crate) asset_exists_in_accout: BoolTarget,
	/// Subpool consume authority public key.
	pub(crate) subpool_consume_key: PubkeyTarget,
	/// Subpool approval authority public key.
	pub(crate) approval_key: PubkeyTarget,
	/// Subpool rejection authority public key.
	pub(crate) rejection_key: PubkeyTarget,
	/// Authority key membership proofs for the subpool.
	pub subpool_proof_targets: SubpoolFullProofTargets,
	/// Schnorr signature targets for consume and approval.
	pub(crate) sig_targets: DepositTxSignatureTargets,
}

impl DepositTxPrivateTargets {
	fn set_real(
		&self,
		pw: &mut PartialWitness<F>,
		main_pool: MainPoolConfigTree<HashOutput>,
		accin: &StandardAccount,
		accin_act_merkle_proof: MerkleProof<HashOutput>,
		deposit_note: DepositNote,
		approval_key: CompPubKey,
		rejection_key: CompPubKey,
		consume_key: CompPubKey,
		eth_address: H160,
		subpool_id: SubpoolId,
		consume_sig: Signature,
		approval_sig: Signature,
	) {
		let subpool = SubpoolConfigTree::new(approval_key, rejection_key, consume_key);
		let subpool_proof = main_pool
			.full_subpool_proof(&subpool, subpool_id)
			.expect("subpool not registered in main_pool at the given subpool_id");

		self.set_witnesses(
			pw,
			subpool_proof,
			subpool.root(),
			accin,
			accin_act_merkle_proof,
			deposit_note,
			approval_key,
			rejection_key,
			consume_key,
			eth_address,
			subpool_id.0,
			consume_sig,
			approval_sig,
		);
	}

	fn set_fake(&self, pw: &mut PartialWitness<F>) {
		use tessera_trees::MerkleTree;

		// Use non-zero private identifier so the derived public_identifier is
		// consistent with the deposit note recipient (circuit hard-connects them).
		let accin = StandardAccount::fake();
		let accout = accin.clone_with_incremented_nonce();

		let key = fake_authority_key();

		let (subpool, subpool_proof) = SubpoolConfigTree::fake_instance();

		let mut act = MerkleTree::<HashOutput>::new(COM_TREE_DEPTH);
		let accin_pos = act.insert(accin.commitment().0).unwrap();
		let accin_act_merkle_proof = act.merkle_proof(accin_pos).unwrap();

		// Recipient must match accin's public identifier (circuit enforces this
		// via connect_array), and asset_exists_in_accout must be false so that
		// the accout AST leaf uses AST_DEFAULT_LEAF (consistent with empty AST root).
		let deposit_note = DepositNote {
			identifier: crate::NoteIdentifier::ZERO,
			recipient: crate::AccountAddress::from_acc(&accin),
			amount: U256::zero(),
			asset_id: AssetId::ZERO,
		};

		// ── Deposit note ──────────────────────────────────────────────────────────
		self.deposit_note.set_witness(pw, deposit_note);

		// ── Amounts and exists flags ───────────────────────────────────────────────
		self.accin_amt.set_witness(pw, U256::zero());
		self.accout_amt.set_witness(pw, U256::zero());
		pw.set_bool_target(self.asset_exists_in_accin, false)
			.unwrap();
		pw.set_bool_target(self.asset_exists_in_accout, false)
			.unwrap();
		pw.set_target(
			self.accin_pos,
			F::from_canonical_usize(accin_act_merkle_proof.pos),
		)
		.unwrap();

		// ── ACT Merkle proof (real path of accin in a fresh tree) ────────────────
		self.accin_act_merkle
			.set_witness(pw, &accin_act_merkle_proof);

		// ── AccIn AST Merkle proof ────────────────────────────────────────────────
		self.accin_ast_merkle
			.set_witness(pw, &accin.ast.merkle_proof_at(0));

		// ── Subpool full proof ────────────────────────────────────────────────────
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

		// ── Authority keys ────────────────────────────────────────────────────────
		set_authority_keys(
			pw,
			self.approval_key,
			self.rejection_key,
			self.subpool_consume_key,
			key,
			key,
			key,
		);

		// ── Accounts ─────────────────────────────────────────────────────────────
		self.accin.set_witness(pw, &accin);
		self.accout.set_witness(pw, &accout);

		// ── Signatures (fake — not enforced when not_fake_tx = false) ─────────────
		// Q must match the key set in the authority_keys targets above.
		self.sig_targets.consume.set_fake(pw, key);
		self.sig_targets.approval.set_fake(pw, key);
	}

	fn set_witnesses(
		&self,
		pw: &mut PartialWitness<F>,
		subpool_proof: SubpoolFullProof<HashOutput>,
		subpool_root: HashOutput,
		accin: &StandardAccount,
		accin_act_merkle_proof: MerkleProof<HashOutput>,
		deposit_note: DepositNote,
		approval_key: CompPubKey,
		rejection_key: CompPubKey,
		consume_key: CompPubKey,
		eth_address: H160,
		subpool_id: F,
		consume_sig: Signature,
		approval_sig: Signature,
	) {
		let asset_id = deposit_note.asset_id;
		let deposit_amt = deposit_note.amount;

		// ── Build accout ──────────────────────────────────────────────────────────
		let (ast_index, old_bal) = accin
			.ast
			.amount_for(asset_id)
			.unwrap_or_else(|| (accin.ast.next_index(), U256::zero()));
		let new_bal = old_bal + deposit_amt;
		let mut accout = accin.clone_with_incremented_nonce();
		accout.ast.insert_or_update_asset(asset_id, new_bal);

		// ── Deposit note ─────────────────────────────────────────────────────────
		self.deposit_note.set_witness(pw, deposit_note.clone());

		// ── Amounts and exists flags ───────────────────────────────────────────────
		let (_, accin_amt) = accin.ast.amount_for(asset_id).unwrap_or((0, U256::zero()));
		let (_, accout_amt) = accout.ast.amount_for(asset_id).unwrap_or((0, U256::zero()));
		let asset_exists_in_accin = accin.ast.amount_for(asset_id).is_some();
		let asset_exists_in_accout = true; // always true after deposit

		// ── Asset / amounts ───────────────────────────────────────────────────────
		self.accin_amt.set_witness(pw, accin_amt);
		self.accout_amt.set_witness(pw, accout_amt);
		pw.set_bool_target(self.asset_exists_in_accin, asset_exists_in_accin)
			.unwrap();
		pw.set_bool_target(self.asset_exists_in_accout, asset_exists_in_accout)
			.unwrap();
		pw.set_target(
			self.accin_pos,
			F::from_canonical_usize(accin_act_merkle_proof.pos),
		)
		.unwrap();

		// ── ACT Merkle proof ──────────────────────────────────────────────────────
		self.accin_act_merkle
			.set_witness(pw, &accin_act_merkle_proof);

		// ── AccIn AST Merkle proof ────────────────────────────────────────────────
		self.accin_ast_merkle
			.set_witness(pw, &accin.ast.merkle_proof_at(ast_index));

		// ── Subpool full proof ────────────────────────────────────────────────────
		set_subpool_full_proof(
			pw,
			&self.subpool_proof_targets,
			subpool_proof,
			subpool_root,
			SubpoolId(subpool_id),
			approval_key,
			rejection_key,
			consume_key,
		);

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

		// ── Native TxHash ─────────────────────────────────────────────────────────
		// H(accin_null[4] || accout_comm[4] || deposit_note_comm[4] || eth_address[5])
		let accin_null = accin.nullifier();
		let deposit_note_comm_native = deposit_note.commitment();

		// ── Accounts ──────────────────────────────────────────────────────────────
		self.accin.set_witness(pw, accin);
		self.accout.set_witness(pw, &accout);

		let tx_hash = derive_deposit_tx_hash(
			accin_null,
			accout.commitment(),
			deposit_note_comm_native,
			eth_address,
		);

		// ── Signatures ────────────────────────────────────────────────────────────

		// Consume: uses accin.consume_auth.config to pick key (same as circuit)
		self.sig_targets.consume.set(
			pw,
			if accin.consume_auth.config {
				accin.consume_auth.pk.unwrap()
			} else {
				consume_key
			},
			tx_hash,
			consume_sig,
		);

		// Approval
		self.sig_targets
			.approval
			.set(pw, approval_key, tx_hash, approval_sig);
	}
}
