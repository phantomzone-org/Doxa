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
	AccountCommitment, AccountNullifier, AssetId, DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER,
	STATE_TREE_DEPTH, StandardAccount, SubpoolId, derive_deposit_tx_hash,
	ecgfp5::CompressedPoint,
	note::DepositNote,
	plonky2_gadgets::{
		merkle::MerkleRootTarget,
		priv_tx::targets::{
			AccountCommitmentTarget, AccountNullifierTarget, AccountTarget, AssetIdTarget,
			MainPoolConfigRootTarget, PublicIdentifierTaregt, StateRootTarget,
			SubpoolFullProofTargets, SubpoolIdTarget,
		},
		set_hash,
		signature::{PubkeyTarget, SchnorrTargets},
		u256::U256Target,
		witness::fake_authority_key,
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfig, SubpoolFullProof},
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
	pub(crate) fn set(&self, pw: &mut PartialWitness<F>, note: DepositNote) {
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

		self.amount.set(pw, note.amount);
		pw.set_target(self.asset_id.0, note.asset_id.0).unwrap();
	}
}

/// Circuit target for the commitment to a deposit note.
///
/// Derived in-circuit by [`DepositTxCircuitBuilder::derive_deposit_note_comm`];
/// exposed as a public input so the on-chain verifier can match it to the
/// corresponding Ethereum event.
#[derive(Clone, Copy)]
pub struct DepositNoteCommitmentTarget(pub HashOutTarget);

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
pub struct DepositTxTargets {
	pub public_targets: DepositTxPublicTargets,
	pub private_targets: DepositTxPrivateTargets,
}

/// Fill `pw` with a complete DepositTx witness.
///
/// `accout` is derived internally: cloned from `accin`, nonce incremented by one,
/// AST updated with `deposit_note.amount` credited to `deposit_note.asset_id`.
#[allow(clippy::too_many_arguments)]
impl DepositTxTargets {
	pub(crate) fn set(
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
		subpool_id: SubpoolId,
		consume_sig: Option<Signature>,
		approval_sig: Signature,
	) {
		self.public_targets.set_real(
			pw,
			true,
			main_pool.root(),
			act_root,
			accin.nullifier(),
			accout.commitment(),
			eth_address,
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
			eth_address,
			subpool_id,
			consume_sig,
			approval_sig,
		);
	}

	pub(crate) fn set_dummy(&self, pw: &mut PartialWitness<F>) {
		self.public_targets.set_fake(pw);
		self.private_targets.set_fake(pw);
	}

	pub(crate) fn set_dummy_with_roots(
		&self,
		pw: &mut PartialWitness<F>,
		act_root: HashOutput,
		mainpool_config_root: HashOutput,
	) {
		self.public_targets
			.set_fake_with_roots(pw, act_root, mainpool_config_root);
		self.private_targets.set_fake(pw);
	}
}

pub struct DepositTxPublicTargets {
	/// PI[0..4]: State Tree root.
	pub state_root: StateRootTarget,
	/// PI[4..8]: Main pool configuration tree root.
	pub mainpool_config_root: MainPoolConfigRootTarget,
	/// PI[8]: 1 for a real transaction, 0 for a dummy/padding proof.
	pub not_fake_tx: BoolTarget,
	/// PI[9..13]: Input account nullifier.
	pub accin_null: AccountNullifierTarget,
	/// PI[13..17]: Output account commitment.
	pub accout_comm: AccountCommitmentTarget,
	/// PI[17..21]: Derived commitment to `deposit_note`.
	pub note_comm: DepositNoteCommitmentTarget, //<- optimistic update
	/// PI[21..26]: Ethereum address (5 × u32 LE limbs).
	pub eth_address: [Target; 5], //<- optimistic update
	/// PI[26..34]: Deposit amount.
	pub amount: U256Target, //<- optimistic update
	/// PI[34]: Asset being deposited.
	pub asset_id: AssetIdTarget, //<- optimistic update
}

impl DepositTxPublicTargets {
	pub fn register<F, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>)
	where
		F: RichField + Extendable<D> + Poseidon,
	{
		builder.register_public_inputs(&self.state_root.0.elements);
		builder.register_public_inputs(&self.mainpool_config_root.0.elements);
		builder.register_public_input(self.not_fake_tx.target);
		builder.register_public_inputs(&self.accin_null.0.elements);
		builder.register_public_inputs(&self.accout_comm.0.elements);
		builder.register_public_inputs(&self.note_comm.0.elements);
		builder.register_public_inputs(&self.eth_address);
		builder.register_public_inputs(&self.amount.0.map(|v| v.0));
		builder.register_public_input(self.asset_id.0);
	}

	/// Construct from a flat PI slice. Reads fields in the same order as `register()`.
	pub fn from_pis(pis: &[Target]) -> Self {
		use tessera_utils::plonky2_gadgets::u32::U32Target;
		let (root_s, rest) = pis.split_at(4);
		let (main_s, rest) = rest.split_at(4);
		let (nft_s, rest) = rest.split_at(1);
		let (ain_s, rest) = rest.split_at(4);
		let (aout_s, rest) = rest.split_at(4);
		let (nc_s, rest) = rest.split_at(4);
		let (eth_s, rest) = rest.split_at(5);
		let (amt_s, rest) = rest.split_at(8);
		let (aid_s, _) = rest.split_at(1);
		Self {
			state_root: StateRootTarget(HashOutTarget {
				elements: root_s.try_into().unwrap(),
			}),
			mainpool_config_root: MainPoolConfigRootTarget(HashOutTarget {
				elements: main_s.try_into().unwrap(),
			}),
			not_fake_tx: BoolTarget::new_unsafe(nft_s[0]),
			accin_null: AccountNullifierTarget(HashOutTarget {
				elements: ain_s.try_into().unwrap(),
			}),
			accout_comm: AccountCommitmentTarget(HashOutTarget {
				elements: aout_s.try_into().unwrap(),
			}),
			note_comm: DepositNoteCommitmentTarget(HashOutTarget {
				elements: nc_s.try_into().unwrap(),
			}),
			eth_address: eth_s.try_into().unwrap(),
			amount: U256Target(core::array::from_fn(|i| U32Target(amt_s[i]))),
			asset_id: AssetIdTarget(aid_s[0]),
		}
	}

	/// Output commitment target (AC only — deposit has one output commitment per slot).
	pub fn output_commitment(&self) -> [Target; 4] {
		self.accout_comm.0.elements
	}

	/// Unique PI targets (not_fake_tx onwards) for Keccak preimage.
	/// Matches PIHelper::batch_unique_pis() order. Uses only named fields.
	pub fn unique_pi_targets(&self) -> Vec<Target> {
		let mut out = vec![self.not_fake_tx.target];
		out.extend(self.accin_null.0.elements);
		out.extend(self.accout_comm.0.elements);
		out.extend(self.note_comm.0.elements);
		out.extend(self.eth_address);
		out.extend(self.amount.0.map(|u| u.0));
		out.push(self.asset_id.0);
		out
	}
}

impl DepositTxPublicTargets {
	pub fn set_real(
		&self,
		pw: &mut PartialWitness<F>,
		not_fake_tx: bool,
		main_pool_root: HashOutput,
		act_root: HashOutput,
		accin_null: AccountNullifier,
		accout_comm: AccountCommitment,
		eth_address: H160,
		amount: U256,
		asset_id: AssetId,
	) {
		self.set_witnesses(
			pw,
			not_fake_tx,
			main_pool_root,
			act_root,
			accin_null.0,
			accout_comm.0,
			eth_address,
			amount,
			asset_id.0,
		);
	}

	pub fn set_fake(&self, pw: &mut PartialWitness<F>) {
		self.set_fake_with_roots(pw, HashOutput::ZERO, HashOutput::ZERO);
	}

	/// Like [`set_fake`](Self::set_fake) but with explicit `act_root` and
	/// `mainpool_config_root`, so that padding proofs share the same common PIs
	/// as the real proofs in their batch.
	pub fn set_fake_with_roots(
		&self,
		pw: &mut PartialWitness<F>,
		act_root: HashOutput,
		mainpool_config_root: HashOutput,
	) {
		// Only set truly free variables. Derived targets (accin_null, accout_comm,
		// deposit_note_comm) are computed automatically by circuit generators from
		// the private witness set in DepositTxPrivateTargets::set_fake, so they
		// must NOT be set here to avoid "wire set twice" conflicts.
		pw.set_bool_target(self.not_fake_tx, false).unwrap();
		pw.set_hash_target(
			self.mainpool_config_root.0,
			mainpool_config_root.to_hash_out(),
		)
		.unwrap();
		pw.set_hash_target(self.state_root.0, act_root.to_hash_out())
			.unwrap();
		pw.set_target_arr(&self.eth_address, &map_h160_to_f(H160::zero()))
			.unwrap();
	}

	fn set_witnesses(
		&self,
		pw: &mut PartialWitness<F>,
		not_fake_tx: bool,
		main_pool_root: HashOutput,
		act_root: HashOutput,
		accin_null: HashOutput,
		accout_comm: HashOutput,
		eth_address: H160,
		amount: U256,
		asset_id: F,
	) {
		pw.set_bool_target(self.not_fake_tx, not_fake_tx).unwrap();
		pw.set_hash_target(self.mainpool_config_root.0, main_pool_root.to_hash_out())
			.unwrap();
		pw.set_hash_target(self.state_root.0, act_root.to_hash_out())
			.unwrap();
		pw.set_hash_target(self.accin_null.0, accin_null.to_hash_out())
			.unwrap();
		pw.set_hash_target(self.accout_comm.0, accout_comm.to_hash_out())
			.unwrap();
		pw.set_target_arr(&self.eth_address, &map_h160_to_f(eth_address))
			.unwrap();
		self.amount.set(pw, amount);
		pw.set_target(self.asset_id.0, asset_id).unwrap();
	}
}

pub struct DepositTxPrivateTargets {
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
	/// Whether `asset_id` already exists in AccIn's AST.
	pub(crate) asset_exists_in_accin: BoolTarget,
	/// Whether `asset_id` exists in AccOut's AST (always true after deposit).
	pub(crate) asset_exists_in_accout: BoolTarget,
	/// Subpool approval authority public key.
	pub(crate) approval_key: PubkeyTarget,
	/// Authority key membership proofs for the subpool.
	pub(crate) subpool_proof_targets: SubpoolFullProofTargets,
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
		eth_address: H160,
		subpool_id: SubpoolId,
		consume_sig: Option<Signature>,
		approval_sig: Signature,
	) {
		let subpool = SubpoolConfig::new(approval_key);
		let subpool_proof = main_pool
			.full_subpool_proof(&subpool, subpool_id)
			.expect("subpool not registered in main_pool at the given subpool_id");

		self.set_witnesses(
			pw,
			subpool_proof,
			subpool.commitment(),
			accin,
			accin_act_merkle_proof,
			deposit_note,
			approval_key,
			eth_address,
			subpool_id,
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

		let (subpool, subpool_proof) = SubpoolConfig::fake_instance();

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
		self.accin_amt.set(pw, U256::zero());
		self.accout_amt.set(pw, U256::zero());
		pw.set_bool_target(self.asset_exists_in_accin, false)
			.unwrap();
		pw.set_bool_target(self.asset_exists_in_accout, false)
			.unwrap();

		// ── ACT Merkle proof (dummy) ────────────────
		self.accin_act_merkle.set_dummy_witness(pw);

		// ── AccIn AST Merkle proof ────────────────────────────────────────────────
		self.accin_ast_merkle
			.set_witness(pw, &accin.ast.merkle_proof_at(0));

		// ── Subpool full proof ────────────────────────────────────────────────────
		self.subpool_proof_targets.set_fake(pw);

		// ── Authority keys ────────────────────────────────────────────────────────
		self.approval_key.set_witness(pw, key);

		// ── Accounts ─────────────────────────────────────────────────────────────
		self.accin.set_witness(pw, &accin);
		self.accout.set_witness(pw, &accout);

		// ── Signatures (fake — not enforced when not_fake_tx = false) ─────────────
		// Q must match the key used at the time of verification.
		self.sig_targets
			.consume
			.set_dummy(pw, accin.consume_pk_or_default());
		self.sig_targets.approval.set_dummy(pw, key);
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
		eth_address: H160,
		subpool_id: SubpoolId,
		consume_sig: Option<Signature>,
		approval_sig: Signature,
	) {
		let asset_id = deposit_note.asset_id;
		let deposit_amt = deposit_note.amount;

		// ── Build accout ──────────────────────────────────────────────────────────
		let (ast_index, accin_amt, asset_exists_in_accin) = accin
			.ast
			.amount_for(asset_id)
			.map(|(i, b)| (i, b, true))
			.unwrap_or_else(|| (accin.ast.next_index(), U256::zero(), false));
		let accout_amt = accin_amt + deposit_amt;
		let mut accout = accin.clone_with_incremented_nonce();
		accout.ast.insert_or_update_asset(asset_id, accout_amt);
		let asset_exists_in_accout = true; // always true after deposit

		// ── Deposit note ─────────────────────────────────────────────────────────
		self.deposit_note.set(pw, deposit_note.clone());

		// ── Asset / amounts ───────────────────────────────────────────────────────
		self.accin_amt.set(pw, accin_amt);
		self.accout_amt.set(pw, accout_amt);
		pw.set_bool_target(self.asset_exists_in_accin, asset_exists_in_accin)
			.unwrap();
		pw.set_bool_target(self.asset_exists_in_accout, asset_exists_in_accout)
			.unwrap();

		// ── ACT Merkle proof ──────────────────────────────────────────────────────
		self.accin_act_merkle
			.set_witness(pw, &accin_act_merkle_proof);

		// ── AccIn AST Merkle proof ────────────────────────────────────────────────
		self.accin_ast_merkle
			.set_witness(pw, &accin.ast.merkle_proof_at(ast_index));

		// ── Subpool full proof ────────────────────────────────────────────────────
		self.subpool_proof_targets
			.set_witness(pw, subpool_proof, subpool_root, subpool_id);

		// ── Authority keys ────────────────────────────────────────────────────────
		self.approval_key.set_witness(pw, approval_key);

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

		// Consume: real sig if accin.consume_auth.config=1 otherwise fake sig
		let consume_pk = accin.consume_pk_or_default();
		if let Some(sig) = consume_sig {
			self.sig_targets.consume.set(pw, consume_pk, tx_hash, sig);
		} else {
			self.sig_targets.consume.set_dummy(pw, consume_pk);
		}

		// Approval
		self.sig_targets
			.approval
			.set(pw, approval_key, tx_hash, approval_sig);
	}
}
