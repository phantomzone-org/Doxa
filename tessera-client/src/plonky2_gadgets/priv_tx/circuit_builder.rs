use plonky2::{
	hash::{
		hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS, RichField},
		poseidon::PoseidonHash,
	},
	iop::target::{BoolTarget, Target},
	plonk::circuit_builder::CircuitBuilder,
};
use plonky2_field::extension::Extendable;
use tessera_utils::{
	HASH_SIZE,
	hasher::{HashOutput, MerkleHashCircuit, MerkleHashTarget},
	plonky2_gadgets::u32::{U32Target, add_u8_range_check_lookup_table},
};

use crate::{
	ACC_AST_DEPTH, AST_DEFAULT_LEAF, AST_DEFAULT_ROOT, DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER,
	DEFAULT_SPEND_AUTH_PK, DS_ACC_AST_LEAF, DS_NULLIFIER_KEY, DS_PUBLIC_IDENTIFIER,
	MAIN_POOL_CONFIG_DEPTH, NOTE_BATCH, STATE_TREE_DEPTH, SUBPOOL_CONFIG_DEPTH,
	plonky2_gadgets::{
		merkle::{MerkleRootTarget, compute_merkle_root_gadget, conditional_merkle_verify_gadget},
		priv_tx::{
			targets::{
				AccountAddressTarget, AccountCommitmentTarget, AccountNullifierTarget,
				AccountTarget, AssetIdTarget, ConsumeAuthTarget, DummyAccountCommitment,
				DummyAccountNullifier, DummyAccountTarget, DummyNoteTarget,
				MainPoolConfigRootTarget, NoteCommitmentTarget, NoteNullifierTarget,
				NullifierKeyTarget, PrivateIdentifierTarget, PublicIdentifierTarget,
				StandardNoteTarget, StateRootTarget, SubpoolFullProofTargets, SubpoolIdTarget,
				TxHashTarget, TxSignatureTargets,
			},
			utils::double_hash,
		},
		signature::{LocalQuinticExtension, PubkeyTarget, conditional_schnorr_verify_gadget},
		u256::{CircuitBuilderU256, U256Target},
	},
};

/// Extension trait on [`CircuitBuilder`] with all Tessera-specific gadgets.
///
/// Implemented for [`CircuitBuilder<F, D>`] so that circuit construction can be
/// expressed with domain-appropriate method calls rather than raw gate wiring.
///
/// The trait is split into logical groups:
/// - **Allocation** — `add_virtual_*` methods mirror native structs.
/// - **Derivation** — `derive_*` methods build Poseidon hash chains in-circuit.
/// - **Assertion** — `assert_*` methods add constraint groups (equality, Merkle, signature) and
///   return the targets needed for witness-filling.
pub trait PrivTxCircuitBuilder<F: RichField + Extendable<D>, const D: usize> {
	// ---- Add virtual methods ----

	/// Allocate a single dummy note target (an opaque 4-element hash).
	fn add_virtual_dummy_note_target(&mut self) -> DummyNoteTarget;
	/// Allocate a single dummy account target (an opaque 4-element hash).
	fn add_virtual_dummy_account_target(&mut self) -> DummyAccountTarget;
	/// Allocate all targets for a full account. `subpool_id` is a plain target;
	/// callers must register it as a public input explicitly via their circuit's PI block.
	fn add_virtual_account_target(&mut self) -> AccountTarget;
	/// Allocate an account address target.
	fn add_virtual_account_address_target(&mut self) -> AccountAddressTarget;
	/// Allocate all targets for a full note.
	fn add_virtual_note_target(&mut self) -> StandardNoteTarget;
	/// Allocate a pubkey target
	fn add_virtual_public_key_target(&mut self) -> PubkeyTarget;

	// ---- Account related methods ----

	/// Derive `H(private_id || subpool_id || ast_root || nonce || spend_pk || consume_auth)`.
	fn derive_account_commitment(&mut self, acc: AccountTarget) -> AccountCommitmentTarget;

	/// Derive `H(commitment || nk)` — the account's spend-once nullifier.
	fn derive_account_nullifier(
		&mut self,
		acc: AccountCommitmentTarget,
		nk: NullifierKeyTarget,
	) -> AccountNullifierTarget;

	/// Derive a dummy account commitment via double-Poseidon-hash of the raw target.
	fn derive_dummy_account_commitment(
		&mut self,
		dacc: DummyAccountTarget,
	) -> DummyAccountCommitment;

	/// Derive a dummy account nullifier via double-Poseidon-hash of the raw target.
	fn derive_dummy_account_nullifier(&mut self, dacc: DummyAccountTarget)
	-> DummyAccountNullifier;

	/// Add a conditional ACT membership check gated on `condition`.
	///
	/// When `condition=0` all path elements are accepted as-is; the root
	/// constraint is bypassed, so dummy proofs can supply zero-filled paths.
	fn conditionally_assert_account_commitment_exists_in_act<
		H: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<4>>,
	>(
		&mut self,
		acc_comm: AccountCommitmentTarget,
		root: StateRootTarget,
		condition: BoolTarget,
	) -> MerkleRootTarget;

	fn conditionally_assert_hash_equal(
		&mut self,
		condition: BoolTarget,
		h0: HashOutTarget,
		h1: HashOutTarget,
	);

	/// Derive `nk = H(DS_NULLIFIER_KEY || private_identifier)` in-circuit.
	fn derive_nullifier_key(&mut self, priv_id: PrivateIdentifierTarget) -> NullifierKeyTarget;

	/// Derive `public_id = H(DS_PUBLIC_IDENTIFIER || private_identifier)` in-circuit.
	fn derive_public_identifier(
		&mut self,
		priv_id: PrivateIdentifierTarget,
	) -> PublicIdentifierTarget;

	/// When `condition=1`, assert that `acc` is in a fresh (pre-activation) state:
	/// `nonce=0`, default spend/consume keys, and empty AST root.
	fn assert_fresh_account(&mut self, acc: AccountTarget, condition: BoolTarget);

	/// Unconditionally enforce the invariants that hold for **every** tx kind:
	/// `private_identifier` and `subpool_id` are immutable, `nonce` increments
	/// by one, and the two auth keys (`spend_auth`, `consume_auth`) are frozen.
	///
	/// Used by deposit and withdraw circuits where these invariants always apply
	/// without any conditional gating.
	fn assert_account_invariants_simple(&mut self, accin: AccountTarget, accout: AccountTarget);

	/// Enforce per-tx-kind account transition invariants for the private transaction circuit.
	///
	/// - `private_identifier` and `subpool_id` are always immutable.
	/// - `nonce` always increments by 1.
	/// - `acc_ast_root` is frozen for non-spend tx kinds.
	/// - `spend_auth` and `consume_auth` are frozen for spend tx.
	fn assert_account_invariants(
		&mut self,
		accin: AccountTarget,
		accout: AccountTarget,
		is_fresh_acc: BoolTarget,
		is_update_auth: BoolTarget,
		is_priv_tx: BoolTarget,
	);

	/// Prove that `(asset_id, amt)` is a leaf in the AST with root `acc_ast_root`.
	///
	/// When `selector=0`, the leaf is treated as the default (empty) leaf and
	/// `amt` is constrained to zero — this handles assets not yet in the tree.
	fn assert_asset_amt_or_default_in_ast(
		&mut self,
		asset_id: AssetIdTarget,
		amt: U256Target,
		acc_ast_root: HashOutTarget,
		selector: BoolTarget,
	) -> MerkleRootTarget;

	/// Verify that accin's and accout's ASTs both contain the same asset leaf at
	/// the **same position** (same siblings and path bits).
	///
	/// This prevents a prover from swapping the leaf position between accin and
	/// accout, which would allow balance fabrication.
	#[allow(clippy::too_many_arguments)]
	fn assert_ast_update(
		&mut self,
		asset_id: AssetIdTarget,
		accin_amt: U256Target,
		accout_amt: U256Target,
		accin_ast_root: HashOutTarget,
		accout_ast_root: HashOutTarget,
		asset_exists_in_accin: BoolTarget,
		asset_exists_in_accout: BoolTarget,
	) -> MerkleRootTarget;

	// ---- Note related methods ----

	/// Derive the note commitment in-circuit.
	///
	/// Matches [`StandardNote::commitment`](crate::note::StandardNote::commitment) natively.
	fn derive_note_commitment(&mut self, note: StandardNoteTarget) -> NoteCommitmentTarget;

	/// Derive the note nullifier: `H(note_commitment || pos || nk)`.
	fn derive_note_nullifier(
		&mut self,
		nc: NoteCommitmentTarget,
		pos: Target,
		nk: NullifierKeyTarget,
	) -> NoteNullifierTarget;

	/// Derive a dummy note nullifier via double-hash of the raw dummy target.
	fn derive_dummy_note_nullifier(&mut self, dnote: DummyNoteTarget) -> NoteNullifierTarget;

	/// Derive a dummy note commitment via double-hash of the raw dummy target.
	fn derive_dummy_note_commitment(&mut self, dnote: DummyNoteTarget) -> NoteCommitmentTarget;

	/// For each active input note, verify NCT membership and that the note's
	/// spend condition matches the spender's `(subpool_id, public_identifier)`.
	#[allow(clippy::too_many_arguments)]
	fn assert_inotes_valid<H: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<4>>>(
		&mut self,
		inotes: [StandardNoteTarget; NOTE_BATCH],
		inote_isactive: [BoolTarget; NOTE_BATCH],
		inotes_comm: [NoteCommitmentTarget; NOTE_BATCH],
		public_identifier: PublicIdentifierTarget,
		subpool_id: SubpoolIdTarget,
		root: StateRootTarget,
	) -> [MerkleRootTarget; NOTE_BATCH];

	// ---- Other priv tx methods ----

	/// Verify all three authority key proofs (depth-2) and the main-pool inclusion proof
	/// (depth-20).  All checks are gated on `not_fake_tx`.
	fn assert_subpool_full_proof(
		&mut self,
		subpool_id: SubpoolIdTarget,
		approval_key: PubkeyTarget,
		mainpoolconfig_root: MainPoolConfigRootTarget,
		not_fake_tx: BoolTarget,
	) -> SubpoolFullProofTargets;

	/// Derive the private transaction hash:
	/// `H(accin_null[4] || accout_comm[4] || NN[NOTE_BATCH×4] || NC[NOTE_BATCH×4])`.
	///
	/// Active-slot nullifiers / commitments must already be selected before calling
	/// (i.e. replace inactive slots with dummy values).
	fn derive_tx_hash(
		&mut self,
		effective_inotes_null: [NoteNullifierTarget; NOTE_BATCH],
		effective_onotes_comm: [NoteCommitmentTarget; NOTE_BATCH],
		accin_null: AccountNullifierTarget,
		accout_comm: AccountCommitmentTarget,
	) -> TxHashTarget;

	/// For each pair `i` where `is_note_pair_rjct[i]=1`, enforce that the output note is a
	/// mirror of the corresponding input note with the spend/reject conditions swapped (i.e.
	/// the note is returned to the sender).
	fn assert_reject_note_pairs(
		&mut self,
		inotes: [StandardNoteTarget; NOTE_BATCH],
		onotes: [StandardNoteTarget; NOTE_BATCH],
		inote_isactive: [BoolTarget; NOTE_BATCH],
		is_note_pair_rjct: [BoolTarget; NOTE_BATCH],
	);

	/// Enforce the asset conservation law:
	/// `accin_amt + Σ(active inote amounts) == accout_amt + Σ(active onote amounts)`.
	///
	/// Inactive slots contribute zero to both sides.
	fn assert_balance_invariant(
		&mut self,
		accin_amt: U256Target,
		accout_amt: U256Target,
		inotes: [StandardNoteTarget; NOTE_BATCH],
		onotes: [StandardNoteTarget; NOTE_BATCH],
		inotes_isactive: [BoolTarget; NOTE_BATCH],
		onotes_isactive: [BoolTarget; NOTE_BATCH],
	);

	/// Verify the three Schnorr signatures required for a private transaction.
	///
	/// - **Spend** — required when any output note is active and not a reject pair. Signed by
	///   `accin.spend_auth`.
	/// - **Consume** — required when any input note is active and no output note is active (pure
	///   consume).  Key selected by `accin.consume_auth.config`.
	/// - **Approval** — always required (gated by `not_fake_tx`).  Signed by the subpool approval
	///   key.
	#[allow(clippy::too_many_arguments)]
	fn assert_tx_signatures(
		&mut self,
		tx_hash: TxHashTarget,
		inotes_isactive: [BoolTarget; NOTE_BATCH],
		onotes_isactive: [BoolTarget; NOTE_BATCH],
		accin: AccountTarget,
		approval_key: PubkeyTarget,
		is_note_pair_rjct: [BoolTarget; NOTE_BATCH],
		not_fake_tx: BoolTarget,
	) -> TxSignatureTargets;
}

// TODO: rearrange this as per the trait declaration
impl<F: RichField + Extendable<D>, const D: usize> PrivTxCircuitBuilder<F, D>
	for CircuitBuilder<F, D>
where
	HashOutput: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<4>>,
{
	// TODO: change this to only return pubkey target
	fn add_virtual_public_key_target(&mut self) -> PubkeyTarget {
		PubkeyTarget(LocalQuinticExtension(self.add_virtual_target_arr()))
	}

	fn add_virtual_dummy_note_target(&mut self) -> DummyNoteTarget {
		DummyNoteTarget(self.add_virtual_hash())
	}

	fn add_virtual_dummy_account_target(&mut self) -> DummyAccountTarget {
		DummyAccountTarget(self.add_virtual_hash())
	}

	fn add_virtual_account_target(&mut self) -> AccountTarget {
		AccountTarget {
			private_identifier: PrivateIdentifierTarget(self.add_virtual_target_arr()),
			nonce: self.add_virtual_target(),
			subpool_id: SubpoolIdTarget(self.add_virtual_target()),
			acc_ast_root: self.add_virtual_hash(),
			spend_auth: PubkeyTarget(LocalQuinticExtension(self.add_virtual_target_arr())),
			consume_auth: ConsumeAuthTarget {
				config: self.add_virtual_bool_target_safe(),
				pk: PubkeyTarget(LocalQuinticExtension(self.add_virtual_target_arr())),
			},
		}
	}

	fn add_virtual_account_address_target(&mut self) -> AccountAddressTarget {
		AccountAddressTarget {
			subpool_id: SubpoolIdTarget(self.add_virtual_target()),
			public_identifier: PublicIdentifierTarget(self.add_virtual_hash()),
		}
	}

	fn add_virtual_note_target(&mut self) -> StandardNoteTarget {
		StandardNoteTarget {
			identifier: self.add_virtual_target_arr(),
			amount: self.add_virtual_u256_target(),
			asset_id: AssetIdTarget(self.add_virtual_target()),
			recipient: self.add_virtual_account_address_target(),
			sender: self.add_virtual_account_address_target(),
		}
	}

	fn derive_account_commitment(&mut self, acc: AccountTarget) -> AccountCommitmentTarget {
		// Hash input (19 targets), mirroring StandardAccount::commitment():
		// private_identifier[2] || subpool_id[1] || acc_ast_root[4] || nonce[1]
		// || spend_auth[5] || consume_auth.config[1] || consume_auth.pk[5]
		let mut input = Vec::with_capacity(19);
		input.extend_from_slice(&acc.private_identifier.0);
		input.push(acc.subpool_id.0);
		input.extend_from_slice(&acc.acc_ast_root.elements);
		input.push(acc.nonce);
		input.extend_from_slice(&acc.spend_auth.0.0);
		input.push(acc.consume_auth.config.target);
		input.extend_from_slice(&acc.consume_auth.pk.0.0);
		AccountCommitmentTarget(self.hash_n_to_hash_no_pad::<PoseidonHash>(input))
	}

	fn conditionally_assert_account_commitment_exists_in_act<
		H: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<4>>,
	>(
		&mut self,
		acc_comm: AccountCommitmentTarget,
		root: StateRootTarget,
		condition: BoolTarget,
	) -> MerkleRootTarget {
		conditional_merkle_verify_gadget::<F, D>(
			self,
			acc_comm.0,
			root.0,
			condition,
			STATE_TREE_DEPTH,
		)
	}

	fn conditionally_assert_hash_equal(
		&mut self,
		condition: BoolTarget,
		h0: HashOutTarget,
		h1: HashOutTarget,
	) {
		for i in 0..HASH_SIZE {
			self.conditional_assert_eq(condition.target, h0.elements[i], h1.elements[i]);
		}
	}

	fn derive_account_nullifier(
		&mut self,
		acc: AccountCommitmentTarget,
		nk: NullifierKeyTarget,
	) -> AccountNullifierTarget {
		let mut input = Vec::with_capacity(9);
		input.extend_from_slice(&acc.0.elements);
		input.extend_from_slice(&nk.0.elements);
		AccountNullifierTarget(self.hash_n_to_hash_no_pad::<PoseidonHash>(input))
	}

	fn derive_dummy_account_commitment(
		&mut self,
		dacc: DummyAccountTarget,
	) -> DummyAccountCommitment {
		DummyAccountCommitment(double_hash(self, dacc.0))
	}

	fn derive_dummy_account_nullifier(
		&mut self,
		dacc: DummyAccountTarget,
	) -> DummyAccountNullifier {
		DummyAccountNullifier(double_hash(self, dacc.0))
	}

	fn derive_note_commitment(&mut self, note: StandardNoteTarget) -> NoteCommitmentTarget {
		// Matches StandardNote::commitment(): 21-element flat hash
		// identifier[2] || amount[8]  || asset_id || spend_cond.subpool_id[1] ||
		// spend_cond.pub_id[4]              || reject_cond.subpool_id[1] || reject_cond.pub_id[4]
		let mut input: Vec<Target> = Vec::with_capacity(20);
		input.extend_from_slice(&note.identifier);
		input.extend(note.amount.0.map(|u| u.0));
		input.push(note.asset_id.0);
		input.push(note.recipient.subpool_id.0);
		input.extend_from_slice(&note.recipient.public_identifier.0.elements);
		input.push(note.sender.subpool_id.0);
		input.extend_from_slice(&note.sender.public_identifier.0.elements);
		NoteCommitmentTarget(self.hash_n_to_hash_no_pad::<PoseidonHash>(input))
	}

	fn derive_note_nullifier(
		&mut self,
		nc: NoteCommitmentTarget,
		pos: Target,
		nk: NullifierKeyTarget,
	) -> NoteNullifierTarget {
		let mut input = nc.0.elements.to_vec();
		input.push(pos);
		input.extend_from_slice(nk.0.elements.as_ref());
		let nullifier = self.hash_n_to_hash_no_pad::<PoseidonHash>(input);
		NoteNullifierTarget(nullifier)
	}

	fn derive_nullifier_key(&mut self, priv_id: PrivateIdentifierTarget) -> NullifierKeyTarget {
		let mut input = vec![self.constant(F::from_canonical_u64(DS_NULLIFIER_KEY))];
		input.extend(priv_id.0);
		NullifierKeyTarget(self.hash_n_to_hash_no_pad::<PoseidonHash>(input))
	}

	fn derive_public_identifier(
		&mut self,
		priv_id: PrivateIdentifierTarget,
	) -> PublicIdentifierTarget {
		let ds = self.constant(F::from_canonical_u64(DS_PUBLIC_IDENTIFIER));
		let mut input = vec![ds];
		input.extend(priv_id.0);
		PublicIdentifierTarget(self.hash_n_to_hash_no_pad::<PoseidonHash>(input))
	}

	fn derive_dummy_note_nullifier(&mut self, dnote: DummyNoteTarget) -> NoteNullifierTarget {
		NoteNullifierTarget(double_hash(self, dnote.0))
	}

	fn derive_dummy_note_commitment(&mut self, dnote: DummyNoteTarget) -> NoteCommitmentTarget {
		NoteCommitmentTarget(double_hash(self, dnote.0))
	}

	fn derive_tx_hash(
		&mut self,
		effective_inotes_null: [NoteNullifierTarget; NOTE_BATCH],
		effective_onotes_comm: [NoteCommitmentTarget; NOTE_BATCH],
		accin_null: AccountNullifierTarget,
		accout_comm: AccountCommitmentTarget,
	) -> TxHashTarget {
		let mut input = Vec::with_capacity(4 + 4 + 4 * NOTE_BATCH + 4 * NOTE_BATCH);
		input.extend_from_slice(&accin_null.0.elements);
		input.extend_from_slice(&accout_comm.0.elements);
		for null in &effective_inotes_null {
			input.extend_from_slice(&null.0.elements);
		}
		for comm in &effective_onotes_comm {
			input.extend_from_slice(&comm.0.elements);
		}
		TxHashTarget(self.hash_n_to_hash_no_pad::<PoseidonHash>(input))
	}

	fn assert_asset_amt_or_default_in_ast(
		&mut self,
		asset_id: AssetIdTarget,
		amt: U256Target,
		acc_ast_root: HashOutTarget,
		selector: BoolTarget,
	) -> MerkleRootTarget {
		let tr = self._true();
		// derive asset leaf
		let leaf = {
			let mut inputs: [Target; 10] = self.add_virtual_target_arr();
			inputs[0] = self.constant(F::from_canonical_u64(DS_ACC_AST_LEAF));
			inputs[1] = asset_id.0;
			inputs[2..].copy_from_slice(amt.0.map(|t| t.0).as_slice());
			self.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.to_vec())
		};
		let default_leaf: [Target; HASH_SIZE] =
			core::array::from_fn(|i| self.constant(F::from_canonical_u64(AST_DEFAULT_LEAF[i])));
		let exists_or_default: [Target; HASH_SIZE] =
			core::array::from_fn(|i| self._if(selector, leaf.elements[i], default_leaf[i]));

		let merkletargets = compute_merkle_root_gadget::<F, D>(
			self,
			HashOutTarget {
				elements: exists_or_default,
			},
			ACC_AST_DEPTH,
		);
		// computed ast root must equal acc_ast_root
		self.connect_hashes(merkletargets.root, acc_ast_root);

		// if selector == 0 then amt must be 0
		let not_sel = self.not(selector);
		let zero = self.zero();
		for i in 0..amt.0.len() {
			self.conditional_assert_eq(not_sel.target, amt.0[i].0, zero);
		}

		merkletargets
	}

	fn assert_subpool_full_proof(
		&mut self,
		subpool_id: SubpoolIdTarget,
		approval_key: PubkeyTarget,
		mainpool_config_root: MainPoolConfigRootTarget,
		not_fake_tx: BoolTarget,
	) -> SubpoolFullProofTargets {
		// Step A: SubpoolConfig Commitment = H(approval_key)
		let subpool_config_comm =
			self.hash_n_to_hash_no_pad::<PoseidonHash>(approval_key.0.0.to_vec());

		// Step B: Verify the subpool config commitment is a leaf in the depth-20 main pool tree.
		// Main pool leaf = H([subpool_id, 0, 0, 0] || subpool_config_comm).
		// TODO: add a DS in the derivation of the leaf?
		let zero = self.zero();
		let main_pool_leaf_hash = {
			let mut inputs: [Target; NUM_HASH_OUT_ELTS * 2] = core::array::from_fn(|_| zero);
			inputs[0] = subpool_id.0;
			inputs[4..].copy_from_slice(subpool_config_comm.elements.as_slice());
			self.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.to_vec())
		};
		let main_pool_proof = conditional_merkle_verify_gadget::<F, D>(
			self,
			main_pool_leaf_hash,
			mainpool_config_root.0,
			not_fake_tx,
			MAIN_POOL_CONFIG_DEPTH,
		);

		SubpoolFullProofTargets {
			main_pool_proof,
		}
	}

	fn assert_ast_update(
		&mut self,
		asset_id: AssetIdTarget,
		accin_amt: U256Target,
		accout_amt: U256Target,
		accin_ast_root: HashOutTarget,
		accout_ast_root: HashOutTarget,
		asset_exists_in_accin: BoolTarget,
		asset_exists_in_accout: BoolTarget,
	) -> MerkleRootTarget {
		let accin_merkletrgts = self.assert_asset_amt_or_default_in_ast(
			asset_id,
			accin_amt,
			accin_ast_root,
			asset_exists_in_accin,
		);
		let accout_merkletrgts = self.assert_asset_amt_or_default_in_ast(
			asset_id,
			accout_amt,
			accout_ast_root,
			asset_exists_in_accout,
		);

		// Siblings and path bits must match: the same leaf position is updated in both trees
		for i in 0..ACC_AST_DEPTH {
			self.connect_hashes(
				accin_merkletrgts.siblings[i],
				accout_merkletrgts.siblings[i],
			);

			self.connect(
				accin_merkletrgts.bits[i].target,
				accout_merkletrgts.bits[i].target,
			);
		}

		accin_merkletrgts
	}

	fn assert_inotes_valid<H: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<4>>>(
		&mut self,
		inotes: [StandardNoteTarget; NOTE_BATCH],
		inote_isactive: [BoolTarget; NOTE_BATCH],
		inotes_comm: [NoteCommitmentTarget; NOTE_BATCH],
		public_identifier: PublicIdentifierTarget,
		subpool_id: SubpoolIdTarget,
		root: StateRootTarget,
	) -> [MerkleRootTarget; NOTE_BATCH] {
		let merkle_proofs: [MerkleRootTarget; NOTE_BATCH] = core::array::from_fn(|i| {
			conditional_merkle_verify_gadget::<F, D>(
				self,
				inotes_comm[i].0,
				root.0,
				inote_isactive[i],
				STATE_TREE_DEPTH,
			)
		});

		// each note must be spendable by the account
		for note in inotes.iter() {
			self.connect_array(
				note.recipient.public_identifier.0.elements,
				public_identifier.0.elements,
			);
			self.connect(note.recipient.subpool_id.0, subpool_id.0);
		}

		merkle_proofs
	}

	fn assert_account_invariants_simple(&mut self, accin: AccountTarget, accout: AccountTarget) {
		self.connect_array(accin.private_identifier.0, accout.private_identifier.0);
		self.connect(accin.subpool_id.0, accout.subpool_id.0);
		let one = self.one();
		let expected_nonce = self.add(accin.nonce, one);
		self.connect(accout.nonce, expected_nonce);
		self.connect_array(accin.spend_auth.0.0, accout.spend_auth.0.0);
		self.connect_array(accin.consume_auth.pk.0.0, accout.consume_auth.pk.0.0);
		self.connect(
			accin.consume_auth.config.target,
			accout.consume_auth.config.target,
		);
	}

	fn assert_account_invariants(
		&mut self,
		accin: AccountTarget,
		accout: AccountTarget,
		is_fresh_acc: BoolTarget,
		is_update_auth: BoolTarget,
		is_priv_tx: BoolTarget,
	) {
		// AccIn, AccOut must have private_identifier, subpool_id
		self.connect_array(accin.private_identifier.0, accout.private_identifier.0);
		self.connect(accin.subpool_id.0, accout.subpool_id.0);

		// Nonce is always incremented by 1 for every tx kind
		let one = self.one();
		let expected_nonce = self.add(accin.nonce, one);
		self.connect(accout.nonce, expected_nonce);

		// acc_ast_root is immutable for FreshAccTx and UpdateAuthTx; PrivTx may update it
		//
		// not_spend = !is_priv_tx = is_fresh_acc | is_update_auth | (reject pairs), because we
		// constrain elsewhere that only 1 flag of the set is set to true at any time
		let not_spend = self.not(is_priv_tx);
		for i in 0..HASH_SIZE {
			// TODO: use is_fresh_acc | is_update_auth here instead of not_spend
			// self.conditional_assert_eq(
			// 	not_spend.target,
			// 	accout.acc_ast_root.elements[i],
			// 	accin.acc_ast_root.elements[i],
			// );
			self.conditional_assert_eq(
				not_spend.target,
				accout.acc_ast_root.elements[i],
				accin.acc_ast_root.elements[i],
			);
		}

		// spend_auth and consume_auth are immutable for PrivTx only
		for i in 0..5 {
			self.conditional_assert_eq(
				is_priv_tx.target,
				accout.spend_auth.0.0[i],
				accin.spend_auth.0.0[i],
			);
			self.conditional_assert_eq(
				is_priv_tx.target,
				accout.consume_auth.pk.0.0[i],
				accin.consume_auth.pk.0.0[i],
			);
		}
		self.conditional_assert_eq(
			is_priv_tx.target,
			accout.consume_auth.config.target,
			accin.consume_auth.config.target,
		);
	}

	fn assert_reject_note_pairs(
		&mut self,
		inotes: [StandardNoteTarget; NOTE_BATCH],
		onotes: [StandardNoteTarget; NOTE_BATCH],
		inotes_isactive: [BoolTarget; NOTE_BATCH],
		is_note_pair_rjct: [BoolTarget; NOTE_BATCH],
	) {
		for i in 0..NOTE_BATCH {
			// if pair is rjct kind, the input note must be asserted to be active, otherwise in
			// situations where user has delegated consumption to the subpool owner, owner can
			// perform arbitrary spends without user's approval with configuration: inotes_acitve[i]
			// = false, is_note_pair_rjct[i] = true, onotes_active[i] = true. This is because
			// spend signature check is skipped for output notes part of rjct note pairs.
			//
			// Same is not required for output notes, however. Because when an output note is
			// inactive but corresponding input note and rjct flag is active, then the only action
			// possible is to consume the input note.
			let tr = self._true();
			self.conditional_assert_eq(
				is_note_pair_rjct[i].target,
				inotes_isactive[i].target,
				tr.target,
			);

			// identifier
			for j in 0..2 {
				self.conditional_assert_eq(
					is_note_pair_rjct[i].target,
					inotes[i].identifier[j],
					onotes[i].identifier[j],
				);
			}

			// amount (8 u32 limbs)
			for j in 0..8 {
				self.conditional_assert_eq(
					is_note_pair_rjct[i].target,
					inotes[i].amount.0[j].0,
					onotes[i].amount.0[j].0,
				);
			}

			// asset_id
			self.conditional_assert_eq(
				is_note_pair_rjct[i].target,
				inotes[i].asset_id.0,
				onotes[i].asset_id.0,
			);

			// spend_cond of onote == reject_cond of inote (note returns to sender)
			self.conditional_assert_eq(
				is_note_pair_rjct[i].target,
				inotes[i].sender.subpool_id.0,
				onotes[i].recipient.subpool_id.0,
			);
			for j in 0..HASH_SIZE {
				self.conditional_assert_eq(
					is_note_pair_rjct[i].target,
					inotes[i].sender.public_identifier.0.elements[j],
					onotes[i].recipient.public_identifier.0.elements[j],
				);
			}

			// reject_cond of onote == reject_cond of inote (sender unchanged)
			self.conditional_assert_eq(
				is_note_pair_rjct[i].target,
				inotes[i].sender.subpool_id.0,
				onotes[i].sender.subpool_id.0,
			);
			for j in 0..HASH_SIZE {
				self.conditional_assert_eq(
					is_note_pair_rjct[i].target,
					inotes[i].sender.public_identifier.0.elements[j],
					onotes[i].sender.public_identifier.0.elements[j],
				);
			}
		}
	}

	fn assert_balance_invariant(
		&mut self,
		accin_amt: U256Target,
		accout_amt: U256Target,
		inotes: [StandardNoteTarget; NOTE_BATCH],
		onotes: [StandardNoteTarget; NOTE_BATCH],
		inotes_isactive: [BoolTarget; NOTE_BATCH],
		onotes_isactive: [BoolTarget; NOTE_BATCH],
	) {
		let zero = self.zero();
		let inote_amts: [U256Target; NOTE_BATCH] = core::array::from_fn(|i| {
			U256Target(core::array::from_fn(|j| {
				U32Target(self._if(inotes_isactive[i], inotes[i].amount.0[j].0, zero))
			}))
		});
		let onote_amts: [U256Target; NOTE_BATCH] = core::array::from_fn(|i| {
			U256Target(core::array::from_fn(|j| {
				U32Target(self._if(onotes_isactive[i], onotes[i].amount.0[j].0, zero))
			}))
		});
		let u8rngchk_lut = add_u8_range_check_lookup_table(self);
		let lhs = self.u256_addition_chain(&accin_amt, &inote_amts, u8rngchk_lut);
		let rhs = self.u256_addition_chain(&accout_amt, &onote_amts, u8rngchk_lut);
		self.connect_u256(&lhs, &rhs);
	}

	fn assert_fresh_account(&mut self, acc: AccountTarget, condition: BoolTarget) {
		let zero = self.zero();

		let default_ast_root: [Target; HASH_SIZE] =
			core::array::from_fn(|i| self.constant(F::from_canonical_u64(AST_DEFAULT_ROOT[i])));
		for (&elem, &default) in acc
			.acc_ast_root
			.elements
			.iter()
			.zip(default_ast_root.iter())
		{
			self.conditional_assert_eq(condition.target, elem, default);
		}

		self.conditional_assert_eq(condition.target, acc.nonce, zero);

		let default_spend: [Target; 5] =
			DEFAULT_SPEND_AUTH_PK.map(|v| self.constant(F::from_canonical_u64(v)));
		for (&t, &d) in acc.spend_auth.0.0.iter().zip(default_spend.iter()) {
			self.conditional_assert_eq(condition.target, t, d);
		}

		self.conditional_assert_eq(condition.target, acc.consume_auth.config.target, zero);

		let default_consume: [Target; 5] = DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER
			.map(|v| self.constant(F::from_canonical_u64(v)));
		for (&t, &d) in acc.consume_auth.pk.0.0.iter().zip(default_consume.iter()) {
			self.conditional_assert_eq(condition.target, t, d);
		}
	}

	fn assert_tx_signatures(
		&mut self,
		tx_hash: TxHashTarget,
		inotes_isactive: [BoolTarget; NOTE_BATCH],
		onotes_isactive: [BoolTarget; NOTE_BATCH],
		accin: AccountTarget,
		approval_key: PubkeyTarget,
		is_note_pair_rjct: [BoolTarget; NOTE_BATCH],
		not_fake_tx: BoolTarget,
	) -> TxSignatureTargets {
		// ── Spend signature ───────────────────────────────────────────────────
		// Required when ≥1 output note is active AND that note is not a reject pair.
		// Reject pairs do not require a spend signature.
		let not_pair_rjct_0 = self.not(is_note_pair_rjct[0]);
		let mut is_spend_req = self.and(onotes_isactive[0], not_pair_rjct_0);
		for (i, sel) in onotes_isactive.iter().enumerate().skip(1) {
			let not_pair_rjct_i = self.not(is_note_pair_rjct[i]);
			let contributes = self.and(*sel, not_pair_rjct_i);
			is_spend_req = self.or(contributes, is_spend_req);
		}

		// Note: the public key used in verification must match the key stored in accin —
		// even for "fake" signatures the key must be correct or the proof will fail.
		// For pre-FreshAcc accounts the default placeholder key is used.
		let spend =
			conditional_schnorr_verify_gadget(self, tx_hash.0, accin.spend_auth, is_spend_req);

		// ── Consume signature ─────────────────────────────────────────────────
		// Required when ≥1 input note is active AND no output note is active AND
		// consume_auth.config = 1 (pure consume, no outgoing transfer).
		let mut has_inotes = inotes_isactive[0];
		for sel in inotes_isactive.iter().skip(1) {
			has_inotes = self.or(*sel, has_inotes);
		}
		let not_is_spend_req = self.not(is_spend_req);
		let is_consume_req = self.and(has_inotes, not_is_spend_req);
		let check_consume_sig = self.and(is_consume_req, accin.consume_auth.config);
		let consume = conditional_schnorr_verify_gadget(
			self,
			tx_hash.0,
			accin.consume_auth.pk,
			check_consume_sig,
		);

		// ── Approval signature ────────────────────────────────────────────────
		// Always required for real transactions; bypassed for dummy proofs.
		let approval =
			conditional_schnorr_verify_gadget(self, tx_hash.0, approval_key, not_fake_tx);

		TxSignatureTargets {
			spend,
			consume,
			approval,
		}
	}
}
