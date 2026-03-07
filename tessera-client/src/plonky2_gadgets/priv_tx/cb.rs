use plonky2::{
	hash::{
		hash_types::{HashOutTarget, RichField},
		poseidon::PoseidonHash,
	},
	iop::target::{BoolTarget, Target},
	plonk::circuit_builder::CircuitBuilder,
};
use plonky2_field::extension::Extendable;
use tessera_trees::{
	plonky2_gadgets::u32::{U32Target, add_u8_range_check_lookup_table},
	tree::HASH_SIZE,
};

use crate::{
	ACC_AST_DEPTH, ACT_DEPTH, AST_DEFAULT_LEAF, AST_DEFAULT_ROOT,
	DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER, DEFAULT_SPEND_AUTH_PK, DS_ACC_AST_LEAF,
	DS_NULLIFIER_KEY, MAIN_POOL_CONFIG_DEPTH, NCT_DEPTH, NOTE_BATCH, SUBPOOL_CONFIG_DEPTH,
	plonky2_gadgets::{
		merkle::{
			ConditionalMerkleTarget, MerkleTarget, conditional_merkle_verify_gadget,
			merkle_verify_gadget,
		},
		priv_tx::targets::{
			AccountCommitmentTarget, AccountNullifierTarget, AccountTarget, ActMerkleTarget,
			ActRootTarget, AssetIdTarget, AstMerkleTargets, ConsumeAuthTarget, ConsumeCondTarget,
			DummyAccountCommitment, DummyAccountNullifier, DummyAccountTarget, DummyNoteTarget,
			NctRootTarget, NoteCommitmentTarget, NoteNullifierTarget, NoteTarget,
			NullifierKeyTarget, PrivateIdentifierTarget, PublicIdentifierTaregt, RejectCondTarget,
			SubpoolFullProofTargets, SubpoolIdTarget, TxHashTarget, TxSignatureTargets,
		},
		signature::{LocalQuinticExtension, PubkeyTarget, conditional_schnorr_verify_gadget},
		u256::{CircuitBuilderU256, U256Target},
	},
};

pub trait LocalCB {
	// ---- Add virtual methods ----

	fn add_virtual_dummy_note_target(&mut self) -> DummyNoteTarget;
	fn add_virtual_account_target(&mut self) -> AccountTarget;
	fn add_virtual_consume_cond_target(&mut self) -> ConsumeCondTarget;
	fn add_virtual_reject_cond_target(&mut self) -> RejectCondTarget;
	fn add_virtual_note_target(&mut self) -> NoteTarget;

	// ---- Account related methods ----

	fn derive_account_commitment(&mut self, acc: AccountTarget) -> AccountCommitmentTarget;

	fn derive_account_nullifier(
		&mut self,
		acc: AccountCommitmentTarget,
		pos: Target,
		nk: NullifierKeyTarget,
	) -> AccountNullifierTarget;

	fn derive_fresh_account_nullifier(
		&mut self,
		acc: AccountCommitmentTarget,
		nk: NullifierKeyTarget,
	) -> AccountNullifierTarget;

	fn derive_dummy_account_commitment(
		&mut self,
		dacc: DummyAccountTarget,
	) -> DummyAccountCommitment;

	fn derive_dummy_account_nullifier(&mut self, dacc: DummyAccountTarget)
	-> DummyAccountNullifier;

	fn conditionally_assert_account_commitment_exists_in_act(
		&mut self,
		acc_comm: AccountCommitmentTarget,
		act_root: ActRootTarget,
		condition: BoolTarget,
	) -> ActMerkleTarget;

	fn derive_nullifier_key(&mut self, priv_id: PrivateIdentifierTarget) -> NullifierKeyTarget;

	fn assert_fresh_account(&mut self, acc: AccountTarget, condition: BoolTarget);

	fn assert_account_invariants(
		&mut self,
		accin: AccountTarget,
		accout: AccountTarget,
		is_fresh_acc: BoolTarget,
		is_update_auth: BoolTarget,
		is_priv_tx: Target,
	);

	fn assert_asset_amt_or_default_in_ast(
		&mut self,
		asset_id: AssetIdTarget,
		amt: U256Target,
		acc_ast_root: HashOutTarget,
		selector: BoolTarget,
	) -> AstMerkleTargets;

	fn assert_ast_update(
		&mut self,
		asset_id: AssetIdTarget,
		accin_amt: U256Target,
		accout_amt: U256Target,
		accin: AccountTarget,
		accout: AccountTarget,
		asset_exists_in_accin: BoolTarget,
		asset_exists_in_accout: BoolTarget,
	) -> (AstMerkleTargets, AstMerkleTargets);

	// ---- Note related methods ----

	fn derive_note_commitment(&mut self, note: NoteTarget) -> NoteCommitmentTarget;

	fn derive_note_nullifier(
		&mut self,
		nc: NoteCommitmentTarget,
		pos: Target,
		nk: NullifierKeyTarget,
	) -> NoteNullifierTarget;

	fn derive_dummy_note_nullifier(&mut self, dnote: DummyNoteTarget) -> NoteNullifierTarget;

	fn derive_dummy_note_commitment(&mut self, dnote: DummyNoteTarget) -> NoteCommitmentTarget;

	fn assert_inotes_valid(
		&mut self,
		inotes: [NoteTarget; NOTE_BATCH],
		inote_isactive: [BoolTarget; NOTE_BATCH],
		inotes_comm: [NoteCommitmentTarget; NOTE_BATCH],
		public_identifier: PublicIdentifierTaregt,
		subpool_id: SubpoolIdTarget,
		nct_root: NctRootTarget,
	) -> [ConditionalMerkleTarget<NCT_DEPTH>; NOTE_BATCH];

	// ---- Other priv tx methods ----

	fn assert_subpool_full_proof(
		&mut self,
		subpool_id: SubpoolIdTarget,
		approval_key: PubkeyTarget,
		rejection_key: PubkeyTarget,
		consume_key: PubkeyTarget,
	) -> SubpoolFullProofTargets;

	fn derive_tx_hash(
		&mut self,
		inotes_isactive: [BoolTarget; NOTE_BATCH],
		inotes_null: [NoteNullifierTarget; NOTE_BATCH],
		dinotes_null: [NoteNullifierTarget; NOTE_BATCH],
		onotes_isactive: [BoolTarget; NOTE_BATCH],
		onotes_comm: [NoteCommitmentTarget; NOTE_BATCH],
		donotes_comm: [NoteCommitmentTarget; NOTE_BATCH],
		accin_null: AccountNullifierTarget,
		accout_comm: AccountCommitmentTarget,
	) -> TxHashTarget;

	fn assert_balance_invariant(
		&mut self,
		accin_amt: U256Target,
		accout_amt: U256Target,
		inotes: [NoteTarget; NOTE_BATCH],
		onotes: [NoteTarget; NOTE_BATCH],
		inotes_isactive: [BoolTarget; NOTE_BATCH],
		onotes_isactive: [BoolTarget; NOTE_BATCH],
	);

	fn assert_tx_signatures(
		&mut self,
		tx_hash: TxHashTarget,
		inotes_isactive: [BoolTarget; NOTE_BATCH],
		onotes_isactive: [BoolTarget; NOTE_BATCH],
		accin: AccountTarget,
		subpool_consume_key: PubkeyTarget,
		approval_key: PubkeyTarget,
	) -> TxSignatureTargets;
}

fn double_hash<F: RichField + Extendable<D>, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	input: [Target; HASH_SIZE],
) -> HashOutTarget {
	let input = input.to_vec();
	let out0 = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input);
	let out1 = builder.hash_n_to_hash_no_pad::<PoseidonHash>(out0.elements.to_vec());
	out1
}

impl<F: RichField + Extendable<D>, const D: usize> LocalCB for CircuitBuilder<F, D> {
	fn add_virtual_dummy_note_target(&mut self) -> DummyNoteTarget {
		DummyNoteTarget(self.add_virtual_target_arr())
	}

	fn add_virtual_account_target(&mut self) -> AccountTarget {
		AccountTarget {
			private_identifier: PrivateIdentifierTarget(self.add_virtual_target_arr()),
			nonce: self.add_virtual_target(),
			subpool_id: SubpoolIdTarget(self.add_virtual_public_input()),
			acc_ast_root: self.add_virtual_hash(),
			spend_auth: PubkeyTarget(LocalQuinticExtension(self.add_virtual_target_arr())),
			consume_auth: ConsumeAuthTarget {
				config: self.add_virtual_bool_target_safe(),
				pk: PubkeyTarget(LocalQuinticExtension(self.add_virtual_target_arr())),
			},
		}
	}

	fn add_virtual_consume_cond_target(&mut self) -> ConsumeCondTarget {
		ConsumeCondTarget {
			subpool_id: SubpoolIdTarget(self.add_virtual_target()),
			public_identifier: PublicIdentifierTaregt(self.add_virtual_hash()),
		}
	}

	fn add_virtual_reject_cond_target(&mut self) -> RejectCondTarget {
		RejectCondTarget {
			subpool_id: SubpoolIdTarget(self.add_virtual_target()),
			public_identifier: PublicIdentifierTaregt(self.add_virtual_hash()),
		}
	}

	fn add_virtual_note_target(&mut self) -> NoteTarget {
		let identifier = self.add_virtual_target_arr();
		let amount = self.add_virtual_u256_target();
		let asset_id = AssetIdTarget(self.add_virtual_target());
		let spend_cond = self.add_virtual_consume_cond_target();
		let reject_cond = self.add_virtual_reject_cond_target();
		NoteTarget {
			identifier,
			amount,
			asset_id,
			spend_cond,
			reject_cond,
		}
	}

	fn derive_account_commitment(&mut self, acc: AccountTarget) -> AccountCommitmentTarget {
		// flat hash: public_identifier[2] || subpool_id[1] || acc_ast_root[4] || nonce[1]
		//          || spend_auth[5] || consume_auth.config[1] || consume_auth.pk[5]
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

	fn conditionally_assert_account_commitment_exists_in_act(
		&mut self,
		acc_comm: AccountCommitmentTarget,
		act_root: ActRootTarget,
		condition: BoolTarget,
	) -> ActMerkleTarget {
		let merkletargets = conditional_merkle_verify_gadget::<F, D, ACT_DEPTH>(
			self, acc_comm.0, act_root.0, condition,
		);
		ActMerkleTarget(merkletargets)
	}

	fn derive_account_nullifier(
		&mut self,
		acc: AccountCommitmentTarget,
		pos: Target,
		nk: NullifierKeyTarget,
	) -> AccountNullifierTarget {
		let mut input = Vec::with_capacity(9);
		input.extend_from_slice(&acc.0.elements);
		input.extend_from_slice(&nk.0.elements);
		input.push(pos);
		AccountNullifierTarget(self.hash_n_to_hash_no_pad::<PoseidonHash>(input))
	}

	fn derive_fresh_account_nullifier(
		&mut self,
		acc: AccountCommitmentTarget,
		nk: NullifierKeyTarget,
	) -> AccountNullifierTarget {
		let mut input = Vec::with_capacity(8);
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

	fn derive_note_commitment(&mut self, note: NoteTarget) -> NoteCommitmentTarget {
		// Matches StandardNote::commitment(): 21-element flat hash
		// identifier[2] || amount[8]  || asset_id || spend_cond.subpool_id[1] ||
		// spend_cond.pub_id[4]              || reject_cond.subpool_id[1] || reject_cond.pub_id[4]
		let mut input: Vec<Target> = Vec::with_capacity(20);
		input.extend_from_slice(&note.identifier);
		input.extend(note.amount.0.map(|u| u.0));
		input.push(note.asset_id.0);
		input.push(note.spend_cond.subpool_id.0);
		input.extend_from_slice(&note.spend_cond.public_identifier.0.elements);
		input.push(note.reject_cond.subpool_id.0);
		input.extend_from_slice(&note.reject_cond.public_identifier.0.elements);
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

	fn derive_dummy_note_nullifier(&mut self, dnote: DummyNoteTarget) -> NoteNullifierTarget {
		NoteNullifierTarget(double_hash(self, dnote.0))
	}

	fn derive_dummy_note_commitment(&mut self, dnote: DummyNoteTarget) -> NoteCommitmentTarget {
		NoteCommitmentTarget(double_hash(self, dnote.0))
	}

	fn derive_tx_hash(
		&mut self,
		inotes_isactive: [BoolTarget; NOTE_BATCH],
		inotes_null: [NoteNullifierTarget; NOTE_BATCH],
		dinotes_null: [NoteNullifierTarget; NOTE_BATCH],
		onotes_isactive: [BoolTarget; NOTE_BATCH],
		onotes_comm: [NoteCommitmentTarget; NOTE_BATCH],
		donotes_comm: [NoteCommitmentTarget; NOTE_BATCH],
		accin_null: AccountNullifierTarget,
		accout_comm: AccountCommitmentTarget,
	) -> TxHashTarget {
		// select valid inote nullifiers, onote commitments as per respective isactive selector
		let act_inotenulls: [NoteNullifierTarget; NOTE_BATCH] = core::array::from_fn(|i| {
			NoteNullifierTarget(HashOutTarget {
				elements: core::array::from_fn(|j| {
					self._if(
						inotes_isactive[i],
						inotes_null[i].0.elements[j],
						dinotes_null[i].0.elements[j],
					)
				}),
			})
		});
		let act_onotecomms: [NoteCommitmentTarget; NOTE_BATCH] = core::array::from_fn(|i| {
			NoteCommitmentTarget(HashOutTarget {
				elements: core::array::from_fn(|j| {
					self._if(
						onotes_isactive[i],
						onotes_comm[i].0.elements[j],
						donotes_comm[i].0.elements[j],
					)
				}),
			})
		});

		let mut input = Vec::with_capacity(4 + 4 + 4 * NOTE_BATCH + 4 * NOTE_BATCH);
		input.extend_from_slice(&accin_null.0.elements);
		input.extend_from_slice(&accout_comm.0.elements);
		for null in &act_inotenulls {
			input.extend_from_slice(&null.0.elements);
		}
		for comm in &act_onotecomms {
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
	) -> AstMerkleTargets {
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
		// TODO: change from conditional to normal
		let merkletargets = conditional_merkle_verify_gadget::<F, D, ACC_AST_DEPTH>(
			self,
			HashOutTarget {
				elements: exists_or_default,
			},
			acc_ast_root,
			tr,
		);

		// if selector == 0 then amt must be 0
		let not_sel = self.not(selector);
		let zero = self.zero();
		for i in 0..amt.0.len() {
			self.conditional_assert_eq(not_sel.target, amt.0[i].0, zero);
		}

		AstMerkleTargets(merkletargets)
	}

	fn assert_subpool_full_proof(
		&mut self,
		subpool_id: SubpoolIdTarget,
		approval_key: PubkeyTarget,
		rejection_key: PubkeyTarget,
		consume_key: PubkeyTarget,
	) -> SubpoolFullProofTargets {
		// Subpool config root — shared across the 3 key proofs
		let subpool_config_root = self.add_virtual_hash();

		// Helper: verify one depth-2 key proof and connect leaf + root
		let mut verify_key_proof = |key: PubkeyTarget| -> MerkleTarget<SUBPOOL_CONFIG_DEPTH> {
			let leaf_hash = self.hash_n_to_hash_no_pad::<PoseidonHash>(key.0.0.to_vec());
			let mt = merkle_verify_gadget::<F, D, SUBPOOL_CONFIG_DEPTH>(self, leaf_hash);

			// connect subpool config roots for all keys
			self.connect_array(subpool_config_root.elements, mt.root);

			mt
		};

		let approval_proof = verify_key_proof(approval_key);
		let rejection_proof = verify_key_proof(rejection_key);
		let consume_proof = verify_key_proof(consume_key);

		// Main pool proof: leaf = H(subpool_config_root[4] || subpool_id)
		let main_pool_leaf_hash = {
			let mut inputs = subpool_config_root.elements.to_vec();
			inputs.push(subpool_id.0);
			self.hash_n_to_hash_no_pad::<PoseidonHash>(inputs)
		};
		let main_pool_proof =
			merkle_verify_gadget::<F, D, MAIN_POOL_CONFIG_DEPTH>(self, main_pool_leaf_hash);
		// self.connect_array(main_pool_root.0.elements, main_pool_mt.root);

		SubpoolFullProofTargets {
			approval_proof,
			rejection_proof,
			consume_proof,
			main_pool_proof,
		}
	}

	fn assert_ast_update(
		&mut self,
		asset_id: AssetIdTarget,
		accin_amt: U256Target,
		accout_amt: U256Target,
		accin: AccountTarget,
		accout: AccountTarget,
		asset_exists_in_accin: BoolTarget,
		asset_exists_in_accout: BoolTarget,
	) -> (AstMerkleTargets, AstMerkleTargets) {
		let accin_merkletrgts = self.assert_asset_amt_or_default_in_ast(
			asset_id,
			accin_amt,
			accin.acc_ast_root,
			asset_exists_in_accin,
		);
		let accout_merkletrgts = self.assert_asset_amt_or_default_in_ast(
			asset_id,
			accout_amt,
			accout.acc_ast_root,
			asset_exists_in_accout,
		);

		// Siblings and path bits must match: the same leaf position is updated in both trees
		for i in 0..ACC_AST_DEPTH {
			self.connect_array(
				accin_merkletrgts.0.siblings[i],
				accout_merkletrgts.0.siblings[i],
			);
			self.connect(accin_merkletrgts.0.bits[i], accout_merkletrgts.0.bits[i]);
		}

		(accin_merkletrgts, accout_merkletrgts)
	}

	fn assert_inotes_valid(
		&mut self,
		inotes: [NoteTarget; NOTE_BATCH],
		inote_isactive: [BoolTarget; NOTE_BATCH],
		inotes_comm: [NoteCommitmentTarget; NOTE_BATCH],
		public_identifier: PublicIdentifierTaregt,
		subpool_id: SubpoolIdTarget,
		nct_root: NctRootTarget,
	) -> [ConditionalMerkleTarget<NCT_DEPTH>; NOTE_BATCH] {
		let merkle_proofs: [ConditionalMerkleTarget<NCT_DEPTH>; NOTE_BATCH] =
			core::array::from_fn(|i| {
				conditional_merkle_verify_gadget(
					self,
					inotes_comm[i].0,
					nct_root.0,
					inote_isactive[i],
				)
			});

		// each note must be spendable by the account
		for note in inotes.iter() {
			self.connect_array(
				note.spend_cond.public_identifier.0.elements,
				public_identifier.0.elements,
			);
			self.connect(note.spend_cond.subpool_id.0, subpool_id.0);
		}

		merkle_proofs
	}

	fn assert_account_invariants(
		&mut self,
		accin: AccountTarget,
		accout: AccountTarget,
		is_fresh_acc: BoolTarget,
		is_update_auth: BoolTarget,
		is_priv_tx: Target,
	) {
		// AccIn, AccOut must have private_identifier, subpool_id
		self.connect_array(accin.private_identifier.0, accout.private_identifier.0);
		self.connect(accin.subpool_id.0, accout.subpool_id.0);

		// Nonce is always incremented by 1 for every tx kind
		let one = self.one();
		let expected_nonce = self.add(accin.nonce, one);
		self.connect(accout.nonce, expected_nonce);

		// acc_ast_root is immutable for FreshAccTx and UpdateAuthTx; PrivTx may update it
		for i in 0..HASH_SIZE {
			self.conditional_assert_eq(
				is_fresh_acc.target,
				accout.acc_ast_root.elements[i],
				accin.acc_ast_root.elements[i],
			);
			self.conditional_assert_eq(
				is_update_auth.target,
				accout.acc_ast_root.elements[i],
				accin.acc_ast_root.elements[i],
			);
		}

		// spend_auth and consume_auth are immutable for PrivTx only
		for i in 0..5 {
			self.conditional_assert_eq(
				is_priv_tx,
				accout.spend_auth.0.0[i],
				accin.spend_auth.0.0[i],
			);
			self.conditional_assert_eq(
				is_priv_tx,
				accout.consume_auth.pk.0.0[i],
				accin.consume_auth.pk.0.0[i],
			);
		}
		self.conditional_assert_eq(
			is_priv_tx,
			accout.consume_auth.config.target,
			accin.consume_auth.config.target,
		);
	}

	fn assert_balance_invariant(
		&mut self,
		accin_amt: U256Target,
		accout_amt: U256Target,
		inotes: [NoteTarget; NOTE_BATCH],
		onotes: [NoteTarget; NOTE_BATCH],
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
		for i in 0..HASH_SIZE {
			self.conditional_assert_eq(
				condition.target,
				acc.acc_ast_root.elements[i],
				default_ast_root[i],
			);
		}

		self.conditional_assert_eq(condition.target, acc.nonce, zero);

		let default_spend: [Target; 5] =
			DEFAULT_SPEND_AUTH_PK.map(|v| self.constant(F::from_canonical_u64(v)));
		for i in 0..5 {
			self.conditional_assert_eq(condition.target, acc.spend_auth.0.0[i], default_spend[i]);
		}

		self.conditional_assert_eq(condition.target, acc.consume_auth.config.target, zero);

		let default_consume: [Target; 5] = DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER
			.map(|v| self.constant(F::from_canonical_u64(v)));
		for i in 0..5 {
			self.conditional_assert_eq(
				condition.target,
				acc.consume_auth.pk.0.0[i],
				default_consume[i],
			);
		}
	}

	fn assert_tx_signatures(
		&mut self,
		tx_hash: TxHashTarget,
		inotes_isactive: [BoolTarget; NOTE_BATCH],
		onotes_isactive: [BoolTarget; NOTE_BATCH],
		accin: AccountTarget,
		subpool_consume_key: PubkeyTarget,
		approval_key: PubkeyTarget,
	) -> TxSignatureTargets {
		// spend sig: required when any onote is active
		let mut is_spend_req = onotes_isactive[0];
		for sel in onotes_isactive.iter().skip(1) {
			is_spend_req = self.or(*sel, is_spend_req);
		}

		let spend =
			conditional_schnorr_verify_gadget(self, tx_hash.0, accin.spend_auth, is_spend_req);

		// consume sig: required when any inote is active AND no onote is active
		let mut has_inotes = inotes_isactive[0];
		for sel in inotes_isactive.iter().skip(1) {
			has_inotes = self.or(*sel, has_inotes);
		}
		let not_is_spend_req = self.not(is_spend_req);
		let is_consume_req = self.and(has_inotes, not_is_spend_req);
		let consume_key = PubkeyTarget(LocalQuinticExtension(core::array::from_fn(|i| {
			self._if(
				accin.consume_auth.config,
				accin.consume_auth.pk.0.0[i],
				subpool_consume_key.0.0[i],
			)
		})));
		let consume =
			conditional_schnorr_verify_gadget(self, tx_hash.0, consume_key, is_consume_req);

		// approval sig: always required
		let tr = self._true();
		let approval = conditional_schnorr_verify_gadget(self, tx_hash.0, approval_key, tr);

		TxSignatureTargets {
			spend,
			consume,
			approval,
		}
	}
}
