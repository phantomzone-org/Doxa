use std::{
	array,
	hash::{BuildHasherDefault, Hash},
	sync::Arc,
};

use itertools::{Itertools, izip};
use plonky2::{
	hash::{
		hash_types::{HashOutTarget, NUM_HASH_OUT_ELTS, RichField},
		hashing::PlonkyPermutation,
		poseidon::{Poseidon, PoseidonHash, PoseidonPermutation},
	},
	iop::{
		target::{BoolTarget, Target},
		witness::{PartialWitness, PartitionWitness, Witness, WitnessWrite},
	},
	plonk::{
		circuit_builder::CircuitBuilder, circuit_data::CommonCircuitData, config::AlgebraicHasher,
	},
	util::serialization::{Buffer, IoResult, Read as _, Write as _},
};
use plonky2_field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field};
use rand::seq::index::IndexVecIntoIter;
use tessera_trees::{
	F,
	plonky2_gadgets::u32::gadgets::{
		CircuitBuilderU32, CircuitBuilderU32Arithmetic, U32Target, add_u8_range_check_lookup_table,
	},
	tree::{HASH_SIZE, hasher::HashOutput},
};

use crate::{
	ACC_AST_DEPTH, ACT_DEPTH, AST_DEFAULT_LEAF, AST_DEFAULT_ROOT, DEFAULT_CONSUME_INVALID_PK,
	DEFAULT_SPEND_AUTH_INVALID_PK, DS_ACC_AST, DS_NULLIFIER_KEY, DS_PUBLIC_IDENTIFIER,
	MAIN_POOL_CONFIG_DEPTH, NCT_DEPTH, NOTE_BATCH, SUBPOOL_CONFIG_DEPTH,
	account::{NullifierKey, StandardAccount},
	p2::{
		signature::{
			LocalPointEw, LocalQuinticExtension, PubkeyTarget, SchnorrTargets,
			conditional_schnorr_verify_gadget, set_gfp5_target, set_schnorr_witness,
		},
		u256::{CircuitBuilderU256, U256Target},
	},
	pool_config::{MainPoolConfigNode, MainPoolConfigTree, SubpoolConfigNode, SubpoolConfigTree},
	schnorr::{PrivateKey, PublicKey, Scalar, poseidon_hash_to_scalar, schnorr_sign},
	tree::{Direction, MerkleProof, Node},
};

#[derive(Clone, Copy)]
pub(crate) struct SubpoolIdTarget(pub(crate) Target);

#[derive(Clone, Copy)]
pub(crate) struct PublicIdentifierTaregt(pub(crate) HashOutTarget);

#[derive(Clone, Copy)]
pub(crate) struct ConsumeCondTarget {
	pub(crate) subpool_id: SubpoolIdTarget,
	pub(crate) public_identifier: PublicIdentifierTaregt,
}

#[derive(Clone, Copy)]
pub(crate) struct RejectCondTarget {
	pub(crate) subpool_id: SubpoolIdTarget,
	pub(crate) public_identifier: PublicIdentifierTaregt,
}

#[derive(Clone, Copy)]
pub(crate) struct ConsumeAuthTarget {
	// if 0 then subpool owner can consume, otherwise the public key
	pub(crate) config: BoolTarget,
	pub(crate) pk: PubkeyTarget<Target>,
}

#[derive(Clone, Copy)]
pub(crate) struct AccountTarget {
	pub(crate) private_identifier: PrivateIdentifierTarget,
	pub(crate) nonce: Target,
	pub(crate) subpool_id: SubpoolIdTarget,
	pub(crate) acc_ast_root: HashOutTarget,
	pub(crate) spend_auth: PubkeyTarget<Target>,
	pub(crate) consume_auth: ConsumeAuthTarget,
}

impl AccountTarget {
	pub(crate) fn set_witness(
		&self,
		pw: &mut PartialWitness<GoldilocksField>,
		acc: &StandardAccount,
	) {
		pw.set_target(self.private_identifier.0[0], acc.private_identifier.0[0])
			.unwrap();
		pw.set_target(self.private_identifier.0[1], acc.private_identifier.0[1])
			.unwrap();
		pw.set_target(self.nonce, acc.nonce.0).unwrap();
		pw.set_target(self.subpool_id.0, acc.subpool_id.0).unwrap();
		for (i, &x) in acc.ast.root().0.iter().enumerate() {
			pw.set_target(self.acc_ast_root.elements[i], x).unwrap();
		}
		let spend_cpk: [GoldilocksField; 5] = acc.spend_auth.spend_pk.map_or_else(
			|| DEFAULT_SPEND_AUTH_INVALID_PK.map(GoldilocksField::from_canonical_u64),
			|pk| pk.0.w.0,
		);
		for (t, v) in self.spend_auth.0.0.iter().zip(spend_cpk.iter()) {
			pw.set_target(*t, *v).unwrap();
		}
		pw.set_bool_target(self.consume_auth.config, acc.consume_auth.config)
			.unwrap();
		let consume_cpk: [GoldilocksField; 5] = acc.consume_auth.pk.map_or_else(
			|| DEFAULT_CONSUME_INVALID_PK.map(GoldilocksField::from_canonical_u64),
			|pk| pk.0.w.0,
		);
		for (t, v) in self.consume_auth.pk.0.0.iter().zip(consume_cpk.iter()) {
			pw.set_target(*t, *v).unwrap();
		}
	}
}

struct AccCommitmentTarget(HashOutTarget);

struct NoteNullifierTarget(HashOutTarget);

#[derive(Clone, Copy)]
struct BalanceTarget([Target; 8]);

#[derive(Clone, Copy)]
pub(crate) struct NoteTarget {
	pub(crate) identifier: [Target; 2],
	pub(crate) amount: U256Target,
	pub(crate) asset_id: AssetIdTarget,
	pub(crate) spend_cond: ConsumeCondTarget,
	pub(crate) reject_cond: RejectCondTarget,
}

impl NoteTarget {
	pub(crate) fn set_witness(&self, pw: &mut PartialWitness<F>, note: &crate::note::StandardNote) {
		pw.set_target(self.identifier[0], note.identifier.0[0])
			.unwrap();
		pw.set_target(self.identifier[1], note.identifier.0[1])
			.unwrap();
		// amount: U256.0 is [u64; 4] little-endian words, split into lo/hi u32 limbs
		for (i, word) in note.amt.0.iter().enumerate() {
			pw.set_target(self.amount.0[2 * i].0, F::from_canonical_u32(*word as u32))
				.unwrap();
			pw.set_target(
				self.amount.0[2 * i + 1].0,
				F::from_canonical_u32((*word >> 32) as u32),
			)
			.unwrap();
		}
		pw.set_target(self.asset_id.0, note.asset_id.0).unwrap();
		pw.set_target(self.spend_cond.subpool_id.0, note.recipient.subpool_id.0)
			.unwrap();
		for (j, &x) in note.recipient.public_id.0.0.iter().enumerate() {
			pw.set_target(self.spend_cond.public_identifier.0.elements[j], x)
				.unwrap();
		}
		pw.set_target(self.reject_cond.subpool_id.0, note.sender.subpool_id.0)
			.unwrap();
		for (j, &x) in note.sender.public_id.0.0.iter().enumerate() {
			pw.set_target(self.reject_cond.public_identifier.0.elements[j], x)
				.unwrap();
		}
	}
}

#[derive(Clone, Copy)]
pub(crate) struct DummyNoteTarget(pub(crate) [Target; 4]);

struct PositionedNoteTargetWithProof {
	note: NoteTarget,
	position: Target,
}

#[derive(Clone, Copy)]
pub(crate) struct NoteCommitmentTarget(pub(crate) HashOutTarget);

#[derive(Clone, Copy)]
struct TxHashTarget(HashOutTarget);

pub(crate) struct TxSignatureTargets {
	pub(crate) spend: SchnorrTargets,
	pub(crate) spend_dummy_pk: PubkeyTarget<Target>,
	pub(crate) consume: SchnorrTargets,
	pub(crate) approval: SchnorrTargets,
}

#[derive(Clone, Copy)]
struct AccountNullifierTarget(HashOutTarget);
#[derive(Clone, Copy)]
struct AccountCommitmentTarget(HashOutTarget);

#[derive(Clone, Copy)]
struct NullifierKeyTarget(HashOutTarget);
#[derive(Clone, Copy)]
pub(crate) struct PrivateIdentifierTarget(pub(crate) [Target; 2]);

#[derive(Clone, Copy)]
pub(crate) struct ActMerkleTarget(pub(crate) MerkleTargets<ACT_DEPTH>);

#[derive(Clone, Copy)]
pub(crate) struct ActRootTarget(pub(crate) HashOutTarget);

#[derive(Clone, Copy)]
pub(crate) struct NctRootTarget(pub(crate) HashOutTarget);

#[derive(Clone, Copy)]
struct DummyAccountTarget([Target; 4]);

#[derive(Clone, Copy)]
struct DummyAccountCommitment(HashOutTarget);
#[derive(Clone, Copy)]
struct DummyAccountNullifier(HashOutTarget);

#[derive(Clone, Copy)]
struct SubpoolConfigRootTarget(HashOutTarget);

#[derive(Clone, Copy)]
pub(crate) struct MainPoolConfigRootTarget(pub(crate) HashOutTarget);

pub(crate) struct SubpoolFullProofTargets {
	pub(crate) approval_proof: MerkleTargets<SUBPOOL_CONFIG_DEPTH>,
	pub(crate) rejection_proof: MerkleTargets<SUBPOOL_CONFIG_DEPTH>,
	pub(crate) consume_proof: MerkleTargets<SUBPOOL_CONFIG_DEPTH>,
	pub(crate) main_pool_proof: MerkleTargets<MAIN_POOL_CONFIG_DEPTH>,
}

pub trait LocalCB {
	fn add_virtual_dummy_note_target(&mut self) -> DummyNoteTarget;
	fn add_virtual_account_target(&mut self) -> AccountTarget;
	fn add_virtual_consume_cond_target(&mut self) -> ConsumeCondTarget;
	fn add_virtual_reject_cond_target(&mut self) -> RejectCondTarget;
	fn add_virtual_note_target(&mut self) -> NoteTarget;

	fn derive_account_commitment(
		&mut self,
		acc: AccountTarget,
		priv_id: PrivateIdentifierTarget,
		subpool_id: SubpoolIdTarget,
	) -> AccountCommitmentTarget;
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

	fn derive_note_commitment(&mut self, note: NoteTarget) -> NoteCommitmentTarget;
	fn derive_note_nullifier(
		&mut self,
		nc: NoteCommitmentTarget,
		pos: Target,
		nk: NullifierKeyTarget,
	) -> NoteNullifierTarget;
	fn derive_dummy_note_nullifier(&mut self, dnote: DummyNoteTarget) -> NoteNullifierTarget;
	fn derive_dummy_note_commitment(&mut self, dnote: DummyNoteTarget) -> NoteCommitmentTarget;

	fn derive_nullifier_key(&mut self, priv_id: PrivateIdentifierTarget) -> NullifierKeyTarget;

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

	fn assert_asset_amt_or_default_in_ast(
		&mut self,
		asset_id: AssetIdTarget,
		amt: U256Target,
		acc_ast_root: HashOutTarget,
		selector: BoolTarget,
	) -> AstMerkleTargets;

	fn assert_subpool_full_proof(
		&mut self,
		main_pool_root: MainPoolConfigRootTarget,
		subpool_id: SubpoolIdTarget,
		approval_key: PubkeyTarget<Target>,
		rejection_key: PubkeyTarget<Target>,
		consume_key: PubkeyTarget<Target>,
	) -> SubpoolFullProofTargets;

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

	fn assert_inotes_valid(
		&mut self,
		inotes: [NoteTarget; NOTE_BATCH],
		inote_isactive: [BoolTarget; NOTE_BATCH],
		inotes_comm: [NoteCommitmentTarget; NOTE_BATCH],
		public_identifier: PublicIdentifierTaregt,
		subpool_id: SubpoolIdTarget,
		nct_root: NctRootTarget,
	) -> [MerkleTargets<NCT_DEPTH>; NOTE_BATCH];

	fn assert_fresh_account(&mut self, acc: AccountTarget, condition: BoolTarget);

	fn assert_account_invariants(
		&mut self,
		accin: AccountTarget,
		accout: AccountTarget,
		is_fresh_acc: BoolTarget,
		is_update_auth: BoolTarget,
		is_priv_tx: Target,
	);

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
		subpool_consume_key: PubkeyTarget<Target>,
		approval_key: PubkeyTarget<Target>,
	) -> TxSignatureTargets;

	// fn assert_asset_amt_in_ast(
	// 	&mut self,
	// 	asset_id: AssetIdTarget,
	// 	amt: U256Target,
	// 	acc: AccountTarget,
	// ) -> AstMerkleTargets;
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

	fn derive_account_commitment(
		&mut self,
		acc: AccountTarget,
		priv_id: PrivateIdentifierTarget,
		subpool_id: SubpoolIdTarget,
	) -> AccountCommitmentTarget {
		// flat hash: public_identifier[2] || subpool_id[1] || acc_ast_root[4] || nonce[1]
		//          || spend_auth[5] || consume_auth.config[1] || consume_auth.pk[5]
		let mut input = Vec::with_capacity(19);
		input.extend_from_slice(&priv_id.0);
		input.push(subpool_id.0);
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
		let merkletargets =
			merkle_verify_gadget::<F, D, ACT_DEPTH>(self, acc_comm.0, act_root.0, condition);

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
		// Matches StandardNote::commitment(): 20-element flat hash
		// identifier[2] || amount[8] || spend_cond.subpool_id[1] || spend_cond.pub_id[4]
		//              || reject_cond.subpool_id[1] || reject_cond.pub_id[4]
		let mut input: Vec<Target> = Vec::with_capacity(20);
		input.extend_from_slice(&note.identifier);
		input.extend(note.amount.0.map(|u| u.0));
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
		let act_inotenulls: [NoteNullifierTarget; NOTE_BATCH] = array::from_fn(|i| {
			NoteNullifierTarget(HashOutTarget {
				elements: array::from_fn(|j| {
					self._if(
						inotes_isactive[i],
						inotes_null[i].0.elements[j],
						dinotes_null[i].0.elements[j],
					)
				}),
			})
		});
		let act_onotecomms: [NoteCommitmentTarget; NOTE_BATCH] = array::from_fn(|i| {
			NoteCommitmentTarget(HashOutTarget {
				elements: array::from_fn(|j| {
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
			inputs[0] = self.constant(F::from_canonical_u64(DS_ACC_AST));
			inputs[1] = asset_id.0;
			inputs[2..].copy_from_slice(amt.0.map(|t| t.0).as_slice());
			self.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.to_vec())
		};
		let default_leaf: [Target; HASH_SIZE] =
			array::from_fn(|i| self.constant(F::from_canonical_u64(AST_DEFAULT_LEAF[i])));
		let exists_or_default: [Target; HASH_SIZE] =
			array::from_fn(|i| self._if(selector, leaf.elements[i], default_leaf[i]));
		let merkletargets = merkle_verify_gadget::<F, D, ACC_AST_DEPTH>(
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
		main_pool_root: MainPoolConfigRootTarget,
		subpool_id: SubpoolIdTarget,
		approval_key: PubkeyTarget<Target>,
		rejection_key: PubkeyTarget<Target>,
		consume_key: PubkeyTarget<Target>,
	) -> SubpoolFullProofTargets {
		let tr = self._true();

		// Subpool config root — shared across the 3 key proofs
		let subpool_config_root = self.add_virtual_hash();

		// Helper: verify one depth-2 key proof and connect leaf + root
		let mut verify_key_proof =
			|key: PubkeyTarget<Target>| -> MerkleTargets<SUBPOOL_CONFIG_DEPTH> {
				let leaf_hash = self.hash_n_to_hash_no_pad::<PoseidonHash>(key.0.0.to_vec());
				let mt = merkle_verify_gadget::<F, D, SUBPOOL_CONFIG_DEPTH>(
					self,
					leaf_hash,
					subpool_config_root,
					tr,
				);
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
		let main_pool_mt = merkle_verify_gadget::<F, D, MAIN_POOL_CONFIG_DEPTH>(
			self,
			main_pool_leaf_hash,
			main_pool_root.0,
			tr,
		);

		SubpoolFullProofTargets {
			approval_proof,
			rejection_proof,
			consume_proof,
			main_pool_proof: main_pool_mt,
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
	) -> [MerkleTargets<NCT_DEPTH>; NOTE_BATCH] {
		let merkle_proofs: [MerkleTargets<NCT_DEPTH>; NOTE_BATCH] = array::from_fn(|i| {
			merkle_verify_gadget(self, inotes_comm[i].0, nct_root.0, inote_isactive[i])
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
		let inote_amts: [U256Target; NOTE_BATCH] = array::from_fn(|i| {
			U256Target(array::from_fn(|j| {
				U32Target(self._if(inotes_isactive[i], inotes[i].amount.0[j].0, zero))
			}))
		});
		let onote_amts: [U256Target; NOTE_BATCH] = array::from_fn(|i| {
			U256Target(array::from_fn(|j| {
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

		// Compute the actual default AST root at circuit-build time via Poseidon two_to_one.
		let default_ast_root: [Target; HASH_SIZE] = {
			use plonky2::{hash::hash_types::HashOut, plonk::config::Hasher};
			let mut cur: [F; HASH_SIZE] = AST_DEFAULT_LEAF.map(F::from_canonical_u64);
			for _ in 0..ACC_AST_DEPTH {
				let r = <PoseidonHash as Hasher<F>>::two_to_one(
					HashOut {
						elements: cur,
					},
					HashOut {
						elements: cur,
					},
				);
				cur = r.elements;
			}
			array::from_fn(|i| self.constant(cur[i]))
		};
		for i in 0..HASH_SIZE {
			self.conditional_assert_eq(
				condition.target,
				acc.acc_ast_root.elements[i],
				default_ast_root[i],
			);
		}

		self.conditional_assert_eq(condition.target, acc.nonce, zero);

		let default_spend: [Target; 5] =
			DEFAULT_SPEND_AUTH_INVALID_PK.map(|v| self.constant(F::from_canonical_u64(v)));
		for i in 0..5 {
			self.conditional_assert_eq(condition.target, acc.spend_auth.0.0[i], default_spend[i]);
		}

		self.conditional_assert_eq(condition.target, acc.consume_auth.config.target, zero);

		let default_consume: [Target; 5] =
			DEFAULT_CONSUME_INVALID_PK.map(|v| self.constant(F::from_canonical_u64(v)));
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
		subpool_consume_key: PubkeyTarget<Target>,
		approval_key: PubkeyTarget<Target>,
	) -> TxSignatureTargets {
		// spend sig: required when any onote is active
		let mut is_spend_req = onotes_isactive[0];
		for sel in onotes_isactive.iter().skip(1) {
			is_spend_req = self.or(*sel, is_spend_req);
		}
		let spend_dummy_pk = PubkeyTarget(LocalQuinticExtension(self.add_virtual_target_arr()));
		let effective_spend_pk = PubkeyTarget(LocalQuinticExtension(array::from_fn(|i| {
			self._if(is_spend_req, accin.spend_auth.0.0[i], spend_dummy_pk.0.0[i])
		})));
		let spend =
			conditional_schnorr_verify_gadget(self, tx_hash.0, effective_spend_pk, is_spend_req);

		// consume sig: required when any inote is active AND no onote is active
		let mut has_inotes = inotes_isactive[0];
		for sel in inotes_isactive.iter().skip(1) {
			has_inotes = self.or(*sel, has_inotes);
		}
		let not_is_spend_req = self.not(is_spend_req);
		let is_consume_req = self.and(has_inotes, not_is_spend_req);
		let consume_key = PubkeyTarget(LocalQuinticExtension(array::from_fn(|i| {
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
			spend_dummy_pk,
			consume,
			approval,
		}
	}
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AssetIdTarget(pub(crate) Target);
pub(crate) struct AstMerkleTargets(pub(crate) MerkleTargets<ACC_AST_DEPTH>);

pub(crate) struct TxCircuitTargets {
	// tx kind flags
	pub(crate) is_rjct: BoolTarget,
	pub(crate) is_fresh_acc: BoolTarget,
	pub(crate) is_update_auth: BoolTarget,
	pub(crate) is_priv_tx: Target,
	// tree roots
	pub(crate) act_root: ActRootTarget,
	pub(crate) nct_root: NctRootTarget,
	pub(crate) main_pool_root: MainPoolConfigRootTarget,
	// authority public keys
	pub(crate) approval_key: PubkeyTarget<Target>,
	pub(crate) rejection_key: PubkeyTarget<Target>,
	pub(crate) subpool_consume_key: PubkeyTarget<Target>,
	// accounts
	pub(crate) accin: AccountTarget,
	pub(crate) accout: AccountTarget,
	pub(crate) accin_amt: U256Target,
	pub(crate) accout_amt: U256Target,
	pub(crate) asset_id: AssetIdTarget,
	pub(crate) asset_exists_in_accin: BoolTarget,
	pub(crate) asset_exists_in_accout: BoolTarget,
	// accin position (needed for nullifier witness)
	pub(crate) accin_pos: Target,
	// merkle targets
	pub(crate) accin_act_merkle: ActMerkleTarget,
	pub(crate) accin_ast_merkle: AstMerkleTargets,
	pub(crate) accout_ast_merkle: AstMerkleTargets,
	pub(crate) inotes_nct_merkle: [MerkleTargets<NCT_DEPTH>; NOTE_BATCH], /* inotes NCT merkle
	                                                                       * proofs (one per
	                                                                       * inote) */
	// notes
	pub(crate) inotes: [NoteTarget; NOTE_BATCH],
	pub(crate) inotes_pos: [Target; NOTE_BATCH],
	pub(crate) inotes_isactive: [BoolTarget; NOTE_BATCH],
	pub(crate) inotes_comm: [NoteCommitmentTarget; NOTE_BATCH],
	pub(crate) onotes: [NoteTarget; NOTE_BATCH],
	pub(crate) onotes_isactive: [BoolTarget; NOTE_BATCH],
	pub(crate) dinotes: [DummyNoteTarget; NOTE_BATCH],
	pub(crate) donotes: [DummyNoteTarget; NOTE_BATCH],
	// subpool proof
	pub(crate) subpool_proof_targets: SubpoolFullProofTargets,
	// signature targets
	pub(crate) sig_targets: TxSignatureTargets,
}

pub fn tx_circuit<F: RichField + Extendable<D> + Poseidon, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
) -> TxCircuitTargets {
	// Mint constants
	let ds_nullifier_key = builder.constant(F::from_canonical_u64(DS_NULLIFIER_KEY));
	let ds_public_identifier = builder.constant(F::from_canonical_u64(DS_PUBLIC_IDENTIFIER));

	// Tx kinds
	let is_rjct = builder.add_virtual_bool_target_safe();
	let is_fresh_acc = builder.add_virtual_bool_target_safe();
	let is_update_auth = builder.add_virtual_bool_target_safe();
	let is_priv_tx = builder.add_virtual_public_input();

	let act_root = ActRootTarget(builder.add_virtual_hash());
	let nct_root = NctRootTarget(builder.add_virtual_hash());
	let main_pool_root = MainPoolConfigRootTarget(builder.add_virtual_hash());

	// Subpool authority keys
	let approval_key = PubkeyTarget(LocalQuinticExtension(builder.add_virtual_target_arr()));
	let rejection_key = PubkeyTarget(LocalQuinticExtension(builder.add_virtual_target_arr()));
	let subpool_consume_key = PubkeyTarget(LocalQuinticExtension(builder.add_virtual_target_arr()));

	let asset_id = AssetIdTarget(builder.add_virtual_target());
	let accin_amt = builder.add_virtual_u256_target();
	let asset_exists_in_accin = builder.add_virtual_bool_target_safe();
	let accout_amt = builder.add_virtual_u256_target();
	let asset_exists_in_accout = builder.add_virtual_bool_target_safe();

	let accin = builder.add_virtual_account_target();
	let accout = builder.add_virtual_account_target();
	let private_identifier = accin.private_identifier;
	let subpool_id = accin.subpool_id;
	let public_identifier = {
		let mut input = vec![ds_public_identifier];
		input.extend(private_identifier.0);
		let pubid = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input);
		PublicIdentifierTaregt(pubid)
	};
	let nk = builder.derive_nullifier_key(accin.private_identifier);

	let accin_comm = builder.derive_account_commitment(accin, private_identifier, subpool_id);
	let accout_comm = builder.derive_account_commitment(accout, private_identifier, subpool_id);

	// Assert AccIn matches FreshAccount defaults when is_fresh_acc
	builder.assert_fresh_account(accin, is_fresh_acc);

	// AccIn → AccOut transition invariants
	// private_identifier, subpool_id are immutable for all tx kinds — enforced by sharing the
	// same wires in `derive_account_commitment` for both accin and accout.
	builder.assert_account_invariants(accin, accout, is_fresh_acc, is_update_auth, is_priv_tx);

	let accin_pos = builder.add_virtual_target();
	let not_is_fresh_acc = builder.not(is_fresh_acc);
	let accin_merkletrgts = builder.conditionally_assert_account_commitment_exists_in_act(
		accin_comm,
		act_root,
		not_is_fresh_acc,
	);

	// AccIn nullifier — select fresh vs regular based on is_fresh_acc
	let accin_null_regular = builder.derive_account_nullifier(accin_comm, accin_pos, nk);
	let accin_null_fresh = builder.derive_fresh_account_nullifier(accin_comm, nk);
	let accin_null = AccountNullifierTarget(HashOutTarget {
		elements: array::from_fn(|i| {
			builder._if(
				is_fresh_acc,
				accin_null_fresh.0.elements[i],
				accin_null_regular.0.elements[i],
			)
		}),
	});

	// Verify asset/amt proofs in AccIn and AccOut ASTs; enforce same leaf position was updated
	let (accin_ast_merkle, accout_ast_merkle) = builder.assert_ast_update(
		asset_id,
		accin_amt,
		accout_amt,
		accin,
		accout,
		asset_exists_in_accin,
		asset_exists_in_accout,
	);

	// Input and Output notes //

	let inotes: [NoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_note_target());
	let inotes_pos: [Target; NOTE_BATCH] = core::array::from_fn(|_| builder.add_virtual_target());
	let inotes_isactive: [BoolTarget; NOTE_BATCH] =
		array::from_fn(|_| builder.add_virtual_bool_target_safe());
	let inotes_comm = array::from_fn(|i| builder.derive_note_commitment(inotes[i]));
	let inotes_null: [NoteNullifierTarget; NOTE_BATCH] =
		array::from_fn(|i| builder.derive_note_nullifier(inotes_comm[i], inotes_pos[i], nk));

	let onotes: [NoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_note_target());
	let onotes_isactive: [BoolTarget; NOTE_BATCH] =
		array::from_fn(|_| builder.add_virtual_bool_target_safe());
	let onotes_comm = onotes.map(|n| builder.derive_note_commitment(n));

	let dinotes: [DummyNoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_dummy_note_target());
	let dinotes_null: [NoteNullifierTarget; NOTE_BATCH] =
		array::from_fn(|i| builder.derive_dummy_note_nullifier(dinotes[i]));

	let donotes: [DummyNoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_dummy_note_target());
	let donotes_comm = donotes.map(|dn| builder.derive_dummy_note_commitment(dn));

	// All inotes and onotes share the same asset_id
	for note in inotes.iter().chain(onotes.iter()) {
		builder.connect(note.asset_id.0, asset_id.0);
	}

	// for each inote verify NCT membership, and check spend auth
	let inotes_mrkltrgt = builder.assert_inotes_valid(
		inotes,
		inotes_isactive,
		inotes_comm,
		public_identifier,
		subpool_id,
		nct_root,
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
	let tx_hash = builder.derive_tx_hash(
		inotes_isactive,
		inotes_null,
		dinotes_null,
		onotes_isactive,
		onotes_comm,
		donotes_comm,
		accin_null,
		accout_comm,
	);

	// Validate authorization //

	// Verify SubpoolFullProof: 3 authority key proofs (depth-2) + main pool proof (depth-20)
	let subpool_proof_targets = builder.assert_subpool_full_proof(
		main_pool_root,
		SubpoolIdTarget(accin.subpool_id.0),
		approval_key,
		rejection_key,
		subpool_consume_key,
	);

	let sig_targets = builder.assert_tx_signatures(
		tx_hash,
		inotes_isactive,
		onotes_isactive,
		accin,
		subpool_consume_key,
		approval_key,
	);

	TxCircuitTargets {
		is_rjct,
		is_fresh_acc,
		is_update_auth,
		is_priv_tx,
		act_root,
		nct_root,
		main_pool_root,
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
		accout_ast_merkle,
		inotes,
		inotes_pos,
		inotes_isactive,
		inotes_comm,
		onotes,
		onotes_isactive,
		dinotes,
		donotes,
		subpool_proof_targets,
		sig_targets,
		inotes_nct_merkle: inotes_mrkltrgt,
	}
}

pub(crate) fn set_merkle_siblings_and_bits<F: Field, const DEPTH: usize>(
	pw: &mut PartialWitness<F>,
	t: &MerkleTargets<DEPTH>,
	siblings: [[F; 4]; DEPTH],
	bits: [bool; DEPTH],
) {
	for lvl in 0..DEPTH {
		for i in 0..4 {
			pw.set_target(t.siblings[lvl][i], siblings[lvl][i]).unwrap();
		}
		pw.set_bool_target(BoolTarget::new_unsafe(t.bits[lvl]), bits[lvl])
			.unwrap();
	}
}

/// Extract siblings and direction bits from a native MerkleProof.
/// Direction::Left  (sibling on left, current is right child) → bit = true
/// Direction::Right (sibling on right, current is left child) → bit = false
pub(crate) fn proof_siblings_bits<F: Field, N: Node, const DEPTH: usize>(
	proof: &crate::tree::MerkleProof<N>,
) -> ([[F; 4]; DEPTH], [bool; DEPTH]) {
	let siblings: [[F; 4]; DEPTH] = core::array::from_fn(|i| {
		proof.path[i].sibling.inner().0.map(|f| {
			use plonky2_field::types::PrimeField64;
			F::from_canonical_u64(f.to_canonical_u64())
		})
	});
	let bits: [bool; DEPTH] =
		core::array::from_fn(|i| proof.path[i].direction == crate::tree::Direction::Left);
	(siblings, bits)
}

#[derive(Clone, Copy)]
pub struct MerkleTargets<const DEPTH: usize> {
	pub siblings: [[Target; HASH_SIZE]; DEPTH],
	pub bits: [Target; DEPTH],
}

/// Builds a depth-32 Merkle path verification gadget using the existing
/// PoseidonGate.
///
/// Each of the 32 levels adds one `PoseidonGate` via
/// `PoseidonHash::permute_swapped`. The gate's built-in SWAP wire handles
/// left/right child ordering: when `bit=0` the node is the left child, when
/// `bit=1` the node is the right child.
///
/// After all 32 levels, if `selector=1` the computed root is constrained to
/// equal `expected_root`; if `selector=0` no equality is enforced.
pub fn merkle_verify_gadget<
	F: RichField + Extendable<D> + Poseidon,
	const D: usize,
	const DEPTH: usize,
>(
	builder: &mut CircuitBuilder<F, D>,
	leaf: HashOutTarget,
	expected_root: HashOutTarget,
	selector: BoolTarget,
) -> MerkleTargets<DEPTH> {
	let mut current: [Target; HASH_SIZE] = leaf.elements;
	let mut siblings: [[Target; HASH_SIZE]; DEPTH] = [[builder.zero(); 4]; DEPTH];
	let mut bits: [Target; DEPTH] = [builder.zero(); DEPTH];

	for level in 0..DEPTH {
		let sibling: [Target; 4] = core::array::from_fn(|_| builder.add_virtual_target());
		let bit = builder.add_virtual_bool_target_safe();

		// Build the 12-element Poseidon input:
		//   [current[0..4] || sibling[0..4] || zero[0..4]]
		// PoseidonGate SWAP will swap the first 4 with the next 4 when bit=1,
		// so the permutation always receives [left || right || zeros].
		let zero = builder.zero();
		let perm_inputs = PoseidonPermutation::new(
			current
				.iter()
				.chain(sibling.iter())
				.copied()
				.chain(core::iter::repeat(zero).take(4)),
		);

		let perm_output = PoseidonHash::permute_swapped(perm_inputs, bit, builder);
		let output = perm_output.squeeze();

		let parent: [Target; HASH_SIZE] = core::array::from_fn(|i| output[i]);

		siblings[level] = sibling;
		bits[level] = bit.target;
		current = parent;
	}

	let computed_root = current;

	// Selector-gated root equality: selector * (computed_root[i] -
	// expected_root[i]) = 0
	for i in 0..HASH_SIZE {
		let diff = builder.sub(computed_root[i], expected_root.elements[i]);
		let product = builder.mul(selector.target, diff);
		builder.assert_zero(product);
	}

	MerkleTargets {
		siblings,
		bits,
	}
}

#[cfg(test)]
mod tests {
	use plonky2::{
		hash::{hash_types::HashOut, poseidon::PoseidonHash},
		iop::witness::{PartialWitness, WitnessWrite},
		plonk::{
			circuit_data::CircuitConfig,
			config::{GenericConfig, PoseidonGoldilocksConfig},
		},
	};
	use plonky2_field::{goldilocks_field::GoldilocksField, types::Field};

	use super::*;

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = <C as GenericConfig<D>>::F;

	/// Build a depth-32 Merkle tree from a leaf and return the root along with
	/// the sibling and bit arrays for the path at index 0 (all bits = 0 means
	/// the target leaf is always the left child at every level).
	fn build_merkle_path(leaf: HashOut<F>) -> (HashOut<F>, [HashOut<F>; 32], [bool; 32]) {
		// All siblings are a fixed non-zero hash so the tree is non-trivial.
		let sibling_val = HashOut {
			elements: [
				GoldilocksField::from_canonical_u64(0xdeadbeef),
				GoldilocksField::from_canonical_u64(0xcafebabe),
				GoldilocksField::from_canonical_u64(0x12345678),
				GoldilocksField::from_canonical_u64(0xabcdef01),
			],
		};

		// Index 0 → all bits = 0 (leaf is always the left child).
		let bits = [false; 32];
		let siblings = [sibling_val; 32];

		let mut current = leaf;
		for i in 0..32 {
			// bit=0 means current is left child
			current = <PoseidonHash as plonky2::plonk::config::Hasher<F>>::two_to_one(
				current,
				siblings[i],
			);
		}

		(current, siblings, bits)
	}

	#[test]
	fn test_merkle_gadget_valid() {
		let leaf_elements = [
			GoldilocksField::from_canonical_u64(1),
			GoldilocksField::from_canonical_u64(2),
			GoldilocksField::from_canonical_u64(3),
			GoldilocksField::from_canonical_u64(4),
		];
		let leaf = HashOut {
			elements: leaf_elements,
		};

		let (root, siblings, bits) = build_merkle_path(leaf);

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let expected_root_targets = builder.add_virtual_hash();
		let selector = builder.add_virtual_bool_target_safe();
		let leaf_target = builder.add_virtual_hash();
		let targets = merkle_verify_gadget::<F, D, 32>(
			&mut builder,
			leaf_target,
			expected_root_targets,
			selector,
		);

		let data = builder.build::<C>();

		let mut pw = PartialWitness::new();

		// Set leaf
		for i in 0..4 {
			pw.set_target(leaf_target.elements[i], leaf_elements[i])
				.unwrap();
		}
		// Set siblings and bits
		for level in 0..32 {
			for i in 0..4 {
				pw.set_target(targets.siblings[level][i], siblings[level].elements[i])
					.unwrap();
			}
			pw.set_bool_target(BoolTarget::new_unsafe(targets.bits[level]), bits[level])
				.unwrap();
		}
		// Set expected root = computed root
		for i in 0..4 {
			pw.set_target(expected_root_targets.elements[i], root.elements[i])
				.unwrap();
		}
		pw.set_bool_target(selector, true).unwrap();

		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}

	#[test]
	fn test_merkle_gadget_selector_off() {
		let leaf_elements = [
			GoldilocksField::from_canonical_u64(1),
			GoldilocksField::from_canonical_u64(2),
			GoldilocksField::from_canonical_u64(3),
			GoldilocksField::from_canonical_u64(4),
		];
		let leaf = HashOut {
			elements: leaf_elements,
		};
		let (_, siblings, bits) = build_merkle_path(leaf);

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let expected_root_targets = builder.add_virtual_hash();
		let selector = builder.add_virtual_bool_target_safe();
		let leaf_target = builder.add_virtual_hash();
		let targets = merkle_verify_gadget::<F, D, 32>(
			&mut builder,
			leaf_target,
			expected_root_targets,
			selector,
		);

		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		for i in 0..4 {
			pw.set_target(leaf_target.elements[i], leaf_elements[i])
				.unwrap();
		}
		for level in 0..32 {
			for i in 0..4 {
				pw.set_target(targets.siblings[level][i], siblings[level].elements[i])
					.unwrap();
			}
			pw.set_bool_target(BoolTarget::new_unsafe(targets.bits[level]), bits[level])
				.unwrap();
		}

		// Wrong expected root — but selector = 0, so no equality is enforced.
		let wrong_root = [
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
		];
		for i in 0..4 {
			pw.set_target(expected_root_targets.elements[i], wrong_root[i])
				.unwrap();
		}
		pw.set_bool_target(selector, false).unwrap();

		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}

	#[test]
	fn test_merkle_gadget_wrong_root_selector_on() {
		let leaf_elements = [
			GoldilocksField::from_canonical_u64(1),
			GoldilocksField::from_canonical_u64(2),
			GoldilocksField::from_canonical_u64(3),
			GoldilocksField::from_canonical_u64(4),
		];
		let leaf = HashOut {
			elements: leaf_elements,
		};
		let (_, siblings, bits) = build_merkle_path(leaf);

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let expected_root_targets = builder.add_virtual_hash();
		let selector = builder.add_virtual_bool_target_safe();
		let leaf_target = builder.add_virtual_hash();
		let targets = merkle_verify_gadget::<F, D, 32>(
			&mut builder,
			leaf_target,
			expected_root_targets,
			selector,
		);

		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		for i in 0..4 {
			pw.set_target(leaf_target.elements[i], leaf_elements[i])
				.unwrap();
		}
		for level in 0..32 {
			for i in 0..4 {
				pw.set_target(targets.siblings[level][i], siblings[level].elements[i])
					.unwrap();
			}
			pw.set_bool_target(BoolTarget::new_unsafe(targets.bits[level]), bits[level])
				.unwrap();
		}

		// Wrong expected root with selector = 1 — must fail.
		let wrong_root = [
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
		];
		for i in 0..4 {
			pw.set_target(expected_root_targets.elements[i], wrong_root[i])
				.unwrap();
		}
		pw.set_bool_target(selector, true).unwrap();

		assert!(
			data.prove(pw).is_err(),
			"Expected proof to fail with wrong root and selector=1"
		);
	}

	// ── Native helper functions for test_prove_fresh_acc_tx ──────────────────

	/// Matches `derive_fresh_account_nullifier`: 8-element Poseidon hash of comm || nk.
	fn fresh_acc_null_native(comm: [F; 4], nk: [F; 4]) -> [F; 4] {
		use plonky2::plonk::config::Hasher;
		let inp: Vec<F> = comm.iter().chain(nk.iter()).copied().collect();
		<PoseidonHash as Hasher<F>>::hash_no_pad(&inp).elements
	}

	// ── Witness-setting helpers ───────────────────────────────────────────────
}

// TODO: assert account is fresh
//
// AccountFresh
// if account is fresh, then what things need to be chcked:
//  - all values of the account are set to default
//  - one should only be allowed to update the configuration of the account
//  - if acc_fresh, then it's a new type of tx
//
// PrivateTrafer
//      - for each inote:
//          - Comm(inote) exists in NCT
//          - Null(inote) is derived correctly
//          - inote.spend_cond = AccIn
//      - for each dinote:
//          - Comm(dinote) is derived correctly
//      - for each onote:
//          - Comm(onote) is derived correctly
//      - accin.amt + sum(inote) == accout.amt + sum(onote)
//      - approval signature
//      - if [onote].len > 0: user spend sig
//      - if [inote].len > 0 && [onote].len == 0: consume sig
//      - approval_key exists in MainConfigTree root
//
//
