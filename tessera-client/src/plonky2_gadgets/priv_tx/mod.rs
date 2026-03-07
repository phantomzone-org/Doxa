use plonky2::{
	hash::{
		hash_types::{HashOutTarget, RichField},
		poseidon::Poseidon,
	},
	iop::{
		target::{BoolTarget, Target},
		witness::PartialWitness,
	},
	plonk::circuit_builder::CircuitBuilder,
};
use plonky2_field::{extension::Extendable, types::Field};
use tessera_trees::F;

use crate::{
	ACC_AST_DEPTH, ACT_DEPTH, DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER, DEFAULT_SPEND_AUTH_PK,
	DS_PUBLIC_IDENTIFIER, MAIN_POOL_CONFIG_DEPTH, NCT_DEPTH, NOTE_BATCH, SUBPOOL_CONFIG_DEPTH,
	StandardAccount,
	plonky2_gadgets::{
		merkle::{ConditionalMerkleTarget, MerkleTarget},
		signature::{PubkeyTarget, SchnorrTargets},
		u256::{CircuitBuilderU256, U256Target},
	},
};

mod freshacc;
mod spend;

// ----- Account related targets -----

#[derive(Clone, Copy)]
pub(crate) struct PrivateIdentifierTarget(pub(crate) [Target; 2]);
#[derive(Clone, Copy)]
pub(crate) struct PublicIdentifierTaregt(pub(crate) HashOutTarget);
#[derive(Clone, Copy)]
pub(crate) struct NullifierKeyTarget(HashOutTarget);
#[derive(Clone, Copy)]
pub(crate) struct SubpoolIdTarget(pub(crate) Target);

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
	// TODO: make the function generic over Field
	pub(crate) fn set_witness(&self, pw: &mut PartialWitness<F>, acc: &StandardAccount) {
		pw.set_target(self.private_identifier.0[0], acc.private_identifier.0[0])
			.unwrap();
		pw.set_target(self.private_identifier.0[1], acc.private_identifier.0[1])
			.unwrap();
		pw.set_target(self.nonce, acc.nonce.0).unwrap();
		pw.set_target(self.subpool_id.0, acc.subpool_id.0).unwrap();
		for (i, &x) in acc.ast.root().0.iter().enumerate() {
			pw.set_target(self.acc_ast_root.elements[i], x).unwrap();
		}
		let spend_cpk: [F; 5] = acc.spend_auth.spend_pk.map_or_else(
			|| DEFAULT_SPEND_AUTH_PK.map(F::from_canonical_u64),
			|pk| pk.0.w.0,
		);
		for (t, v) in self.spend_auth.0.0.iter().zip(spend_cpk.iter()) {
			pw.set_target(*t, *v).unwrap();
		}
		pw.set_bool_target(self.consume_auth.config, acc.consume_auth.config)
			.unwrap();
		let consume_cpk: [F; 5] = acc.consume_auth.pk.map_or_else(
			|| DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER.map(F::from_canonical_u64),
			|pk| pk.0.w.0,
		);
		for (t, v) in self.consume_auth.pk.0.0.iter().zip(consume_cpk.iter()) {
			pw.set_target(*t, *v).unwrap();
		}
	}
}

#[derive(Clone, Copy)]
struct AccountCommitmentTarget(HashOutTarget);
#[derive(Clone, Copy)]
struct AccountNullifierTarget(HashOutTarget);

#[derive(Clone, Copy)]
struct DummyAccountTarget([Target; 4]);
#[derive(Clone, Copy)]
struct DummyAccountCommitment(HashOutTarget);
#[derive(Clone, Copy)]
struct DummyAccountNullifier(HashOutTarget);

// ---- Note related targets ----

#[derive(Clone, Copy)]
pub(crate) struct NoteTarget {
	pub(crate) identifier: [Target; 2],
	pub(crate) amount: U256Target,
	pub(crate) asset_id: AssetIdTarget,
	// TODO: change the naming to match of StandardNote
	pub(crate) spend_cond: ConsumeCondTarget,
	pub(crate) reject_cond: RejectCondTarget,
}

impl NoteTarget {
	pub(crate) fn set_witness<F: Field>(
		&self,
		pw: &mut PartialWitness<F>,
		note: &crate::note::StandardNote,
	) {
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
pub(crate) struct NoteCommitmentTarget(pub(crate) HashOutTarget);
#[derive(Clone, Copy)]
struct NoteNullifierTarget(HashOutTarget);

#[derive(Clone, Copy)]
pub(crate) struct DummyNoteTarget(pub(crate) [Target; 4]);

// ---- Other tx related targets ----

#[derive(Clone, Copy)]
struct TxHashTarget(HashOutTarget);

#[derive(Clone)]
pub(crate) struct TxSignatureTargets {
	pub(crate) spend: SchnorrTargets,
	pub(crate) consume: SchnorrTargets,
	pub(crate) approval: SchnorrTargets,
}

#[derive(Clone, Copy)]
pub(crate) struct ActRootTarget(pub(crate) HashOutTarget);
#[derive(Clone, Copy)]
pub(crate) struct NctRootTarget(pub(crate) HashOutTarget);

#[derive(Clone, Copy)]
pub(crate) struct MainPoolConfigRootTarget(pub(crate) HashOutTarget);
#[derive(Clone, Copy)]
struct SubpoolConfigRootTarget(HashOutTarget);

#[derive(Clone, Copy)]
pub(crate) struct AssetIdTarget(pub(crate) Target);

#[derive(Clone)]
pub(crate) struct ActMerkleTarget(pub(crate) ConditionalMerkleTarget<ACT_DEPTH>);

#[derive(Clone)]
pub(crate) struct AstMerkleTargets(pub(crate) ConditionalMerkleTarget<ACC_AST_DEPTH>);

#[derive(Clone)]
pub(crate) struct SubpoolFullProofTargets {
	pub(crate) approval_proof: MerkleTarget<SUBPOOL_CONFIG_DEPTH>,
	pub(crate) rejection_proof: MerkleTarget<SUBPOOL_CONFIG_DEPTH>,
	pub(crate) consume_proof: MerkleTarget<SUBPOOL_CONFIG_DEPTH>,
	pub(crate) main_pool_proof: MerkleTarget<MAIN_POOL_CONFIG_DEPTH>,
}

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
	pub(crate) inotes_nct_merkle: [ConditionalMerkleTarget<NCT_DEPTH>; NOTE_BATCH], /* inotes NCT merkle
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
	// let ds_nullifier_key = builder.constant(F::from_canonical_u64(DS_NULLIFIER_KEY));
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
