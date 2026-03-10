use plonky2::{
	hash::hash_types::HashOutTarget,
	iop::{
		target::{BoolTarget, Target},
		witness::{PartialWitness, WitnessWrite},
	},
};
use plonky2_field::types::Field;
use tessera_trees::F;

use crate::{
	ACC_AST_DEPTH, ACT_DEPTH, DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER, DEFAULT_SPEND_AUTH_PK,
	MAIN_POOL_CONFIG_DEPTH, NCT_DEPTH, NOTE_BATCH, SUBPOOL_CONFIG_DEPTH, StandardAccount,
	plonky2_gadgets::{
		merkle::{CommitmentTreeMerkleTarget, ComputeMerkleRootTarget, ConditionalMerkleTarget},
		signature::{PubkeyTarget, SchnorrTargets},
		u256::U256Target,
	},
};

// ----- Account related targets -----

#[derive(Clone, Copy)]
pub(crate) struct PrivateIdentifierTarget(pub(crate) [Target; 2]);
#[derive(Clone, Copy)]
pub(crate) struct PublicIdentifierTaregt(pub(crate) HashOutTarget);
#[derive(Clone, Copy)]
pub(crate) struct NullifierKeyTarget(pub(crate) HashOutTarget);
#[derive(Clone, Copy)]
pub(crate) struct SubpoolIdTarget(pub(crate) Target);

#[derive(Clone, Copy)]
pub(crate) struct ConsumeAuthTarget {
	// if 0 then subpool owner can consume, otherwise the public key
	pub(crate) config: BoolTarget,
	pub(crate) pk: PubkeyTarget,
}

#[derive(Clone, Copy)]
pub(crate) struct AccountTarget {
	pub(crate) private_identifier: PrivateIdentifierTarget,
	pub(crate) nonce: Target,
	pub(crate) subpool_id: SubpoolIdTarget,
	pub(crate) acc_ast_root: HashOutTarget,
	pub(crate) spend_auth: PubkeyTarget,
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
pub(crate) struct AccountCommitmentTarget(pub(crate) HashOutTarget);
#[derive(Clone, Copy)]
pub(crate) struct AccountNullifierTarget(pub(crate) HashOutTarget);

#[derive(Clone, Copy)]
pub(crate) struct DummyAccountTarget(pub(crate) [Target; 4]);
#[derive(Clone, Copy)]
pub(crate) struct DummyAccountCommitment(pub(crate) HashOutTarget);
#[derive(Clone, Copy)]
pub(crate) struct DummyAccountNullifier(pub(crate) HashOutTarget);

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
	pub(crate) fn set_witness(&self, pw: &mut PartialWitness<F>, note: &crate::note::StandardNote) {
		pw.set_target(self.identifier[0], note.identifier.0[0])
			.unwrap();
		pw.set_target(self.identifier[1], note.identifier.0[1])
			.unwrap();
		self.amount.set_witness(pw, note.amt);
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
pub(crate) struct NoteNullifierTarget(pub(crate) HashOutTarget);

#[derive(Clone, Copy)]
pub(crate) struct DummyNoteTarget(pub(crate) [Target; 4]);

// ---- Other tx related targets ----

#[derive(Clone, Copy)]
pub(crate) struct TxHashTarget(pub(crate) HashOutTarget);

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
pub(crate) struct SubpoolConfigRootTarget(pub(crate) HashOutTarget);

#[derive(Clone, Copy)]
pub(crate) struct AssetIdTarget(pub(crate) Target);

#[derive(Clone)]
pub(crate) struct SubpoolFullProofTargets {
	pub(crate) approval_proof: ConditionalMerkleTarget<SUBPOOL_CONFIG_DEPTH>,
	pub(crate) rejection_proof: ConditionalMerkleTarget<SUBPOOL_CONFIG_DEPTH>,
	pub(crate) consume_proof: ConditionalMerkleTarget<SUBPOOL_CONFIG_DEPTH>,
	pub(crate) main_pool_proof: ConditionalMerkleTarget<MAIN_POOL_CONFIG_DEPTH>,
	pub(crate) subpool_config_root: SubpoolConfigRootTarget,
}

pub(crate) struct TxCircuitTargets {
	pub(crate) not_fake_tx: BoolTarget,
	// tx kind flags
	pub(crate) is_rjct: BoolTarget,
	pub(crate) is_fresh_acc: BoolTarget,
	pub(crate) is_update_auth: BoolTarget,
	pub(crate) is_priv_tx: BoolTarget,
	// tree roots
	pub(crate) act_root: ActRootTarget,
	pub(crate) nct_root: NctRootTarget,
	pub(crate) mainpool_config_root: MainPoolConfigRootTarget,
	// authority public keys
	pub(crate) approval_key: PubkeyTarget,
	pub(crate) rejection_key: PubkeyTarget,
	pub(crate) subpool_consume_key: PubkeyTarget,
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
	pub(crate) accin_act_merkle: CommitmentTreeMerkleTarget<ACT_DEPTH>,
	pub(crate) accin_ast_merkle: ComputeMerkleRootTarget<ACC_AST_DEPTH>,
	pub(crate) inotes_nct_merkle: [CommitmentTreeMerkleTarget<NCT_DEPTH>; NOTE_BATCH], /* inotes NCT merkle
	                                                                                    * proofs (one per
	                                                                                    * inote) */
	// notes
	pub(crate) inotes: [NoteTarget; NOTE_BATCH],
	pub(crate) inotes_pos: [Target; NOTE_BATCH],
	pub(crate) inotes_isactive: [BoolTarget; NOTE_BATCH],
	pub(crate) onotes: [NoteTarget; NOTE_BATCH],
	pub(crate) onotes_isactive: [BoolTarget; NOTE_BATCH],
	pub(crate) dinotes: [DummyNoteTarget; NOTE_BATCH],
	pub(crate) donotes: [DummyNoteTarget; NOTE_BATCH],
	// subpool proof
	pub(crate) subpool_proof_targets: SubpoolFullProofTargets,
	// signature targets
	pub(crate) sig_targets: TxSignatureTargets,
}
