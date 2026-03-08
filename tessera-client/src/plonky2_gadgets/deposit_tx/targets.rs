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
	ACT_DEPTH,
	note::DepositNote,
	plonky2_gadgets::{
		merkle::MerkleTarget,
		priv_tx::targets::{
			AccountTarget, ActMerkleTarget, ActRootTarget, AssetIdTarget, AstMerkleTargets,
			MainPoolConfigRootTarget, PublicIdentifierTaregt, SubpoolFullProofTargets,
			SubpoolIdTarget,
		},
		signature::{PubkeyTarget, SchnorrTargets},
		u256::U256Target,
	},
};

// ----- DepositNote targets -----

#[derive(Clone, Copy)]
pub(crate) struct DepositNoteTarget {
	pub(crate) identifier: [Target; 2],
	pub(crate) recipient_subpool_id: SubpoolIdTarget,
	pub(crate) recipient_public_id: PublicIdentifierTaregt,
	pub(crate) amount: U256Target,
	pub(crate) asset_id: AssetIdTarget,
}

impl DepositNoteTarget {
	pub(crate) fn set_witness(&self, pw: &mut PartialWitness<F>, note: &DepositNote) {
		pw.set_target(self.identifier[0], note.identifier[0])
			.unwrap();
		pw.set_target(self.identifier[1], note.identifier[1])
			.unwrap();
		pw.set_target(self.recipient_subpool_id.0, note.recipient.subpool_id.0)
			.unwrap();
		for (j, &x) in note.recipient.public_id.0.0.iter().enumerate() {
			pw.set_target(self.recipient_public_id.0.elements[j], x)
				.unwrap();
		}
		for (i, word) in note.amount.0.iter().enumerate() {
			pw.set_target(self.amount.0[2 * i].0, F::from_canonical_u32(*word as u32))
				.unwrap();
			pw.set_target(
				self.amount.0[2 * i + 1].0,
				F::from_canonical_u32((*word >> 32) as u32),
			)
			.unwrap();
		}
		pw.set_target(self.asset_id.0, note.asset_id.0).unwrap();
	}
}

#[derive(Clone, Copy)]
pub(crate) struct DepositNoteCommitmentTarget(pub(crate) HashOutTarget);

// ----- Signature targets -----

#[derive(Clone)]
pub(crate) struct DepositTxSignatureTargets {
	pub(crate) consume: SchnorrTargets,
	pub(crate) approval: SchnorrTargets,
}

// ----- Top-level DepositTxTargets -----

pub(crate) struct DepositTxTargets {
	// tree roots
	pub(crate) act_root: ActRootTarget,
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
	pub(crate) accin_act_merkle: MerkleTarget<ACT_DEPTH>,
	pub(crate) accin_ast_merkle: AstMerkleTargets,
	pub(crate) accout_ast_merkle: AstMerkleTargets,
	// deposit note
	pub(crate) deposit_note: DepositNoteTarget,
	pub(crate) deposit_note_comm: DepositNoteCommitmentTarget,
	// eth address (5 u32 field elements for 160-bit Ethereum address)
	pub(crate) eth_address: [Target; 5],
	// subpool proof
	pub(crate) subpool_proof_targets: SubpoolFullProofTargets,
	// signature targets
	pub(crate) sig_targets: DepositTxSignatureTargets,
}
