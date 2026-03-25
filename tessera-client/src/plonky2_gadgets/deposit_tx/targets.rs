use plonky2::{
	hash::hash_types::HashOutTarget,
	iop::{
		target::{BoolTarget, Target},
		witness::{PartialWitness, WitnessWrite},
	},
};
use tessera_utils::F;

use crate::{
	COM_TREE_DEPTH,
	note::DepositNote,
	plonky2_gadgets::{
		merkle::MerkleRootTarget,
		priv_tx::targets::{
			AccountTarget, AssetIdTarget, MainPoolConfigRootTarget, PublicIdentifierTaregt,
			RootTarget, SubpoolFullProofTargets, SubpoolIdTarget,
		},
		signature::{PubkeyTarget, SchnorrTargets},
		u256::U256Target,
	},
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
	pub(crate) fn set_witness(&self, pw: &mut PartialWitness<F>, note: &DepositNote) {
		pw.set_target(self.identifier[0], note.identifier[0])
			.unwrap();
		pw.set_target(self.identifier[1], note.identifier[1])
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
	/// 1 for a real transaction, 0 for a dummy/padding proof.
	pub(crate) not_fake_tx: BoolTarget,
	/// Account Commitment Tree root (public input).
	pub(crate) root: RootTarget,
	/// Main pool configuration tree root (public input).
	pub(crate) mainpool_config_root: MainPoolConfigRootTarget,
	/// Subpool approval authority public key.
	pub(crate) approval_key: PubkeyTarget,
	/// Subpool rejection authority public key.
	pub(crate) rejection_key: PubkeyTarget,
	/// Subpool consume authority public key.
	pub(crate) subpool_consume_key: PubkeyTarget,
	/// Pre-transaction account state.
	pub(crate) accin: AccountTarget,
	/// Post-transaction account state (nonce+1, AST updated).
	pub(crate) accout: AccountTarget,
	/// AccIn balance for `asset_id` before the deposit.
	pub(crate) accin_amt: U256Target,
	/// AccOut balance for `asset_id` after the deposit.
	pub(crate) accout_amt: U256Target,
	/// Asset being deposited.
	pub(crate) asset_id: AssetIdTarget,
	/// Whether `asset_id` already exists in AccIn's AST.
	pub(crate) asset_exists_in_accin: BoolTarget,
	/// Whether `asset_id` exists in AccOut's AST (always true after deposit).
	pub(crate) asset_exists_in_accout: BoolTarget,
	/// AccIn leaf index in the ACT (supplied by the prover for nullifier derivation).
	pub(crate) accin_pos: Target,
	/// Merkle proof that AccIn's commitment is in the ACT.
	pub(crate) accin_act_merkle: MerkleRootTarget,
	/// Merkle proof for the AST leaf update (accin → accout).
	pub(crate) accin_ast_merkle: MerkleRootTarget,
	/// The deposit note fields.
	pub(crate) deposit_note: DepositNoteTarget,
	/// Derived commitment to `deposit_note` (public input).
	pub(crate) deposit_note_comm: DepositNoteCommitmentTarget,
	/// Ethereum origin address as 5 u32 field elements (public input).
	pub(crate) eth_address: [Target; 5],
	/// Authority key membership proofs for the subpool.
	pub(crate) subpool_proof_targets: SubpoolFullProofTargets,
	/// Schnorr signature targets for consume and approval.
	pub(crate) sig_targets: DepositTxSignatureTargets,
}
