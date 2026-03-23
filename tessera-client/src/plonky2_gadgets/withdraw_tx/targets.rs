use plonky2::iop::target::{BoolTarget, Target};

use crate::{
	ACC_AST_DEPTH, COM_TREE_DEPTH, NOTE_BATCH,
	plonky2_gadgets::{
		merkle::{CommitmentTreeMerkleTarget, ComputeMerkleRootTarget},
		priv_tx::targets::{
			AccountTarget, AssetIdTarget, MainPoolConfigRootTarget, RootTarget,
			SubpoolFullProofTargets,
		},
		signature::{PubkeyTarget, SchnorrTargets},
		u256::U256Target,
	},
};

/// All targets allocated by
/// [`withdraw_tx_circuit`](crate::plonky2_gadgets::withdraw_tx::withdraw_tx_circuit).
///
/// A withdrawal processes up to `NOTE_BATCH` asset slots in a single proof.
/// Each slot has its own AST update; the slots are chained so that the output
/// of slot `i` is the input of slot `i+1`.
pub(crate) struct WithdrawTxTargets {
	/// 1 for a real withdrawal, 0 for a dummy/padding proof.
	pub(crate) not_fake_tx: BoolTarget,
	/// Account Commitment Tree root (public input).
	pub(crate) root: RootTarget,
	/// Main pool configuration tree root (public input).
	pub(crate) mainpool_config_root: MainPoolConfigRootTarget,
	/// Subpool approval authority public key.
	pub(crate) approval_key: PubkeyTarget,
	/// Subpool rejection authority public key (carried for subpool proof; not used in signing).
	pub(crate) rejection_key: PubkeyTarget,
	/// Subpool consume authority public key.
	pub(crate) subpool_consume_key: PubkeyTarget,
	/// Pre-withdrawal account state.
	pub(crate) accin: AccountTarget,
	/// Post-withdrawal account state (nonce+1, AST updated for each slot).
	pub(crate) accout: AccountTarget,
	/// AccIn leaf index in the ACT (prover-supplied for nullifier derivation).
	pub(crate) accin_pos: Target,
	/// Asset IDs for each withdrawal slot (zero for padding slots).
	pub(crate) asset_ids: [AssetIdTarget; NOTE_BATCH],
	/// Withdrawal amounts per slot.
	pub(crate) withdrawal_amts: [U256Target; NOTE_BATCH],
	/// AccIn asset balances per slot (before withdrawal).
	pub(crate) accin_amts: [U256Target; NOTE_BATCH],
	/// AccOut asset balances per slot (after withdrawal).
	pub(crate) accout_amts: [U256Target; NOTE_BATCH],
	/// Whether each asset exists in AccIn's AST (false for padding slots).
	pub(crate) asset_exists_in_accin: [BoolTarget; NOTE_BATCH],
	/// Whether each asset remains in AccOut's AST (false when balance hits zero).
	pub(crate) asset_exists_in_accout: [BoolTarget; NOTE_BATCH],
	/// Ethereum destination address as 5 u32 field elements (public input).
	pub(crate) w_acc_addr: [Target; 5],
	/// ACT membership proof for AccIn.
	pub(crate) accin_act_merkle: CommitmentTreeMerkleTarget<COM_TREE_DEPTH>,
	/// Per-slot AST update proofs (chained: slot `i` output root feeds slot `i+1` input root).
	/// `ast_merkles[i]` proves the leaf update from intermediate AST[i] → AST[i+1].
	pub(crate) ast_merkles: [ComputeMerkleRootTarget<ACC_AST_DEPTH>; NOTE_BATCH],
	/// Authority key membership proofs for the subpool.
	pub(crate) subpool_proof_targets: SubpoolFullProofTargets,
	/// Approval Schnorr signature over the withdrawal tx hash.
	pub(crate) approval_sig: SchnorrTargets,
}
