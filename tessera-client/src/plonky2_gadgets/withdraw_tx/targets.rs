use plonky2::iop::target::{BoolTarget, Target};

use crate::{
	ACC_AST_DEPTH, ACT_DEPTH, NOTE_BATCH,
	plonky2_gadgets::{
		merkle::{CommitmentTreeMerkleTarget, ComputeMerkleRootTarget},
		priv_tx::targets::{
			AccountTarget, ActRootTarget, AssetIdTarget, MainPoolConfigRootTarget,
			SubpoolFullProofTargets,
		},
		signature::{PubkeyTarget, SchnorrTargets},
		u256::U256Target,
	},
};

pub(crate) struct WithdrawTxTargets {
	// Tx flag
	pub(crate) not_fake_tx: BoolTarget,
	// Tree roots (public inputs)
	pub(crate) act_root: ActRootTarget,
	pub(crate) mainpool_config_root: MainPoolConfigRootTarget,
	// Authority public keys
	pub(crate) approval_key: PubkeyTarget,
	pub(crate) rejection_key: PubkeyTarget,
	pub(crate) subpool_consume_key: PubkeyTarget,
	// Accounts
	pub(crate) accin: AccountTarget,
	pub(crate) accout: AccountTarget,
	// AccIn position in ACT (for nullifier derivation)
	pub(crate) accin_pos: Target,
	// Per-asset withdrawal fields (NOTE_BATCH slots)
	pub(crate) asset_ids: [AssetIdTarget; NOTE_BATCH],
	pub(crate) withdrawal_amts: [U256Target; NOTE_BATCH],
	pub(crate) accin_amts: [U256Target; NOTE_BATCH],
	pub(crate) accout_amts: [U256Target; NOTE_BATCH],
	pub(crate) asset_exists_in_accin: [BoolTarget; NOTE_BATCH],
	pub(crate) asset_exists_in_accout: [BoolTarget; NOTE_BATCH],
	// Withdrawal destination: Ethereum address as 5 u32 field elements
	pub(crate) w_acc_addr: [Target; 5],
	// Merkle targets
	pub(crate) accin_act_merkle: CommitmentTreeMerkleTarget<ACT_DEPTH>,
	/// One AST merkle proof per withdrawal slot (indexed from accin side).
	/// ast_merkles[i] proves the leaf update from intermediate AST[i] → AST[i+1].
	pub(crate) ast_merkles: [ComputeMerkleRootTarget<ACC_AST_DEPTH>; NOTE_BATCH],
	// Subpool full proof
	pub(crate) subpool_proof_targets: SubpoolFullProofTargets,
	// Approval signature on the withdrawal tx hash
	pub(crate) approval_sig: SchnorrTargets,
}
