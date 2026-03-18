use tessera_trees::{F, tree::hasher::HashOutput};

use crate::{
	ACT_DEPTH, ConsumeAuth, NCT_DEPTH, NOTE_BATCH, SpendAuth, StandardAccount, SubpoolId,
	note::StandardNote,
	pool_config::{CompPubKey, MainPoolConfigTree},
	schnorr::Signature,
	tree::CommitmentTreeMerkleProof,
};

/// Inputs for a FreshAcc transaction.
///
/// Creates a new account (`accin` is registered for the first time).
/// No ACT or NCT membership proof is required.
pub struct FreshAccInputs {
	pub accin: StandardAccount,
	pub new_spend_auth: SpendAuth,
	pub new_consume_auth: ConsumeAuth,
	/// ACT root at proof time. Not checked by the circuit for FreshAcc, but
	/// registered as PI[77-80] so the super-aggregator can bind to it.
	pub act_root: HashOutput,
	/// NCT root at proof time. Same caveat as `act_root`.
	pub nct_root: HashOutput,
	pub approval_key: CompPubKey,
	pub rejection_key: CompPubKey,
	pub consume_key: CompPubKey,
	pub subpool_id: SubpoolId,
	pub main_pool: MainPoolConfigTree,
	pub approval_sig: Signature,
	pub dinotes: [[F; 4]; NOTE_BATCH],
	pub donotes: [[F; 4]; NOTE_BATCH],
}

/// Inputs for a Spend (private) transaction.
///
/// Transfers assets between notes. `accin` must exist in the ACT at `act_root`,
/// and each active input note must exist in the NCT at `nct_root`.
pub struct SpendTxInputs {
	pub accin: StandardAccount,
	/// ACT root that `accin_merkle_proof` is valid against.
	pub act_root: HashOutput,
	/// NCT root that `inotes_nct_proofs` are valid against.
	pub nct_root: HashOutput,
	pub accin_merkle_proof: CommitmentTreeMerkleProof<ACT_DEPTH>,
	pub inotes: Vec<StandardNote>,
	pub inotes_nct_proofs: Vec<CommitmentTreeMerkleProof<NCT_DEPTH>>,
	pub onotes: Vec<StandardNote>,
	pub dinotes: [[F; 4]; NOTE_BATCH],
	pub donotes: [[F; 4]; NOTE_BATCH],
	pub approval_key: CompPubKey,
	pub rejection_key: CompPubKey,
	pub consume_key: CompPubKey,
	pub subpool_id: SubpoolId,
	pub main_pool: MainPoolConfigTree,
	/// Spend-auth signature. `Some` when there are active output notes; `None`
	/// lets the circuit use a fake signature (not enforced for inactive slots).
	pub spend_sig: Option<Signature>,
	/// Consume-auth signature. `Some` when consuming active input notes without
	/// active output notes; `None` for a fake signature.
	pub consume_sig: Option<Signature>,
	pub approval_sig: Signature,
}

/// Inputs for a Reject transaction.
///
/// The operator rejects a set of pending notes back to the sender.
/// `accin` must exist in the ACT and the input notes must exist in the NCT.
pub struct RejectTxInputs {
	pub accin: StandardAccount,
	pub accin_act_merkle_proof: CommitmentTreeMerkleProof<ACT_DEPTH>,
	/// ACT root that `accin_act_merkle_proof` is valid against.
	pub act_root: HashOutput,
	/// NCT root that `inotes_nct_proofs` are valid against.
	pub nct_root: HashOutput,
	pub inotes: Vec<StandardNote>,
	pub inotes_nct_proofs: Vec<CommitmentTreeMerkleProof<NCT_DEPTH>>,
	pub onotes: Vec<StandardNote>,
	pub dinotes: [[F; 4]; NOTE_BATCH],
	pub donotes: [[F; 4]; NOTE_BATCH],
	pub approval_key: CompPubKey,
	pub rejection_key: CompPubKey,
	pub consume_key: CompPubKey,
	pub subpool_id: SubpoolId,
	pub main_pool: MainPoolConfigTree,
	pub consume_sig: Signature,
	pub approval_sig: Signature,
}

/// Inputs for a fake/dummy transaction (`not_fake_tx = 0`).
///
/// Used to pad empty aggregation slots. No circuit constraints are enforced
/// beyond the boolean shape of `not_fake_tx`. The override fields become the
/// proof's public inputs for AN/AC/NN/NC, allowing alignment with tree padding
/// leaves chosen by the sequencer.
pub struct FakeTxInputs {
	pub act_root: HashOutput,
	pub nct_root: HashOutput,
	pub mainpool_config_root: HashOutput,
	pub override_an: [F; 4],
	pub override_ac: [F; 4],
	pub override_nn: [[F; 4]; NOTE_BATCH],
	pub override_nc: [[F; 4]; NOTE_BATCH],
}

/// Discriminated union of all possible PrivTx witness inputs.
///
/// Pass to [`prove_real_priv_tx`] to generate a proof. The `Fake` variant
/// produces a dummy proof (`not_fake_tx = 0`); all other variants produce real
/// proofs (`not_fake_tx = 1`) with fully enforced circuit constraints.
pub enum PrivTxInputs {
	FreshAcc(FreshAccInputs),
	Spend(SpendTxInputs),
	Reject(RejectTxInputs),
	Fake(FakeTxInputs),
}
