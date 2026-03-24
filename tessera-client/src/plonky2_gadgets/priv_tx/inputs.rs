use tessera_trees::MerkleProof;
use tessera_utils::{F, hasher::HashOutput};

use crate::{
	ConsumeAuth, NOTE_BATCH, SpendAuth, StandardAccount, SubpoolId,
	note::StandardNote,
	pool_config::{CompPubKey, MainPoolConfigTree},
	schnorr::Signature,
};

/// Inputs for a FreshAcc transaction.
///
/// Creates a new account (`accin` is registered for the first time).
/// No ACT or NCT membership proof is required.
pub struct FreshAccInputs {
	pub accin: StandardAccount,
	pub new_spend_auth: SpendAuth,
	pub new_consume_auth: ConsumeAuth,
	/// On-chain Poseidon IMT root at proof time. Registered as both PI[77-80]
	/// and PI[81-84] (V2 uses a single IMT for accounts and notes). Not
	/// checked by the circuit for FreshAcc, but bound in the super-aggregator.
	pub root: HashOutput,
	pub approval_key: CompPubKey,
	pub rejection_key: CompPubKey,
	pub consume_key: CompPubKey,
	pub subpool_id: SubpoolId,
	pub main_pool: MainPoolConfigTree<HashOutput>,
	pub approval_sig: Signature,
	pub dinotes: [[F; 4]; NOTE_BATCH],
	pub donotes: [[F; 4]; NOTE_BATCH],
}

/// Inputs for a Spend (private) transaction.
///
/// Transfers assets between notes. `accin` must exist in the on-chain IMT at
/// `root`, and each active input note must also exist in the same IMT.
pub struct SpendTxInputs {
	pub accin: StandardAccount,
	/// On-chain Poseidon IMT root. Used for both the account commitment (ACT)
	/// and input-note commitment (NCT) Merkle proofs. In V2 both PI slots
	/// (PI[77-80] and PI[81-84]) carry this same value.
	pub root: HashOutput,
	pub accin_merkle_proof: MerkleProof<HashOutput>,
	pub inotes: Vec<StandardNote>,
	pub inotes_nct_proofs: Vec<MerkleProof<HashOutput>>,
	pub onotes: Vec<StandardNote>,
	pub dinotes: [[F; 4]; NOTE_BATCH],
	pub donotes: [[F; 4]; NOTE_BATCH],
	pub approval_key: CompPubKey,
	pub rejection_key: CompPubKey,
	pub consume_key: CompPubKey,
	pub subpool_id: SubpoolId,
	pub main_pool: MainPoolConfigTree<HashOutput>,
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
/// `accin` must exist in the on-chain IMT and the input notes must also exist there.
pub struct RejectTxInputs {
	pub accin: StandardAccount,
	pub accin_act_merkle_proof: MerkleProof<HashOutput>,
	/// On-chain Poseidon IMT root. Used for both the account commitment (ACT)
	/// and input-note commitment (NCT) Merkle proofs. In V2 both PI slots
	/// (PI[77-80] and PI[81-84]) carry this same value.
	pub root: HashOutput,
	pub inotes: Vec<StandardNote>,
	pub inotes_nct_proofs: Vec<MerkleProof<HashOutput>>,
	pub onotes: Vec<StandardNote>,
	pub dinotes: [[F; 4]; NOTE_BATCH],
	pub donotes: [[F; 4]; NOTE_BATCH],
	pub approval_key: CompPubKey,
	pub rejection_key: CompPubKey,
	pub consume_key: CompPubKey,
	pub subpool_id: SubpoolId,
	pub main_pool: MainPoolConfigTree<HashOutput>,
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
	pub root: HashOutput,
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
