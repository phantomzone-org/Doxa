//! Builder for Fake (dummy) transactions.

use plonky2_field::types::Field;
use tessera_utils::{F, hasher::HashOutput};

use super::{BuiltPrivTx, errors::FakeTxBuilderError};
use crate::{
	NOTE_BATCH, StandardAccount, SubpoolId,
	plonky2_gadgets::priv_tx::{targets::TxKindFlags, utils::fake_approval_key},
	pool_config::{SubpoolConfig, SubpoolFullProof},
};

/// Builder for constructing fake (dummy) transactions.
///
/// Fake transactions have `not_fake_tx = false` and are used to pad empty
/// aggregation slots. No circuit constraints are enforced beyond the boolean
/// shape of `not_fake_tx`.
pub struct FakeTxBuilder {
	/// State tree root (passed through to public inputs, not enforced)
	state_root: HashOutput,

	/// Main pool config root (passed through to public inputs, not enforced)
	mainpool_config_root: HashOutput,
}

/// Validated, ready-to-prove fake transaction.
pub struct BuiltFakeTx {
	/// State tree root
	state_root: HashOutput,

	/// Main pool config root
	mainpool_config_root: HashOutput,
}

impl FakeTxBuilder {
	/// Create a new fake transaction builder.
	pub fn new(state_root: HashOutput, mainpool_config_root: HashOutput) -> Self {
		Self {
			state_root,
			mainpool_config_root,
		}
	}

	/// Build the fake transaction (infallible — no validation needed).
	pub fn build(self) -> BuiltFakeTx {
		BuiltFakeTx {
			state_root: self.state_root,
			mainpool_config_root: self.mainpool_config_root,
		}
	}
}

impl BuiltFakeTx {
	/// Convert this built fake transaction to a unified [`BuiltPrivTx`].
	///
	/// Populates all fields with dummy/zero values. Since `not_fake_tx = false`,
	/// the circuit does not enforce any of these values. The accin nullifier and
	/// accout commitment in the public inputs are derived from the fixed fake
	/// accounts (`StandardAccount::fake()`).
	pub fn into_priv_tx(self) -> BuiltPrivTx {
		let accin = StandardAccount::fake();
		let accout = accin.clone_with_incremented_nonce();

		// Get a real subpool proof built from the fake authority key.
		// The circuit does not verify this when not_fake_tx = false.
		let approval_key = fake_approval_key();

		// Dummy account merkle proof (not enforced for fake tx)
		let dummy_merkle_proof = tessera_trees::MerkleProof {
			leaf: HashOutput([F::ZERO; 4]),
			siblings: vec![HashOutput([F::ZERO; 4]); crate::STATE_TREE_DEPTH],
			path: vec![false; crate::STATE_TREE_DEPTH],
			pos: 0,
			num_leaves: 0,
			root: HashOutput([F::ZERO; 4]),
		};

		// Fake signatures (circuit does not verify when not_fake_tx = false)
		let spend_pk = accin.spend_pk_or_default();
		let consume_pk = accin.consume_pk_or_default();

		BuiltPrivTx {
			tx_kind_flags: TxKindFlags::FAKE,

			// Account data
			accin,
			accout,
			accin_merkle_proof: dummy_merkle_proof,

			// No real notes or reject pairs
			rejected_inotes: Vec::new(),
			rejected_inotes_nct_proofs: Vec::new(),
			inotes: Vec::new(),
			inotes_nct_proofs: Vec::new(),
			onotes: Vec::new(),

			// Zero dummy note seeds
			dinotes: vec![[F::ZERO; 4]; NOTE_BATCH],
			donotes: vec![[F::ZERO; 4]; NOTE_BATCH],

			// Zero tx hash (not enforced)
			tx_hash: HashOutput([F::ZERO; 4]),

			// Roots from caller
			state_root: self.state_root,

			// Pool config
			subpool_id: SubpoolId::ZERO,
			mainpool_config_root: self.mainpool_config_root,
			subpool_proof: SubpoolFullProof::default(),
			approval_key,

			spend_sig: None,
			consume_sig: None,
			approval_sig: None,
		}
	}
}
