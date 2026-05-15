//! Builder for FreshAcc transactions.

use std::array;

use plonky2_field::types::Field;
use rand::CryptoRng;
use tessera_utils::{F, hasher::HashOutput};

use super::{
	BuiltPrivTx,
	errors::{FreshAccTxBuilderError, TxSignError},
};
use crate::{
	ConsumeAuth, NOTE_BATCH, NoteCommitment, NoteNullifier, SpendAuth, StandardAccount, SubpoolId,
	derive_priv_tx_hash,
	plonky2_gadgets::priv_tx::{targets::TxKindFlags, utils::double_hash_native},
	pool_config::SubpoolFullProof,
	schnorr::{CompressedPublicKey, PrivateKey, Scalar, Signature, schnorr_sign},
};

/// Builder for constructing FreshAcc transactions with validation.
pub struct FreshAccTxBuilder {
	/// Input account (must have nonce=0)
	accin: StandardAccount,

	/// New spend authorization (set via with_new_spend_key)
	new_spend_auth: Option<SpendAuth>,

	/// New consume authorization (set via with_new_consume_key or with_delegated_consume)
	new_consume_auth: Option<ConsumeAuth>,

	/// Pre-sampled dummy input note seeds (None → deterministic defaults in build())
	dinotes: Option<Vec<[F; 4]>>,

	/// Pre-sampled dummy output note seeds (None → deterministic defaults in build())
	donotes: Option<Vec<[F; 4]>>,
}

/// Validated, ready-to-prove FreshAcc transaction.
pub struct BuiltFreshAccTx {
	/// Input account (nonce=0)
	accin: StandardAccount,

	/// Output account (nonce=1, with new auth keys)
	accout: StandardAccount,

	/// Dummy input note seeds (length = NOTE_BATCH)
	dinotes: Vec<[F; 4]>,

	/// Dummy output note seeds (length = NOTE_BATCH)
	donotes: Vec<[F; 4]>,

	/// Transaction hash
	tx_hash: HashOutput,

	/// Subpool ID (from accin)
	subpool_id: SubpoolId,

	/// State tree root (set via with_state_root)
	state_root: Option<HashOutput>,

	/// Subpool merkle proof in the main pool config tree (set via with_subpool_proof)
	subpool_proof: Option<SubpoolFullProof<HashOutput>>,

	/// Approval signature (set via approval_sign)
	approval_sig: Option<Signature>,
}

impl FreshAccTxBuilder {
	/// Create a new FreshAcc transaction builder.
	///
	/// # Errors
	/// - `AccountAlreadyInitialized`: Account has nonce != 0
	pub fn new(accin: StandardAccount) -> Result<Self, FreshAccTxBuilderError> {
		if accin.nonce.0 != F::ZERO {
			return Err(FreshAccTxBuilderError::AccountAlreadyInitialized);
		}

		Ok(Self {
			accin,
			new_spend_auth: None,
			new_consume_auth: None,
			dinotes: None,
			donotes: None,
		})
	}

	/// Set the new spend authorization key.
	pub fn with_new_spend_key(mut self, spend_pk: CompressedPublicKey<F>) -> Self {
		self.new_spend_auth = Some(SpendAuth::new(spend_pk));
		self
	}

	/// Set the new consume authorization key (non-delegated mode).
	pub fn with_new_consume_key(mut self, consume_pk: CompressedPublicKey<F>) -> Self {
		self.new_consume_auth = Some(ConsumeAuth {
			config: true,
			pk: Some(consume_pk),
		});
		self
	}

	/// Set consume authorization to delegated mode.
	pub fn with_delegated_consume(mut self) -> Self {
		self.new_consume_auth = Some(ConsumeAuth {
			config: false,
			pk: None,
		});
		self
	}

	/// Sample random dummy input note seeds for all NOTE_BATCH inactive inote slots.
	pub fn fill_dinotes<R: rand::Rng>(mut self, rng: &mut R) -> Self {
		self.dinotes = Some(
			(0..NOTE_BATCH)
				.map(|_| core::array::from_fn(|_| F::from_noncanonical_u64(rng.next_u64())))
				.collect(),
		);
		self
	}

	/// Sample random dummy output note seeds for all NOTE_BATCH inactive onote slots.
	pub fn fill_donotes<R: rand::Rng>(mut self, rng: &mut R) -> Self {
		self.donotes = Some(
			(0..NOTE_BATCH)
				.map(|_| core::array::from_fn(|_| F::from_noncanonical_u64(rng.next_u64())))
				.collect(),
		);
		self
	}

	/// Validate inputs and compute all derived values.
	///
	/// # Errors
	/// - `SpendKeyNotSet`: Must call with_new_spend_key() first
	/// - `ConsumeKeyNotSet`: Must call with_new_consume_key() or with_delegated_consume() first
	/// - `DummyNotesNotFilled`: `fill_dinotes()` or `fill_donotes()` was not called
	pub fn build(self) -> Result<BuiltFreshAccTx, FreshAccTxBuilderError> {
		let new_spend_auth = self
			.new_spend_auth
			.ok_or(FreshAccTxBuilderError::SpendKeyNotSet)?;
		let new_consume_auth = self
			.new_consume_auth
			.ok_or(FreshAccTxBuilderError::ConsumeKeyNotSet)?;

		let subpool_id = self.accin.subpool_id;

		let mut accout = self.accin.clone_with_incremented_nonce();
		accout.spend_auth = new_spend_auth.clone();
		accout.consume_auth = new_consume_auth.clone();

		let dinotes = self
			.dinotes
			.ok_or(FreshAccTxBuilderError::DummyNotesNotFilled {
				kind: "input",
			})?;
		let donotes = self
			.donotes
			.ok_or(FreshAccTxBuilderError::DummyNotesNotFilled {
				kind: "output",
			})?;

		let dinote_nulls: [NoteNullifier; NOTE_BATCH] =
			array::from_fn(|i| NoteNullifier(HashOutput(double_hash_native(dinotes[i]))));
		let donote_comms: [NoteCommitment; NOTE_BATCH] =
			array::from_fn(|i| NoteCommitment(HashOutput(double_hash_native(donotes[i]))));

		let accin_null = self.accin.nullifier();
		let tx_hash =
			derive_priv_tx_hash(accin_null, accout.commitment(), dinote_nulls, donote_comms);

		Ok(BuiltFreshAccTx {
			accin: self.accin,
			accout,
			dinotes,
			donotes,
			tx_hash,
			subpool_id,
			state_root: None,
			subpool_proof: None,
			approval_sig: None,
		})
	}
}

impl BuiltFreshAccTx {
	/// Generate and store the approval signature for this transaction.
	///
	/// Approval signature is ALWAYS required for FreshAcc transactions.
	/// Returns `self` to allow chaining.
	pub fn approval_sign<R: CryptoRng + rand::Rng>(
		mut self,
		approval_sk: &PrivateKey,
		rng: &mut R,
	) -> Result<Self, TxSignError> {
		let k = Scalar::sample(rng);
		let sig = schnorr_sign(approval_sk, &self.tx_hash.0, k);
		self.approval_sig = Some(sig);
		Ok(self)
	}

	/// Get the transaction hash that needs to be signed.
	pub fn tx_hash(&self) -> &HashOutput {
		&self.tx_hash
	}

	/// Set the state tree root.
	///
	/// Because FreshAcc accounts are not yet committed to the state tree, the
	/// state root must be provided explicitly (no account merkle proof exists).
	/// Must be called before `into_priv_tx`.
	pub fn with_state_root(mut self, state_root: HashOutput) -> Self {
		self.state_root = Some(state_root);
		self
	}

	/// Provide the subpool merkle proof in the main pool config tree.
	///
	/// The main pool config root is derived from `subpool_proof.main_pool_proof.root`.
	/// The approval key is derived from `subpool_proof.subpool_config.approval_key()`.
	/// Must be called before `into_priv_tx`.
	pub fn with_subpool_proof(mut self, subpool_proof: SubpoolFullProof<HashOutput>) -> Self {
		self.subpool_proof = Some(subpool_proof);
		self
	}

	/// Convert this built FreshAcc transaction to a unified `BuiltPrivTx`.
	///
	/// Requires `approval_sign`, `with_state_root`, and `with_subpool_proof` to
	/// have been called first.
	///
	/// # Errors
	/// - `ApprovalSigNotSet`: `approval_sign` was not called
	/// - `StateRootNotSet`: `with_state_root` was not called
	/// - `SubpoolProofNotSet`: `with_subpool_proof` was not called
	pub fn into_priv_tx(self) -> Result<BuiltPrivTx, FreshAccTxBuilderError> {
		let approval_sig = self
			.approval_sig
			.ok_or(FreshAccTxBuilderError::ApprovalSigNotSet)?;
		let state_root = self
			.state_root
			.ok_or(FreshAccTxBuilderError::StateRootNotSet)?;
		let subpool_proof = self
			.subpool_proof
			.ok_or(FreshAccTxBuilderError::SubpoolProofNotSet)?;

		let mainpool_config_root = subpool_proof.main_pool_proof.root;
		let approval_key = subpool_proof.subpool_config.approval_key();

		// Dummy account merkle proof — FreshAcc accounts are not yet in the state tree
		let dummy_merkle_proof = tessera_trees::MerkleProof {
			leaf: HashOutput([F::ZERO; 4]),
			siblings: vec![HashOutput([F::ZERO; 4]); crate::STATE_TREE_DEPTH],
			path: vec![false; crate::STATE_TREE_DEPTH],
			pos: 0,
			num_leaves: 0,
			root: HashOutput([F::ZERO; 4]),
		};

		Ok(BuiltPrivTx {
			tx_kind_flags: TxKindFlags::FRESH_ACC,

			accin: self.accin,
			accout: self.accout,
			accin_merkle_proof: dummy_merkle_proof,

			rejected_inotes: Vec::new(),
			rejected_inotes_nct_proofs: Vec::new(),
			inotes: Vec::new(),
			inotes_nct_proofs: Vec::new(),
			onotes: Vec::new(),

			dinotes: self.dinotes,
			donotes: self.donotes,

			tx_hash: self.tx_hash,
			state_root,

			subpool_id: self.subpool_id,
			mainpool_config_root,
			subpool_proof,
			approval_key,

			spend_sig: None,
			consume_sig: None,
			approval_sig: Some(approval_sig),
		})
	}
}
