//! Builder for FreshAcc transactions.

use std::{array, sync::Arc};

use plonky2_field::types::Field;
use rand::CryptoRng;
use tessera_trees::MerkleTree;
use tessera_utils::{F, hasher::HashOutput};

use super::{
	BuiltPrivTx,
	errors::{FreshAccTxBuilderError, TxSignError},
};
use crate::{
	ConsumeAuth, NOTE_BATCH, NoteCommitment, NoteNullifier, SpendAuth, StandardAccount, SubpoolId,
	derive_priv_tx_hash,
	plonky2_gadgets::priv_tx::targets::TxKindFlags,
	pool_config::MainPoolConfigTree,
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
}

impl FreshAccTxBuilder {
	/// Create a new FreshAcc transaction builder.
	///
	/// # Arguments
	/// - `accin`: Input account (must have nonce=0)
	///
	/// Note: `subpool_id` is automatically extracted from `accin.subpool_id`
	///
	/// # Errors
	/// - `AccountAlreadyInitialized`: Account has nonce != 0
	pub fn new(accin: StandardAccount) -> Result<Self, FreshAccTxBuilderError> {
		// Validate that account is not initialized
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
	///
	/// This sets the spend public key that will be used to authorize
	/// spending from this account after FreshAcc.
	pub fn with_new_spend_key(mut self, spend_pk: CompressedPublicKey<F>) -> Self {
		self.new_spend_auth = Some(SpendAuth::new(spend_pk));
		self
	}

	/// Set the new consume authorization key (non-delegated mode).
	///
	/// This sets the consume public key that will be used to authorize
	/// consuming notes into this account.
	pub fn with_new_consume_key(mut self, consume_pk: CompressedPublicKey<F>) -> Self {
		self.new_consume_auth = Some(ConsumeAuth {
			config: true, // Non-delegated
			pk: Some(consume_pk),
		});
		self
	}

	/// Set consume authorization to delegated mode.
	///
	/// In delegated mode, the subpool owner's key is used for consume authorization.
	pub fn with_delegated_consume(mut self) -> Self {
		self.new_consume_auth = Some(ConsumeAuth {
			config: false, // Delegated
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
	/// This method:
	/// 1. Validates that spend and consume keys are set
	/// 2. Derives accout (output account with nonce=1 and new auth keys)
	/// 3. Generates dummy notes for padding
	/// 4. Computes tx_hash
	///
	/// # Arguments
	/// - `approval_key`: Subpool approval key (needed for signature verification)
	///
	/// # Errors
	/// - `SpendKeyNotSet`: Must call with_new_spend_key() first
	/// - `ConsumeKeyNotSet`: Must call with_new_consume_key() or with_delegated_consume() first
	pub fn build(self) -> Result<BuiltFreshAccTx, FreshAccTxBuilderError> {
		// Validate that required keys are set
		let new_spend_auth = self
			.new_spend_auth
			.ok_or(FreshAccTxBuilderError::SpendKeyNotSet)?;
		let new_consume_auth = self
			.new_consume_auth
			.ok_or(FreshAccTxBuilderError::ConsumeKeyNotSet)?;

		// Extract subpool_id from accin
		let subpool_id = self.accin.subpool_id;

		// Derive accout (nonce=1, new auth keys)
		let mut accout = self.accin.clone_with_incremented_nonce();
		accout.spend_auth = new_spend_auth.clone();
		accout.consume_auth = new_consume_auth.clone();

		// Generate dummy notes (all NOTE_BATCH slots are inactive for FreshAcc)
		let dinotes = self.dinotes.unwrap_or_else(|| {
			(0..NOTE_BATCH)
				.map(|i| [F::from_canonical_usize(i); 4])
				.collect()
		});
		let donotes = self.donotes.unwrap_or_else(|| {
			(0..NOTE_BATCH)
				.map(|i| [F::from_canonical_usize(i + NOTE_BATCH); 4])
				.collect()
		});

		// Compute tx_hash
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
		})
	}
}

impl BuiltFreshAccTx {
	/// Generate approval signature for this transaction.
	///
	/// Approval signature is ALWAYS required for all FreshAcc transactions.
	///
	/// # Arguments
	/// - `approval_sk`: Private key for subpool approval key
	/// - `rng`: Random number generator for signature randomness
	pub fn approval_sign<R: CryptoRng + rand::Rng>(
		&self,
		approval_sk: &PrivateKey,
		rng: &mut R,
	) -> Result<Signature, TxSignError> {
		// Generate signature
		let k = Scalar::sample(rng);
		let sig = schnorr_sign(approval_sk, &self.tx_hash.0, k);
		Ok(sig)
	}

	/// Get the transaction hash that needs to be signed.
	///
	/// Useful for external signing (e.g., hardware wallets, remote signers).
	pub fn tx_hash(&self) -> &HashOutput {
		&self.tx_hash
	}

	/// Convert this built FreshAcc transaction to a unified BuiltPrivTx with signature.
	///
	/// This method populates all fields needed for the circuit, including:
	/// - Setting tx_kind_flags to FRESH_ACC
	/// - Copying FreshAcc-specific data (new auth keys are in accout)
	/// - Filling unused fields (notes, proofs) with empty/dummy values
	/// - Including the provided approval signature
	/// - Providing fake/dummy signatures for spend and consume (not used in FreshAcc)
	///
	/// This is the bridge between the ergonomic builder API and the unified
	/// proving interface.
	pub fn into_priv_tx_with_signature(
		self,
		approval_sig: Signature,
		state_tree: &MerkleTree<HashOutput>,
		main_pool: Arc<MainPoolConfigTree<HashOutput>>,
		approval_key: crate::pool_config::CompPubKey,
	) -> Result<BuiltPrivTx, FreshAccTxBuilderError> {
		// Create a dummy merkle proof for FreshAcc (not validated by circuit)
		let dummy_merkle_proof = tessera_trees::MerkleProof {
			leaf: HashOutput([F::ZERO; 4]),
			siblings: vec![HashOutput([F::ZERO; 4]); crate::STATE_TREE_DEPTH],
			path: vec![false; crate::STATE_TREE_DEPTH],
			pos: 0,
			num_leaves: 0,
			root: HashOutput([F::ZERO; 4]),
		};

		// Get state root
		let state_root = state_tree.root();

		// Get main pool root and compute subpool proof
		let main_pool_root = main_pool.root();

		// Create a temporary SubpoolConfig to get the subpool proof
		let subpool_config = crate::pool_config::SubpoolConfig::new(approval_key);
		let subpool_proof = main_pool
			.full_subpool_proof(&subpool_config, self.subpool_id)
			.map_err(|e| anyhow::anyhow!("Failed to get subpool proof: {}", e))?;

		// Generate fake signatures for spend and consume (use public keys from accout)
		let spend_pk = self.accout.spend_pk_or_default();
		let consume_pk = self.accout.consume_pk_or_default();

		Ok(BuiltPrivTx {
			tx_kind_flags: TxKindFlags::FRESH_ACC,

			// Account data
			accin: self.accin,
			accout: self.accout,
			accin_merkle_proof: dummy_merkle_proof,

			// No reject pairs or regular notes for FreshAcc
			rejected_inotes: Vec::new(),
			rejected_inotes_nct_proofs: Vec::new(),
			inotes: Vec::new(),
			inotes_nct_proofs: Vec::new(),
			onotes: Vec::new(),

			// Dummy notes (Vec already, no conversion needed)
			dinotes: self.dinotes,
			donotes: self.donotes,

			// Computed values
			tx_hash: self.tx_hash,
			state_root,

			// Pool config
			subpool_id: self.subpool_id,
			main_pool_root,
			subpool_proof,
			approval_key,

			// Signatures (fake/dummy for spend and consume, real for approval)
			spend_sig: crate::schnorr::generate_fake_signature(&spend_pk),
			consume_sig: crate::schnorr::generate_fake_signature(&consume_pk),
			approval_sig,
		})
	}
}
