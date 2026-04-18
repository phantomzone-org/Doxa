//! Builder for Spend transactions.

use std::{array, sync::Arc};

use plonky2_field::types::Field;
use primitive_types::U256;
use rand::CryptoRng;
use tessera_trees::MerkleTree;
use tessera_utils::{F, hasher::HashOutput};

use super::{
	BuiltPrivTx,
	errors::{SpendTxBuilderError, TxSignError},
};
use crate::{
	AccountAddress, AssetId, NOTE_BATCH, NoteCommitment, NoteNullifier, StandardAccount,
	StandardNote, SubpoolId, derive_priv_tx_hash,
	plonky2_gadgets::priv_tx::{targets::TxKindFlags, utils::double_hash_native},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfig},
	schnorr::{CompressedPublicKey, PrivateKey, Scalar, Signature, schnorr_sign},
};

/// Builder for constructing spend transactions with validation.
pub struct SpendTxBuilder {
	/// Input account (must exist in state tree)
	accin: StandardAccount,

	/// Asset being transacted
	asset_id: AssetId,

	/// Subpool approval key
	approval_key: CompPubKey,

	/// Accumulated input notes with their positions
	input_notes: Vec<(StandardNote, usize)>,

	/// Accumulated output notes
	output_notes: Vec<StandardNote>,

	/// Rejected input notes with their state-tree positions (returned to sender)
	rejected_notes: Vec<(StandardNote, usize)>,

	/// Pre-sampled dummy input note seeds (must be set via fill_dinotes before build())
	dinotes: Option<Vec<[F; 4]>>,

	/// Pre-sampled dummy output note seeds (must be set via fill_donotes before build())
	donotes: Option<Vec<[F; 4]>>,
}

/// Validated, ready-to-prove spend transaction.
pub struct BuiltSpendTx {
	/// Original input account
	accin: StandardAccount,

	/// Derived output account (nonce+1, AST updated)
	accout: StandardAccount,

	/// Rejected input notes with their state-tree positions
	rejected_inotes: Vec<(StandardNote, usize)>,

	/// Input notes with their positions in the state tree
	inotes: Vec<(StandardNote, usize)>,

	/// Output notes
	onotes: Vec<StandardNote>,

	/// Dummy input note seeds (length = NOTE_BATCH - inotes.len() - rejected_inotes.len())
	dinotes: Vec<[F; 4]>,

	/// Dummy output note seeds (length = NOTE_BATCH - onotes.len() - rejected_inotes.len())
	donotes: Vec<[F; 4]>,

	/// Transaction hash (computed with placeholder nullifiers)
	tx_hash: HashOutput,

	/// Subpool ID (from accin)
	subpool_id: SubpoolId,

	/// Subpool approval key
	approval_key: CompPubKey,
}

/// Spend-specific signature bundle.
#[derive(Debug, Clone)]
pub struct SpendTxSignatures {
	pub spend_sig: Option<Signature>,
	pub consume_sig: Option<Signature>,
	pub approval_sig: Signature,
}

/// Information about which signatures are required for a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequiredSignatures {
	pub spend: bool,
	pub consume: bool,
	pub approval: bool,
}

impl SpendTxBuilder {
	/// Create a new spend transaction builder.
	///
	/// # Arguments
	/// - `accin`: Input account (must exist in state tree with nonce > 0)
	/// - `asset_id`: Asset being transacted
	/// - `approval_key`: Subpool approval key
	///
	/// Note: `subpool_id` is automatically extracted from `accin.subpool_id`
	///
	/// # Errors
	/// - `AccountNotInitialized`: Account has nonce=0 (must perform FreshAcc first)
	pub fn new(
		accin: StandardAccount,
		asset_id: AssetId,
		approval_key: crate::pool_config::CompPubKey, // TODO: why is approval_key provided here?
	) -> Result<Self, SpendTxBuilderError> {
		// Validate preconditions
		if accin.nonce.0 == F::ZERO {
			return Err(SpendTxBuilderError::AccountNotInitialized);
		}

		Ok(Self {
			accin,
			asset_id,
			approval_key,
			input_notes: Vec::new(),
			output_notes: Vec::new(),
			rejected_notes: Vec::new(),
			dinotes: None,
			donotes: None,
		})
	}

	/// Add an input note to consume.
	///
	/// # Arguments
	/// - `note`: The note to consume
	/// - `position`: Position of the note in the state tree
	///
	/// # Errors
	/// - `NoteBatchLimitReached`: Already have NOTE_BATCH input notes
	/// - `AssetMismatch`: Note's asset_id doesn't match builder's asset_id
	/// - `RecipientMismatch`: Note recipient doesn't match accin
	pub fn add_input_note(
		mut self,
		note: StandardNote,
		position: usize,
	) -> Result<Self, SpendTxBuilderError> {
		// Validate note batch limit: rejected + input slots must not exceed NOTE_BATCH
		if self.rejected_notes.len() + self.input_notes.len() + 1 > NOTE_BATCH {
			return Err(SpendTxBuilderError::NoteBatchLimitReached {
				kind: "input",
				limit: NOTE_BATCH,
			});
		}

		// Validate asset_id matches
		if note.asset_id != self.asset_id {
			return Err(SpendTxBuilderError::AssetMismatch {
				expected: self.asset_id,
				got: note.asset_id,
			});
		}

		// Validate recipient matches account
		let expected_recipient = AccountAddress::from_acc(&self.accin);
		if note.recipient != expected_recipient {
			return Err(SpendTxBuilderError::RecipientMismatch);
		}

		self.input_notes.push((note, position));
		Ok(self)
	}

	/// Add an output note to create.
	///
	/// The note identifier will be randomly generated.
	///
	/// # Errors
	/// - `NoteBatchLimitReached`: Already have NOTE_BATCH output notes
	pub fn add_output_note<R: rand::CryptoRng + rand::Rng>(
		mut self,
		recipient: AccountAddress,
		amount: U256,
		memo: [u8; 512],
		rng: &mut R,
	) -> Result<Self, SpendTxBuilderError> {
		// Validate note batch limit: rejected + output slots must not exceed NOTE_BATCH
		if self.rejected_notes.len() + self.output_notes.len() + 1 > NOTE_BATCH {
			return Err(SpendTxBuilderError::NoteBatchLimitReached {
				kind: "output",
				limit: NOTE_BATCH,
			});
		}

		let sender = AccountAddress::from_acc(&self.accin);
		let note = StandardNote::create(rng, recipient, sender, amount, self.asset_id, memo);

		self.output_notes.push(note);
		Ok(self)
	}

	/// Add a rejected input note (will be returned to its original sender).
	///
	/// The note is consumed from the input side and a mirror output note
	/// (recipient = sender) is generated automatically by the proving layer.
	///
	/// # Errors
	/// - `NoteBatchLimitReached`: Adding this note would exceed NOTE_BATCH slots
	/// - `AssetMismatch`: Note asset_id doesn't match transaction asset_id
	/// - `RecipientMismatch`: Note recipient doesn't match accin
	pub fn add_rejected_note(
		mut self,
		note: StandardNote,
		position: usize,
	) -> Result<Self, SpendTxBuilderError> {
		// Validate note batch limit: each reject pair occupies one inote and one onote slot,
		// so both rejected+input and rejected+output must stay within NOTE_BATCH.
		if self.rejected_notes.len() + 1 + self.input_notes.len().max(self.output_notes.len())
			> NOTE_BATCH
		{
			return Err(SpendTxBuilderError::NoteBatchLimitReached {
				kind: "rejected",
				limit: NOTE_BATCH,
			});
		}
		if note.asset_id != self.asset_id {
			return Err(SpendTxBuilderError::AssetMismatch {
				expected: self.asset_id,
				got: note.asset_id,
			});
		}
		if note.recipient != AccountAddress::from_acc(&self.accin) {
			return Err(SpendTxBuilderError::RecipientMismatch);
		}
		self.rejected_notes.push((note, position));
		Ok(self)
	}

	/// Sample random dummy input note seeds for the inactive inote slots.
	///
	/// Must be called after all input notes and rejected notes have been added
	/// (seed count = `NOTE_BATCH - input_notes.len() - rejected_notes.len()`),
	/// and before `build()` — which will error if dinotes are absent.
	pub fn fill_dinotes<R: rand::Rng>(mut self, rng: &mut R) -> Self {
		let count = NOTE_BATCH - self.input_notes.len() - self.rejected_notes.len();
		self.dinotes = Some(
			(0..count)
				.map(|_| core::array::from_fn(|_| F::from_noncanonical_u64(rng.next_u64())))
				.collect(),
		);
		self
	}

	/// Sample random dummy output note seeds for the inactive onote slots.
	///
	/// Must be called after all output notes and rejected notes have been added
	/// (seed count = `NOTE_BATCH - output_notes.len() - rejected_notes.len()`),
	/// and before `build()` — which will error if donotes are absent.
	pub fn fill_donotes<R: rand::Rng>(mut self, rng: &mut R) -> Self {
		let count = NOTE_BATCH - self.output_notes.len() - self.rejected_notes.len();
		self.donotes = Some(
			(0..count)
				.map(|_| core::array::from_fn(|_| F::from_noncanonical_u64(rng.next_u64())))
				.collect(),
		);
		self
	}

	/// Validate inputs and compute all derived values.
	///
	/// This method:
	/// 1. Validates transaction consistency (balances, etc.)
	/// 2. Derives accout (output account state)
	/// 3. Generates dummy notes for padding
	/// 4. Computes tx_hash (with placeholder nullifiers)
	///
	/// Note: Merkle proofs are NOT generated here. They will be generated later
	/// in `into_priv_tx_with_signatures()` when the state tree is available.
	///
	/// # Errors
	/// - `NoActiveNotes`: Must have at least one input, output, or rejected note
	/// - `InsufficientBalance`: Outputs exceed inputs + existing balance
	/// - `DummyNotesNotFilled`: `fill_dinotes()` or `fill_donotes()` was not called
	pub fn build(self) -> Result<BuiltSpendTx, SpendTxBuilderError> {
		// Validation
		if self.input_notes.is_empty()
			&& self.output_notes.is_empty()
			&& self.rejected_notes.is_empty()
		{
			return Err(SpendTxBuilderError::NoActiveNotes);
		}

		let n_rjct = self.rejected_notes.len();
		let n_in = self.input_notes.len();
		let n_out = self.output_notes.len();

		// Extract subpool_id from accin
		let subpool_id = self.accin.subpool_id;

		// Compute balance changes (rejected notes cancel out: consumed then re-emitted)
		let delta_in: U256 = self
			.input_notes
			.iter()
			.map(|(note, _)| note.amt)
			.fold(U256::zero(), |a, b| a + b);
		let delta_out: U256 = self
			.output_notes
			.iter()
			.map(|note| note.amt)
			.fold(U256::zero(), |a, b| a + b);

		let (ast_index, old_bal) = self
			.accin
			.ast
			.amount_for(self.asset_id)
			.unwrap_or_else(|| (self.accin.ast.next_index(), U256::zero()));

		// Validate balance (old_bal + delta_in >= delta_out)
		let new_bal = old_bal
			.checked_add(delta_in)
			.and_then(|b| b.checked_sub(delta_out))
			.ok_or(SpendTxBuilderError::InsufficientBalance {
				old_balance: old_bal,
				delta_in,
				delta_out,
			})?;

		// Derive accout
		let mut accout = self.accin.clone_with_incremented_nonce();
		accout.ast.insert_or_update_asset(self.asset_id, new_bal);

		// Require that dummy note seeds have been explicitly sampled via fill_dinotes/fill_donotes
		// TODO: I find it better to store dinotes, donotes as Vec::new() and throw error when
		// vector length is 0, instead of setting them to an option
		let dinotes = self
			.dinotes
			.ok_or(SpendTxBuilderError::DummyNotesNotFilled {
				kind: "input",
			})?;
		let donotes = self
			.donotes
			.ok_or(SpendTxBuilderError::DummyNotesNotFilled {
				kind: "output",
			})?;

		// Compute tx_hash: reject pairs occupy slots 0..n_rjct,
		// regular notes follow, then dummy seeds.
		let nk = self.accin.nk();
		let tx_inote_nulls: [NoteNullifier; NOTE_BATCH] = array::from_fn(|i| {
			if i < n_rjct {
				let (note, pos) = &self.rejected_notes[i];
				note.nullifier(*pos, &nk).unwrap()
			} else {
				let j = i - n_rjct;
				if j < n_in {
					let (note, pos) = &self.input_notes[j];
					note.nullifier(*pos, &nk).unwrap()
				} else {
					NoteNullifier(HashOutput(double_hash_native(dinotes[j - n_in])))
				}
			}
		});

		let tx_onote_comms: [NoteCommitment; NOTE_BATCH] = array::from_fn(|i| {
			if i < n_rjct {
				let (inote, _) = &self.rejected_notes[i];
				let mut onote = inote.clone();
				onote.recipient = inote.sender;
				onote.commitment()
			} else {
				let j = i - n_rjct;
				if j < n_out {
					self.output_notes[j].commitment()
				} else {
					NoteCommitment(HashOutput(double_hash_native(donotes[j - n_out])))
				}
			}
		});

		let accin_null = self.accin.nullifier();
		let tx_hash = derive_priv_tx_hash(
			accin_null,
			accout.commitment(),
			tx_inote_nulls,
			tx_onote_comms,
		);

		Ok(BuiltSpendTx {
			accin: self.accin,
			accout,
			rejected_inotes: self.rejected_notes,
			inotes: self.input_notes,
			onotes: self.output_notes,
			dinotes,
			donotes,
			tx_hash,
			subpool_id,
			approval_key: self.approval_key,
		})
	}
}

impl BuiltSpendTx {
	/// Generate consume signature for this transaction.
	///
	/// This signature is required when:
	/// - There are active input notes (consuming assets), AND
	/// - There are no active output notes, AND
	/// - Consume auth is NOT delegated to subpool owner
	///
	/// # Arguments
	/// - `consume_sk`: Private key corresponding to `accin.consume_auth.pk`
	/// - `rng`: Random number generator for signature randomness
	///
	/// # Returns
	/// `Some(Signature)` if consume signature is required, `None` otherwise
	///
	/// # Errors
	/// - `ConsumeDelegated`: Called when consume is delegated (config = false)
	/// - `ConsumeNotRequired`: Called when no input notes or has output notes
	/// - `ConsumeKeyNotSet`: accin.consume_auth.pk is None
	/// - `KeyMismatch`: Provided key doesn't match accin.consume_auth.pk
	pub fn consume_sign<R: CryptoRng + rand::Rng>(
		&self,
		consume_sk: &PrivateKey,
		rng: &mut R,
	) -> Result<Option<Signature>, TxSignError> {
		// Check if consume signature is needed.
		// Rejected notes count as active input notes for this check.
		let no_input_notes = self.inotes.is_empty() && self.rejected_inotes.is_empty();
		let has_output_notes = !self.onotes.is_empty();

		if no_input_notes || has_output_notes {
			return Err(TxSignError::ConsumeNotRequired {
				has_input_notes: !no_input_notes,
				has_output_notes,
			});
		}

		if !self.accin.consume_auth.config {
			return Err(TxSignError::ConsumeDelegated);
		}

		// Verify key is set
		let expected_pk = self
			.accin
			.consume_auth
			.pk
			.ok_or(TxSignError::ConsumeKeyNotSet)?;

		// Verify key matches
		let provided_pk: CompressedPublicKey<F> = consume_sk.public_key().into();

		if expected_pk != provided_pk {
			return Err(TxSignError::KeyMismatch {
				key_type: "consume",
				expected: expected_pk,
				provided: provided_pk,
			});
		}

		// Generate signature
		let k = Scalar::sample(rng);
		let sig = schnorr_sign(consume_sk, &self.tx_hash.0, k);
		Ok(Some(sig))
	}

	/// Generate spend signature for this transaction.
	///
	/// This signature is required when there are active output notes.
	///
	/// # Arguments
	/// - `spend_sk`: Private key corresponding to `accin.spend_auth.spend_pk`
	/// - `rng`: Random number generator for signature randomness
	///
	/// # Returns
	/// `Some(Signature)` if spend signature is required, `None` otherwise
	///
	/// # Errors
	/// - `SpendNotRequired`: Called when no output notes exist
	/// - `SpendKeyNotSet`: accin.spend_auth.spend_pk is None
	/// - `KeyMismatch`: Provided key doesn't match accin.spend_auth.spend_pk
	pub fn spend_sign<R: CryptoRng + rand::Rng>(
		&self,
		spend_sk: &PrivateKey,
		rng: &mut R,
	) -> Result<Option<Signature>, TxSignError> {
		// Check if spend signature is needed
		if self.onotes.is_empty() {
			return Err(TxSignError::SpendNotRequired);
		}

		// Verify key is set
		let expected_pk = self
			.accin
			.spend_auth
			.spend_pk
			.ok_or(TxSignError::SpendKeyNotSet)?;

		// Verify key matches
		let provided_pk: CompressedPublicKey<F> = spend_sk.public_key().into();

		if expected_pk != provided_pk {
			return Err(TxSignError::KeyMismatch {
				key_type: "spend",
				expected: expected_pk,
				provided: provided_pk,
			});
		}

		// Generate signature
		let k = Scalar::sample(rng);
		let sig = schnorr_sign(spend_sk, &self.tx_hash.0, k);
		Ok(Some(sig))
	}

	/// Generate approval signature for this transaction.
	///
	/// Approval signature is ALWAYS required for all spend transactions.
	///
	/// # Arguments
	/// - `approval_sk`: Private key for subpool approval key
	/// - `rng`: Random number generator for signature randomness
	///
	/// # Errors
	/// - `KeyMismatch`: Provided key doesn't match subpool's approval key
	pub fn approval_sign<R: CryptoRng + rand::Rng>(
		&self,
		approval_sk: &PrivateKey,
		rng: &mut R,
	) -> Result<Signature, TxSignError> {
		// Verify key matches
		let provided_pk: CompressedPublicKey<F> = approval_sk.public_key().into();

		if self.approval_key != provided_pk {
			return Err(TxSignError::KeyMismatch {
				key_type: "approval",
				expected: self.approval_key,
				provided: provided_pk,
			});
		}

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

	/// Check which signatures are required for this transaction.
	pub fn required_signatures(&self) -> RequiredSignatures {
		RequiredSignatures {
			spend: !self.onotes.is_empty(),
			consume: !self.inotes.is_empty()
				&& self.onotes.is_empty()
				&& self.accin.consume_auth.config,
			approval: true, // Always required
		}
	}

	/// Convert this built spend transaction to a unified BuiltPrivTx with signatures.
	///
	/// This method populates all fields needed for the circuit, including:
	/// - Setting tx_kind_flags to SPEND
	/// - Generating merkle proofs from the provided trees
	/// - Copying relevant spend-specific data
	/// - Including the provided signatures (or fake signatures if not provided)
	///
	/// # Arguments
	/// - `signatures`: Signature bundle for this transaction
	/// - `state_tree`: State tree to generate merkle proofs from
	/// - `main_pool`: Main pool config tree
	///
	/// This is the bridge between the ergonomic builder API and the unified
	/// proving interface.
	///
	/// # Errors
	/// - `AccountNotInTree`: Account commitment not found in state tree
	/// - `NoteNotInTree`: Input note commitment not found in state tree
	pub fn into_priv_tx_with_signatures(
		self,
		signatures: SpendTxSignatures,
		state_tree: &MerkleTree<HashOutput>,
		main_pool: Arc<MainPoolConfigTree<HashOutput>>,
	) -> Result<BuiltPrivTx, SpendTxBuilderError> {
		// TODO return an error if necessary signatures are not set

		// Get state root
		let state_root = state_tree.root();

		// Get main pool root and compute subpool proof
		let main_pool_root = main_pool.root();

		// Create a temporary SubpoolConfig to get the subpool proof
		let subpool_config = SubpoolConfig::new(self.approval_key);
		let subpool_full_proof = main_pool.full_subpool_proof(&subpool_config, self.subpool_id)?;

		// Generate merkle proof for accin
		let accin_comm = self.accin.commitment();

		// Search for account commitment in state tree leaves
		// TODO: add a `find` method to MerkleTree
		let accin_pos = state_tree
			.leaves()
			.iter()
			.position(|&leaf| leaf == accin_comm.0)
			.ok_or(SpendTxBuilderError::AccountNotInTree)?;
		let accin_merkle_proof = state_tree.merkle_proof(accin_pos)?;

		// Generate merkle proofs for rejected input notes
		let mut rejected_inotes_nct_proofs = Vec::with_capacity(self.rejected_inotes.len());
		for (_note, pos) in &self.rejected_inotes {
			rejected_inotes_nct_proofs.push(state_tree.merkle_proof(*pos)?);
		}

		// Generate merkle proofs for regular input notes using stored positions
		let mut inotes_nct_proofs = Vec::with_capacity(self.inotes.len());
		for (_note, pos) in &self.inotes {
			// TODO: verify that position of the input note is indeed correct
			inotes_nct_proofs.push(state_tree.merkle_proof(*pos)?);
		}

		// Extract public keys before moving self.accin
		let spend_pk = self.accin.spend_pk_or_default();
		let consume_pk = self.accin.consume_pk_or_default();

		// dinotes/donotes are already correctly sized from build() — no slicing needed.

		Ok(BuiltPrivTx {
			tx_kind_flags: TxKindFlags::SPEND,

			// Accounts
			accin: self.accin,
			accout: self.accout,
			accin_merkle_proof,

			// Reject pairs
			rejected_inotes: self.rejected_inotes.into_iter().map(|(n, _)| n).collect(),
			rejected_inotes_nct_proofs,

			// Notes (extract just the notes, positions already used for proofs)
			inotes: self.inotes.into_iter().map(|(n, _)| n).collect(),
			inotes_nct_proofs,
			onotes: self.onotes,

			// Dummy notes (already correctly sized from build())
			dinotes: self.dinotes,
			donotes: self.donotes,

			// Computed values
			tx_hash: self.tx_hash,
			state_root,

			// Pool config
			subpool_id: self.subpool_id,
			mainpool_config_root: main_pool_root,
			subpool_proof: subpool_full_proof,
			approval_key: self.approval_key,

			spend_sig: signatures.spend_sig,
			consume_sig: signatures.consume_sig,
			approval_sig: Some(signatures.approval_sig),
		})
	}
}

impl SpendTxSignatures {
	/// Create a new signature bundle.
	pub fn new(
		spend_sig: Option<Signature>,
		consume_sig: Option<Signature>,
		approval_sig: Signature,
	) -> Self {
		Self {
			spend_sig,
			consume_sig,
			approval_sig,
		}
	}
}
