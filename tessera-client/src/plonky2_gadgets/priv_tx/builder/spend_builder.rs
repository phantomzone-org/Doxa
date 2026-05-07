//! Builder for Spend transactions.

use std::array;

use plonky2_field::types::Field;
use primitive_types::U256;
use rand::CryptoRng;
use tessera_trees::MerkleProof;
use tessera_utils::{F, hasher::HashOutput};

use super::{
	BuiltPrivTx,
	errors::{SpendTxBuilderError, TxSignError},
};
use crate::{
	AccountAddress, AssetId, NOTE_BATCH, NoteCommitment, NoteNullifier, StandardAccount,
	StandardNote, SubpoolId, derive_priv_tx_hash,
	plonky2_gadgets::priv_tx::{targets::TxKindFlags, utils::double_hash_native},
	pool_config::SubpoolFullProof,
	schnorr::{CompressedPublicKey, PrivateKey, Scalar, Signature, schnorr_sign},
};

/// Builder for constructing spend transactions with validation.
pub struct SpendTxBuilder {
	/// Input account (must exist in state tree)
	accin: StandardAccount,

	/// Asset being transacted
	asset_id: AssetId,

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

	/// Merkle proof of accin commitment in the state tree (set via with_account_path)
	accin_proof: Option<MerkleProof<HashOutput>>,

	/// Merkle proofs for regular input note commitments (set via with_input_notes_path)
	inotes_nct_proofs: Option<Vec<MerkleProof<HashOutput>>>,

	/// Merkle proofs for rejected input note commitments (set via with_rejected_notes_path)
	rejected_inotes_nct_proofs: Option<Vec<MerkleProof<HashOutput>>>,

	/// Subpool merkle proof in the main pool config tree (set via with_subpool_proof)
	subpool_proof: Option<SubpoolFullProof<HashOutput>>,

	/// Spend signature (set via spend_sign)
	spend_sig: Option<Signature>,

	/// Consume signature (set via consume_sign)
	consume_sig: Option<Signature>,

	/// Approval signature (set via approval_sign)
	approval_sig: Option<Signature>,
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
	/// # Errors
	/// - `AccountNotInitialized`: Account has nonce=0 (must perform FreshAcc first)
	pub fn new(accin: StandardAccount, asset_id: AssetId) -> Result<Self, SpendTxBuilderError> {
		if accin.nonce.0 == F::ZERO {
			return Err(SpendTxBuilderError::AccountNotInitialized);
		}

		Ok(Self {
			accin,
			asset_id,
			input_notes: Vec::new(),
			output_notes: Vec::new(),
			rejected_notes: Vec::new(),
			dinotes: None,
			donotes: None,
		})
	}

	/// Add an input note to consume.
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
		if self.rejected_notes.len() + self.input_notes.len() + 1 > NOTE_BATCH {
			return Err(SpendTxBuilderError::NoteBatchLimitReached {
				kind: "input",
				limit: NOTE_BATCH,
			});
		}

		if note.asset_id != self.asset_id {
			return Err(SpendTxBuilderError::AssetMismatch {
				expected: self.asset_id,
				got: note.asset_id,
			});
		}

		let expected_recipient = AccountAddress::from_acc(&self.accin);
		if note.recipient != expected_recipient {
			return Err(SpendTxBuilderError::RecipientMismatch);
		}

		self.input_notes.push((note, position));
		Ok(self)
	}

	/// Add an output note to create.
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
	/// # Errors
	/// - `NoteBatchLimitReached`: Adding this note would exceed NOTE_BATCH slots
	/// - `AssetMismatch`: Note asset_id doesn't match transaction asset_id
	/// - `RecipientMismatch`: Note recipient doesn't match accin
	pub fn add_rejected_note(
		mut self,
		note: StandardNote,
		position: usize,
	) -> Result<Self, SpendTxBuilderError> {
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
	/// # Errors
	/// - `NoActiveNotes`: Must have at least one input, output, or rejected note
	/// - `InsufficientBalance`: Outputs exceed inputs + existing balance
	/// - `DummyNotesNotFilled`: `fill_dinotes()` or `fill_donotes()` was not called
	pub fn build(self) -> Result<BuiltSpendTx, SpendTxBuilderError> {
		if self.input_notes.is_empty()
			&& self.output_notes.is_empty()
			&& self.rejected_notes.is_empty()
		{
			return Err(SpendTxBuilderError::NoActiveNotes);
		}

		let n_rjct = self.rejected_notes.len();
		let n_in = self.input_notes.len();
		let n_out = self.output_notes.len();

		let subpool_id = self.accin.subpool_id;

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

		let new_bal = old_bal
			.checked_add(delta_in)
			.and_then(|b| b.checked_sub(delta_out))
			.ok_or(SpendTxBuilderError::InsufficientBalance {
				old_balance: old_bal,
				delta_in,
				delta_out,
			})?;

		let mut accout = self.accin.clone_with_incremented_nonce();
		accout.ast.insert_or_update_asset(self.asset_id, new_bal);

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
			accin_proof: None,
			inotes_nct_proofs: None,
			rejected_inotes_nct_proofs: None,
			subpool_proof: None,
			spend_sig: None,
			consume_sig: None,
			approval_sig: None,
		})
	}
}

impl BuiltSpendTx {
	/// Generate and store a consume signature for this transaction.
	///
	/// Required only when there are active input notes, no output notes, and
	/// consume auth is non-delegated (`consume_auth.config == true`).
	///
	/// # Errors
	/// - `ConsumeDelegated`: consume auth is delegated (config = false)
	/// - `ConsumeNotRequired`: no input notes or has output notes
	/// - `ConsumeKeyNotSet`: accin.consume_auth.pk is None
	/// - `KeyMismatch`: provided key doesn't match accin.consume_auth.pk
	pub fn consume_sign<R: CryptoRng + rand::Rng>(
		mut self,
		consume_sk: &PrivateKey,
		rng: &mut R,
	) -> Result<Self, TxSignError> {
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

		let expected_pk = self
			.accin
			.consume_auth
			.pk
			.ok_or(TxSignError::ConsumeKeyNotSet)?;

		let provided_pk: CompressedPublicKey<F> = consume_sk.public_key().into();
		if expected_pk != provided_pk {
			return Err(TxSignError::KeyMismatch {
				key_type: "consume",
				expected: expected_pk,
				provided: provided_pk,
			});
		}

		let k = Scalar::sample(rng);
		let sig = schnorr_sign(consume_sk, &self.tx_hash.0, k);
		self.consume_sig = Some(sig);
		Ok(self)
	}

	/// Generate and store a spend signature for this transaction.
	///
	/// Required when there are active output notes.
	///
	/// # Errors
	/// - `SpendNotRequired`: no output notes exist
	/// - `SpendKeyNotSet`: accin.spend_auth.spend_pk is None
	/// - `KeyMismatch`: provided key doesn't match accin.spend_auth.spend_pk
	pub fn spend_sign<R: CryptoRng + rand::Rng>(
		mut self,
		spend_sk: &PrivateKey,
		rng: &mut R,
	) -> Result<Self, TxSignError> {
		if self.onotes.is_empty() {
			return Err(TxSignError::SpendNotRequired);
		}

		let expected_pk = self
			.accin
			.spend_auth
			.spend_pk
			.ok_or(TxSignError::SpendKeyNotSet)?;

		let provided_pk: CompressedPublicKey<F> = spend_sk.public_key().into();
		if expected_pk != provided_pk {
			return Err(TxSignError::KeyMismatch {
				key_type: "spend",
				expected: expected_pk,
				provided: provided_pk,
			});
		}

		let k = Scalar::sample(rng);
		let sig = schnorr_sign(spend_sk, &self.tx_hash.0, k);
		self.spend_sig = Some(sig);
		Ok(self)
	}

	/// Generate and store an approval signature for this transaction.
	///
	/// Approval signature is ALWAYS required for all spend transactions.
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

	/// Provide the merkle proof for the account commitment in the state tree.
	///
	/// The state tree root is derived from `accin_proof.root`.
	/// Must be called before `into_priv_tx`.
	pub fn with_account_path(mut self, accin_proof: MerkleProof<HashOutput>) -> Self {
		self.accin_proof = Some(accin_proof);
		self
	}

	/// Provide merkle proofs for the regular input note commitments.
	///
	/// Proofs must be in the same order as notes were added via `add_input_note`.
	/// Must be called before `into_priv_tx`.
	pub fn with_input_notes_path(mut self, inotes_proofs: Vec<MerkleProof<HashOutput>>) -> Self {
		self.inotes_nct_proofs = Some(inotes_proofs);
		self
	}

	/// Provide merkle proofs for the rejected input note commitments.
	///
	/// Proofs must be in the same order as notes were added via `add_rejected_note`.
	/// Must be called before `into_priv_tx`.
	pub fn with_rejected_notes_path(
		mut self,
		rejected_proofs: Vec<MerkleProof<HashOutput>>,
	) -> Self {
		self.rejected_inotes_nct_proofs = Some(rejected_proofs);
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

	/// Check which signatures are required for this transaction.
	pub fn required_signatures(&self) -> RequiredSignatures {
		RequiredSignatures {
			spend: !self.onotes.is_empty(),
			consume: !self.inotes.is_empty()
				&& self.onotes.is_empty()
				&& self.accin.consume_auth.config,
			approval: true,
		}
	}

	/// Convert this built spend transaction to a unified `BuiltPrivTx`.
	///
	/// Requires `with_account_path`, `with_input_notes_path`, `with_rejected_notes_path`,
	/// and `with_subpool_proof` to have been called first, plus all required signatures
	/// set via `spend_sign`, `consume_sign`, and `approval_sign`.
	///
	/// # Errors
	/// - `AccountPathNotSet`: `with_account_path` was not called
	/// - `NotePathsNotSet`: note paths were not set
	/// - `SubpoolProofNotSet`: `with_subpool_proof` was not called
	pub fn into_priv_tx(self) -> Result<BuiltPrivTx, SpendTxBuilderError> {
		let accin_merkle_proof = self
			.accin_proof
			.ok_or(SpendTxBuilderError::AccountPathNotSet)?;
		let inotes_nct_proofs = self
			.inotes_nct_proofs
			.ok_or(SpendTxBuilderError::NotePathsNotSet)?;
		let rejected_inotes_nct_proofs = self
			.rejected_inotes_nct_proofs
			.ok_or(SpendTxBuilderError::NotePathsNotSet)?;
		let subpool_full_proof = self
			.subpool_proof
			.ok_or(SpendTxBuilderError::SubpoolProofNotSet)?;

		let state_root = accin_merkle_proof.root;
		let mainpool_config_root = subpool_full_proof.main_pool_proof.root;
		let approval_key = subpool_full_proof.subpool_config.approval_key();

		Ok(BuiltPrivTx {
			tx_kind_flags: TxKindFlags::SPEND,

			accin: self.accin,
			accout: self.accout,
			accin_merkle_proof,

			rejected_inotes: self.rejected_inotes.into_iter().map(|(n, _)| n).collect(),
			rejected_inotes_nct_proofs,

			inotes: self.inotes.into_iter().map(|(n, _)| n).collect(),
			inotes_nct_proofs,
			onotes: self.onotes,

			dinotes: self.dinotes,
			donotes: self.donotes,

			tx_hash: self.tx_hash,
			state_root,

			subpool_id: self.subpool_id,
			mainpool_config_root,
			subpool_proof: subpool_full_proof,
			approval_key,

			spend_sig: self.spend_sig,
			consume_sig: self.consume_sig,
			approval_sig: self.approval_sig,
		})
	}
}
