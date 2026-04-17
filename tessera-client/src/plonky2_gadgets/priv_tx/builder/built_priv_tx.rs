//! Unified representation of a built private transaction, ready to be proven.
//!
//! This module provides `BuiltPrivTx`, a unified representation for all transaction
//! kinds (Spend, FreshAcc, Reject, Fake) that handles witness setting and proof
//! generation.
//!
//! ## Design Philosophy: True Unification
//!
//! `BuiltPrivTx` achieves true unification by:
//!
//! 1. **Data-driven witness setting**: The presence/absence of data determines behavior
//!    - If notes are present → derive asset_id from them (Spend/Reject)
//!    - If no notes → use zero asset_id (FreshAcc)
//!    - Account proof presence → determines real vs dummy merkle proof
//!
//! 2. **No transaction-type branching**: Single `set_transaction_witnesses()` method works for all
//!    tx types without matching on `tx_kind_flags`
//!
//! 3. **No redundant storage**:
//! 3. **No redundancy**:
//!    - Auth keys stored only in `accout` (not separately for FreshAcc)
//!    - Asset amounts derived from AST on-demand
//!    - Merkle proof always populated (real or dummy, determined during conversion)
//!
//! 4. **Complete representation**: All necessary values (including signatures) are stored
//!    - Signatures are ALWAYS present (real or fake/dummy, never `None`)
//!    - Generated when converting from `BuiltSpendTx` / `BuiltFreshAccTx`
//!    - `prove()` just generates the proof - no additional inputs needed
//!    - Ensures signatures can't be forgotten or mismatched
//!
//! This design makes it impossible to have inconsistent state and ensures that
//! adding new transaction types doesn't require modifying the core proving logic.

use std::{array, hash::Hash, sync::Arc};

use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2_field::types::{Field, PrimeField64};
use tessera_trees::MerkleProof;
use tessera_utils::{CircuitDataNative, F, ProofNative, hasher::HashOutput};

use super::errors::PrivTxProveError;
use crate::{
	NOTE_BATCH, NoteCommitment, NoteNullifier, StandardAccount, StandardNote, SubpoolId,
	plonky2_gadgets::priv_tx::{
		targets::{TxCircuitTargets, TxKindFlags},
		utils::double_hash_native,
	},
	pool_config::{MainPoolConfigTree, SubpoolFullProof},
	schnorr::Signature,
};

/// Unified representation of a built private transaction, ready to be proven.
///
/// This struct contains all values needed to set `TxCircuitTargets`, regardless
/// of transaction kind (Spend, FreshAcc, Reject, or Fake).
///
/// ## Complete Representation Philosophy
///
/// `BuiltPrivTx` is a **complete, ready-to-prove** representation:
/// - All witness values (including signatures) are already present
/// - Signatures are NEVER `None` - always real or fake/dummy (`Signature::ZERO`)
/// - Merkle proofs always populated - real for Spend/Reject, dummy for FreshAcc
/// - No additional parameters needed at `prove()` time
/// - No branching on transaction type in witness setting
///
/// ## Witness Setting Philosophy
///
/// Rather than branching on transaction type, witness setting is **data-driven**:
/// - The presence of `inotes`/`onotes` determines asset handling
/// - The `tx_kind_flags.is_fresh_acc` determines account proof handling
/// - All other values are derived uniformly from the stored data
///
/// This means transaction-specific builders only need to populate the right
/// data (including signatures), and the unified witness-setting logic handles
/// the rest automatically.
pub struct BuiltPrivTx {
	/// Transaction kind flags
	pub tx_kind_flags: TxKindFlags,

	/// Input account
	pub accin: StandardAccount,

	/// Output account (derived from accin with modifications)
	pub accout: StandardAccount,

	/// Merkle proof of accin commitment in state tree
	pub accin_merkle_proof: MerkleProof<HashOutput>,

	/// Rejected input notes (empty unless tx contains reject pairs).
	///
	/// Reject pairs occupy the first slots (0..rejected_inotes.len()); regular
	/// inotes/onotes follow.  The corresponding rejected onotes are derived on-the-fly:
	/// `rejected_onote[i] = rejected_inotes[i]` with `recipient` set to `sender`.
	pub rejected_inotes: Vec<StandardNote>,

	/// Merkle proofs of rejected input note commitments in state tree
	pub rejected_inotes_nct_proofs: Vec<MerkleProof<HashOutput>>,

	/// Input notes (empty for FreshAcc)
	pub inotes: Vec<StandardNote>,

	/// Merkle proofs of input note commitments in state tree
	pub inotes_nct_proofs: Vec<MerkleProof<HashOutput>>,

	/// Output notes (empty for FreshAcc)
	pub onotes: Vec<StandardNote>,

	/// Dummy input note seeds (for padding inactive inote slots)
	pub dinotes: Vec<[F; 4]>,

	/// Dummy output note seeds (for padding inactive onote slots)
	pub donotes: Vec<[F; 4]>,

	/// Transaction hash (computed from nullifiers and commitments)
	pub tx_hash: HashOutput,

	/// State tree root at proof time
	pub state_root: HashOutput,

	/// Subpool ID (extracted from accin)
	pub subpool_id: SubpoolId,

	/// Main pool configuration tree root
	pub main_pool_root: HashOutput,

	/// Subpool merkle proof in the main pool config tree
	pub subpool_proof: SubpoolFullProof<HashOutput>,

	/// Subpool approval key
	pub approval_key: crate::pool_config::CompPubKey,

	/// Spend signature.
	///
	/// - For Spend with output notes: real signature from spend key
	/// - For other cases: fake/dummy signature (`Signature::ZERO`)
	/// - Never `None` - always present
	pub spend_sig: Signature,

	/// Consume signature.
	///
	/// - For Spend with input notes and no output notes (non-delegated): real signature
	/// - For other cases: fake/dummy signature (`Signature::ZERO`)
	/// - Never `None` - always present
	pub consume_sig: Signature,

	/// Approval signature (always real, never fake).
	///
	/// Required for all transaction types.
	pub approval_sig: Signature,
}

/// Final proven transaction ready for submission.
pub struct ProvenPrivTx {
	pub proof: ProofNative,
	pub public_inputs: PrivTxPublicInputs,
}

/// Public inputs extracted from a proven transaction.
#[derive(Debug, Clone)]
pub struct PrivTxPublicInputs {
	pub state_root: HashOutput,
	pub mainpool_config_root: HashOutput,
	pub accin_nullifier: HashOutput,
	pub accout_commitment: HashOutput,
	pub input_note_nullifiers: [NoteNullifier; NOTE_BATCH],
	pub output_note_commitments: [NoteCommitment; NOTE_BATCH],
	pub not_fake_tx: bool,
}

impl BuiltPrivTx {
	/// Generate a zero-knowledge proof for this transaction.
	///
	/// All necessary data (including signatures) must already be present in this struct.
	///
	/// # Arguments
	/// - `circuit_data`: Pre-built PrivTx circuit data (must contain targets)
	/// - `targets`: Circuit targets for witness setting
	///
	/// # Errors
	/// - `ProofGenerationFailed`: Circuit constraints not satisfied
	pub fn prove(
		&self,
		circuit_data: &CircuitDataNative,
		targets: &TxCircuitTargets,
	) -> Result<ProvenPrivTx, PrivTxProveError> {
		// Build partial witness
		let mut pw = PartialWitness::new();

		// Set transaction kind flags
		targets.set_tx_kind_flags(&mut pw, self.tx_kind_flags);

		// Set all witness values based on tx kind
		self.set_witness(&mut pw, targets)?;

		// Generate proof
		let proof = circuit_data.prove(pw)?;

		Ok(ProvenPrivTx {
			proof,
			public_inputs: self.extract_public_inputs(),
		})
	}

	/// Set witness values for TxCircuitTargets.
	///
	/// This is the unified witness-setting logic that handles all tx kinds.
	/// Replaces the individual `set_spend_tx_witness`, `set_freshacc_tx_witness`, etc.
	fn set_witness(
		&self,
		pw: &mut PartialWitness<F>,
		t: &TxCircuitTargets,
	) -> Result<(), PrivTxProveError> {
		// Set common witnesses (roots, keys, account nullifier/commitment)
		t.set_common_witnesses(
			pw,
			self.main_pool_root,
			self.state_root,
			self.approval_key,
			&self.subpool_proof,
			&self.accin,
			&self.accout,
		);

		// Set authorization signatures
		self.set_authorization_witness(pw, t)?;

		// Set transaction-specific witnesses uniformly
		self.set_transaction_witnesses(pw, t)?;

		Ok(())
	}

	/// Set authorization-related witness values (signatures).
	///
	/// All signatures are already stored in `self`, populated during conversion
	/// from transaction-specific builders (e.g., `BuiltSpendTx::into_priv_tx()`).
	/// Signatures are always present (either real or fake/dummy).
	fn set_authorization_witness(
		&self,
		pw: &mut PartialWitness<F>,
		t: &TxCircuitTargets,
	) -> Result<(), PrivTxProveError> {
		// Set spend signature (real or fake/dummy)
		t.private.sig_targets.spend.set(
			pw,
			self.accin.spend_pk_or_default(),
			self.tx_hash,
			&self.spend_sig,
		);

		// Set consume signature (real or fake/dummy)
		t.private.sig_targets.consume.set(
			pw,
			self.accin.consume_pk_or_default(),
			self.tx_hash,
			&self.consume_sig,
		);

		// Set approval signature (always real)
		t.private
			.sig_targets
			.approval
			.set(pw, self.approval_key, self.tx_hash, &self.approval_sig);

		Ok(())
	}

	/// Set transaction-specific witness values uniformly for all transaction types.
	///
	/// This method achieves true unification by being **data-driven** rather than
	/// **type-driven**. It examines the data present in `BuiltPrivTx` and sets
	/// witness values accordingly:
	///
	/// **Asset Handling:**
	/// - If `inotes` or `onotes` present → derive asset_id from first note
	/// - If no notes → use zero asset_id (FreshAcc case)
	///
	/// **Account Proof:**
	/// - If `is_fresh_acc` flag set → use dummy account proof (not enforced)
	/// - Otherwise → use real account merkle proof
	///
	/// **AST Amounts:**
	/// - Derived from `accin.ast` and `accout.ast` at the determined asset_id
	/// - Zero amounts naturally occur when asset not in AST (FreshAcc)
	///
	/// **Note Witnesses:**
	/// - Real notes set for indices < inotes.len() / onotes.len()
	/// - Dummy notes set for remaining indices
	///
	/// This approach eliminates the need for separate `set_spend_witness()`,
	/// `set_freshacc_witness()`, etc., making the code simpler and more maintainable.
	fn set_transaction_witnesses(
		&self,
		pw: &mut PartialWitness<F>,
		t: &TxCircuitTargets,
	) -> Result<(), PrivTxProveError> {
		use plonky2_field::types::Field;

		// Determine asset_id based on presence of notes
		// If we have active notes, use their asset_id; otherwise use zero
		let asset_id = self
			.inotes
			.first()
			.or(self.onotes.first())
			.map(|n| n.asset_id)
			.unwrap_or(crate::AssetId(F::ZERO));

		// Set asset_id
		pw.set_target(t.private.asset_id.0, asset_id.0).unwrap();

		// Derive amounts from AST at the asset_id
		let accin_result = self.accin.ast.amount_for(asset_id);
		let accout_result = self.accout.ast.amount_for(asset_id);

		let (ast_index, accin_amt) = accin_result.unwrap_or((0, primitive_types::U256::zero()));
		let (_, accout_amt) = accout_result.unwrap_or((0, primitive_types::U256::zero()));

		// Set asset_exists flags based on the lookup results
		let asset_exists_in_accin = accin_result.is_some();
		let asset_exists_in_accout = accout_result.is_some();

		// Set amounts (convert U256 to [u32; 8])
		// U256.0 is [u64; 4] little-endian; each u64 splits into two u32 limbs
		// TODO: add helper for U256 -> u8;32
		let accin_amt_u32: [u32; 8] = [
			accin_amt.0[0] as u32,
			(accin_amt.0[0] >> 32) as u32,
			accin_amt.0[1] as u32,
			(accin_amt.0[1] >> 32) as u32,
			accin_amt.0[2] as u32,
			(accin_amt.0[2] >> 32) as u32,
			accin_amt.0[3] as u32,
			(accin_amt.0[3] >> 32) as u32,
		];
		let accout_amt_u32: [u32; 8] = [
			accout_amt.0[0] as u32,
			(accout_amt.0[0] >> 32) as u32,
			accout_amt.0[1] as u32,
			(accout_amt.0[1] >> 32) as u32,
			accout_amt.0[2] as u32,
			(accout_amt.0[2] >> 32) as u32,
			accout_amt.0[3] as u32,
			(accout_amt.0[3] >> 32) as u32,
		];
		crate::plonky2_gadgets::set_u256(pw, &t.private.accin_amt, accin_amt_u32);
		crate::plonky2_gadgets::set_u256(pw, &t.private.accout_amt, accout_amt_u32);
		pw.set_bool_target(t.private.asset_exists_in_accin, asset_exists_in_accin)
			.unwrap();
		pw.set_bool_target(t.private.asset_exists_in_accout, asset_exists_in_accout)
			.unwrap();

		// Set account merkle proof
		// The conversion from transaction-specific builders ensures this is
		// populated correctly (real proof for Spend, dummy for FreshAcc)
		t.private
			.accin_act_merkle
			.set_witness(pw, &self.accin_merkle_proof);

		// Set accin AST merkle proof at the asset's index
		// For FreshAcc with no asset, this will be index 0 (empty leaf)
		t.private
			.accin_ast_merkle
			.set_witness(pw, &self.accin.ast.merkle_proof_at(ast_index));

		// Set notes witnesses
		self.set_notes_witness(pw, t)?;

		Ok(())
	}

	/// Set note-related witness values (inputs and outputs).
	///
	/// Slot layout:
	///   0 .. n_rjct          — reject pairs (`is_note_pair_rjct[i] = true`, both active)
	///   n_rjct .. NOTE_BATCH — regular inotes / onotes (independent lengths), then dummies
	fn set_notes_witness(
		&self,
		pw: &mut PartialWitness<F>,
		t: &TxCircuitTargets,
	) -> Result<(), PrivTxProveError> {
		let n_rjct = self.rejected_inotes.len();
		let n_in = self.inotes.len();
		let n_out = self.onotes.len();

		if n_rjct + n_in.max(n_out) >= NOTE_BATCH {
			return Err(PrivTxProveError::ProofGenerationFailed(anyhow::anyhow!(
				"note batch overflow: rejected={n_rjct}, inotes={n_in}, onotes={n_out}, limit={NOTE_BATCH}"
			)));
		}
		let expected_dinotes = NOTE_BATCH - n_in - n_rjct;
		if self.dinotes.len() != expected_dinotes {
			return Err(PrivTxProveError::ProofGenerationFailed(anyhow::anyhow!(
				"dinotes length mismatch: expected {expected_dinotes}, got {}",
				self.dinotes.len()
			)));
		}
		let expected_donotes = NOTE_BATCH - n_out - n_rjct;
		if self.donotes.len() != expected_donotes {
			return Err(PrivTxProveError::ProofGenerationFailed(anyhow::anyhow!(
				"donotes length mismatch: expected {expected_donotes}, got {}",
				self.donotes.len()
			)));
		}

		// ── Reject pair slots (0..n_rjct) ────────────────────────────────────────
		for i in 0..n_rjct {
			let inote = &self.rejected_inotes[i];
			let proof = &self.rejected_inotes_nct_proofs[i];

			// Derive rejected onote: return note to original sender
			let mut onote = inote.clone();
			onote.recipient = inote.sender;

			// Input note
			t.private.inotes[i].set_witness(pw, inote);
			t.private.inotes_nct_merkle[i].set_witness(pw, proof);
			pw.set_target(
				t.private.inotes_pos[i],
				F::from_canonical_u64(proof.pos as u64),
			)
			.unwrap();
			pw.set_bool_target(t.private.inotes_isactive[i], true)
				.unwrap();
			t.private.dinotes[i].set_zero(pw); // active slot — value unused but target must be set

			// Output note
			t.private.onotes[i].set_witness(pw, &onote);
			pw.set_bool_target(t.private.onotes_isactive[i], true)
				.unwrap();
			t.private.donotes[i].set_zero(pw);

			pw.set_bool_target(t.private.is_note_pair_rjct[i], true)
				.unwrap();
		}

		// ── Regular / dummy slots (n_rjct..NOTE_BATCH) ───────────────────────────
		for slot in n_rjct..NOTE_BATCH {
			let j = slot - n_rjct;

			// Input note
			if j < self.inotes.len() {
				let note = &self.inotes[j];
				let proof = &self.inotes_nct_proofs[j];
				t.private.inotes[slot].set_witness(pw, note);
				t.private.inotes_nct_merkle[slot].set_witness(pw, proof);
				pw.set_target(
					t.private.inotes_pos[slot],
					F::from_canonical_u64(proof.pos as u64),
				)
				.unwrap();
				pw.set_bool_target(t.private.inotes_isactive[slot], true)
					.unwrap();
				t.private.dinotes[slot].set_zero(pw); // active slot — value unused
			} else {
				pw.set_target(t.private.inotes_pos[slot], F::ZERO).unwrap();
				pw.set_bool_target(t.private.inotes_isactive[slot], false)
					.unwrap();
				t.private.dinotes[slot].set(pw, self.dinotes[j - n_in]);
				t.private.inotes[slot].set_dummy_inote(pw);
				t.private.inotes_nct_merkle[slot].set_dummy_witness(pw);
			}

			// Output note
			if j < self.onotes.len() {
				t.private.onotes[slot].set_witness(pw, &self.onotes[j]);
				pw.set_bool_target(t.private.onotes_isactive[slot], true)
					.unwrap();
				t.private.donotes[slot].set_zero(pw); // active slot — value unused
			} else {
				pw.set_bool_target(t.private.onotes_isactive[slot], false)
					.unwrap();
				t.private.donotes[slot].set(pw, self.donotes[j - n_out]);
				t.private.onotes[slot].set_dummy_onote(pw);
			}

			pw.set_bool_target(t.private.is_note_pair_rjct[slot], false)
				.unwrap();
		}

		Ok(())
	}

	/// Extract public inputs from this built transaction.
	fn extract_public_inputs(&self) -> PrivTxPublicInputs {
		PrivTxPublicInputs {
			state_root: self.state_root,
			mainpool_config_root: self.main_pool_root,
			accin_nullifier: self.accin.nullifier().0,
			accout_commitment: self.accout.commitment().0,
			input_note_nullifiers: self.compute_input_nullifiers(),
			output_note_commitments: self.compute_output_commitments(),
			not_fake_tx: self.tx_kind_flags != TxKindFlags::FAKE,
		}
	}

	/// Compute input note nullifiers for all NOTE_BATCH slots.
	///
	/// Mirrors the slot layout in `set_notes_witness`:
	///   slots 0..n_rjct              → rejected input note nullifiers
	///   slots n_rjct..n_rjct+n_in   → regular input note nullifiers
	///   remaining                    → dummy nullifiers
	fn compute_input_nullifiers(&self) -> [NoteNullifier; NOTE_BATCH] {
		let nk = self.accin.nk();
		let n_rjct = self.rejected_inotes.len();
		array::from_fn(|i| {
			if i < n_rjct {
				let pos = self.rejected_inotes_nct_proofs[i].pos;
				self.rejected_inotes[i].nullifier(pos, &nk).unwrap()
			} else {
				let j = i - n_rjct;
				if j < self.inotes.len() {
					let pos = self.inotes_nct_proofs[j].pos;
					self.inotes[j].nullifier(pos, &nk).unwrap()
				} else {
					NoteNullifier(HashOutput(double_hash_native(
						self.dinotes[j - self.inotes.len()],
					)))
				}
			}
		})
	}

	/// Compute output note commitments for all NOTE_BATCH slots.
	///
	/// Mirrors the slot layout in `set_notes_witness`:
	///   slots 0..n_rjct              → rejected onote commitments (derived from rejected_inotes)
	///   slots n_rjct..n_rjct+n_out  → regular output note commitments
	///   remaining                    → dummy commitments
	fn compute_output_commitments(&self) -> [NoteCommitment; NOTE_BATCH] {
		let n_rjct = self.rejected_inotes.len();
		array::from_fn(|i| {
			if i < n_rjct {
				let mut onote = self.rejected_inotes[i].clone();
				onote.recipient = self.rejected_inotes[i].sender;
				onote.commitment()
			} else {
				let j = i - n_rjct;
				if j < self.onotes.len() {
					self.onotes[j].commitment()
				} else {
					NoteCommitment(HashOutput(double_hash_native(
						self.donotes[j - self.onotes.len()],
					)))
				}
			}
		})
	}
}
