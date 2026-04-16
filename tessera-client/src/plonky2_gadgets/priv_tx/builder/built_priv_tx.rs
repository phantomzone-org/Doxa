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
		double_hash_native,
		targets::{TxCircuitTargets, TxKindFlags},
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

	/// Input notes (empty for FreshAcc)
	pub inotes: Vec<StandardNote>,

	/// Merkle proofs of input note commitments in state tree
	pub inotes_nct_proofs: Vec<MerkleProof<HashOutput>>,

	/// Output notes (empty for FreshAcc)
	pub onotes: Vec<StandardNote>,

	/// Dummy input note seeds (for padding to NOTE_BATCH)
	pub dinotes: [[F; 4]; NOTE_BATCH],

	/// Dummy output note seeds (for padding to NOTE_BATCH)
	pub donotes: [[F; 4]; NOTE_BATCH],

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
		t.set_spend_sig_witness(pw, &self.spend_sig);

		// Set consume signature (real or fake/dummy)
		t.set_consume_sig_witness(pw, &self.consume_sig);

		// Set approval signature (always real)
		t.set_approval_sig_witness(pw, &self.approval_sig);

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
	fn set_notes_witness(
		&self,
		pw: &mut PartialWitness<F>,
		t: &TxCircuitTargets,
	) -> Result<(), PrivTxProveError> {
		// Set input notes
		for i in 0..NOTE_BATCH {
			if i < self.inotes.len() {
				// Real input note
				let note = &self.inotes[i];
				let proof = &self.inotes_nct_proofs[i];
				t.set_input_note_witness(pw, i, note, proof);
			} else {
				// Dummy input note
				t.set_dummy_input_note_witness(pw, i, self.dinotes[i]);
			}
		}

		// Set output notes
		for i in 0..NOTE_BATCH {
			if i < self.onotes.len() {
				// Real output note
				let note = &self.onotes[i];
				t.set_output_note_witness(pw, i, note);
			} else {
				// Dummy output note
				t.set_dummy_output_note_witness(pw, i, self.donotes[i]);
			}
		}

		// Spend/FreshAcc transactions have no reject pairs.
		for i in 0..NOTE_BATCH {
			pw.set_bool_target(t.private.is_note_pair_rjct[i], false)
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
	fn compute_input_nullifiers(&self) -> [NoteNullifier; NOTE_BATCH] {
		let nk = self.accin.nk();
		array::from_fn(|i| {
			if i < self.inotes.len() {
				let pos = self.inotes_nct_proofs[i].pos;
				self.inotes[i].nullifier(pos, &nk).unwrap()
			} else {
				NoteNullifier(HashOutput(double_hash_native(self.dinotes[i])))
			}
		})
	}

	/// Compute output note commitments for all NOTE_BATCH slots.
	fn compute_output_commitments(&self) -> [NoteCommitment; NOTE_BATCH] {
		array::from_fn(|i| {
			if i < self.onotes.len() {
				self.onotes[i].commitment()
			} else {
				NoteCommitment(HashOutput(double_hash_native(self.donotes[i])))
			}
		})
	}
}
