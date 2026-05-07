//! Error types for transaction builders.

use core::fmt;

use primitive_types::U256;
use tessera_trees::error::MerkleTreeError;
use tessera_utils::F;

use crate::{AssetId, SubpoolId, schnorr::CompressedPublicKey};

/// Errors that can occur while building a spend transaction.
#[derive(Debug)]
pub enum SpendTxBuilderError {
	AccountNotInitialized,
	NoteBatchLimitReached {
		kind: &'static str,
		limit: usize,
	},
	AssetMismatch {
		expected: AssetId,
		got: AssetId,
	},
	NoteNotInTree {
		position: usize,
	},
	NoteCommitmentMismatch {
		position: usize,
	},
	RecipientMismatch,
	NoActiveNotes,
	InsufficientBalance {
		old_balance: U256,
		delta_in: U256,
		delta_out: U256,
	},
	SubpoolNotFound {
		subpool_id: SubpoolId,
	},
	DummyNotesNotFilled {
		kind: &'static str,
	},
	AccountPathNotSet,
	NotePathsNotSet,
	SubpoolProofNotSet,
	TreeError(anyhow::Error),
}

impl fmt::Display for SpendTxBuilderError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::AccountNotInitialized => {
				write!(
					f,
					"Account not initialized (nonce is 0). Must perform FreshAcc first"
				)
			},
			Self::NoteBatchLimitReached {
				kind,
				limit,
			} => {
				write!(
					f,
					"Note batch limit reached: {kind} notes already at limit ({limit})"
				)
			},
			Self::AssetMismatch {
				expected,
				got,
			} => {
				write!(f, "Asset mismatch: expected {expected:?}, got {got:?}")
			},
			Self::NoteNotInTree {
				position,
			} => {
				write!(f, "Note not found in state tree at position {position}")
			},
			Self::NoteCommitmentMismatch {
				position,
			} => {
				write!(f, "Note commitment mismatch at position {position}")
			},
			Self::RecipientMismatch => {
				write!(f, "Note recipient doesn't match input account")
			},
			Self::NoActiveNotes => {
				write!(f, "Must have at least one input or output note")
			},
			Self::InsufficientBalance {
				old_balance,
				delta_in,
				delta_out,
			} => write!(
				f,
				"Insufficient balance: old_balance={old_balance}, delta_in={delta_in}, delta_out={delta_out}"
			),
			Self::SubpoolNotFound {
				subpool_id,
			} => {
				write!(f, "Subpool {subpool_id:?} not found in main pool config")
			},
			Self::DummyNotesNotFilled {
				kind,
			} => {
				write!(
					f,
					"Dummy {kind} notes not filled. Call fill_dinotes()/fill_donotes() before build()"
				)
			},
			Self::AccountPathNotSet => write!(
				f,
				"Account commitment merkle path not set. Call with_account_path() before into_priv_tx()"
			),
			Self::NotePathsNotSet => write!(
				f,
				"Note commitment merkle paths not set. Call with_input_notes_path()/with_rejected_notes_path() before into_priv_tx()"
			),
			Self::SubpoolProofNotSet => write!(
				f,
				"Subpool proof not set. Call with_subpool_proof() before into_priv_tx()"
			),
			Self::TreeError(e) => write!(f, "Tree error: {e}"),
		}
	}
}

impl std::error::Error for SpendTxBuilderError {}

impl From<MerkleTreeError> for SpendTxBuilderError {
	fn from(e: MerkleTreeError) -> Self {
		Self::TreeError(anyhow::anyhow!("{}", e))
	}
}

impl From<anyhow::Error> for SpendTxBuilderError {
	fn from(e: anyhow::Error) -> Self {
		Self::TreeError(e)
	}
}

/// Errors that can occur while building a FreshAcc transaction.
#[derive(Debug)]
pub enum FreshAccTxBuilderError {
	AccountAlreadyInitialized,
	SpendKeyNotSet,
	ConsumeKeyNotSet,
	DummyNotesNotFilled { kind: &'static str },
	SubpoolNotFound { subpool_id: SubpoolId },
	StateRootNotSet,
	SubpoolProofNotSet,
	ApprovalSigNotSet,
	TreeError(anyhow::Error),
}

impl fmt::Display for FreshAccTxBuilderError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::AccountAlreadyInitialized => {
				write!(
					f,
					"Account already initialized (nonce != 0). FreshAcc requires nonce=0"
				)
			},
			Self::SpendKeyNotSet => {
				write!(
					f,
					"Spend key not set. Call with_new_spend_key() before building"
				)
			},
			Self::ConsumeKeyNotSet => write!(
				f,
				"Consume key not set. Call with_new_consume_key() or with_delegated_consume() before building"
			),
			Self::DummyNotesNotFilled {
				kind,
			} => {
				write!(
					f,
					"Dummy {kind} notes not filled. Call fill_dinotes()/fill_donotes() before build()"
				)
			},
			Self::SubpoolNotFound {
				subpool_id,
			} => {
				write!(f, "Subpool {subpool_id:?} not found in main pool config")
			},
			Self::StateRootNotSet => write!(
				f,
				"State root not set. Call with_state_root() before into_priv_tx()"
			),
			Self::SubpoolProofNotSet => write!(
				f,
				"Subpool proof not set. Call with_subpool_proof() before into_priv_tx()"
			),
			Self::ApprovalSigNotSet => write!(
				f,
				"Approval signature not set. Call approval_sign() before into_priv_tx()"
			),
			Self::TreeError(e) => write!(f, "Tree error: {e}"),
		}
	}
}

impl std::error::Error for FreshAccTxBuilderError {}

impl From<MerkleTreeError> for FreshAccTxBuilderError {
	fn from(e: MerkleTreeError) -> Self {
		Self::TreeError(anyhow::anyhow!("{}", e))
	}
}

impl From<anyhow::Error> for FreshAccTxBuilderError {
	fn from(e: anyhow::Error) -> Self {
		Self::TreeError(e)
	}
}

/// Errors that can occur while building a fake transaction.
///
/// Currently has no variants — fake tx construction is infallible. Defined for
/// pattern consistency and future extensibility.
#[derive(Debug)]
pub enum FakeTxBuilderError {}

impl fmt::Display for FakeTxBuilderError {
	fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match *self {}
	}
}

impl std::error::Error for FakeTxBuilderError {}

/// Errors that can occur while signing a transaction.
#[derive(Debug)]
pub enum TxSignError {
	ConsumeNotRequired {
		has_input_notes: bool,
		has_output_notes: bool,
	},
	ConsumeDelegated,
	ConsumeKeyNotSet,
	SpendNotRequired,
	SpendKeyNotSet,
	KeyMismatch {
		key_type: &'static str,
		expected: CompressedPublicKey<F>,
		provided: CompressedPublicKey<F>,
	},
}

impl fmt::Display for TxSignError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::ConsumeNotRequired {
				has_input_notes,
				has_output_notes,
			} => write!(
				f,
				"Consume signature not required: has_input_notes={has_input_notes}, has_output_notes={has_output_notes}"
			),
			Self::ConsumeDelegated => {
				write!(
					f,
					"Consume auth is delegated to subpool owner (config=false)"
				)
			},
			Self::ConsumeKeyNotSet => {
				write!(
					f,
					"Consume key not set in account (consume_auth.pk is None)"
				)
			},
			Self::SpendNotRequired => {
				write!(f, "Spend signature not required: no output notes")
			},
			Self::SpendKeyNotSet => {
				write!(
					f,
					"Spend key not set in account (spend_auth.spend_pk is None)"
				)
			},
			Self::KeyMismatch {
				key_type,
				expected,
				provided,
			} => write!(
				f,
				"{key_type} key mismatch: expected {expected:?}, provided {provided:?}"
			),
		}
	}
}

impl std::error::Error for TxSignError {}

/// Errors that can occur while proving a transaction.
#[derive(Debug)]
pub enum PrivTxProveError {
	MissingRequiredSignature {
		sig_type: &'static str,
		reason: &'static str,
	},
	SubpoolNotFound {
		subpool_id: SubpoolId,
	},
	ProofGenerationFailed(anyhow::Error),
}

impl fmt::Display for PrivTxProveError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::MissingRequiredSignature {
				sig_type,
				reason,
			} => {
				write!(f, "Missing required {sig_type} signature: {reason}")
			},
			Self::SubpoolNotFound {
				subpool_id,
			} => {
				write!(f, "Subpool {subpool_id:?} not found in main pool config")
			},
			Self::ProofGenerationFailed(e) => write!(f, "Proof generation failed: {e}"),
		}
	}
}

impl std::error::Error for PrivTxProveError {}

impl From<anyhow::Error> for PrivTxProveError {
	fn from(e: anyhow::Error) -> Self {
		Self::ProofGenerationFailed(e)
	}
}

impl From<SpendTxBuilderError> for PrivTxProveError {
	fn from(e: SpendTxBuilderError) -> Self {
		Self::ProofGenerationFailed(e.into())
	}
}
