use tessera_utils::hasher::HashOutput;
use tracing::warn;

use super::super::handle::SubmitTxRequest;
use crate::{sequencer::BatchBuilder, state_service::StateServiceHandle};

// ---------------------------------------------------------------------------
// Rejection reasons
// ---------------------------------------------------------------------------

/// Describes why a submitted TX was rejected before entering the batch.
#[derive(Debug)]
pub enum TxRejectionReason {
	/// The root embedded in the TX was not found in the confirmed-root set.
	UnconfirmedRoot { root: HashOutput },
	/// The account nullifier (AN) has already been spent on-chain.
	AccountNullifierSpent,
	/// One of the note nullifiers (NN) has already been spent on-chain.
	NoteNullifierSpent { index: usize },
	/// The account nullifier is already present in the current batch.
	DuplicateAnInBatch,
	/// One of the note nullifiers is already present in the current batch.
	DuplicateNnInBatch { index: usize },
	/// The StateService returned an unexpected error during a query.
	StateQueryError(anyhow::Error),
}

impl std::fmt::Display for TxRejectionReason {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::UnconfirmedRoot {
				root,
			} => write!(f, "unconfirmed root {root:?}"),
			Self::AccountNullifierSpent => write!(f, "account nullifier already spent"),
			Self::NoteNullifierSpent {
				index,
			} => {
				write!(f, "note nullifier at index {index} already spent")
			},
			Self::DuplicateAnInBatch => write!(f, "duplicate AN in current batch"),
			Self::DuplicateNnInBatch {
				index,
			} => {
				write!(f, "duplicate NN at index {index} in current batch")
			},
			Self::StateQueryError(e) => write!(f, "state query error: {e}"),
		}
	}
}

// ---------------------------------------------------------------------------
// Validation entry point
// ---------------------------------------------------------------------------

/// Validate a single TX request against the confirmed on-chain state and the
/// current in-progress batch.
///
/// Performs (in order):
/// 1. Root confirmation check.
/// 2. Account-nullifier (AN) spent check.
/// 3. Note-nullifier (NN) spent check for each of the `NOTE_BATCH` slots.
/// 4. Within-batch duplicate check for AN.
/// 5. Within-batch duplicate check for each NN.
pub async fn validate_tx(
	req: &SubmitTxRequest,
	state: &StateServiceHandle,
	batch: &BatchBuilder,
) -> Result<(), TxRejectionReason> {
	let confirmed = state
		.is_confirmed_root(req.root)
		.await
		.map_err(TxRejectionReason::StateQueryError)?;
	if !confirmed {
		return Err(TxRejectionReason::UnconfirmedRoot {
			root: req.root,
		});
	}

	let an_spent = state
		.contains_nullifier(req.an)
		.await
		.map_err(TxRejectionReason::StateQueryError)?;
	if an_spent {
		return Err(TxRejectionReason::AccountNullifierSpent);
	}

	for (i, nn) in req.nn.iter().enumerate() {
		let nn_spent = state
			.contains_nullifier(*nn)
			.await
			.map_err(TxRejectionReason::StateQueryError)?;
		if nn_spent {
			return Err(TxRejectionReason::NoteNullifierSpent {
				index: i,
			});
		}
	}

	if batch.contains_an(&req.an) {
		return Err(TxRejectionReason::DuplicateAnInBatch);
	}

	for (i, nn) in req.nn.iter().enumerate() {
		if batch.contains_nn(nn) {
			return Err(TxRejectionReason::DuplicateNnInBatch {
				index: i,
			});
		}
	}

	Ok(())
}

/// Log a TX rejection at WARN level.
pub fn log_rejection(reason: &TxRejectionReason, tx_id: Option<&str>) {
	warn!(
		tx_id = tx_id.unwrap_or("unknown"),
		reason = %reason,
		"TX rejected by prover_service"
	);
}
