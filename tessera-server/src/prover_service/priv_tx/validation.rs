use tessera_utils::hasher::HashOutput;
use tracing::warn;

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

/// Log a TX rejection at WARN level.
pub fn log_rejection(reason: &TxRejectionReason, tx_id: Option<&str>) {
	warn!(
		tx_id = tx_id.unwrap_or("unknown"),
		reason = %reason,
		"TX rejected by prover_service"
	);
}
