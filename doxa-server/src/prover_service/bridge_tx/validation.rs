use doxa_utils::hasher::HashOutput;
use tracing::warn;

/// Describes why a submitted deposit was rejected before entering the batch.
#[derive(Debug)]
pub enum DepositRejectionReason {
	/// The root embedded in the request was not found in the confirmed-root set.
	UnconfirmedRoot { root: HashOutput },
	/// The deposit note commitment is already present in the current batch.
	DuplicateNcInBatch,
	/// The StateService returned an unexpected error during a query.
	StateQueryError(anyhow::Error),
}

impl std::fmt::Display for DepositRejectionReason {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::UnconfirmedRoot {
				root,
			} => write!(f, "unconfirmed root {root:?}"),
			Self::DuplicateNcInBatch => write!(f, "duplicate NC in current batch"),
			Self::StateQueryError(e) => write!(f, "state query error: {e}"),
		}
	}
}

/// Log a deposit rejection at WARN level.
pub fn log_deposit_rejection(reason: &DepositRejectionReason, nc: Option<&str>) {
	warn!(
		nc = nc.unwrap_or("unknown"),
		reason = %reason,
		"deposit rejected by prover_service"
	);
}
