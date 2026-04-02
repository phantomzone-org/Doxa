use tessera_utils::hasher::HashOutput;
use tracing::warn;

use super::batch::{Deposit, DepositBatch};
use crate::state_service::StateServiceHandle;

// ---------------------------------------------------------------------------
// Rejection reasons
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Validation entry point
// ---------------------------------------------------------------------------

/// Validate a single deposit request against the confirmed on-chain state and
/// the current in-progress batch.
///
/// Performs (in order):
/// 1. Root confirmation check.
/// 2. Within-batch duplicate check for the NC.
pub async fn validate_deposit(
	req: &Deposit,
	state: &StateServiceHandle,
	batch: &DepositBatch,
) -> Result<(), DepositRejectionReason> {
	let confirmed = state
		.is_confirmed_root(req.root)
		.await
		.map_err(DepositRejectionReason::StateQueryError)?;
	if !confirmed {
		return Err(DepositRejectionReason::UnconfirmedRoot {
			root: req.root,
		});
	}

	if batch.contains_nc(&req.note_commitment) {
		return Err(DepositRejectionReason::DuplicateNcInBatch);
	}

	Ok(())
}

/// Log a deposit rejection at WARN level.
pub fn log_deposit_rejection(reason: &DepositRejectionReason, nc: Option<&str>) {
	warn!(
		nc = nc.unwrap_or("unknown"),
		reason = %reason,
		"deposit rejected by prover_service"
	);
}
