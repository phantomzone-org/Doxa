use tessera_utils::hasher::HashOutput;

use crate::{prover_service::deposit::DepositBatch, types::ProveOutcome};

// ---------------------------------------------------------------------------
// DepositAggregator trait
// ---------------------------------------------------------------------------

/// Abstraction over deposit batch proof generation.
///
/// The prover service calls [`DepositAggregator::prove`] once a deposit batch
/// is finalized.  Implementations may be:
///
/// - [`MockDepositAggregator`](super::MockDepositAggregator) — used in tests and development;
///   returns a correctly structured [`ProveOutcome`] with a random Groth16 proof.
/// - A real aggregator — communicates with an external proving service and returns a verified
///   Groth16 proof.
pub trait DepositAggregator: Send + Sync + 'static {
	/// Generate a proof for the finalized deposit batch and return the outcome.
	///
	/// Implementations should call
	/// [`compute_pi_commitment`](Self::compute_pi_commitment) internally to
	/// populate `ProveOutcome::Success::super_pi_commitment`.
	///
	/// # Errors
	/// Returns `Err` if proof generation fails.
	fn prove(
		&self,
		batch: &DepositBatch,
		root: HashOutput,
		main_pool_cfg_root: HashOutput,
		batch_id: u64,
	) -> anyhow::Result<ProveOutcome>;
}
