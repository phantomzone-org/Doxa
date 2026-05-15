use crate::{
	batch_helper::{BatchHelper, PiCommitHash},
	types::ProveOutcome,
};

pub trait Aggregator<H: PiCommitHash>: Send + Sync + 'static {
	/// Generate a proof for the finalized TX batch and return the outcome.
	///
	/// Implementations should call
	/// [`compute_pi_commitment`](Self::compute_pi_commitment) internally to
	/// populate `ProveOutcome::Success::super_pi_commitment`.
	///
	/// # Errors
	/// Returns `Err` if proof generation fails.
	fn prove(&self, batch: &impl BatchHelper, batch_id: u64) -> anyhow::Result<ProveOutcome>;
}
