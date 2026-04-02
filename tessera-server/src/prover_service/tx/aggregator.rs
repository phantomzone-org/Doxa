use tessera_utils::hasher::HashOutput;

use crate::{sequencer::FinalizedBatch, types::ProveOutcome};

// ---------------------------------------------------------------------------
// TxAggregator trait
// ---------------------------------------------------------------------------

/// Abstraction over private-TX batch proof generation.
///
/// The prover service calls [`TxAggregator::prove`] once a TX batch is
/// finalized.  Implementations may be:
///
/// - [`MockTxAggregator`](super::MockTxAggregator) — used in tests and development; returns a
///   correctly structured [`ProveOutcome`] with a random Groth16 proof.
/// - A real aggregator — communicates with an external proving service and returns a verified
///   Groth16 proof.
///
/// # Object safety
/// The trait uses only `fn` (not `async fn`), so `dyn TxAggregator` is
/// supported.  For async proof generation wrap the blocking call with
/// `tokio::task::spawn_blocking` inside the implementation.
pub trait TxAggregator: Send + Sync + 'static {
	/// Compute the public-input (PI) commitment for a finalized TX batch.
	///
	/// The PI commitment is `keccak256` over the LE-packed preimage:
	/// `root || mainPoolConfigRoot || batchPoseidonRoot ||
	///  accountCommitments (all slots) || accountNullifiers (real slots only) ||
	///  noteCommitments (7 per slot, all slots) || noteNullifiers (real slots only)`.
	///
	/// This matches `_computeTxPiCommitment` in the Solidity contract and
	/// [`SuperAggregator::compute_pi_commitment_native`] in the proving circuit.
	///
	/// # Errors
	/// Returns `Err` if any leaf cannot be decoded as a valid Goldilocks hash.
	fn compute_pi_commitment(
		&self,
		batch: &FinalizedBatch,
		root: HashOutput,
		main_pool_cfg_root: [u8; 32],
	) -> anyhow::Result<[u8; 32]>;

	/// Generate a proof for the finalized TX batch and return the outcome.
	///
	/// Implementations should call
	/// [`compute_pi_commitment`](Self::compute_pi_commitment) internally to
	/// populate `ProveOutcome::Success::super_pi_commitment`.
	///
	/// # Errors
	/// Returns `Err` if proof generation fails.
	fn prove(
		&self,
		batch: &FinalizedBatch,
		root: HashOutput,
		main_pool_cfg_root: [u8; 32],
		batch_id: u64,
	) -> anyhow::Result<ProveOutcome>;
}
