use tessera_client::NOTE_BATCH;
use tessera_utils::hasher::HashOutput;
use tokio::sync::{broadcast, mpsc};

use super::deposit::Deposit;
use crate::types::ProveOutcome;

// ---------------------------------------------------------------------------
// TX submission request
// ---------------------------------------------------------------------------

/// All data the prover needs to build one [`BatchSlot::PrivateTx`] slot.
///
/// Submit via [`ProverServiceHandle::submit_tx`].
pub struct SubmitTxRequest {
	/// Output account commitment leaf.
	pub ac: [u8; 32],
	/// Input account nullifier leaf.
	pub an: [u8; 32],
	/// Note commitment leaves (one per note slot).
	pub nc: [[u8; 32]; NOTE_BATCH],
	/// Note nullifier leaves (one per note slot).
	pub nn: [[u8; 32]; NOTE_BATCH],
	/// Plonky2 private-TX proof bytes forwarded to the aggregator.
	/// A dummy value (`vec![0u8; 1]`) is acceptable when using the mock aggregator.
	pub tx_proof: Vec<u8>,
	/// The on-chain Poseidon IMT root that the client's proof was built
	/// against.  Validated against the confirmed-root set before the TX is
	/// accepted into the batch.
	pub root: HashOutput,
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// Cheap-to-clone handle for interacting with the [`ProverService`] actor.
///
/// * Use [`submit_tx`](Self::submit_tx) to enqueue a transaction for proving.
/// * Use [`submit_deposit`](Self::submit_deposit) to enqueue a deposit.
/// * Use [`next_tx_outcome`](Self::next_tx_outcome) /
///   [`next_deposit_outcome`](Self::next_deposit_outcome) to receive outcomes.
///
/// Each clone of this handle subscribes independently to both broadcast
/// streams, so all active clones receive every future outcome.
pub struct ProverServiceHandle {
	pub(super) tx_tx: mpsc::Sender<SubmitTxRequest>,
	/// Kept so that [`Clone`] can call `subscribe()` to create a new
	/// independent receiver.
	pub(super) tx_outcome_sender: broadcast::Sender<ProveOutcome>,
	pub(super) tx_outcomes: broadcast::Receiver<ProveOutcome>,

	pub(super) deposit_tx: mpsc::Sender<Deposit>,
	pub(super) deposit_outcome_sender: broadcast::Sender<ProveOutcome>,
	pub(super) deposit_outcomes: broadcast::Receiver<ProveOutcome>,
}

impl Clone for ProverServiceHandle {
	fn clone(&self) -> Self {
		Self {
			tx_tx: self.tx_tx.clone(),
			tx_outcome_sender: self.tx_outcome_sender.clone(),
			tx_outcomes: self.tx_outcome_sender.subscribe(),
			deposit_tx: self.deposit_tx.clone(),
			deposit_outcome_sender: self.deposit_outcome_sender.clone(),
			deposit_outcomes: self.deposit_outcome_sender.subscribe(),
		}
	}
}

impl ProverServiceHandle {
	/// Enqueue `req` for inclusion in the next TX batch.
	///
	/// # Errors
	/// Returns `Err` if the actor channel is closed (service has shut down).
	pub async fn submit_tx(&self, req: SubmitTxRequest) -> anyhow::Result<()> {
		self.tx_tx
			.send(req)
			.await
			.map_err(|_| anyhow::anyhow!("ProverService actor is no longer running"))
	}

	/// Wait for and return the next TX [`ProveOutcome`] emitted by the service.
	///
	/// # Errors
	/// Returns `Err` if the sender has been dropped or the buffer overflowed.
	pub async fn next_tx_outcome(&mut self) -> anyhow::Result<ProveOutcome> {
		self.tx_outcomes
			.recv()
			.await
			.map_err(|e| anyhow::anyhow!("ProverService TX outcome channel error: {e}"))
	}

	/// Enqueue `req` for inclusion in the next deposit batch.
	///
	/// # Errors
	/// Returns `Err` if the actor channel is closed (service has shut down).
	pub async fn submit_deposit(&self, req: Deposit) -> anyhow::Result<()> {
		self.deposit_tx
			.send(req)
			.await
			.map_err(|_| anyhow::anyhow!("ProverService actor is no longer running"))
	}

	/// Wait for and return the next deposit [`ProveOutcome`] emitted by the
	/// service.
	///
	/// # Errors
	/// Returns `Err` if the sender has been dropped or the buffer overflowed.
	pub async fn next_deposit_outcome(&mut self) -> anyhow::Result<ProveOutcome> {
		self.deposit_outcomes
			.recv()
			.await
			.map_err(|e| anyhow::anyhow!("ProverService deposit outcome channel error: {e}"))
	}
}
