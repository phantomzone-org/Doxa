//! [`SequencerHandle`] — the application-facing interface to the sequencer.
//!
//! The handle is returned by [`Sequencer::new`] and is the only way for
//! application code to push deposits and transactions into the sequencer.
//! All fields are channel senders, so the handle is cheap to clone and share.

use tokio::sync::mpsc;

use super::PrivateTxRequest;

/// Owned by the application; allows submitting deposits and transactions to a
/// running [`Sequencer`] event loop.
#[derive(Clone)]
pub struct SequencerHandle {
	pub(super) private_tx_tx: mpsc::Sender<PrivateTxRequest>,
}

impl SequencerHandle {
	/// Submit a private transaction.
	///
	/// `tx_proof` is the serialised Plonky2 leaf proof bytes. The sequencer
	/// forwards it to the remote prover for batch aggregation.
	pub async fn submit_private_tx(
		&self,
		tx_id: Option<String>,
		input_account_leaf: [u8; 32],
		output_account_leaf: [u8; 32],
		input_notes: Vec<[u8; 32]>,
		output_notes: Vec<[u8; 32]>,
		tx_proof: Vec<u8>,
	) -> anyhow::Result<()> {
		self.private_tx_tx
			.send(PrivateTxRequest {
				tx_id,
				input_notes,
				output_notes,
				input_account_leaf,
				output_account_leaf,
				tx_proof,
			})
			.await
			.map_err(|_| anyhow::anyhow!("sequencer channel closed"))
	}
}
