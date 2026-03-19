//! [`SequencerHandle`] — the application-facing interface to the sequencer.
//!
//! The handle is returned by [`Sequencer::new`] and is the only way for
//! application code to push deposits and transactions into the sequencer.
//! All fields are channel senders, so the handle is cheap to clone and share.

use tokio::sync::{mpsc, oneshot};

use super::{NotesCommitmentRequest, PrivateTxRequest, TestTxRequest};

/// Owned by the application; allows submitting deposits and transactions to a
/// running [`Sequencer`] event loop.
#[derive(Clone)]
pub struct SequencerHandle {
	pub(super) notes_commitment_tx: mpsc::Sender<NotesCommitmentRequest>,
	pub(super) private_tx_tx: mpsc::Sender<PrivateTxRequest>,
	/// `Some` only when `TESSERA_TESTING=1`.
	pub(super) test_deposit_tx: Option<mpsc::Sender<[u8; 32]>>,
	/// `Some` only when `TESSERA_TESTING=1`.
	pub(super) test_tx_tx: Option<mpsc::Sender<TestTxRequest>>,
	/// `Some` only when `TESSERA_TESTING=1`.
	pub(super) test_consume_validate_tx: Option<mpsc::Sender<oneshot::Sender<anyhow::Result<()>>>>,
	/// `Some` only when `TESSERA_TESTING=1`.
	pub(super) test_tx_validate_tx: Option<mpsc::Sender<oneshot::Sender<anyhow::Result<()>>>>,
}

impl SequencerHandle {
	/// Submit a deposit note commitment.
	///
	/// The sequencer verifies the note is in `Pending` status on-chain before
	/// adding it to the consume batch. `consume_proof` can be `None` when the
	/// caller does not have an associated consume proof.
	pub async fn submit_deposit(
		&self,
		note: [u8; 32],
		consume_proof: Option<Vec<u8>>,
	) -> anyhow::Result<()> {
		self.notes_commitment_tx
			.send(NotesCommitmentRequest {
				note,
				consume_proof,
			})
			.await
			.map_err(|_| anyhow::anyhow!("sequencer channel closed"))
	}

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

	// ------------------------------------------------------------------
	// Test-only methods (available only when `TESSERA_TESTING=1`)
	// ------------------------------------------------------------------

	/// \[Test\] Submit a deposit note without the on-chain Pending check or a consume proof.
	pub async fn test_submit_deposit(&self, note: [u8; 32]) -> anyhow::Result<()> {
		self.test_deposit_tx
			.as_ref()
			.ok_or_else(|| anyhow::anyhow!("testing mode not enabled (TESSERA_TESTING=1)"))?
			.send(note)
			.await
			.map_err(|_| anyhow::anyhow!("sequencer channel closed"))
	}

	/// \[Test\] Submit a transaction slot with raw leaf values — no Plonky2 proof required.
	pub async fn test_submit_tx(
		&self,
		an: [u8; 32],
		ac: [u8; 32],
		nn: [[u8; 32]; 8],
		nc: [[u8; 32]; 8],
	) -> anyhow::Result<()> {
		self.test_tx_tx
			.as_ref()
			.ok_or_else(|| anyhow::anyhow!("testing mode not enabled (TESSERA_TESTING=1)"))?
			.send(TestTxRequest {
				an,
				ac,
				nn,
				nc,
			})
			.await
			.map_err(|_| anyhow::anyhow!("sequencer channel closed"))
	}

	/// \[Test\] Flush the pending deposit batch on-chain and confirm it with a zero proof.
	///
	/// Blocks until the on-chain `proveDepositBatch` transaction is confirmed.
	pub async fn test_validate_deposits(&self) -> anyhow::Result<()> {
		let tx = self
			.test_consume_validate_tx
			.as_ref()
			.ok_or_else(|| anyhow::anyhow!("testing mode not enabled (TESSERA_TESTING=1)"))?;
		let (resp_tx, resp_rx) = oneshot::channel();
		tx.send(resp_tx)
			.await
			.map_err(|_| anyhow::anyhow!("sequencer channel closed"))?;
		resp_rx
			.await
			.map_err(|_| anyhow::anyhow!("sequencer dropped response"))?
	}

	/// \[Test\] Flush the pending TX batch on-chain and confirm it with a zero proof.
	///
	/// Blocks until the on-chain `proveTransactionBatch` transaction is confirmed.
	pub async fn test_validate_txs(&self) -> anyhow::Result<()> {
		let tx = self
			.test_tx_validate_tx
			.as_ref()
			.ok_or_else(|| anyhow::anyhow!("testing mode not enabled (TESSERA_TESTING=1)"))?;
		let (resp_tx, resp_rx) = oneshot::channel();
		tx.send(resp_tx)
			.await
			.map_err(|_| anyhow::anyhow!("sequencer channel closed"))?;
		resp_rx
			.await
			.map_err(|_| anyhow::anyhow!("sequencer dropped response"))?
	}
}
