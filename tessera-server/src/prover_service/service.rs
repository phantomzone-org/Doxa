use std::time::{Duration, Instant};

use alloy::{
	network::EthereumWallet,
	providers::{Provider, ProviderBuilder},
	signers::{local::PrivateKeySigner, Signer},
};
use anyhow::Context;
use tessera_client::NOTE_BATCH;
use tessera_utils::hasher::HashOutput;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

use super::{
	config::ProverServiceConfig,
	deposit::{self, Deposit, DepositAggregator, DepositBatch, FinalizedDepositBatchValidation},
	handle::{ProverServiceHandle, SubmitTxRequest},
	tx::{self, TxAggregator},
};
use crate::{
	contract::{self, ITesseraRollupV2},
	sequencer::{BatchBuilder, FinalizedBatch},
	state_service::StateServiceHandle,
	types::ProveOutcome,
};

/// Receipt polling timeout for on-chain transactions.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Capacity of each submission channel.
const TX_CHANNEL_CAPACITY: usize = 256;

/// Number of [`ProveOutcome`]s buffered in each broadcast channel.
const OUTCOME_CHANNEL_CAPACITY: usize = 64;

// ---------------------------------------------------------------------------
// ProverService actor
// ---------------------------------------------------------------------------

/// Actor that collects transactions and deposits, validates them against the
/// on-chain state, and drives the full batch-proving pipeline.
///
/// `TA` is the [`TxAggregator`] and `DA` is the [`DepositAggregator`].
/// Pass [`MockTxAggregator`](super::MockTxAggregator) and
/// [`MockDepositAggregator`](super::MockDepositAggregator) for tests and
/// development; swap in real implementations for production.
///
/// # Lifecycle
/// 1. Create with [`ProverService::new`] → returns `(ProverService, ProverServiceHandle)`.
/// 2. Spawn [`ProverService::run`] in a dedicated `tokio::spawn` task.
/// 3. Interact via the cloneable [`ProverServiceHandle`].
pub struct ProverService<TA: TxAggregator, DA: DepositAggregator> {
	config: ProverServiceConfig,
	state_handle: StateServiceHandle,
	tx_aggregator: TA,
	deposit_aggregator: DA,
	tx_rx: mpsc::Receiver<SubmitTxRequest>,
	tx_outcome_tx: broadcast::Sender<ProveOutcome>,
	deposit_rx: mpsc::Receiver<Deposit>,
	deposit_outcome_tx: broadcast::Sender<ProveOutcome>,
	tx_batch_builder: Option<BatchBuilder>,
	tx_batch_pending_since: Option<Instant>,
	deposit_batch_builder: Option<DepositBatch>,
	deposit_batch_pending_since: Option<Instant>,
	next_batch_id: u64,
}

impl<TA: TxAggregator, DA: DepositAggregator> ProverService<TA, DA> {
	/// Create a new [`ProverService`] and return its client-facing handle.
	pub fn new(
		config: ProverServiceConfig,
		state_handle: StateServiceHandle,
		tx_aggregator: TA,
		deposit_aggregator: DA,
	) -> (Self, ProverServiceHandle) {
		let (tx_tx, tx_rx) = mpsc::channel(TX_CHANNEL_CAPACITY);
		let (tx_outcome_tx, tx_outcomes) = broadcast::channel(OUTCOME_CHANNEL_CAPACITY);

		let (deposit_tx, deposit_rx) = mpsc::channel(TX_CHANNEL_CAPACITY);
		let (deposit_outcome_tx, deposit_outcomes) = broadcast::channel(OUTCOME_CHANNEL_CAPACITY);

		let handle = ProverServiceHandle {
			tx_tx,
			tx_outcome_sender: tx_outcome_tx.clone(),
			tx_outcomes,
			deposit_tx,
			deposit_outcome_sender: deposit_outcome_tx.clone(),
			deposit_outcomes,
		};
		let service = Self {
			config,
			state_handle,
			tx_aggregator,
			deposit_aggregator,
			tx_rx,
			tx_outcome_tx,
			deposit_rx,
			deposit_outcome_tx,
			tx_batch_builder: None,
			tx_batch_pending_since: None,
			deposit_batch_builder: None,
			deposit_batch_pending_since: None,
			next_batch_id: 0,
		};

		(service, handle)
	}

	// -----------------------------------------------------------------------
	// Event loop
	// -----------------------------------------------------------------------

	/// Start the service event loop.
	pub async fn run(&mut self) -> anyhow::Result<()> {
		let provider = self.build_provider()?;

		let batch_timeout = Duration::from_secs(self.config.batch_timeout_secs);
		let mut interval = tokio::time::interval(batch_timeout);

		info!("prover service running");

		loop {
			tokio::select! {
				_ = interval.tick() => {
					if let Err(e) = self.maybe_flush_tx_batch(&provider).await {
						error!(error = %e, "failed to flush TX batch; will retry next tick");
					}
					if let Err(e) = self.maybe_flush_deposit_batch(&provider).await {
						error!(error = %e, "failed to flush deposit batch; will retry next tick");
					}
				}

				req = self.tx_rx.recv() => {
					let Some(req) = req else { break; };
					self.handle_submitted_tx(req, &provider).await;
				}

				req = self.deposit_rx.recv() => {
					let Some(req) = req else { break; };
					self.handle_submitted_deposit(req, &provider).await;
				}

				_ = tokio::signal::ctrl_c() => {
					info!("prover service shutting down");
					break;
				}
			}
		}

		Ok(())
	}

	// -----------------------------------------------------------------------
	// TX handling
	// -----------------------------------------------------------------------

	async fn handle_submitted_tx<P: Provider + Clone>(
		&mut self,
		req: SubmitTxRequest,
		provider: &P,
	) {
		self.ensure_tx_batch_builder();

		let bb_ref = self.tx_batch_builder.as_ref().unwrap();
		match tx::validate_tx(&req, &self.state_handle, bb_ref).await {
			Err(reason) => {
				tx::log_rejection(&reason, None);
			},
			Ok(()) => {
				let nc: [[u8; 32]; NOTE_BATCH] = req.nc;
				let bb = self.tx_batch_builder.as_mut().unwrap();
				match bb.add_private_tx(req.tx_proof, req.ac, req.an, nc, req.nn) {
					Err(e) => {
						warn!(error = %e, "batch builder rejected TX");
					},
					Ok(is_full) => {
						let slots = self.tx_batch_builder.as_ref().map_or(0, |b| b.len());
						info!(slots, "TX added to batch");
						if is_full {
							if let Err(e) = self.flush_tx_batch(provider).await {
								error!(error = %e, "failed to flush full TX batch");
							}
						}
					},
				}
			},
		}
	}

	async fn maybe_flush_tx_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
	) -> anyhow::Result<()> {
		if self
			.tx_batch_builder
			.as_ref()
			.is_some_and(|b| !b.is_empty())
		{
			self.flush_tx_batch(provider).await?;
		}
		Ok(())
	}

	async fn flush_tx_batch<P: Provider + Clone>(&mut self, provider: &P) -> anyhow::Result<()> {
		let (finalized, batch_id) = self.finalize_tx_batch()?;

		let confirmed_root = self
			.state_handle
			.current_root()
			.await
			.context("failed to fetch current root from StateService")?;

		let pool_cfg_root = self.fetch_pool_cfg_root(provider).await?;

		let outcome =
			self.tx_aggregator
				.prove(&finalized, confirmed_root, pool_cfg_root, batch_id)?;

		let pi_commitment = self
			.submit_tx_batch_on_chain(provider, &finalized, confirmed_root, pool_cfg_root)
			.await?;

		self.prove_tx_batch_on_chain(provider, pi_commitment, &outcome)
			.await?;

		info!(batch_id, "TX batch proven");

		let _ = self.tx_outcome_tx.send(outcome);

		Ok(())
	}

	fn finalize_tx_batch(&mut self) -> anyhow::Result<(FinalizedBatch, u64)> {
		let bb = self
			.tx_batch_builder
			.take()
			.ok_or_else(|| anyhow::anyhow!("finalize_tx_batch called with no batch builder"))?;
		self.tx_batch_pending_since = None;

		let batch_id = self.next_batch_id;
		self.next_batch_id = self.next_batch_id.saturating_add(1);

		Ok((bb.finalize(), batch_id))
	}

	async fn submit_tx_batch_on_chain<P: Provider + Clone>(
		&self,
		provider: &P,
		finalized: &FinalizedBatch,
		confirmed_root: HashOutput,
		pool_cfg_root: [u8; 32],
	) -> anyhow::Result<[u8; 32]> {
		let rollup =
			ITesseraRollupV2::ITesseraRollupV2Instance::new(self.config.bridge_address, provider);

		let n_slots = finalized.ac_leaves.len();
		let stride = NOTE_BATCH + 1;

		let mut note_commitments = Vec::with_capacity(n_slots * NOTE_BATCH);
		for s in 0..n_slots {
			let nc_base = s * stride;
			for j in 0..NOTE_BATCH {
				note_commitments.push(contract::bytes32_be_to_u256_le(
					&finalized.nc_leaves[nc_base + j],
				));
			}
		}

		let account_commitments: Vec<alloy::primitives::U256> = finalized
			.ac_leaves
			.iter()
			.map(contract::bytes32_be_to_u256_le)
			.collect();

		let mut note_nullifiers = Vec::new();
		let mut account_nullifiers = Vec::new();
		for s in 0..n_slots {
			if !finalized.tx_proofs_by_slot.contains_key(&s) {
				continue;
			}
			let nn_base = s * stride;
			for j in 0..NOTE_BATCH {
				note_nullifiers.push(contract::bytes32_be_to_u256_le(
					&finalized.nn_leaves[nn_base + j],
				));
			}
			account_nullifiers.push(contract::bytes32_be_to_u256_le(&finalized.an_leaves[s]));
		}

		let batch_poseidon_root = contract::hash_to_u256_le(&finalized.batch_poseidon_root);
		let root = contract::hash_to_u256_le(&confirmed_root);

		let batch = ITesseraRollupV2::TransactionBatch {
			root,
			mainPoolConfigRoot: pool_cfg_root.into(),
			noteCommitments: note_commitments,
			noteNullifiers: note_nullifiers,
			accountCommitments: account_commitments,
			accountNullifiers: account_nullifiers,
			batchPoseidonRoot: batch_poseidon_root,
			confirmed: false,
		};

		let receipt = rollup
			.submitTransactionBatch(batch)
			.send()
			.await
			.map_err(|e| anyhow::anyhow!("submitTransactionBatch reverted: {e}"))?
			.with_required_confirmations(1)
			.with_timeout(Some(RECEIPT_TIMEOUT))
			.get_receipt()
			.await
			.map_err(|e| anyhow::anyhow!("submitTransactionBatch receipt error: {e}"))?;

		anyhow::ensure!(
			receipt.status(),
			"submitTransactionBatch reverted on-chain (tx={:?})",
			receipt.transaction_hash
		);

		let pi_commitment: [u8; 32] = receipt
			.inner
			.logs()
			.iter()
			.find_map(|log| {
				log.log_decode::<ITesseraRollupV2::TransactionBatchSubmitted>()
					.ok()
					.map(|d| d.inner.piCommitment.into())
			})
			.ok_or_else(|| {
				anyhow::anyhow!("TransactionBatchSubmitted event not found in receipt")
			})?;

		info!(
			pi_commitment = hex::encode(pi_commitment),
			real_slots = finalized.tx_proofs_by_slot.len(),
			"TX batch submitted on-chain"
		);
		Ok(pi_commitment)
	}

	async fn prove_tx_batch_on_chain<P: Provider + Clone>(
		&self,
		provider: &P,
		pi_commitment: [u8; 32],
		outcome: &ProveOutcome,
	) -> anyhow::Result<HashOutput> {
		let rollup =
			ITesseraRollupV2::ITesseraRollupV2Instance::new(self.config.bridge_address, provider);

		let ProveOutcome::Success {
			batch_id,
			solidity_proof,
			..
		} = outcome
		else {
			anyhow::bail!("prove_tx_batch_on_chain called with a Failure outcome");
		};

		let sol_proof = ITesseraRollupV2::Proof {
			proof: solidity_proof.proof,
			commitments: solidity_proof.commitments,
			commitmentPok: solidity_proof.commitment_pok,
		};

		let receipt = rollup
			.proveTransactionBatch(pi_commitment.into(), sol_proof)
			.send()
			.await
			.map_err(|e| anyhow::anyhow!("proveTransactionBatch send failed: {e}"))?
			.with_required_confirmations(1)
			.with_timeout(Some(RECEIPT_TIMEOUT))
			.get_receipt()
			.await
			.map_err(|e| anyhow::anyhow!("proveTransactionBatch receipt error: {e}"))?;

		anyhow::ensure!(
			receipt.status(),
			"proveTransactionBatch reverted (batch_id={batch_id}, tx={:?})",
			receipt.transaction_hash
		);

		let new_root_u256 = receipt
			.inner
			.logs()
			.iter()
			.find_map(|log| {
				log.log_decode::<ITesseraRollupV2::TransactionBatchProven>()
					.ok()
					.map(|d| d.inner.newTreeRoot)
			})
			.ok_or_else(|| anyhow::anyhow!("TransactionBatchProven event not found in receipt"))?;

		let new_root = contract::u256_le_to_hash(new_root_u256)
			.context("newTreeRoot is not a valid Goldilocks hash")?;

		Ok(new_root)
	}

	fn ensure_tx_batch_builder(&mut self) -> &mut BatchBuilder {
		if self.tx_batch_builder.is_none() {
			self.tx_batch_builder = Some(BatchBuilder::new());
			self.tx_batch_pending_since = Some(Instant::now());
		}
		self.tx_batch_builder.as_mut().unwrap()
	}

	// -----------------------------------------------------------------------
	// Deposit handling
	// -----------------------------------------------------------------------

	async fn handle_submitted_deposit<P: Provider + Clone>(&mut self, req: Deposit, provider: &P) {
		self.ensure_deposit_batch_builder();

		let bb_ref = self.deposit_batch_builder.as_ref().unwrap();
		match deposit::validate_deposit(&req, &self.state_handle, bb_ref).await {
			Err(reason) => {
				deposit::log_deposit_rejection(&reason, None);
			},
			Ok(()) => {
				let bb = self.deposit_batch_builder.as_mut().unwrap();
				match bb.add_deposit(req.note_commitment, req.eth_address, req.proof) {
					Err(e) => {
						warn!(error = %e, "deposit batch builder rejected deposit");
					},
					Ok(is_full) => {
						let slots = self.deposit_batch_builder.as_ref().map_or(0, |b| b.len());
						info!(slots, "deposit added to batch");
						if is_full {
							if let Err(e) = self.flush_deposit_batch(provider).await {
								error!(error = %e, "failed to flush full deposit batch");
							}
						}
					},
				}
			},
		}
	}

	async fn maybe_flush_deposit_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
	) -> anyhow::Result<()> {
		if self
			.deposit_batch_builder
			.as_ref()
			.is_some_and(|b| !b.is_empty())
		{
			self.flush_deposit_batch(provider).await?;
		}
		Ok(())
	}

	async fn flush_deposit_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
	) -> anyhow::Result<()> {
		let (finalized, batch_id) = self.finalize_deposit_batch()?;

		let confirmed_root = self
			.state_handle
			.current_root()
			.await
			.context("failed to fetch current root from StateService")?;

		let pool_cfg_root = self.fetch_pool_cfg_root(provider).await?;

		let outcome =
			self.deposit_aggregator
				.prove(&finalized, confirmed_root, pool_cfg_root, batch_id)?;

		let pi_commitment = self
			.submit_deposit_batch_on_chain(provider, &finalized, confirmed_root, pool_cfg_root)
			.await?;

		self.prove_deposit_batch_on_chain(provider, pi_commitment, &outcome)
			.await?;

		info!(batch_id, "deposit batch proven");

		let _ = self.deposit_outcome_tx.send(outcome);

		Ok(())
	}

	fn finalize_deposit_batch(&mut self) -> anyhow::Result<(FinalizedDepositBatchValidation, u64)> {
		let bb = self.deposit_batch_builder.take().ok_or_else(|| {
			anyhow::anyhow!("finalize_deposit_batch called with no batch builder")
		})?;
		self.deposit_batch_pending_since = None;

		let batch_id = self.next_batch_id;
		self.next_batch_id = self.next_batch_id.saturating_add(1);

		Ok((bb.finalize(), batch_id))
	}

	async fn submit_deposit_batch_on_chain<P: Provider + Clone>(
		&self,
		provider: &P,
		finalized: &FinalizedDepositBatchValidation,
		confirmed_root: HashOutput,
		pool_cfg_root: [u8; 32],
	) -> anyhow::Result<[u8; 32]> {
		let rollup =
			ITesseraRollupV2::ITesseraRollupV2Instance::new(self.config.bridge_address, provider);

		let deposit_note_commitments: Vec<alloy::primitives::FixedBytes<32>> = finalized
			.note_commitments
			.iter()
			.map(|&b| b.into())
			.collect();

		let batch_poseidon_root = contract::hash_to_u256_le(&finalized.batch_root);
		let root = contract::hash_to_u256_le(&confirmed_root);

		let batch = ITesseraRollupV2::DepositBatch {
			root,
			mainPoolConfigRoot: pool_cfg_root.into(),
			depositNoteCommitments: deposit_note_commitments,
			batchPoseidonRoot: batch_poseidon_root,
			confirmed: false,
		};

		let receipt = rollup
			.submitDepositBatch(batch)
			.send()
			.await
			.map_err(|e| anyhow::anyhow!("submitDepositBatch reverted: {e}"))?
			.with_required_confirmations(1)
			.with_timeout(Some(RECEIPT_TIMEOUT))
			.get_receipt()
			.await
			.map_err(|e| anyhow::anyhow!("submitDepositBatch receipt error: {e}"))?;

		anyhow::ensure!(
			receipt.status(),
			"submitDepositBatch reverted on-chain (tx={:?})",
			receipt.transaction_hash
		);

		let pi_commitment: [u8; 32] = receipt
			.inner
			.logs()
			.iter()
			.find_map(|log| {
				log.log_decode::<ITesseraRollupV2::DepositBatchSubmitted>()
					.ok()
					.map(|d| d.inner.piCommitment.into())
			})
			.ok_or_else(|| anyhow::anyhow!("DepositBatchSubmitted event not found in receipt"))?;

		info!(
			pi_commitment = hex::encode(pi_commitment),
			real_deposits = finalized.note_commitments.len(),
			"deposit batch submitted on-chain"
		);
		Ok(pi_commitment)
	}

	async fn prove_deposit_batch_on_chain<P: Provider + Clone>(
		&self,
		provider: &P,
		pi_commitment: [u8; 32],
		outcome: &ProveOutcome,
	) -> anyhow::Result<HashOutput> {
		let rollup =
			ITesseraRollupV2::ITesseraRollupV2Instance::new(self.config.bridge_address, provider);

		let ProveOutcome::Success {
			batch_id,
			solidity_proof,
			..
		} = outcome
		else {
			anyhow::bail!("prove_deposit_batch_on_chain called with a Failure outcome");
		};

		let sol_proof = ITesseraRollupV2::Proof {
			proof: solidity_proof.proof,
			commitments: solidity_proof.commitments,
			commitmentPok: solidity_proof.commitment_pok,
		};

		let receipt = rollup
			.proveDepositBatch(pi_commitment.into(), sol_proof)
			.send()
			.await
			.map_err(|e| anyhow::anyhow!("proveDepositBatch send failed: {e}"))?
			.with_required_confirmations(1)
			.with_timeout(Some(RECEIPT_TIMEOUT))
			.get_receipt()
			.await
			.map_err(|e| anyhow::anyhow!("proveDepositBatch receipt error: {e}"))?;

		anyhow::ensure!(
			receipt.status(),
			"proveDepositBatch reverted (batch_id={batch_id}, tx={:?})",
			receipt.transaction_hash
		);

		let new_root_u256 = receipt
			.inner
			.logs()
			.iter()
			.find_map(|log| {
				log.log_decode::<ITesseraRollupV2::DepositBatchProven>()
					.ok()
					.map(|d| d.inner.newTreeRoot)
			})
			.ok_or_else(|| anyhow::anyhow!("DepositBatchProven event not found in receipt"))?;

		let new_root = contract::u256_le_to_hash(new_root_u256)
			.context("newTreeRoot is not a valid Goldilocks hash")?;

		Ok(new_root)
	}

	fn ensure_deposit_batch_builder(&mut self) -> &mut DepositBatch {
		if self.deposit_batch_builder.is_none() {
			self.deposit_batch_builder = Some(DepositBatch::new());
			self.deposit_batch_pending_since = Some(Instant::now());
		}
		self.deposit_batch_builder.as_mut().unwrap()
	}

	// -----------------------------------------------------------------------
	// Shared utilities
	// -----------------------------------------------------------------------

	async fn fetch_pool_cfg_root<P: Provider + Clone>(
		&self,
		provider: &P,
	) -> anyhow::Result<[u8; 32]> {
		let rollup =
			ITesseraRollupV2::ITesseraRollupV2Instance::new(self.config.bridge_address, provider);
		let root: [u8; 32] = rollup
			.poolConfigRoot()
			.call()
			.await
			.context("poolConfigRoot() call failed")?
			.into();
		Ok(root)
	}

	fn build_provider(&self) -> anyhow::Result<impl Provider + Clone> {
		let signer: PrivateKeySigner = self
			.config
			.operator_private_key
			.parse()
			.context("invalid operator_private_key")?;
		let signer = signer.with_chain_id(Some(self.config.chain_id));
		let wallet = EthereumWallet::from(signer);
		let provider = ProviderBuilder::new()
			.with_nonce_management(alloy::providers::fillers::CachedNonceManager::default())
			.wallet(wallet)
			.connect_http(
				self.config
					.rpc_url
					.parse()
					.context("invalid rpc_url in ProverServiceConfig")?,
			);
		Ok(provider)
	}
}
