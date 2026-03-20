use std::{
	collections::{BTreeMap, BTreeSet},
	sync::Arc,
	time::Duration,
};

use alloy::{
	network::EthereumWallet,
	providers::{Provider, ProviderBuilder},
	signers::{local::PrivateKeySigner, Signer},
};
use anyhow::Context;
use tessera_utils::{hasher::HashOutput, F};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use crate::{
	config::SequencerConfig,
	contract::{self, ITesseraRollupV2},
	prover_client::{HttpProverClient, ProverClient},
	types::{ConsumeOutcome, ProveOutcomeV2},
};

pub mod batch;
mod handle;
mod pipeline;
mod recovery;
mod revert;
mod testing;

pub use handle::SequencerHandle;

/// Receipt polling timeout for on-chain transactions.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum number of pending (submitted, not yet proven) batches.
const MAX_PENDING_BATCHES: usize = 128;

/// A batch submitted on-chain and awaiting a Groth16 proof via `proveTransactionBatch`.
struct TxBatchV2 {
	/// On-chain piCommitment (keccak256 of batch public inputs).
	pi_commitment: [u8; 32],
}

/// A deposit batch submitted on-chain and awaiting a Groth16 proof via `proveDepositBatch`.
struct ConsumeBatchV2 {
	/// On-chain piCommitment (keccak256 of deposit batch public inputs).
	pi_commitment: [u8; 32],
}

/// Test-mode transaction: raw leaf values, no proof required.
pub(super) struct TestTxRequest {
	pub an: [u8; 32],
	pub ac: [u8; 32],
	pub nn: [[u8; 32]; 8],
	pub nc: [[u8; 32]; 8],
}

/// A private transaction submitted via [`SequencerHandle::submit_private_tx`].
pub(super) struct PrivateTxRequest {
	pub tx_id: Option<String>,
	/// Input notes (nullifiers being spent).
	pub input_notes: Vec<[u8; 32]>,
	/// Output notes (commitments being created).
	pub output_notes: Vec<[u8; 32]>,
	/// Account nullifier leaf (input account state being consumed).
	pub input_account_leaf: [u8; 32],
	/// Account commitment leaf (output account state being created).
	pub output_account_leaf: [u8; 32],
	/// Plonky2 leaf proof bytes forwarded to the remote prover.
	pub tx_proof: Vec<u8>,
}

/// A deposit note commitment submitted via [`SequencerHandle::submit_deposit`].
pub(super) struct NotesCommitmentRequest {
	pub note: [u8; 32],
	/// Consume proof bytes (may be absent).
	pub consume_proof: Option<Vec<u8>>,
}

/// The V2 sequencer: accumulates TX slots, submits batches to `TesseraRollupV2`,
/// and forwards prove requests to the remote prover.
pub struct Sequencer {
	config: SequencerConfig,
	/// Current on-chain Poseidon IMT root (`currentRoot()` after all proven batches).
	confirmed_root: HashOutput,
	/// All roots ever in `confirmedRoots` on-chain (genesis + every proven batch root).
	confirmed_root_history: BTreeSet<HashOutput>,
	/// Pending batches (submitted but not yet proven), keyed by local `batch_id`.
	pending_batches: BTreeMap<u64, TxBatchV2>,
	/// Monotonically increasing local batch counter.
	next_batch_id: u64,
	prover_client: Option<Arc<dyn ProverClient>>,
	result_tx: Option<mpsc::Sender<ProveOutcomeV2>>,
	result_rx: Option<mpsc::Receiver<ProveOutcomeV2>>,
	notes_commitment_rx: mpsc::Receiver<NotesCommitmentRequest>,
	private_tx_rx: mpsc::Receiver<PrivateTxRequest>,
	batch_builder: Option<batch::BatchBuilder>,
	batch_pending_since: Option<std::time::Instant>,
	/// Consume (deposit) pipeline.
	consume_result_tx: Option<mpsc::Sender<ConsumeOutcome>>,
	consume_result_rx: Option<mpsc::Receiver<ConsumeOutcome>>,
	consume_batch_builder: Option<batch::ConsumeBatchBuilder>,
	consume_batch_pending_since: Option<std::time::Instant>,
	pending_consume_batches: BTreeMap<u64, ConsumeBatchV2>,
	next_consume_batch_id: u64,
	/// Test-only: inject deposits without on-chain Pending check.
	test_deposit_rx: Option<mpsc::Receiver<[u8; 32]>>,
	/// Test-only: inject transactions without proof verification.
	test_tx_rx: Option<mpsc::Receiver<TestTxRequest>>,
	/// Test-only: flush consume batch + confirm with zero proof.
	test_consume_validate_rx: Option<mpsc::Receiver<oneshot::Sender<anyhow::Result<()>>>>,
	/// Test-only: flush TX batch + confirm with zero proof.
	test_tx_validate_rx: Option<mpsc::Receiver<oneshot::Sender<anyhow::Result<()>>>>,
}

impl Sequencer {
	/// Create a new sequencer and return its application-facing handle.
	///
	/// The returned [`SequencerHandle`] is the only way to submit deposits and
	/// transactions. Call [`Sequencer::run`] (typically in a spawned task) to
	/// start the event loop.
	pub fn new(config: SequencerConfig) -> (Self, SequencerHandle) {
		use plonky2::field::types::Field;

		let (notes_commitment_tx, notes_commitment_rx) =
			mpsc::channel::<NotesCommitmentRequest>(1024);
		let (private_tx_tx, private_tx_rx) = mpsc::channel::<PrivateTxRequest>(MAX_PENDING_BATCHES);

		// Initialise test-mode channels only when TESSERA_TESTING=1.
		let (
			test_deposit_rx,
			test_tx_rx,
			test_consume_validate_rx,
			test_tx_validate_rx,
			test_deposit_tx,
			test_tx_tx,
			test_consume_validate_tx,
			test_tx_validate_tx,
		) = if config.testing {
			let (dep_tx, dep_rx) = mpsc::channel::<[u8; 32]>(1024);
			let (tx_tx, tx_rx) = mpsc::channel::<TestTxRequest>(1024);
			let (cv_tx, cv_rx) = mpsc::channel::<oneshot::Sender<anyhow::Result<()>>>(8);
			let (tv_tx, tv_rx) = mpsc::channel::<oneshot::Sender<anyhow::Result<()>>>(8);
			(
				Some(dep_rx),
				Some(tx_rx),
				Some(cv_rx),
				Some(tv_rx),
				Some(dep_tx),
				Some(tx_tx),
				Some(cv_tx),
				Some(tv_tx),
			)
		} else {
			(None, None, None, None, None, None, None, None)
		};

		let handle = SequencerHandle {
			notes_commitment_tx,
			private_tx_tx,
			test_deposit_tx,
			test_tx_tx,
			test_consume_validate_tx,
			test_tx_validate_tx,
		};

		let sequencer = Self {
			config,
			confirmed_root: HashOutput::new([F::ZERO; 4]),
			confirmed_root_history: BTreeSet::new(),
			pending_batches: BTreeMap::new(),
			next_batch_id: 0,
			prover_client: None,
			result_tx: None,
			result_rx: None,
			notes_commitment_rx,
			private_tx_rx,
			batch_builder: None,
			batch_pending_since: None,
			consume_result_tx: None,
			consume_result_rx: None,
			consume_batch_builder: None,
			consume_batch_pending_since: None,
			pending_consume_batches: BTreeMap::new(),
			next_consume_batch_id: 0,
			test_deposit_rx,
			test_tx_rx,
			test_consume_validate_rx,
			test_tx_validate_rx,
		};

		(sequencer, handle)
	}

	/// Create a sequencer pre-wired with an in-process prover (e.g., for E2E tests).
	///
	/// [`Sequencer::run`] will use the supplied `prover` instead of creating an
	/// [`HttpProverClient`] from the config.
	pub fn new_with_prover(
		config: SequencerConfig,
		prover: Arc<dyn ProverClient>,
	) -> (Self, SequencerHandle) {
		let (mut sequencer, handle) = Self::new(config);
		sequencer.prover_client = Some(prover);
		(sequencer, handle)
	}

	/// Emit a debug log showing batch builder state.
	pub(super) fn log_pool_status(&self, reason: &str) {
		let batch_slots = self.batch_builder.as_ref().map_or(0, |b| b.len());
		debug!(
			reason,
			batch_slots,
			pending_batches = self.pending_batches.len(),
			"sequencer pool status"
		);
	}

	/// Lazily create a `ConsumeBatchBuilder` if one doesn't exist.
	fn ensure_consume_batch_builder(&mut self) -> &mut batch::ConsumeBatchBuilder {
		if self.consume_batch_builder.is_none() {
			let dummy_root = contract::hash_to_bytes32(&self.confirmed_root).0;
			self.consume_batch_builder = Some(batch::ConsumeBatchBuilder::new(
				tessera_client::PRIV_TX_BATCH_SIZE * batch::NOTES_PER_SLOT,
				dummy_root,
			));
			self.consume_batch_pending_since = Some(std::time::Instant::now());
		}
		self.consume_batch_builder.as_mut().unwrap()
	}

	/// Evaluate the consume batch builder and flush when full or timed out.
	async fn try_flush_consume_batch_if_ready<P: Provider + Clone>(
		&mut self,
		provider: &P,
		batch_timeout: Duration,
	) -> anyhow::Result<()> {
		if self.pending_consume_batches.len() >= MAX_PENDING_BATCHES {
			return Ok(());
		}
		let Some(cb) = &self.consume_batch_builder else {
			return Ok(());
		};
		let should_flush = cb.is_full()
			|| self
				.consume_batch_pending_since
				.is_some_and(|since| since.elapsed() >= batch_timeout);
		if should_flush {
			self.flush_consume_batch(provider).await?;
		}
		Ok(())
	}

	/// Lazily create a `BatchBuilder` if one doesn't exist.
	fn ensure_batch_builder(&mut self) -> &mut batch::BatchBuilder {
		if self.batch_builder.is_none() {
			let dummy_root = contract::hash_to_bytes32(&self.confirmed_root).0;
			self.batch_builder = Some(batch::BatchBuilder::new_v2(dummy_root));
			self.batch_pending_since = Some(std::time::Instant::now());
		}
		self.batch_builder.as_mut().unwrap()
	}

	/// Evaluate the batch builder and flush when full or timed out.
	async fn try_flush_batch_if_ready<P: Provider + Clone>(
		&mut self,
		provider: &P,
		batch_timeout: Duration,
	) -> anyhow::Result<()> {
		if self.pending_batches.len() >= MAX_PENDING_BATCHES {
			return Ok(());
		}
		let Some(bb) = &self.batch_builder else {
			return Ok(());
		};
		self.log_pool_status("batch scheduling tick");
		let should_flush = bb.is_full()
			|| self
				.batch_pending_since
				.is_some_and(|since| since.elapsed() >= batch_timeout);
		if should_flush {
			self.flush_batch(provider).await?;
		}
		Ok(())
	}

	/// Run the sequencer event loop.
	///
	/// Connects to the blockchain, initialises state from on-chain history, and
	/// processes deposits/transactions until a Ctrl-C signal is received or a
	/// fatal error occurs.
	pub async fn run(&mut self) -> anyhow::Result<()> {
		if self.config.testing {
			warn!("TESSERA_TESTING=1: test methods enabled — do NOT use in production");
		}

		let signer: PrivateKeySigner = self.config.operator_private_key.parse()?;
		let signer = signer.with_chain_id(Some(self.config.chain_id));
		let wallet = EthereumWallet::from(signer);
		let provider = ProviderBuilder::new()
			.with_nonce_management(alloy::providers::fillers::CachedNonceManager::default())
			.wallet(wallet)
			.connect_http(self.config.rpc_url.parse()?);

		let rollup =
			ITesseraRollupV2::ITesseraRollupV2Instance::new(self.config.bridge_address, &provider);

		// Fetch current on-chain root and build the confirmed root history.
		let current_root_u256 = rollup.currentRoot().call().await?;
		self.confirmed_root = contract::u256_le_to_hash(current_root_u256)
			.context("currentRoot is not a valid Goldilocks hash")?;
		self.confirmed_root_history.insert(self.confirmed_root);

		info!(
			current_root = ?contract::hash_to_u256_le(&self.confirmed_root),
			"fetched on-chain currentRoot"
		);

		// Load historical confirmed roots from on-chain events.
		let to_block = provider.get_block_number().await?;
		recovery::load_confirmed_roots(
			&provider,
			self.config.bridge_address,
			0,
			to_block,
			&mut self.confirmed_root_history,
		)
		.await?;
		info!(
			confirmed_roots = self.confirmed_root_history.len(),
			"loaded confirmed root history"
		);

		// Initialise prover client and result channels (TX + consume).
		let (consume_result_tx, consume_result_rx) = mpsc::channel::<ConsumeOutcome>(4);
		self.consume_result_tx = Some(consume_result_tx);
		self.consume_result_rx = Some(consume_result_rx);

		let (result_tx, result_rx) = mpsc::channel::<ProveOutcomeV2>(4);
		if self.prover_client.is_none() {
			let http_client = HttpProverClient::new(
				self.config.prover_api_url.clone(),
				Duration::from_secs(self.config.prover_api_timeout_secs),
			)?;
			info!(url = %self.config.prover_api_url, "remote prover client configured");
			self.prover_client = Some(Arc::new(http_client));
		}
		self.result_tx = Some(result_tx);
		self.result_rx = Some(result_rx);

		let poll_interval = Duration::from_secs(self.config.poll_interval_secs);
		let batch_timeout = Duration::from_secs(self.config.batch_timeout_secs);
		let mut interval = tokio::time::interval(poll_interval);

		info!("V2 sequencer running");

		loop {
			tokio::select! {
				_ = interval.tick() => {
					if let Err(e) = self.try_flush_batch_if_ready(&provider, batch_timeout).await {
						error!("failed to flush batch: {e}");
						break;
					}
				}

				// Deposit: add NC note to the consume batch builder.
				req = self.notes_commitment_rx.recv() => {
					let Some(req) = req else { break; };
					let note = req.note;
					if !self.is_note_available(&provider, &note).await {
						warn!(note = ?note, "deposit rejected: note not Pending on contract");
						continue;
					}
					let cb = self.ensure_consume_batch_builder();
					if let Err(e) = cb.add_note(note, req.consume_proof) {
						warn!(error = %e, "deposit rejected: consume batch builder error");
						continue;
					}
					debug!(
						consume_notes = self.consume_batch_builder.as_ref().map_or(0, |b| b.len()),
						"accepted deposit note into consume batch"
					);
					if let Err(e) = self.try_flush_consume_batch_if_ready(&provider, batch_timeout).await {
						error!("failed to flush consume batch: {e}");
						break;
					}
				}

				// Consume outcome from remote prover.
				Some(outcome) = async {
					if let Some(rx) = &mut self.consume_result_rx { rx.recv().await } else { None }
				} => {
					if let Err(e) = self.handle_consume_outcome(&provider, outcome).await {
						error!("fatal sequencer error while finalizing consume batch: {e}");
						break;
					}
					if let Err(e) = self.try_flush_consume_batch_if_ready(&provider, batch_timeout).await {
						error!("failed to flush consume batch: {e}");
						break;
					}
				}

				// Prove outcome from remote prover.
				Some(outcome) = async {
					if let Some(rx) = &mut self.result_rx { rx.recv().await } else { None }
				} => {
					if let Err(e) = self.handle_prove_outcome(&provider, outcome).await {
						error!("fatal sequencer error while finalizing batch: {e}");
						break;
					}
					if let Err(e) = self.try_flush_batch_if_ready(&provider, batch_timeout).await {
						error!("failed to flush batch: {e}");
						break;
					}
				}

				// Private transactions.
				tx_req = self.private_tx_rx.recv() => {
					let Some(tx_req) = tx_req else { break; };
					let tx_id = tx_req.tx_id.as_deref().unwrap_or("unknown");
					debug!(tx_id, "received private tx");

					// Within-batch duplicate check on AN.
					let an_leaf = tx_req.input_account_leaf;
					if self.batch_builder.as_ref().is_some_and(|b| b.contains_an(&an_leaf)) {
						warn!(tx_id, "private tx rejected: AN leaf already in batch");
						continue;
					}
					// Within-batch duplicate check on NN.
					let mut nn_rejected = false;
					for note in &tx_req.input_notes {
						if self.batch_builder.as_ref().is_some_and(|b| b.contains_nn(note)) {
							warn!(tx_id, note = ?alloy::primitives::B256::from(*note), "private tx rejected: NN leaf already in batch");
							nn_rejected = true;
							break;
						}
					}
					if nn_rejected {
						continue;
					}

					let nc: [[u8; 32]; 8] = {
						let mut arr = [[0u8; 32]; 8];
						// NC[0..NOTE_BATCH] = output notes; NC[NOTE_BATCH] = AC (8th SR leaf).
						for (i, note) in tx_req
							.output_notes
							.iter()
							.enumerate()
							.take(tessera_client::NOTE_BATCH)
						{
							arr[i] = *note;
						}
						arr[tessera_client::NOTE_BATCH] = tx_req.output_account_leaf;
						arr
					};
					let nn: [[u8; 32]; 8] = {
						let mut arr = [[0u8; 32]; 8];
						for (i, note) in tx_req.input_notes.iter().enumerate().take(8) {
							arr[i] = *note;
						}
						arr
					};

					let bb = self.ensure_batch_builder();
					if let Err(e) = bb.add_private_tx(
						tx_req.tx_proof,
						tx_req.output_account_leaf,
						an_leaf,
						nc,
						nn,
					) {
						warn!(tx_id, error = %e, "private tx rejected: batch builder error");
						continue;
					}

					info!(
						tx_id,
						batch_slots = self.batch_builder.as_ref().map_or(0, |b| b.len()),
						"private tx added to batch"
					);
					if let Err(e) = self.try_flush_batch_if_ready(&provider, batch_timeout).await {
						error!("failed to flush batch: {e}");
						break;
					}
				}

				// Test-only: inject deposit without on-chain Pending check.
				Some(note) = async {
					if let Some(rx) = &mut self.test_deposit_rx { rx.recv().await } else { None }
				} => {
					if let Err(e) = self.handle_test_deposit(note) {
						warn!(error = %e, "test deposit rejected");
					}
				}

				// Test-only: inject transaction without proof verification.
				Some(req) = async {
					if let Some(rx) = &mut self.test_tx_rx { rx.recv().await } else { None }
				} => {
					if let Err(e) = self.handle_test_tx(req) {
						warn!(error = %e, "test tx rejected");
					}
				}

				// Test-only: flush consume batch + confirm with zero proof.
				Some(resp_tx) = async {
					if let Some(rx) = &mut self.test_consume_validate_rx { rx.recv().await } else { None }
				} => {
					let result = self.flush_consume_batch_testing(&provider).await;
					let _ = resp_tx.send(result);
				}

				// Test-only: flush TX batch + confirm with zero proof.
				Some(resp_tx) = async {
					if let Some(rx) = &mut self.test_tx_validate_rx { rx.recv().await } else { None }
				} => {
					let result = self.flush_batch_testing(&provider).await;
					let _ = resp_tx.send(result);
				}

				_ = tokio::signal::ctrl_c() => {
					info!("shutting down");
					break;
				}
			}
		}

		Ok(())
	}
}
