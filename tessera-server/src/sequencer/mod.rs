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
use tessera_trees::{tree::hasher::HashOutput, F};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{
	config::SequencerConfig,
	contract::{self, ITesseraRollupV2},
	prover_client::HttpProverClient,
	types::{ConsumeOutcome, ProveOutcomeV2},
};

mod api;
pub mod batch;
mod pipeline;
mod recovery;
mod revert;

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

/// A decoded private transaction forwarded from the API to the sequencer.
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
	/// Validated transaction proof bytes.
	pub tx_proof: Vec<u8>,
}

/// Note-commitment forwarded from the API (deposit path).
pub(super) struct NotesCommitmentRequest {
	pub note: [u8; 32],
	/// Consume proof bytes submitted by the client (may be absent in tests).
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
	prover_client: Option<HttpProverClient>,
	result_tx: Option<mpsc::Sender<ProveOutcomeV2>>,
	result_rx: Option<mpsc::Receiver<ProveOutcomeV2>>,
	notes_commitment_rx: Option<mpsc::Receiver<NotesCommitmentRequest>>,
	private_tx_rx: Option<mpsc::Receiver<PrivateTxRequest>>,
	batch_builder: Option<batch::BatchBuilder>,
	batch_pending_since: Option<std::time::Instant>,
	/// Consume (deposit) pipeline.
	consume_result_tx: Option<mpsc::Sender<ConsumeOutcome>>,
	consume_result_rx: Option<mpsc::Receiver<ConsumeOutcome>>,
	consume_batch_builder: Option<batch::ConsumeBatchBuilder>,
	consume_batch_pending_since: Option<std::time::Instant>,
	pending_consume_batches: BTreeMap<u64, ConsumeBatchV2>,
	next_consume_batch_id: u64,
}

impl Sequencer {
	pub fn new(config: SequencerConfig) -> Self {
		use plonky2::field::types::Field;
		Self {
			config,
			confirmed_root: HashOutput::new([F::ZERO; 4]),
			confirmed_root_history: BTreeSet::new(),
			pending_batches: BTreeMap::new(),
			next_batch_id: 0,
			prover_client: None,
			result_tx: None,
			result_rx: None,
			notes_commitment_rx: None,
			private_tx_rx: None,
			batch_builder: None,
			batch_pending_since: None,
			consume_result_tx: None,
			consume_result_rx: None,
			consume_batch_builder: None,
			consume_batch_pending_since: None,
			pending_consume_batches: BTreeMap::new(),
			next_consume_batch_id: 0,
		}
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
				self.config.account_batch_size * batch::NOTES_PER_SLOT,
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
			self.batch_builder = Some(batch::BatchBuilder::new_v2(
				self.config.account_batch_size,
				dummy_root,
			));
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

	pub async fn run(&mut self) -> anyhow::Result<()> {
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
		let prover_client = HttpProverClient::new(
			self.config.prover_api_url.clone(),
			Duration::from_secs(self.config.prover_api_timeout_secs),
		)?;
		info!(
			url = %self.config.prover_api_url,
			"remote prover client configured"
		);
		self.prover_client = Some(prover_client);
		self.result_tx = Some(result_tx);
		self.result_rx = Some(result_rx);

		let (notes_commitment_tx, notes_commitment_rx) =
			mpsc::channel::<NotesCommitmentRequest>(1024);
		self.notes_commitment_rx = Some(notes_commitment_rx);

		let private_tx_tx = {
			let (tx, rx) = mpsc::channel::<PrivateTxRequest>(MAX_PENDING_BATCHES);
			self.private_tx_rx = Some(rx);
			tx
		};

		let api_addr: std::net::SocketAddr = self
			.config
			.api_bind_addr
			.parse()
			.map_err(|e| anyhow::anyhow!("invalid TESSERA_SEQUENCER_API_ADDR: {e}"))?;
		let consume_proof_verifier = self
			.config
			.consume_artifacts_path
			.as_deref()
			.map(|path| api::LeafProofVerifier::from_artifacts(path).map(Arc::new))
			.transpose()
			.context("failed to load consume proof verifier from consume artifacts")?;
		let tx_proof_verifier = if self.config.aggregator_artifacts_path.is_some() {
			info!("building inner PrivTx circuit verifier for API proof validation...");
			Some(Arc::new(
				tokio::task::spawn_blocking(api::LeafProofVerifier::from_inner_circuit)
					.await
					.context("inner circuit build task panicked")?,
			))
		} else {
			None
		};
		let api_state = api::ApiState {
			notes_commitment_tx,
			private_tx_tx: Some(private_tx_tx),
			consume_proof_verifier,
			tx_proof_verifier,
		};
		let app = api::build_router(api_state);
		tokio::spawn(async move {
			let listener = match tokio::net::TcpListener::bind(api_addr).await {
				Ok(l) => l,
				Err(e) => {
					error!("failed to bind sequencer API listener: {e}");
					return;
				},
			};
			info!(addr = %api_addr, "sequencer API listening");
			if let Err(e) = axum::serve(listener, app).await {
				error!("sequencer API server stopped: {e}");
			}
		});

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
				Some(req) = async {
					if let Some(rx) = &mut self.notes_commitment_rx {
						rx.recv().await
					} else {
						None
					}
				} => {
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
					if let Some(rx) = &mut self.consume_result_rx {
						rx.recv().await
					} else {
						None
					}
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
					if let Some(rx) = &mut self.result_rx {
						rx.recv().await
					} else {
						None
					}
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
				Some(tx_req) = async {
					if let Some(rx) = &mut self.private_tx_rx {
						rx.recv().await
					} else {
						None
					}
				} => {
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
						for (i, note) in tx_req.output_notes.iter().enumerate().take(8) {
							arr[i] = *note;
						}
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

				_ = tokio::signal::ctrl_c() => {
					info!("shutting down");
					break;
				}
			}
		}

		Ok(())
	}
}
