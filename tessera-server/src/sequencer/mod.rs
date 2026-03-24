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
use tessera_client::NOTE_BATCH;
use tessera_utils::{hasher::HashOutput, F};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{
	config::SequencerConfig,
	contract::{self, ITesseraRollupV2},
	prover_client::{HttpProverClient, ProverClient},
	types::ProveOutcome,
};

mod bn128_wrapper_service;
mod deposits;
mod handle;
mod pipeline;
mod recovery;
mod revert;
mod transactions;

pub use bn128_wrapper_service::*;
pub use handle::SequencerHandle;
pub use transactions::*;

/// Receipt polling timeout for on-chain transactions.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum number of pending (submitted, not yet proven) batches.
const MAX_PENDING_BATCHES: usize = 128;

/// A batch submitted on-chain and awaiting a Groth16 proof via `proveTransactionBatch`.
struct SolidityTransactionBatchCommitment {
	/// On-chain piCommitment (keccak256 of batch public inputs).
	pi_commitment: [u8; 32],
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

/// The V2 sequencer: accumulates TX slots, submits batches to `TesseraContract`,
/// and forwards prove requests to the remote prover.
pub struct Sequencer {
	config: SequencerConfig,
	/// Current on-chain Poseidon IMT root (`currentRoot()` after all proven batches).
	confirmed_root: HashOutput,
	/// All roots ever in `confirmedRoots` on-chain (genesis + every proven batch root).
	confirmed_root_history: BTreeSet<HashOutput>,
	/// Pending batches (submitted but not yet proven), keyed by local `batch_id`.
	pending_batches: BTreeMap<u64, SolidityTransactionBatchCommitment>,
	/// Monotonically increasing local batch counter.
	next_batch_id: u64,
	prover_client: Option<Arc<dyn ProverClient>>,
	result_tx: Option<mpsc::Sender<ProveOutcome>>,
	result_rx: Option<mpsc::Receiver<ProveOutcome>>,
	private_tx_rx: mpsc::Receiver<PrivateTxRequest>,
	batch_builder: Option<transactions::BatchBuilder>,
	batch_pending_since: Option<std::time::Instant>,
}

impl Sequencer {
	/// Create a new sequencer and return its application-facing handle.
	///
	/// The returned [`SequencerHandle`] is the only way to submit deposits and
	/// transactions. Call [`Sequencer::run`] (typically in a spawned task) to
	/// start the event loop.
	pub fn new(config: SequencerConfig) -> (Self, SequencerHandle) {
		use plonky2::field::types::Field;

		let (private_tx_tx, private_tx_rx) = mpsc::channel::<PrivateTxRequest>(MAX_PENDING_BATCHES);

		let handle = SequencerHandle {
			private_tx_tx,
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
			private_tx_rx,
			batch_builder: None,
			batch_pending_since: None,
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

	/// Lazily create a `BatchBuilder` if one doesn't exist.
	fn ensure_batch_builder(&mut self) -> &mut transactions::BatchBuilder {
		if self.batch_builder.is_none() {
			self.batch_builder = Some(transactions::BatchBuilder::new());
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

		let (result_tx, result_rx) = mpsc::channel::<ProveOutcome>(4);
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

					let nc: [[u8; 32]; NOTE_BATCH] = {
						let mut arr = [[0u8; 32]; NOTE_BATCH];
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
					let nn: [[u8; 32]; NOTE_BATCH] = {
						let mut arr = [[0u8; 32]; NOTE_BATCH];
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
