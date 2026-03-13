use std::{collections::BTreeMap, sync::Arc, time::Duration};

use alloy::{
	network::EthereumWallet,
	providers::{Provider, ProviderBuilder},
	signers::{local::PrivateKeySigner, Signer},
};
use anyhow::Context;
use tessera_trees::tree::{hasher::HashOutput, CommitmentTree, NullifierTree};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{
	config::SequencerConfig,
	contract::{self, IDepositsRollupBridge},
	prover_client::HttpProverClient,
	states::{CommitmentTreeState, NullifierTreeState},
	tree_store::{StoreMeta, TreeId, TreeStore},
	types::ProveOutcome,
	TREE_DEPTH,
};

mod api;
pub mod batch;
mod pipeline;
mod recovery;
mod revert;

/// Receipt polling timeout for on-chain transactions.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Mirror of `MAX_PENDING_BATCHES` in `TesseraRollup.sol`.
const MAX_PENDING_BATCHES: usize = 128;

/// A batch registered on-chain and awaiting a single SuperAggregator proof
/// via `confirmBatch`.  Stored in `registered_pending_batches` until confirmed.
#[allow(dead_code)]
struct TxBatch {
	batch_id: u64,
	/// Original private TX requests for requeue on proof failure.
	private_tx_reqs: Vec<PrivateTxRequest>,
	/// Original deposit NC notes for requeue on proof failure.
	deposit_notes: Vec<[u8; 32]>,
	/// Padded leaf arrays for WAL commit after on-chain confirmation.
	nc_padded: Vec<[u8; 32]>,
	nn_padded: Vec<[u8; 32]>,
	ac_padded: Vec<[u8; 32]>,
	an_padded: Vec<[u8; 32]>,
}

/// A decoded private transaction forwarded from the API to the sequencer's
/// optimistic register path.
pub(super) struct PrivateTxRequest {
	pub tx_id: Option<String>,
	/// Notes nullifier leaves (input notes being spent).
	pub input_notes: Vec<[u8; 32]>,
	/// Notes commitment leaves (output notes being created).
	pub output_notes: Vec<[u8; 32]>,
	/// Accounts nullifier leaf (input account state being consumed).
	pub input_account_leaf: [u8; 32],
	/// Accounts commitment leaf (output account state being created).
	pub output_account_leaf: [u8; 32],
	/// The validated transaction proof bytes.
	pub tx_proof: Vec<u8>,
}

/// Tree discriminant kept for `recovery.rs` compatibility (Step 12 will remove it).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TreeJob {
	NotesCommitment,
	NotesNullifier,
	AccountsCommitment,
	AccountsNullifier,
}

#[derive(Debug, Clone)]
pub(super) struct NotesCommitmentRequest {
	pub note: [u8; 32],
}

/// Pad `real_bytes` to `batch_size` with deterministic dummy leaves, then convert
/// the result to the native `HashOutput` type expected by the plonky2 circuit.
fn build_proving_commitments(
	current_root: &[u8; 32],
	batch_start_index: usize,
	batch_size: usize,
	real_bytes: &[[u8; 32]],
) -> anyhow::Result<(Vec<[u8; 32]>, Vec<HashOutput>)> {
	let proving_bytes =
		crate::dummy::pad_leaves(current_root, batch_start_index, batch_size, real_bytes)?;
	let proving_hashes = contract::bytes_slice_to_hashes(&proving_bytes)?;
	Ok((proving_bytes, proving_hashes))
}

/// The main sequencer: watches note availability, batches by chain order, proves and finalizes.
pub struct Sequencer {
	config: SequencerConfig,
	pub notes_commitment_state: CommitmentTreeState,
	pub notes_nullifier_state: NullifierTreeState,
	pub accounts_commitment_state: CommitmentTreeState,
	pub accounts_nullifier_state: NullifierTreeState,
	notes_commitment_store: Option<TreeStore<CommitmentTree<HashOutput>>>,
	notes_commitment_meta: Option<StoreMeta>,
	notes_nullifier_store: Option<TreeStore<NullifierTree<HashOutput>>>,
	notes_nullifier_meta: Option<StoreMeta>,
	accounts_commitment_store: Option<TreeStore<CommitmentTree<HashOutput>>>,
	accounts_commitment_meta: Option<StoreMeta>,
	accounts_nullifier_store: Option<TreeStore<NullifierTree<HashOutput>>>,
	accounts_nullifier_meta: Option<StoreMeta>,
	prover_client: Option<HttpProverClient>,
	result_tx: Option<mpsc::Sender<ProveOutcome>>,
	result_rx: Option<mpsc::Receiver<ProveOutcome>>,
	notes_commitment_rx: Option<mpsc::Receiver<NotesCommitmentRequest>>,
	/// Registered-but-unconfirmed two-phase batches keyed by on-chain `batchId`.
	registered_pending_batches: BTreeMap<u64, TxBatch>,
	/// Receiver end of the private-tx channel for optimistic two-phase register.
	private_tx_rx: Option<mpsc::Receiver<PrivateTxRequest>>,
	/// Slot-centric batch builder. Created lazily when the first TX/deposit
	/// arrives; consumed on `flush_batch`.
	batch_builder: Option<batch::BatchBuilder>,
	/// Instant when the first item was added to the current `batch_builder`.
	/// Used for timeout-based partial-batch flushing.
	batch_pending_since: Option<std::time::Instant>,
}

impl Sequencer {
	/// Attempt to flush the batch if it is full or has timed out.
	///
	/// Convenience wrapper called at the tail of every leaf-accept arm in the main event
	/// loop, so that a newly enqueued leaf can immediately trigger a batch flush without
	/// waiting for the next poll-interval tick.
	async fn try_flush_batch_if_ready<P: Provider + Clone>(
		&mut self,
		provider: &P,
		account_batch_size: usize,
		batch_timeout: std::time::Duration,
	) -> anyhow::Result<()> {
		self.maybe_flush_batch(provider, account_batch_size, batch_timeout)
			.await
	}

	/// Emit a `debug!` log showing the current batch builder state.
	pub(super) fn log_pool_status(&self, reason: &str) {
		let batch_slots = self.batch_builder.as_ref().map_or(0, |b| b.len());
		debug!(
			reason,
			batch_slots,
			pending_batches = self.registered_pending_batches.len(),
			"sequencer pool status"
		);
	}

	/// Lazily create a `BatchBuilder` if one doesn't exist.
	fn ensure_batch_builder(&mut self, account_batch_size: usize) -> &mut batch::BatchBuilder {
		if self.batch_builder.is_none() {
			self.batch_builder = Some(batch::BatchBuilder::new(
				account_batch_size,
				&self.accounts_commitment_state.tree,
				&self.accounts_nullifier_state.tree,
				&self.notes_commitment_state.tree,
				&self.notes_nullifier_state.tree,
			));
			self.batch_pending_since = Some(std::time::Instant::now());
		}
		self.batch_builder.as_mut().unwrap()
	}

	pub fn new(config: SequencerConfig) -> Self {
		Self {
			config,
			notes_commitment_state: CommitmentTreeState::new(),
			notes_nullifier_state: NullifierTreeState::new(),
			accounts_commitment_state: CommitmentTreeState::new(),
			accounts_nullifier_state: NullifierTreeState::new(),
			notes_commitment_store: None,
			notes_commitment_meta: None,
			notes_nullifier_store: None,
			notes_nullifier_meta: None,
			accounts_commitment_store: None,
			accounts_commitment_meta: None,
			accounts_nullifier_store: None,
			accounts_nullifier_meta: None,
			prover_client: None,
			result_tx: None,
			result_rx: None,
			notes_commitment_rx: None,
			registered_pending_batches: BTreeMap::new(),
			private_tx_rx: None,
			batch_builder: None,
			batch_pending_since: None,
		}
	}

	pub async fn run(&mut self) -> anyhow::Result<()> {
		std::fs::create_dir_all(&self.config.tree_store_path).with_context(|| {
			format!(
				"create tree store dir: {}",
				self.config.tree_store_path.display()
			)
		})?;

		let signer: PrivateKeySigner = self.config.operator_private_key.parse()?;
		let signer = signer.with_chain_id(Some(self.config.chain_id));
		let wallet = EthereumWallet::from(signer);
		let provider = ProviderBuilder::new()
			.with_nonce_management(alloy::providers::fillers::CachedNonceManager::default())
			.wallet(wallet)
			.connect_http(self.config.rpc_url.parse()?);

		let bridge = IDepositsRollupBridge::IDepositsRollupBridgeInstance::new(
			self.config.bridge_address,
			&provider,
		);

		let on_chain_notes_commitment_root = bridge.notesCommitmentRoot().call().await?;
		let on_chain_notes_nullifier_root = bridge.notesNullifierRoot().call().await?;
		let on_chain_accounts_commitment_root = bridge.accountsCommitmentRoot().call().await?;
		let on_chain_accounts_nullifier_root = bridge.accountsNullifierRoot().call().await?;
		let note_batch_size: usize = bridge
			.noteBatchSize()
			.call()
			.await?
			.try_into()
			.context("noteBatchSize overflow")?;
		let account_batch_size: usize = bridge
			.accountBatchSize()
			.call()
			.await?
			.try_into()
			.context("accountBatchSize overflow")?;
		info!(
			notes_commitment_root = ?on_chain_notes_commitment_root,
			notes_nullifier_root = ?on_chain_notes_nullifier_root,
			accounts_commitment_root = ?on_chain_accounts_commitment_root,
			accounts_nullifier_root = ?on_chain_accounts_nullifier_root,
			note_batch_size,
			account_batch_size,
			"synced on-chain roots"
		);
		anyhow::ensure!(note_batch_size > 0, "on-chain noteBatchSize must be > 0");
		anyhow::ensure!(
			note_batch_size == account_batch_size * 8,
			"on-chain noteBatchSize ({note_batch_size}) != accountBatchSize ({account_batch_size}) × 8"
		);

		// Load all four persisted trees (snapshot + WAL). Treated as cache; may be behind chain.
		let (tree, store, meta) = recovery::load_tree_from_store::<CommitmentTree<HashOutput>>(
			&self.config.tree_store_path,
			TreeId::NotesCommitment,
			"notes_commitment",
			self.config.snapshot_every_batches,
			note_batch_size,
		)?;
		self.notes_commitment_state.tree = tree;
		self.notes_commitment_store = Some(store);
		self.notes_commitment_meta = Some(meta);
		self.load_other_trees(note_batch_size, account_batch_size)?;

		// Step 3: reconcile local cache with chain by replaying only missing batches.
		// This is authoritative recovery: if local is behind, we recover leaves from
		// on-chain transaction calldata and append them locally.
		//
		// Two-phase batches advance notesCommitmentRoot() ahead of the per-tree confirmed
		// roots.  Reconcile local trees against the confirmed roots here;
		// recover_pending_requests re-applies all two-phase batches (confirmed + pending)
		// on top.
		let (recovery_nc_root, recovery_nn_root, recovery_ac_root, recovery_an_root) = (
			bridge.confirmedNotesCommitmentRoot().call().await?,
			bridge.confirmedNotesNullifierRoot().call().await?,
			bridge.confirmedAccountsCommitmentRoot().call().await?,
			bridge.confirmedAccountsNullifierRoot().call().await?,
		);
		self.recover_missing_chain_updates(
			&provider,
			&recovery_nc_root,
			&recovery_nn_root,
			&recovery_ac_root,
			&recovery_an_root,
		)
		.await?;

		// Initialise the prover client and result channel before recover_pending_requests so
		// that the recovery path can submit prove jobs via submit_prove_request_with_retry.
		let (result_tx, result_rx) = mpsc::channel::<ProveOutcome>(4);
		let prover_client = HttpProverClient::new(
			self.config.prover_api_url.clone(),
			Duration::from_secs(self.config.prover_api_timeout_secs),
		)?;
		info!(
			url = %self.config.prover_api_url,
			timeout_secs = self.config.prover_api_timeout_secs,
			"remote prover client configured"
		);
		self.prover_client = Some(prover_client);
		self.result_tx = Some(result_tx);
		self.result_rx = Some(result_rx);

		self.recover_pending_requests(&provider, note_batch_size, account_batch_size)
			.await?;
		info!(
			local_root = ?contract::hash_to_bytes32(&self.notes_commitment_state.current_root()),
			pending_requests = self.notes_commitment_state.pending_requests.len(),
			"state recovery complete"
		);
		self.log_pool_status("after startup recovery");

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
			info!(addr = %api_addr, "sequencer consume-request API listening");
			if let Err(e) = axum::serve(listener, app).await {
				error!("sequencer API server stopped: {e}");
			}
		});

		let poll_interval = Duration::from_secs(self.config.poll_interval_secs);
		let batch_timeout = Duration::from_secs(self.config.batch_timeout_secs);
		let mut interval = tokio::time::interval(poll_interval);

		info!("sequencer running");

		loop {
			tokio::select! {
				_ = interval.tick() => {
					if let Err(e) = self.try_flush_batch_if_ready(&provider, account_batch_size, batch_timeout).await {
						error!("failed to flush batch: {e}");
						break;
					}
				}

				// Deposit: add NC note to the batch builder.
				Some(req) = async {
					if let Some(rx) = &mut self.notes_commitment_rx {
						rx.recv().await
					} else {
						None
					}
				} => {
					let note = req.note;
					if !self.is_note_available(&provider, &note).await {
						warn!(note = ?note, "deposit rejected: note not Pending on bridge");
						continue;
					}
					let bb = self.ensure_batch_builder(account_batch_size);
					if let Err(e) = bb.add_deposit(note) {
						warn!(error = %e, "deposit rejected: batch builder error");
						continue;
					}
					self.log_pool_status("accepted deposit note");
					if let Err(e) = self.try_flush_batch_if_ready(&provider, account_batch_size, batch_timeout).await {
						error!("failed to flush batch: {e}");
						break;
					}
				}

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
					if let Err(e) = self.try_flush_batch_if_ready(&provider, account_batch_size, batch_timeout).await {
						error!("failed to flush batch: {e}");
						break;
					}
				}

				// Private transactions: validate nullifiers, then add to batch builder.
				Some(tx_req) = async {
					if let Some(rx) = &mut self.private_tx_rx {
						rx.recv().await
					} else {
						None
					}
				} => {
					let tx_id = tx_req.tx_id.as_deref().unwrap_or("unknown");
					debug!(tx_id, "validating private tx nullifier leaves");

					// Validate NN: reject if any input note nullifier already in tree or current batch.
					let mut nn_rejected = false;
					for note in &tx_req.input_notes {
						let note_hash = match contract::bytes32_to_hash(&alloy::primitives::B256::from(*note)) {
							Ok(h) => h,
							Err(e) => {
								warn!(tx_id, note = ?alloy::primitives::B256::from(*note), error = %e, "private tx rejected: invalid NN leaf encoding");
								nn_rejected = true;
								break;
							},
						};
						if self.notes_nullifier_state.tree.find_node_index_by_value(&note_hash).is_some() {
							warn!(tx_id, note = ?alloy::primitives::B256::from(*note), "private tx rejected: NN leaf already nullified");
							nn_rejected = true;
							break;
						}
						if self.batch_builder.as_ref().is_some_and(|b| b.contains_nn(note)) {
							warn!(tx_id, note = ?alloy::primitives::B256::from(*note), "private tx rejected: NN leaf already in batch");
							nn_rejected = true;
							break;
						}
					}
					if nn_rejected {
						continue;
					}

					// Validate AN: reject if account nullifier already in tree or current batch.
					let an_leaf = tx_req.input_account_leaf;
					let an_hash = match contract::bytes32_to_hash(&alloy::primitives::B256::from(an_leaf)) {
						Ok(h) => h,
						Err(e) => {
							warn!(tx_id, error = %e, "private tx rejected: invalid AN leaf encoding");
							continue;
						},
					};
					if self.accounts_nullifier_state.tree.find_node_index_by_value(&an_hash).is_some() {
						warn!(tx_id, "private tx rejected: AN leaf already nullified");
						continue;
					}
					if self.batch_builder.as_ref().is_some_and(|b| b.contains_an(&an_leaf)) {
						warn!(tx_id, "private tx rejected: AN leaf already in batch");
						continue;
					}

					// All checks passed — add to batch builder.
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

					let bb = self.ensure_batch_builder(account_batch_size);
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
					if let Err(e) = self.try_flush_batch_if_ready(&provider, account_batch_size, batch_timeout).await {
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
