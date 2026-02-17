use std::time::Duration;

use anyhow::Context;
use alloy::{
	network::EthereumWallet,
	providers::{Provider, ProviderBuilder},
	signers::{local::PrivateKeySigner, Signer},
};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{
	config::SequencerConfig,
	contract::{self, IDepositsRollupBridge},
	prover_client::HttpProverClient,
	states::{CommitmentTreeState, EventOrderKey, NullifierTreeState, PendingRequest},
	tree_store::{StoreMeta, TreeId, TreeStore},
	types::ProveOutcome,
	TREE_DEPTH,
};
use tessera_trees::tree::{hasher::Hash, CommitmentTree, NullifierTree};

mod api;
mod pipeline;
mod recovery;
mod revert;

/// Receipt polling timeout for on-chain transactions.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);

struct InFlightBatch {
	job: TreeJob,
	requests: Vec<PendingRequest>,
	commitments_bytes: Vec<[u8; 32]>,
	commitments_hash: Vec<Hash>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TreeJob {
	NotesCommitment,
	NotesNullifier,
	AccountsCommitment,
	AccountsNullifier,
}

/// The main sequencer: watches note availability, batches by chain order, proves and finalizes.
pub struct Sequencer {
	config: SequencerConfig,
	pub notes_commitment_state: CommitmentTreeState,
	pub notes_nullifier_state: NullifierTreeState,
	pub accounts_commitment_state: CommitmentTreeState,
	pub accounts_nullifier_state: NullifierTreeState,
	notes_commitment_store: Option<TreeStore<CommitmentTree<Hash>>>,
	notes_commitment_meta: Option<StoreMeta>,
	notes_nullifier_store: Option<TreeStore<NullifierTree<Hash>>>,
	notes_nullifier_meta: Option<StoreMeta>,
	accounts_commitment_store: Option<TreeStore<CommitmentTree<Hash>>>,
	accounts_commitment_meta: Option<StoreMeta>,
	accounts_nullifier_store: Option<TreeStore<NullifierTree<Hash>>>,
	accounts_nullifier_meta: Option<StoreMeta>,
	prover_client: Option<HttpProverClient>,
	result_tx: Option<mpsc::Sender<ProveOutcome>>,
	result_rx: Option<mpsc::Receiver<ProveOutcome>>,
	notes_commitment_rx: Option<mpsc::Receiver<[u8; 32]>>,
	notes_nullifier_rx: Option<mpsc::Receiver<[u8; 32]>>,
	accounts_commitment_rx: Option<mpsc::Receiver<[u8; 32]>>,
	accounts_nullifier_rx: Option<mpsc::Receiver<[u8; 32]>>,
	api_order_counter: u64,
}

impl Sequencer {
	pub(super) fn log_pool_status(&self, reason: &str) {
		debug!(
			reason,
			notes_commitment_pending = self.notes_commitment_state.pending_requests.len(),
			notes_nullifier_pending = self.notes_nullifier_state.pending_requests.len(),
			accounts_commitment_pending = self.accounts_commitment_state.pending_requests.len(),
			accounts_nullifier_pending = self.accounts_nullifier_state.pending_requests.len(),
			"sequencer pool status"
		);
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
			notes_nullifier_rx: None,
			accounts_commitment_rx: None,
			accounts_nullifier_rx: None,
			api_order_counter: 0,
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
		let batch_size: usize = bridge
			.batchSize()
			.call()
			.await?
			.try_into()
			.unwrap_or(0usize);
		info!(
			notes_commitment_root = ?on_chain_notes_commitment_root,
			notes_nullifier_root = ?on_chain_notes_nullifier_root,
			accounts_commitment_root = ?on_chain_accounts_commitment_root,
			accounts_nullifier_root = ?on_chain_accounts_nullifier_root,
			batch_size,
			"synced on-chain roots"
		);
		anyhow::ensure!(batch_size > 0, "on-chain batchSize must be > 0");

		// Step 1: load local persisted trees (snapshot + WAL). This is fast-path startup.
		// These local stores are treated as cache and may be behind chain head.
		let mut store = TreeStore::<CommitmentTree<Hash>>::open(
			&self.config.tree_store_path,
			TreeId::NotesCommitment,
			self.config.snapshot_every_batches,
		)?;
		let (mut tree, meta0) = store.load_or_init(|| CommitmentTree::new(TREE_DEPTH))?;
		let (wal_pos, replayed) = store.replay_wal_since_snapshot(&mut tree, &meta0, |t, vals| {
			let leaves: Vec<Hash> = vals
				.into_iter()
				.map(|b| contract::bytes32_to_hash(&alloy::primitives::B256::from(b)))
				.collect::<anyhow::Result<Vec<_>>>()?;
			let proof = t.insert_batch(leaves)?;
			anyhow::ensure!(proof.verify(), "WAL replay produced invalid proof");
			Ok(())
		})?;
		// Backward compatibility for legacy snapshots that predate CommitmentTree::leaf_counts.
		if meta0.snapshot_version < 2 {
			tree.rebuild_leaf_counts();
		}
		let mut meta = meta0.clone();
		meta.wal_pos = wal_pos;
		meta.committed_batches = meta.committed_batches.saturating_add(replayed);
		info!(
			tree = "notes_commitment",
			replayed_batches = replayed,
			wal_pos,
			last_block = meta.last_block,
			last_tx_index = meta.last_tx_index,
			last_log_index = meta.last_log_index,
			"loaded local tree state from snapshot/WAL"
		);

		self.notes_commitment_state.tree = tree;
		self.notes_commitment_store = Some(store);
		self.notes_commitment_meta = Some(meta);

		// Step 2: load the three other persisted trees from disk cache.
		self.load_other_trees()?;

		// Step 3: reconcile local cache with chain by replaying only missing batches.
		// This is authoritative recovery: if local is behind, we recover leaves from
		// on-chain transaction calldata and append them locally.
		self
			.recover_missing_chain_updates(
				&provider,
				&on_chain_notes_commitment_root,
				&on_chain_notes_nullifier_root,
				&on_chain_accounts_commitment_root,
				&on_chain_accounts_nullifier_root,
			)
			.await?;

		self.recover_pending_requests(&provider, batch_size).await?;
		info!(
			local_root = ?contract::hash_to_bytes32(&self.notes_commitment_state.current_root()),
			pending_requests = self.notes_commitment_state.pending_requests.len(),
			"state recovery complete"
		);
		self.log_pool_status("after startup recovery");

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

		let (notes_commitment_tx, notes_commitment_rx) = mpsc::channel::<[u8; 32]>(1024);
		let (notes_nullifier_tx, notes_nullifier_rx) = mpsc::channel::<[u8; 32]>(1024);
		let (accounts_commitment_tx, accounts_commitment_rx) = mpsc::channel::<[u8; 32]>(1024);
		let (accounts_nullifier_tx, accounts_nullifier_rx) = mpsc::channel::<[u8; 32]>(1024);
		self.notes_commitment_rx = Some(notes_commitment_rx);
		self.notes_nullifier_rx = Some(notes_nullifier_rx);
		self.accounts_commitment_rx = Some(accounts_commitment_rx);
		self.accounts_nullifier_rx = Some(accounts_nullifier_rx);
		let api_addr: std::net::SocketAddr = self
			.config
			.api_bind_addr
			.parse()
			.map_err(|e| anyhow::anyhow!("invalid TESSERA_SEQUENCER_API_ADDR: {e}"))?;
		let api_state = api::ApiState {
			notes_commitment_tx,
			notes_nullifier_tx,
			accounts_commitment_tx,
			accounts_nullifier_tx,
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
		let mut interval = tokio::time::interval(poll_interval);
		let mut in_flight: Option<InFlightBatch> = None;

		info!("sequencer running");

		loop {
			tokio::select! {
				_ = interval.tick() => {
					if in_flight.is_none() {
						if let Err(e) = self.maybe_start_next_batch(&provider, batch_size, &mut in_flight).await {
							error!("failed to start next batch: {e}");
							break;
						}
					}
				}

				Some(note) = async {
					if let Some(rx) = &mut self.notes_commitment_rx {
						rx.recv().await
					} else {
						None
					}
				} => {
					if !self.is_note_available(&provider, &note).await {
						warn!(note = ?note, "notes commitment request rejected: note exists on bridge but is not Pending");
						continue;
					}
					let order_key = EventOrderKey {
						block_number: 0,
						transaction_index: 0,
						log_index: self.api_order_counter,
					};
					self.api_order_counter = self.api_order_counter.saturating_add(1);
					self.notes_commitment_state.add_consume_request(order_key, note, batch_size);
					self.log_pool_status("accepted notes commitment leaf");

					if in_flight.is_none() {
						if let Err(e) = self.maybe_start_next_batch(&provider, batch_size, &mut in_flight).await {
							error!("failed to start next batch: {e}");
							break;
						}
					}
				}

				Some(note) = async {
					if let Some(rx) = &mut self.notes_nullifier_rx {
						rx.recv().await
					} else {
						None
					}
				} => {
					let note_hash = match contract::bytes32_to_hash(&alloy::primitives::B256::from(note)) {
						Ok(h) => h,
						Err(e) => {
							warn!(note = ?alloy::primitives::B256::from(note), error = %e, "notes nullifier request rejected: invalid leaf encoding");
							continue;
						},
					};
					if self.notes_nullifier_state.tree.find_node_index_by_value(&note_hash).is_some() {
						warn!(note = ?alloy::primitives::B256::from(note), "notes nullifier request rejected: leaf already nullified");
						continue;
					}
					if !self.is_note_validated(&provider, &note).await {
						warn!(note = ?note, "notes nullifier request rejected: note exists on bridge but is not Validated");
						continue;
					}
					let order_key = EventOrderKey {
						block_number: 0,
						transaction_index: 0,
						log_index: self.api_order_counter,
					};
					self.api_order_counter = self.api_order_counter.saturating_add(1);
					self.notes_nullifier_state.add_consume_request(order_key, note, batch_size);
					self.log_pool_status("accepted notes nullifier leaf");

					if in_flight.is_none() {
						if let Err(e) = self.maybe_start_next_batch(&provider, batch_size, &mut in_flight).await {
							error!("failed to start next batch: {e}");
							break;
						}
					}
				}

				Some(leaf) = async {
					if let Some(rx) = &mut self.accounts_commitment_rx {
						rx.recv().await
					} else {
						None
					}
				} => {
					let order_key = EventOrderKey {
						block_number: 0,
						transaction_index: 0,
						log_index: self.api_order_counter,
					};
					self.api_order_counter = self.api_order_counter.saturating_add(1);
					self.accounts_commitment_state.add_consume_request(order_key, leaf, batch_size);
					self.log_pool_status("accepted accounts commitment leaf");

					if in_flight.is_none() {
						if let Err(e) = self.maybe_start_next_batch(&provider, batch_size, &mut in_flight).await {
							error!("failed to start next batch: {e}");
							break;
						}
					}
				}

				Some(leaf) = async {
					if let Some(rx) = &mut self.accounts_nullifier_rx {
						rx.recv().await
					} else {
						None
					}
				} => {
					let leaf_hash = match contract::bytes32_to_hash(&alloy::primitives::B256::from(leaf)) {
						Ok(h) => h,
						Err(e) => {
							warn!(leaf = ?alloy::primitives::B256::from(leaf), error = %e, "accounts nullifier request rejected: invalid leaf encoding");
							continue;
						},
					};
					if self.accounts_nullifier_state.tree.find_node_index_by_value(&leaf_hash).is_some() {
						warn!(leaf = ?alloy::primitives::B256::from(leaf), "accounts nullifier request rejected: leaf already nullified");
						continue;
					}
					let order_key = EventOrderKey {
						block_number: 0,
						transaction_index: 0,
						log_index: self.api_order_counter,
					};
					self.api_order_counter = self.api_order_counter.saturating_add(1);
					self.accounts_nullifier_state.add_consume_request(order_key, leaf, batch_size);
					self.log_pool_status("accepted accounts nullifier leaf");

					if in_flight.is_none() {
						if let Err(e) = self.maybe_start_next_batch(&provider, batch_size, &mut in_flight).await {
							error!("failed to start next batch: {e}");
							break;
						}
					}
				}

				Some(outcome) = async {
					if let Some(rx) = &mut self.result_rx {
						rx.recv().await
					} else {
						None
					}
				} => {
					if let Err(e) = self.handle_prove_outcome(&provider, outcome, &mut in_flight).await {
						error!("fatal sequencer error while finalizing batch: {e}");
						break;
					}

					if in_flight.is_none() {
						if let Err(e) = self.maybe_start_next_batch(&provider, batch_size, &mut in_flight).await {
							error!("failed to start next batch: {e}");
							break;
						}
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
