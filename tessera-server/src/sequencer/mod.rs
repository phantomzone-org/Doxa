use std::{collections::BTreeMap, sync::Arc, time::Duration};

use alloy::{
	network::EthereumWallet,
	providers::{Provider, ProviderBuilder},
	signers::{local::PrivateKeySigner, Signer},
};
use anyhow::Context;
use tessera_trees::tree::{hasher::Hash, CommitmentTree, NullifierTree};
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

mod api;
mod pipeline;
mod recovery;
mod revert;

const DUMMY_ASSOCIATED_INPUT_PROOF: &[u8] = &[0x01];

/// Receipt polling timeout for on-chain transactions.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Mirror of `MAX_PENDING_BATCHES` in `TesseraRollup.sol`.
const MAX_PENDING_BATCHES: usize = 128;

/// Per-tree batch data stored in a pending two-phase batch.
/// Used for WAL commits after on-chain `confirmBatch` succeeds.
#[allow(dead_code)]
struct TxPerTreeBatch {
	real_commitments_bytes: Vec<[u8; 32]>,
	proving_commitments_bytes: Vec<[u8; 32]>,
	proving_commitments_hash: Vec<Hash>,
}

/// A batch registered on-chain and awaiting a single SuperAggregator proof
/// via `confirmBatch`.  Stored in `registered_pending_batches` until confirmed.
#[allow(dead_code)]
struct TxBatch {
	batch_id: u64,
	/// Pending queue requests popped for notes-commitment tree (for requeue on failure).
	nc_requests: Vec<PendingRequest>,
	/// Pending queue requests popped for notes-nullifier tree (for requeue on failure).
	nn_requests: Vec<PendingRequest>,
	/// Pending queue requests popped for accounts-commitment tree (for requeue on failure).
	ac_requests: Vec<PendingRequest>,
	/// Pending queue requests popped for accounts-nullifier tree (for requeue on failure).
	an_requests: Vec<PendingRequest>,
	/// Batch data for WAL commit after confirmation.
	nc_batch: TxPerTreeBatch,
	nn_batch: TxPerTreeBatch,
	ac_batch: TxPerTreeBatch,
	an_batch: TxPerTreeBatch,
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
	notes_commitment_rx: Option<mpsc::Receiver<NotesCommitmentRequest>>,
	notes_nullifier_rx: Option<mpsc::Receiver<[u8; 32]>>,
	accounts_commitment_rx: Option<mpsc::Receiver<[u8; 32]>>,
	accounts_nullifier_rx: Option<mpsc::Receiver<[u8; 32]>>,
	/// Registered-but-unconfirmed two-phase batches keyed by on-chain `batchId`.
	registered_pending_batches: BTreeMap<u64, TxBatch>,
	/// Receiver end of the private-tx channel for optimistic two-phase register.
	private_tx_rx: Option<mpsc::Receiver<PrivateTxRequest>>,
	api_order_counter: u64,
	notes_commitment_pending_since: Option<std::time::Instant>,
	notes_nullifier_pending_since: Option<std::time::Instant>,
	accounts_commitment_pending_since: Option<std::time::Instant>,
	accounts_nullifier_pending_since: Option<std::time::Instant>,
}

impl Sequencer {
	/// Attempt to start the next proving batch when the pending-batch queue is not full.
	///
	/// Convenience wrapper called at the tail of every leaf-accept arm in the main event
	/// loop, so that a newly enqueued leaf can immediately trigger a batch flush without
	/// waiting for the next poll-interval tick.
	///
	/// # Parameters
	/// - `provider`: Ethereum provider forwarded to `maybe_start_next_batch`.
	/// - `note_batch_size`: circuit batch width for note trees.
	/// - `account_batch_size`: circuit batch width for account trees.
	/// - `batch_timeout`: maximum idle time before flushing a partial batch.
	///
	/// # Errors
	/// Returns `Err` if `maybe_start_next_batch` fails (fatal: caller should `break` the loop).
	///
	/// # Side effects
	/// May submit an async prove request and register a batch on-chain.
	async fn try_start_batch_if_idle<P: Provider + Clone>(
		&mut self,
		provider: &P,
		note_batch_size: usize,
		account_batch_size: usize,
		batch_timeout: std::time::Duration,
	) -> anyhow::Result<()> {
		self.maybe_start_next_batch(provider, note_batch_size, account_batch_size, batch_timeout)
			.await
	}

	/// Emit a `debug!` log showing the current pending-request count for all four trees.
	///
	/// Called at key decision points (batch scheduling, batch completion, leaf acceptance)
	/// to provide an operational snapshot of queue depth.
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

	/// Update a single `pending_since` timer slot.
	///
	/// - If `pending_len == 0`: clear the slot (`None`), resetting the timeout clock.
	/// - If `pending_len > 0` and the slot is `None`: record the current instant as the start of
	///   the non-empty window.
	/// - If `pending_len > 0` and the slot is already `Some`: no-op (clock keeps running).
	fn refresh_pending_since(slot: &mut Option<std::time::Instant>, pending_len: usize) {
		if pending_len == 0 {
			*slot = None;
		} else if slot.is_none() {
			*slot = Some(std::time::Instant::now());
		}
	}

	/// Refresh the `pending_since` timer slots for all four trees.
	///
	/// Calls [`refresh_pending_since`] for each tree using the current pending-queue length.
	/// Should be called whenever the queue lengths may have changed (leaf acceptance,
	/// batch start, batch completion).
	fn refresh_pending_timers(&mut self) {
		Self::refresh_pending_since(
			&mut self.notes_commitment_pending_since,
			self.notes_commitment_state.pending_requests.len(),
		);
		Self::refresh_pending_since(
			&mut self.notes_nullifier_pending_since,
			self.notes_nullifier_state.pending_requests.len(),
		);
		Self::refresh_pending_since(
			&mut self.accounts_commitment_pending_since,
			self.accounts_commitment_state.pending_requests.len(),
		);
		Self::refresh_pending_since(
			&mut self.accounts_nullifier_pending_since,
			self.accounts_nullifier_state.pending_requests.len(),
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
			registered_pending_batches: BTreeMap::new(),
			private_tx_rx: None,
			api_order_counter: 0,
			notes_commitment_pending_since: None,
			notes_nullifier_pending_since: None,
			accounts_commitment_pending_since: None,
			accounts_nullifier_pending_since: None,
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

		// Step 1: load local persisted trees (snapshot + WAL). This is fast-path startup.
		// These local stores are treated as cache and may be behind chain head.
		let mut store = TreeStore::<CommitmentTree<Hash>>::open(
			&self.config.tree_store_path,
			TreeId::NotesCommitment,
			self.config.snapshot_every_batches,
		)?;
		let (mut tree, meta0) = store.load_or_init(|| CommitmentTree::new(TREE_DEPTH))?;
		let (wal_pos, replayed) =
			store.replay_wal_since_snapshot(&mut tree, &meta0, |t, vals| {
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
		let (notes_nullifier_tx, notes_nullifier_rx) = mpsc::channel::<[u8; 32]>(1024);
		let (accounts_commitment_tx, accounts_commitment_rx) = mpsc::channel::<[u8; 32]>(1024);
		let (accounts_nullifier_tx, accounts_nullifier_rx) = mpsc::channel::<[u8; 32]>(1024);
		self.notes_commitment_rx = Some(notes_commitment_rx);
		self.notes_nullifier_rx = Some(notes_nullifier_rx);
		self.accounts_commitment_rx = Some(accounts_commitment_rx);
		self.accounts_nullifier_rx = Some(accounts_nullifier_rx);

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
		let tx_proof_verifier = self
			.config
			.aggregator_artifacts_path
			.as_deref()
			.map(|path| api::LeafProofVerifier::from_artifacts(path).map(Arc::new))
			.transpose()
			.context("failed to load tx proof verifier from aggregator artifacts")?;
		let account_proof_verifier = self
			.config
			.account_artifacts_path
			.as_deref()
			.map(|path| api::LeafProofVerifier::from_artifacts(path).map(Arc::new))
			.transpose()
			.context("failed to load account proof verifier from account artifacts")?;
		let api_state = api::ApiState {
			notes_commitment_tx,
			notes_nullifier_tx,
			accounts_commitment_tx,
			accounts_nullifier_tx,
			private_tx_tx: Some(private_tx_tx),
			consume_proof_verifier,
			tx_proof_verifier,
			account_proof_verifier,
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
					if let Err(e) = self.try_start_batch_if_idle(&provider, note_batch_size, account_batch_size, batch_timeout).await {
						error!("failed to start next batch: {e}");
						break;
					}
				}

				Some(req) = async {
					if let Some(rx) = &mut self.notes_commitment_rx {
						rx.recv().await
					} else {
						None
					}
				} => {
					let note = req.note;
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
					self.notes_commitment_state.add_consume_request(
						order_key,
						note,
						note_batch_size,
					);
					self.log_pool_status("accepted notes commitment leaf");
					if let Err(e) = self.try_start_batch_if_idle(&provider, note_batch_size, account_batch_size, batch_timeout).await {
						error!("failed to start next batch: {e}");
						break;
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
					self.notes_nullifier_state.add_consume_request(order_key, note, note_batch_size);
					self.log_pool_status("accepted notes nullifier leaf");
					if let Err(e) = self.try_start_batch_if_idle(&provider, note_batch_size, account_batch_size, batch_timeout).await {
						error!("failed to start next batch: {e}");
						break;
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
					self.accounts_commitment_state.add_consume_request(
						order_key,
						leaf,
						account_batch_size,
					);
					self.log_pool_status("accepted accounts commitment leaf");
					if let Err(e) = self.try_start_batch_if_idle(&provider, note_batch_size, account_batch_size, batch_timeout).await {
						error!("failed to start next batch: {e}");
						break;
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
					self.accounts_nullifier_state.add_consume_request(order_key, leaf, account_batch_size);
					self.log_pool_status("accepted accounts nullifier leaf");
					if let Err(e) = self.try_start_batch_if_idle(&provider, note_batch_size, account_batch_size, batch_timeout).await {
						error!("failed to start next batch: {e}");
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
					if let Err(e) = self.try_start_batch_if_idle(&provider, note_batch_size, account_batch_size, batch_timeout).await {
						error!("failed to start next batch: {e}");
						break;
					}
				}

				// Optimistic two-phase register path for private transactions.
				Some(tx_req) = async {
					if let Some(rx) = &mut self.private_tx_rx {
						rx.recv().await
					} else {
						None
					}
				} => {
					if let Err(e) = self.register_tx_batch(&provider, tx_req, note_batch_size, account_batch_size).await {
						error!("failed to register private tx batch: {e}");
						// Non-fatal: log and continue processing other requests.
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
