use std::time::Duration;

use alloy::providers::{Provider, ProviderBuilder};
use anyhow::Context;
use tokio::sync::mpsc;
use tracing::{error, info};

use super::{
	config::StateServiceConfig,
	handle::{StateServiceHandle, StateServiceRequest},
	state::StateSnapshot,
	sync,
};

/// Capacity of the request channel between [`StateServiceHandle`] and the
/// actor.  Back-pressure kicks in after this many un-processed requests.
const REQUEST_CHANNEL_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

/// The state-service actor.
///
/// Keeps a local mirror of the on-chain Incremental Merkle Tree and serves
/// leaf-index lookups and Merkle-proof requests to the prover.
///
/// Run [`StateService::run`] in a dedicated `tokio::spawn`ed task; hand the
/// accompanying [`StateServiceHandle`] to every component that needs it.
pub struct StateService {
	/// Verified, in-memory copy of the on-chain tree + auxiliary indexes.
	state: StateSnapshot,
	/// Service configuration (RPC, contract, poll interval …).
	config: StateServiceConfig,
	/// Incoming request queue from all [`StateServiceHandle`] clones.
	rx: mpsc::Receiver<StateServiceRequest>,
	/// The highest block number that has already been incorporated into
	/// `state`.  Starts at 0; updated after every successful poll.
	last_synced_block: u64,
}

impl StateService {
	/// Create a new [`StateService`] and return its client-facing handle.
	///
	/// The service is not started yet; call [`StateService::run`] (typically
	/// inside a `tokio::spawn`) to begin the event loop.
	pub fn new(config: StateServiceConfig) -> (Self, StateServiceHandle) {
		let (tx, rx) = mpsc::channel(REQUEST_CHANNEL_CAPACITY);
		let handle = StateServiceHandle {
			tx,
		};
		let service = Self {
			state: StateSnapshot::new(crate::TREE_DEPTH),
			config,
			rx,
			last_synced_block: 0,
		};
		(service, handle)
	}

	// -----------------------------------------------------------------------
	// Event loop
	// -----------------------------------------------------------------------

	/// Start the service event loop.
	///
	/// 1. Connects to the chain (read-only provider — no wallet needed).
	/// 2. Performs an initial full sync from genesis via [`sync::sync_from_genesis`].
	/// 3. Enters a `select!` loop that:
	///    - Polls for new proven batches on each timer tick.
	///    - Handles incoming [`StateServiceRequest`]s.
	///    - Exits cleanly on `Ctrl-C`.
	///
	/// # Errors
	/// Returns `Err` if the initial sync or provider connection fails.
	pub async fn run(&mut self) -> anyhow::Result<()> {
		let provider = self.build_provider()?;
		self.initial_sync(&provider).await?;

		let poll_interval = Duration::from_secs(self.config.poll_interval_secs);
		let mut interval = tokio::time::interval(poll_interval);

		info!("state service running");

		loop {
			tokio::select! {
				_ = interval.tick() => {
					if let Err(e) = self.poll_new_batches(&provider).await {
						error!(error = %e, "failed to poll new batches; will retry next tick");
					}
				}

				req = self.rx.recv() => {
					let Some(req) = req else { break; };
					self.handle_request(req);
				}

				_ = tokio::signal::ctrl_c() => {
					info!("state service shutting down");
					break;
				}
			}
		}

		Ok(())
	}

	// -----------------------------------------------------------------------
	// Sync
	// -----------------------------------------------------------------------

	/// Fetch the current chain head, then replay all proven batches from
	/// genesis up to that block into `self.state`.
	///
	/// Sets `self.last_synced_block` to the tip block number on success.
	///
	/// # Errors
	/// Propagates any RPC or state-application error.
	async fn initial_sync<P: Provider + Clone>(&mut self, provider: &P) -> anyhow::Result<()> {
		let tip = provider
			.get_block_number()
			.await
			.context("eth_blockNumber during initial sync")?;

		info!(to_block = tip, "starting genesis sync");

		self.state = sync::sync_from_genesis(
			provider,
			self.config.bridge_address,
			self.config.log_chunk_blocks,
			tip,
		)
		.await?;

		self.last_synced_block = tip;
		info!(
			leaf_count = self.state.leaf_count(),
			last_synced_block = self.last_synced_block,
			"genesis sync complete"
		);

		Ok(())
	}

	/// Check for proven batches in `(last_synced_block, tip]` and apply them.
	///
	/// No-ops when the chain has not advanced since the last poll.
	///
	/// # Errors
	/// Propagates any RPC or state-application error.
	async fn poll_new_batches<P: Provider + Clone>(&mut self, provider: &P) -> anyhow::Result<()> {
		let tip = provider
			.get_block_number()
			.await
			.context("eth_blockNumber during poll")?;

		if tip <= self.last_synced_block {
			return Ok(());
		}

		let from_block = self.last_synced_block + 1;
		sync::sync_range(
			provider,
			self.config.bridge_address,
			self.config.log_chunk_blocks,
			from_block,
			tip,
			&mut self.state,
		)
		.await?;

		self.last_synced_block = tip;
		Ok(())
	}

	// -----------------------------------------------------------------------
	// Request dispatch
	// -----------------------------------------------------------------------

	/// Route an incoming request to the appropriate handler.
	fn handle_request(&mut self, req: StateServiceRequest) {
		match req {
			StateServiceRequest::GetLeafIndex {
				commitment,
				reply,
			} => {
				self.handle_get_leaf_index(commitment, reply);
			},
			StateServiceRequest::GetSiblings {
				commitment,
				reply,
			} => {
				self.handle_get_siblings(commitment, reply);
			},
			StateServiceRequest::IsConfirmedRoot {
				root,
				reply,
			} => {
				let _ = reply.send(self.state.is_confirmed_root(&root));
			},
			StateServiceRequest::ContainsNullifier {
				nullifier,
				reply,
			} => {
				let _ = reply.send(self.state.contains_nullifier(&nullifier));
			},
			StateServiceRequest::GetCurrentRoot {
				reply,
			} => {
				let _ = reply.send(self.state.root());
			},
		}
	}

	/// Respond to a [`StateServiceRequest::GetLeafIndex`] request.
	///
	/// Looks up `commitment` in the local index and sends the result on
	/// `reply`.  A missing commitment returns `None` (not an error).
	fn handle_get_leaf_index(
		&self,
		commitment: [u8; 32],
		reply: tokio::sync::oneshot::Sender<Option<usize>>,
	) {
		let index = self.state.leaf_index(&commitment);
		// Ignore send errors: the caller may have timed out.
		let _ = reply.send(index);
	}

	/// Respond to a [`StateServiceRequest::GetSiblings`] request.
	///
	/// Looks up `commitment`, resolves its tree index, generates the full
	/// Merkle proof, and sends it on `reply`.  Returns an error result if the
	/// commitment is unknown.
	fn handle_get_siblings(
		&self,
		commitment: [u8; 32],
		reply: tokio::sync::oneshot::Sender<
			anyhow::Result<tessera_trees::MerkleProof<tessera_utils::hasher::HashOutput>>,
		>,
	) {
		let result = self
			.state
			.leaf_index(&commitment)
			.ok_or_else(|| anyhow::anyhow!("commitment not found in local tree"))
			.and_then(|index| self.state.siblings(index));

		// Ignore send errors: the caller may have timed out.
		let _ = reply.send(result);
	}

	// -----------------------------------------------------------------------
	// Provider construction
	// -----------------------------------------------------------------------

	/// Build a read-only (no wallet) HTTP provider from the service config.
	fn build_provider(&self) -> anyhow::Result<impl Provider + Clone> {
		let provider = ProviderBuilder::new().connect_http(
			self.config
				.rpc_url
				.parse()
				.context("invalid TESSERA_RPC_URL")?,
		);
		Ok(provider)
	}
}
