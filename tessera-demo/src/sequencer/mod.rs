mod batches;
mod config;
mod handlers;
mod helpers;
mod state;

use std::{
	collections::{BTreeSet, HashMap},
	sync::Arc,
};

use alloy::{
	network::EthereumWallet,
	primitives::U256,
	providers::ProviderBuilder,
	signers::{local::PrivateKeySigner, Signer},
};
use axum::{
	routing::{get, post},
	Router,
};
use batches::{flush_deposit_batch, flush_tx_batch};
pub use config::DemoSequencerConfig;
use handlers::{
	handle_ack_notes, handle_config, handle_deposit, handle_forward_note, handle_note_position,
	handle_pending_notes, handle_status, handle_transaction,
};
use state::{AppState, SequencerState, SharedState};
use tessera_client::COM_TREE_DEPTH;
use tessera_server::contract::ITesseraRollupV2;
use tessera_trees::MerkleTree;
use tokio::sync::Mutex;
use tracing::{error, info};

/// A demo sequencer that can be started with [`DemoSequencer::run`].
pub struct DemoSequencer {
	config: DemoSequencerConfig,
}

/// Handle returned by [`DemoSequencer::start`] that keeps the sequencer alive.
pub struct RunningSequencer {
	/// The address the HTTP server is actually bound to (useful when binding to port 0).
	pub addr: std::net::SocketAddr,
	_handle: tokio::task::JoinHandle<()>,
}

impl DemoSequencer {
	pub fn new(config: DemoSequencerConfig) -> Self {
		Self {
			config,
		}
	}

	/// Start the sequencer in the background and return a handle with the
	/// bound address. The sequencer runs until the handle is dropped.
	pub async fn start(self) -> anyhow::Result<RunningSequencer> {
		let (app, bind_addr) = self.build_app().await?;
		let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
		let addr = listener.local_addr()?;

		info!(bind_addr = %addr, "sequencer HTTP API listening");
		info!("  POST /deposit        - request deposit validation");
		info!("  POST /transaction    - submit a private transaction");
		info!("  GET  /status         - sequencer status");
		info!("  GET  /config         - contract addresses");
		info!("  POST /forward_note   - forward note to another subpool");
		info!("  GET  /pending_notes/:id - poll forwarded notes for a subpool");
		info!("  POST /ack_notes/:id     - acknowledge inserted forwarded notes");
		info!("  GET  /note_position/:hex - lookup NCT leaf index for a note commitment");

		let handle = tokio::spawn(async move {
			axum::serve(listener, app).await.ok();
		});

		Ok(RunningSequencer {
			addr,
			_handle: handle,
		})
	}

	/// Run the sequencer: connect to the chain, start the background batch
	/// flushing loop, and serve the HTTP API. Blocks until the server shuts
	/// down.
	pub async fn run(self) -> anyhow::Result<()> {
		let _handle = self.start().await?;
		// Block forever (the spawned task serves requests).
		std::future::pending::<()>().await;
		Ok(())
	}

	async fn build_app(self) -> anyhow::Result<(Router, String)> {
		let config = self.config;

		let signer: PrivateKeySigner = config.operator_key.parse()?;
		let signer = signer.with_chain_id(Some(config.chain_id));
		let operator = signer.address();
		let wallet = EthereumWallet::from(signer);
		let provider = Arc::new(
			ProviderBuilder::new()
				.wallet(wallet)
				.connect_http(config.rpc_url.parse()?),
		);

		// Fetch current on-chain root.
		let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(
			config.bridge_address,
			provider.as_ref(),
		);
		let current_root: U256 = rollup.currentRoot().call().await?;

		let mut root_history = BTreeSet::new();
		root_history.insert(current_root);

		info!(
			%operator,
			bridge = %config.bridge_address,
			token = %config.token_address,
			current_root = %current_root,
			"connected to on-chain contracts"
		);

		let state: SharedState = Arc::new(Mutex::new(SequencerState {
			rollup_addr: config.bridge_address,
			token_addr: config.token_address,
			operator,
			confirmed_root: current_root,
			confirmed_root_history: root_history,
			tx_batch_builder: None,
			tx_batch_pending_since: None,
			deposit_queue: Vec::new(),
			deposit_batch_pending_since: None,
			prove_delay: config.prove_delay,
			local_tree: MerkleTree::new(COM_TREE_DEPTH),
			note_pool: HashMap::new(),
			note_positions: HashMap::new(),
		}));

		let app_state: AppState = (state.clone(), provider.clone());
		let app = Router::new()
			.route("/deposit", post(handle_deposit))
			.route("/transaction", post(handle_transaction))
			.route("/forward_note", post(handle_forward_note))
			.route("/pending_notes/{subpool_id}", get(handle_pending_notes))
			.route("/ack_notes/{subpool_id}", post(handle_ack_notes))
			.route("/note_position/{commitment_hex}", get(handle_note_position))
			.route("/status", get(handle_status))
			.route("/config", get(handle_config))
			.with_state(app_state);

		// Background batch flushing loop.
		let state_bg = state.clone();
		let provider_bg = provider.clone();
		let batch_timeout = config.batch_timeout;
		let poll_interval = config.poll_interval;
		tokio::spawn(async move {
			let mut interval = tokio::time::interval(poll_interval);
			loop {
				interval.tick().await;

				let should_flush_tx = {
					let st = state_bg.lock().await;
					st.tx_batch_builder.as_ref().is_some_and(|b| {
						b.is_full()
							|| st
								.tx_batch_pending_since
								.is_some_and(|since| since.elapsed() >= batch_timeout)
					})
				};
				if should_flush_tx {
					if let Err(e) = flush_tx_batch(&state_bg, &provider_bg).await {
						error!("failed to flush TX batch: {e}");
					}
				}

				let should_flush_dep = {
					let st = state_bg.lock().await;
					!st.deposit_queue.is_empty()
						&& st
							.deposit_batch_pending_since
							.is_some_and(|since| since.elapsed() >= batch_timeout)
				};
				if should_flush_dep {
					if let Err(e) = flush_deposit_batch(&state_bg, &provider_bg).await {
						error!("failed to flush deposit batch: {e}");
					}
				}
			}
		});

		Ok((app, config.bind_addr))
	}
}
