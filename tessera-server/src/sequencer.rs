use std::time::Duration;

use alloy::{
	primitives::B256,
	network::EthereumWallet,
	providers::{Provider, ProviderBuilder},
	rpc::types::{Filter, Log},
	signers::{local::PrivateKeySigner, Signer},
	sol_types::SolEvent,
};
use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::{
	config::SequencerConfig,
	contract::{self, IDepositsRollupBridge},
	prover,
	state::{EventOrderKey, PendingConsumeRequest, SequencerState},
	types::{ProveOutcome, ProveRequest},
};

/// Receipt polling timeout for on-chain transactions.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);

struct InFlightBatch {
	requests: Vec<PendingConsumeRequest>,
}

#[derive(Clone)]
struct ApiState {
	tx: mpsc::Sender<[u8; 32]>,
}

#[derive(Debug, Deserialize)]
struct ConsumeRequestBody {
	note_commitment: String,
}

#[derive(Debug, Serialize)]
struct ConsumeRequestResponse {
	accepted: bool,
}

async fn consume_request_handler(
	State(state): State<ApiState>,
	Json(body): Json<ConsumeRequestBody>,
) -> Result<Json<ConsumeRequestResponse>, axum::http::StatusCode> {
	let note = parse_note_hex(&body.note_commitment)
		.map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
	state
		.tx
		.send(note)
		.await
		.map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
	Ok(Json(ConsumeRequestResponse {
		accepted: true,
	}))
}

fn parse_note_hex(s: &str) -> anyhow::Result<[u8; 32]> {
	let b = s.parse::<B256>()?;
	Ok(b.into())
}

/// The main sequencer: watches note availability, batches by chain order, proves and finalizes.
pub struct Sequencer {
	config: SequencerConfig,
	pub state: SequencerState,
	prove_tx: Option<mpsc::Sender<ProveRequest>>,
	result_rx: Option<mpsc::Receiver<ProveOutcome>>,
	consume_rx: Option<mpsc::Receiver<[u8; 32]>>,
	api_order_counter: u64,
}

impl Sequencer {
	pub fn new(config: SequencerConfig) -> Self {
		Self {
			config,
			state: SequencerState::new(),
			prove_tx: None,
			result_rx: None,
			consume_rx: None,
			api_order_counter: 0,
		}
	}

	pub async fn run(&mut self) -> anyhow::Result<()> {
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

		let on_chain_consumed_root = bridge.consumedRoot().call().await?;
		let consume_batch_size: usize = bridge
			.consumeBatchSize()
			.call()
			.await?
			.try_into()
			.unwrap_or(0usize);
		info!(
			?on_chain_consumed_root,
			consume_batch_size, "synced on-chain consume state"
		);
		anyhow::ensure!(
			consume_batch_size > 0,
			"on-chain consumeBatchSize must be > 0"
		);

		self.recover_consumed_state(&provider, &on_chain_consumed_root)
			.await?;
		self.recover_pending_requests(&provider, consume_batch_size)
			.await?;
		info!(
			local_root = ?contract::hash_to_bytes32(&self.state.current_consumed_root()),
			pending_requests = self.state.pending_requests.len(),
			"state recovery complete"
		);

		let (prove_tx, prove_rx) = mpsc::channel::<ProveRequest>(4);
		let (result_tx, result_rx) = mpsc::channel::<ProveOutcome>(4);
		let plonky2_path = self.config.plonky2_data_path.clone();
		let groth16_path = self.config.groth16_artifacts_path.clone();
		tokio::task::spawn_blocking(move || {
			prover::prover_thread(
				plonky2_path,
				groth16_path,
				consume_batch_size,
				prove_rx,
				result_tx,
			);
		});
		self.prove_tx = Some(prove_tx);
		self.result_rx = Some(result_rx);

		let (consume_tx, consume_rx) = mpsc::channel::<[u8; 32]>(1024);
		self.consume_rx = Some(consume_rx);
		let api_addr: std::net::SocketAddr = self
			.config
			.api_bind_addr
			.parse()
			.map_err(|e| anyhow::anyhow!("invalid TESSERA_SEQUENCER_API_ADDR: {e}"))?;
		let app = Router::new()
			.route("/consume-request", post(consume_request_handler))
			.with_state(ApiState {
				tx: consume_tx,
			});
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
					if in_flight.is_none()
						&& self.state.pending_requests.len() >= consume_batch_size
					{
						if let Err(e) = self.start_next_batch(&provider, consume_batch_size, &mut in_flight).await {
							error!("failed to start consume batch: {e}");
							break;
						}
					}
				}

				Some(note) = async {
					if let Some(rx) = &mut self.consume_rx {
						rx.recv().await
					} else {
						None
					}
				} => {
					if !self.is_note_available(&provider, &note).await {
						warn!(note = ?note, "consume request rejected: note not Available");
						continue;
					}
					let order_key = EventOrderKey {
						block_number: 0,
						transaction_index: 0,
						log_index: self.api_order_counter,
					};
					self.api_order_counter = self.api_order_counter.saturating_add(1);
					self.state.add_consume_request(order_key, note, consume_batch_size);

					if in_flight.is_none() && self.state.pending_requests.len() >= consume_batch_size {
						if let Err(e) = self.start_next_batch(&provider, consume_batch_size, &mut in_flight).await {
							error!("failed to start consume batch: {e}");
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
						error!("fatal sequencer error while finalizing consume batch: {e}");
						break;
					}

					if in_flight.is_none() && self.state.pending_requests.len() >= consume_batch_size {
						if let Err(e) = self.start_next_batch(&provider, consume_batch_size, &mut in_flight).await {
							error!("failed to start consume batch: {e}");
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

	async fn is_note_available<P: Provider + Clone>(&self, provider: &P, note: &[u8; 32]) -> bool {
		let bridge = IDepositsRollupBridge::IDepositsRollupBridgeInstance::new(
			self.config.bridge_address,
			provider,
		);
		let note = alloy::primitives::FixedBytes::<32>::from(*note);
		match bridge.getDepositStatus(note).call().await {
			Ok(status) => matches!(status, IDepositsRollupBridge::DepositStatus::Available),
			Err(e) => {
				warn!("failed to fetch note status: {e}");
				false
			},
		}
	}

	async fn start_next_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
		consume_batch_size: usize,
		in_flight: &mut Option<InFlightBatch>,
	) -> anyhow::Result<()> {
		let bridge = IDepositsRollupBridge::IDepositsRollupBridgeInstance::new(
			self.config.bridge_address,
			provider,
		);

		let batch = self
			.state
			.pop_next_batch(consume_batch_size)
			.ok_or_else(|| {
				anyhow::anyhow!("batch requested but pending queue had insufficient size")
			})?;

		let commitments_bytes: Vec<[u8; 32]> = batch.iter().map(|r| r.commitment).collect();
		self.preflight_batch(bridge, &batch).await?;

		let commitments_hash = commitments_bytes
			.iter()
			.map(|b| contract::bytes32_to_hash(&alloy::primitives::B256::from(*b)))
			.collect();

		let batch_proof = self.state.consumed_tree.insert_commitments(commitments_hash)?;
		anyhow::ensure!(
			batch_proof.verify(),
			"native consume batch proof verification failed"
		);

		if let Some(tx) = &self.prove_tx {
			tx.send(ProveRequest {
				batch_proof,
			})
			.await?;
		} else {
			return Err(anyhow::anyhow!("prover channel not initialized"));
		}

		*in_flight = Some(InFlightBatch {
			requests: batch,
		});
		info!(
			batch_size = consume_batch_size,
			"consume batch sent to prover"
		);
		Ok(())
	}

	async fn handle_prove_outcome<P: Provider + Clone>(
		&mut self,
		provider: &P,
		outcome: ProveOutcome,
		in_flight: &mut Option<InFlightBatch>,
	) -> anyhow::Result<()> {
		let bridge = IDepositsRollupBridge::IDepositsRollupBridgeInstance::new(
			self.config.bridge_address,
			provider,
		);

		let Some(batch) = in_flight.take() else {
			warn!("received prover outcome with no in-flight batch");
			return Ok(());
		};

		match outcome {
			ProveOutcome::Failure {
				error,
			} => {
				self.state.reinsert_batch(batch.requests);
				return Err(anyhow::anyhow!("proof generation failed: {error}"));
			},
			ProveOutcome::Success {
				new_root,
				solidity_proof,
			} => {
				let commitments_vec: Vec<alloy::primitives::FixedBytes<32>> = batch
					.requests
					.iter()
					.map(|r| alloy::primitives::FixedBytes::<32>::from(r.commitment))
					.collect();
				let sol_proof = IDepositsRollupBridge::Proof {
					proof: solidity_proof.proof,
					commitments: solidity_proof.commitments,
					commitmentPok: solidity_proof.commitment_pok,
				};
				let new_root = contract::hash_to_bytes32(&new_root);
				let pending = bridge
					.finalizeConsumeBatch(new_root, commitments_vec, sol_proof)
					.send()
					.await?;
				let receipt = pending
					.with_required_confirmations(1)
					.with_timeout(Some(RECEIPT_TIMEOUT))
					.get_receipt()
					.await?;
				anyhow::ensure!(
					receipt.status(),
					"finalizeConsumeBatch reverted on-chain (tx_hash={:?})",
					receipt.transaction_hash
				);
				info!(
					tx_hash = ?receipt.transaction_hash,
					consumed = batch.requests.len(),
					"finalizeConsumeBatch confirmed"
				);
			},
		}

		Ok(())
	}

	async fn preflight_batch<P: Provider + Clone>(
		&self,
		bridge: IDepositsRollupBridge::IDepositsRollupBridgeInstance<&P>,
		batch: &[PendingConsumeRequest],
	) -> anyhow::Result<()> {
		let on_chain_root = bridge.consumedRoot().call().await?;
		let local_root = contract::hash_to_bytes32(&self.state.current_consumed_root());
		anyhow::ensure!(
			on_chain_root == local_root,
			"preflight failed: consumedRoot mismatch (on-chain={on_chain_root:?}, local={local_root:?})"
		);

		for req in batch {
			let note = alloy::primitives::FixedBytes::<32>::from(req.commitment);
			let status = bridge.getDepositStatus(note).call().await?;
			anyhow::ensure!(
				matches!(status, IDepositsRollupBridge::DepositStatus::Available),
				"preflight failed: note not Available"
			);
		}

		Ok(())
	}

	async fn recover_consumed_state<P: Provider + Clone>(
		&mut self,
		provider: &P,
		on_chain_consumed_root: &alloy::primitives::FixedBytes<32>,
	) -> anyhow::Result<()> {
		let consumed_filter = Filter::new()
			.address(self.config.bridge_address)
			.event_signature(IDepositsRollupBridge::DepositConsumed::SIGNATURE_HASH)
			.from_block(0);
		let mut consumed_logs = provider.get_logs(&consumed_filter).await?;
		consumed_logs.sort_by_key(log_order_key);

		if consumed_logs.is_empty() {
			let local_root = contract::hash_to_bytes32(&SequencerState::genesis_consumed_root());
			anyhow::ensure!(
				*on_chain_consumed_root == local_root,
				"consumed root mismatch at genesis: on-chain={on_chain_consumed_root:?}, local={local_root:?}"
			);
			return Ok(());
		}

		for log in consumed_logs {
			let decoded = log.log_decode::<IDepositsRollupBridge::DepositConsumed>()?;
			let note = contract::bytes32_to_hash(&decoded.inner.noteCommitment);
			self.state.replay_consumed_commitment(note)?;
		}

		let local_root = contract::hash_to_bytes32(&self.state.current_consumed_root());
		anyhow::ensure!(
			*on_chain_consumed_root == local_root,
			"consumed root mismatch after replay: on-chain={on_chain_consumed_root:?}, local={local_root:?}"
		);
		Ok(())
	}

	async fn recover_pending_requests<P: Provider + Clone>(
		&mut self,
		_provider: &P,
		_batch_size: usize,
	) -> anyhow::Result<()> {
		// Direct API mode: pending queue is fed externally and not reconstructed from
		// availability events.
		Ok(())
	}
}

fn log_order_key(log: &Log) -> (u64, u64, u64) {
	let block = log.block_number.unwrap_or_default();
	let tx = log.transaction_index.unwrap_or_default();
	let idx = log.log_index.unwrap_or_default();
	(block, tx, idx)
}
