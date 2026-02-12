use std::time::Duration;

use alloy::{
	network::EthereumWallet,
	primitives::U256,
	providers::{Provider, ProviderBuilder},
	rpc::types::Filter,
	signers::{Signer, local::PrivateKeySigner},
	sol_types::SolEvent,
};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::{
	config::SequencerConfig,
	contract::{self, IDepositsRollupBridge},
	prover,
	state::SequencerState,
	types::{ProveOutcome, ProveRequest},
};

/// Receipt polling timeout for on-chain transactions.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);

/// The main sequencer: watches on-chain deposits, batches them, finalizes proofs.
pub struct Sequencer {
	config: SequencerConfig,
	state: SequencerState,
	prove_tx: mpsc::Sender<ProveRequest>,
	result_rx: mpsc::Receiver<ProveOutcome>,
}

impl Sequencer {
	/// Create a new sequencer and spawn the prover thread.
	pub fn new(config: SequencerConfig) -> Self {
		let (prove_tx, prove_rx) = mpsc::channel::<ProveRequest>(4);
		let (result_tx, result_rx) = mpsc::channel::<ProveOutcome>(4);

		// Spawn prover on a dedicated blocking thread.
		let plonky2_path = config.plonky2_data_path.clone();
		let groth16_path = config.groth16_artifacts_path.clone();
		tokio::task::spawn_blocking(move || {
			prover::prover_thread(plonky2_path, groth16_path, prove_rx, result_tx);
		});

		let state = SequencerState::new();

		Self {
			config,
			state,
			prove_tx,
			result_rx,
		}
	}

	/// Run the main sequencer loop.
	pub async fn run(&mut self) -> anyhow::Result<()> {
		// Set up alloy provider + signer (EIP-155: enforce chain ID).
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

		// ── Sync on-chain state ──
		let on_chain_root = bridge.merkleRoot().call().await?;
		let next_deposit_id: u64 = bridge
			.nextDepositId()
			.call()
			.await?
			.try_into()
			.unwrap_or(0u64);
		let batch_size: u64 = bridge.batchSize().call().await?.try_into().unwrap_or(128u64);
		info!(
			?on_chain_root,
			next_deposit_id,
			batch_size,
			"synced on-chain state"
		);

		// ── Recover state from finalized batches ──
		//
		// Count BatchValidated events to determine how many batches are already
		// finalized, then replay those deposit commitments into the local tree
		// so it matches the on-chain merkleRoot.
		let finalized_deposits = self
			.recover_finalized_state(&provider, batch_size, &on_chain_root)
			.await?;

		info!(
			finalized_deposits,
			next_batch_start_id = self.state.next_batch_start_id,
			batch_count = self.state.batch_count,
			"state recovery complete"
		);

		// ── Main loop ──
		// Start polling from the current block to avoid re-fetching historic events
		// that were already handled during recovery.
		let mut last_block: u64 = provider.get_block_number().await.unwrap_or(0);
		let poll_interval = Duration::from_secs(self.config.poll_interval_secs);
		let mut interval = tokio::time::interval(poll_interval);

		// Track whether we have a batch in-flight (being proved or awaiting
		// finalization). While in-flight, we accumulate events but do NOT seal
		// new batches to avoid cascading failures from on-chain state divergence.
		let mut batch_in_flight = false;

		info!("sequencer running");

		loop {
			tokio::select! {
				// Poll for new DepositPending events.
				_ = interval.tick() => {
					let current_block = match provider.get_block_number().await {
						Ok(b) => b,
						Err(e) => {
							error!("failed to get block number: {e}");
							continue;
						}
					};

					if current_block <= last_block {
						continue;
					}

					let filter = Filter::new()
						.address(self.config.bridge_address)
						.event_signature(IDepositsRollupBridge::DepositPending::SIGNATURE_HASH)
						.from_block(last_block + 1)
						.to_block(current_block);

					let logs = match provider.get_logs(&filter).await {
						Ok(l) => l,
						Err(e) => {
							error!("failed to fetch logs: {e}");
							continue;
						}
					};

					last_block = current_block;

					for log in logs {
						let decoded = match log.log_decode::<IDepositsRollupBridge::DepositPending>() {
							Ok(d) => d.inner,
							Err(e) => {
								error!("failed to decode DepositPending log: {e}");
								continue;
							}
						};

						let deposit_id: u64 = decoded.depositId.try_into().unwrap_or(0);

						// Skip deposits that were already replayed during recovery.
						if deposit_id < finalized_deposits {
							continue;
						}

						let commitment = contract::bytes32_to_hash(&decoded.commitment);
						let batch_ready = self.state.add_commitment(commitment);
						info!(
							deposit_id,
							commitments = self.state.commitments.len(),
							"deposit event processed"
						);

						if batch_ready && !batch_in_flight {
							// ── Seal batch and send to prover ──
							let (start_index, batch_proof) = self.state.seal_batch()?;
							info!(
								start_index,
								new_root = ?contract::hash_to_bytes32(&batch_proof.root_new),
								"batch sealed, sending to prover"
							);

							self.prove_tx
								.send(ProveRequest {
									batch_proof,
									deposit_start_index: start_index,
								})
								.await?;

							batch_in_flight = true;
						} else if batch_ready && batch_in_flight {
							warn!(
								commitments = self.state.commitments.len(),
								"batch ready but previous batch still in-flight, deferring"
							);
						}
					}
				}

				// Proof completed (or failed).
				Some(outcome) = self.result_rx.recv() => {
					let (start_index, new_root, sol_proof) = match outcome {
						ProveOutcome::Failure { deposit_start_index, error } => {
							error!(deposit_start_index, %error, "proof failed, resetting batch_in_flight");
							batch_in_flight = false;
							continue;
						},
						ProveOutcome::Success { deposit_start_index, new_root, solidity_proof } => {
							let sol_proof = IDepositsRollupBridge::Proof {
								proof: solidity_proof.proof,
								commitments: solidity_proof.commitments,
								commitmentPok: solidity_proof.commitment_pok,
							};
							(deposit_start_index, new_root, sol_proof)
						},
					};

					info!(start_index, "proof received, finalizing");

					// ── Finalize batch ──
					let new_root = contract::hash_to_bytes32(&new_root);

					let pending = match bridge
						.finalizeBatch(new_root, U256::from(start_index), sol_proof)
						.send()
						.await
					{
						Ok(tx) => tx,
						Err(e) => {
							error!(start_index, "finalizeBatch send failed: {e}");
							batch_in_flight = false;
							continue;
						}
					};

					match pending
						.with_required_confirmations(1)
						.with_timeout(Some(RECEIPT_TIMEOUT))
						.get_receipt()
						.await
					{
						Ok(receipt) => {
							if !receipt.status() {
								error!(
									tx_hash = ?receipt.transaction_hash,
									start_index,
									"finalizeBatch reverted on-chain"
								);
							} else {
								info!(
									tx_hash = ?receipt.transaction_hash,
									"finalizeBatch confirmed"
								);
								self.state.batch_count += 1;
								info!(batch_count = self.state.batch_count, "batch finalized");
							}
						}
						Err(e) => {
							error!(start_index, "finalizeBatch receipt failed: {e}");
						}
					}

					batch_in_flight = false;

					// If commitments have already accumulated to one or more full
					// batches while we were waiting, kick off the next one.
					// (Sets batch_in_flight = true so at most one is started.)
					while self.state.batch_is_ready() && !batch_in_flight {
						let (start_index, batch_proof) = self.state.seal_batch()?;
						info!(
							start_index,
							new_root = ?contract::hash_to_bytes32(&batch_proof.root_new),
							"batch sealed (deferred), sending to prover"
						);

						self.prove_tx
							.send(ProveRequest {
								batch_proof,
								deposit_start_index: start_index,
							})
							.await?;

						batch_in_flight = true;
					}
				}

				// Graceful shutdown.
				_ = tokio::signal::ctrl_c() => {
					info!("shutting down");
					break;
				}
			}
		}

		Ok(())
	}

	/// Recover local state from on-chain finalized batches.
	///
	/// Counts `BatchValidated` events, fetches the corresponding `DepositPending`
	/// commitments, and replays them into the local Merkle tree so it matches
	/// the on-chain `merkleRoot`. Returns the number of finalized deposits.
	async fn recover_finalized_state<P: Provider + Clone>(
		&mut self,
		provider: &P,
		batch_size: u64,
		on_chain_root: &alloy::primitives::FixedBytes<32>,
	) -> anyhow::Result<u64> {
		// Count finalized batches via BatchValidated events.
		let validated_filter = Filter::new()
			.address(self.config.bridge_address)
			.event_signature(IDepositsRollupBridge::BatchValidated::SIGNATURE_HASH)
			.from_block(0);

		let validated_logs = provider.get_logs(&validated_filter).await?;
		let finalized_batches = validated_logs.len() as u64;

		if finalized_batches == 0 {
			// No batches finalized — verify genesis root matches.
			let local_root = contract::hash_to_bytes32(&SequencerState::genesis_root());
			if *on_chain_root != local_root {
				let msg = format!(
					"genesis root mismatch: on-chain={on_chain_root:?}, local={local_root:?}. \
					Re-deploy with the correct genesis root or reset the chain."
				);
				error!("{msg}");
				return Err(anyhow::anyhow!(msg));
			}
			return Ok(0);
		}

		let finalized_deposits = finalized_batches * batch_size;
		info!(
			finalized_batches,
			finalized_deposits, "replaying finalized deposits into local tree"
		);

		// Fetch all DepositPending events for finalized deposits.
		let deposit_filter = Filter::new()
			.address(self.config.bridge_address)
			.event_signature(IDepositsRollupBridge::DepositPending::SIGNATURE_HASH)
			.from_block(0);

		// Sort by depositId rather than relying on log return order: multiple
		// transactions in the same block may produce logs in tx-index order,
		// not depositId order.
		let mut deposit_logs = provider.get_logs(&deposit_filter).await?;
		deposit_logs.sort_by_key(|log| {
			log.log_decode::<IDepositsRollupBridge::DepositPending>()
				.map(|d| d.inner.depositId)
				.unwrap_or_default()
		});

		// Replay finalized deposits into the local tree, batch by batch.
		let mut replayed: u64 = 0;
		for log in deposit_logs {
			let decoded = log.log_decode::<IDepositsRollupBridge::DepositPending>()?;
			let deposit_id: u64 = decoded.inner.depositId.try_into().unwrap_or(0);

			if deposit_id >= finalized_deposits {
				continue;  // skip unfinalized deposits, don't short-circuit
			}

			let commitment = contract::bytes32_to_hash(&decoded.inner.commitment);
			self.state.add_commitment(commitment);
			replayed += 1;

			// Seal each full batch (inserts into local tree, advances next_batch_start_id).
			if self.state.batch_is_ready() {
				let (start_index, batch_proof) = self.state.seal_batch()?;
				info!(start_index, "replayed finalized batch into local tree");

				// After the last finalized batch, verify root matches on-chain.
				if start_index + batch_size == finalized_deposits {
					let local_root = contract::hash_to_bytes32(&batch_proof.root_new);
					if *on_chain_root != local_root {
						let msg = format!(
							"root mismatch after replaying {finalized_batches} batches: \
							on-chain={on_chain_root:?}, local={local_root:?}"
						);
						error!("{msg}");
						return Err(anyhow::anyhow!(msg));
					}
					info!("local root matches on-chain root after recovery");
				}
			}
		}

		if replayed != finalized_deposits {
			return Err(anyhow::anyhow!(
				"expected {finalized_deposits} deposit events for recovery, found {replayed}"
			));
		}

		self.state.batch_count = finalized_batches;

		Ok(finalized_deposits)
	}
}
