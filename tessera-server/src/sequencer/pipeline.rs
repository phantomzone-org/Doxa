use alloy::primitives::FixedBytes;
use tracing::{debug, error, info, warn};

use super::*;
use crate::{
	contract::{self, ITesseraRollupV2},
	sequencer::revert::humanize_bridge_revert,
	types::{ConsumeOutcome, ConsumeProveRequest, ProveOutcomeV2, ProveRequestV2},
};

impl Sequencer {
	/// Submit a V2 prove request to the remote prover with unlimited exponential-backoff retries.
	pub(super) fn submit_prove_request_v2_with_retry(
		&self,
		request: ProveRequestV2,
	) -> anyhow::Result<()> {
		let Some(client) = self.prover_client.clone() else {
			return Err(anyhow::anyhow!("prover client not initialized"));
		};
		let Some(result_tx) = self.result_tx.clone() else {
			return Err(anyhow::anyhow!("prover result channel not initialized"));
		};
		let batch_id = request.batch_id;

		tokio::spawn(async move {
			let mut attempts: u64 = 0;
			loop {
				match client.prove_v2(request.clone()).await {
					Ok(outcome) => {
						let _ = result_tx.send(outcome).await;
						break;
					},
					Err(e) => {
						attempts = attempts.saturating_add(1);
						warn!(
							batch_id,
							attempts,
							error = %e,
							"prover unavailable; retrying"
						);
						tokio::select! {
							_ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {},
							_ = result_tx.closed() => {
								warn!(batch_id, "sequencer shutting down; abandoning retry");
								break;
							},
						}
					},
				}
			}
		});
		Ok(())
	}

	/// Query the V2 contract and return `true` if `note` is in `Pending` status.
	pub(super) async fn is_note_available<P: Provider + Clone>(
		&self,
		provider: &P,
		note: &[u8; 32],
	) -> bool {
		let rollup =
			ITesseraRollupV2::ITesseraRollupV2Instance::new(self.config.bridge_address, provider);
		let note_key = FixedBytes::<32>::from(*note);
		match rollup.getDeposit(note_key).call().await {
			Ok(dep) => matches!(dep.status, ITesseraRollupV2::DepositStatus::Pending),
			Err(e) => {
				warn!("failed to fetch deposit status: {e}");
				false
			},
		}
	}

	/// Finalize the batch builder, submit on-chain, and return `(batch_id, pi_commitment,
	/// prove_request)`. Does **not** call the prover — the caller decides the proof path
	/// (real prover vs. test zero-proof).
	pub(super) async fn submit_tx_batch_on_chain<P: Provider + Clone>(
		&mut self,
		provider: &P,
	) -> anyhow::Result<(u64, [u8; 32], ProveRequestV2)> {
		let bb = self.batch_builder.take().ok_or_else(|| {
			anyhow::anyhow!("submit_tx_batch_on_chain called with no batch builder")
		})?;
		self.batch_pending_since = None;

		debug!(slots = bb.len(), "flushing V2 batch");

		let finalized = bb.finalize();

		// Fetch current pool config root.
		let rollup =
			ITesseraRollupV2::ITesseraRollupV2Instance::new(self.config.bridge_address, provider);
		let pool_cfg_root: [u8; 32] = rollup.poolConfigRoot().call().await?.into();

		// Build the on-chain TransactionBatch struct.
		// noteCommitments: all 128 NC leaves, LE-packed as uint256.
		let note_commitments: Vec<alloy::primitives::U256> = finalized
			.nc_leaves
			.iter()
			.map(contract::bytes32_be_to_u256_le)
			.collect();

		// noteNullifiers: all 128 NN leaves (sorted), LE-packed.
		let note_nullifiers: Vec<alloy::primitives::U256> = finalized
			.nn_sorted
			.iter()
			.map(contract::bytes32_be_to_u256_le)
			.collect();

		// accountCommitment + accountNullifier: slot 0's AC and AN (circuit convention).
		let account_commitment = contract::bytes32_be_to_u256_le(&finalized.ac_leaves[0]);
		let account_nullifier = contract::bytes32_be_to_u256_le(&finalized.an_sorted[0]);

		// batchPoseidonRoot: Poseidon Merkle root of nc_leaves.
		let batch_poseidon_root = contract::hash_to_u256_le(&finalized.batch_poseidon_root);

		let root = contract::hash_to_u256_le(&self.confirmed_root);

		let batch = ITesseraRollupV2::TransactionBatch {
			root,
			mainPoolConfigRoot: pool_cfg_root.into(),
			noteCommitments: note_commitments,
			noteNullifiers: note_nullifiers,
			accountCommitment: account_commitment,
			accountNullifier: account_nullifier,
			batchPoseidonRoot: batch_poseidon_root,
			confirmed: false,
		};

		// Submit on-chain (phase 1).
		let receipt = rollup
			.submitTransactionBatch(batch)
			.send()
			.await
			.map_err(|e| {
				anyhow::anyhow!(
					"submitTransactionBatch reverted: {}",
					humanize_bridge_revert(&e)
				)
			})?
			.with_required_confirmations(1)
			.with_timeout(Some(RECEIPT_TIMEOUT))
			.get_receipt()
			.await
			.map_err(|e| anyhow::anyhow!("submitTransactionBatch receipt error: {e}"))?;

		anyhow::ensure!(
			receipt.status(),
			"submitTransactionBatch reverted on-chain (tx={:?})",
			receipt.transaction_hash
		);

		// Extract piCommitment from the TransactionBatchSubmitted event.
		let pi_commitment: [u8; 32] = receipt
			.inner
			.logs()
			.iter()
			.find_map(|log| {
				log.log_decode::<ITesseraRollupV2::TransactionBatchSubmitted>()
					.ok()
					.map(|d| d.inner.piCommitment.into())
			})
			.ok_or_else(|| {
				anyhow::anyhow!("TransactionBatchSubmitted event not found in receipt")
			})?;

		let batch_id = self.next_batch_id;
		self.next_batch_id = self.next_batch_id.saturating_add(1);

		info!(
			batch_id,
			pi_commitment = hex::encode(pi_commitment),
			real_slots = finalized.tx_proofs_by_slot.len(),
			"batch submitted on-chain"
		);

		// Build the prove request (returned to caller — may or may not be dispatched).
		let prove_request =
			finalized.into_prove_request_v2(batch_id, self.confirmed_root, pool_cfg_root);

		Ok((batch_id, pi_commitment, prove_request))
	}

	/// Finalize the batch builder, submit on-chain, and dispatch a prove request.
	pub(super) async fn flush_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
	) -> anyhow::Result<()> {
		let (batch_id, pi_commitment, prove_request) =
			self.submit_tx_batch_on_chain(provider).await?;
		self.pending_batches.insert(
			batch_id,
			TxBatchV2 {
				pi_commitment,
			},
		);
		self.submit_prove_request_v2_with_retry(prove_request)?;
		self.log_pool_status("batch submitted, pending proof");
		Ok(())
	}

	/// Process a completed [`ProveOutcomeV2`] from the remote prover.
	pub(super) async fn handle_prove_outcome<P: Provider + Clone>(
		&mut self,
		provider: &P,
		outcome: ProveOutcomeV2,
	) -> anyhow::Result<()> {
		self.confirm_tx_batch(provider, outcome).await
	}

	/// On proof success, call `proveTransactionBatch` on-chain and update state.
	pub(super) async fn confirm_tx_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
		outcome: ProveOutcomeV2,
	) -> anyhow::Result<()> {
		match outcome {
			ProveOutcomeV2::Failure {
				batch_id,
				error,
			} => {
				error!(
					batch_id,
					error, "prover failure; batch will not be confirmed"
				);
				self.pending_batches.remove(&batch_id);
			},

			ProveOutcomeV2::Success {
				batch_id,
				batch_poseidon_root: _,
				solidity_proof,
				super_pi_commitment,
			} => {
				let Some(pending) = self.pending_batches.get(&batch_id) else {
					warn!(
						batch_id,
						"proof arrived for unknown/already-confirmed batch; skipping"
					);
					return Ok(());
				};
				let pi_commitment = pending.pi_commitment;

				let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(
					self.config.bridge_address,
					provider,
				);

				let sol_proof = ITesseraRollupV2::Proof {
					proof: solidity_proof.proof,
					commitments: solidity_proof.commitments,
					commitmentPok: solidity_proof.commitment_pok,
				};

				info!(
					batch_id,
					pi_commitment = hex::encode(pi_commitment),
					prover_commitment = hex::encode(super_pi_commitment),
					"submitting proveTransactionBatch"
				);

				let confirm_result: Result<_, anyhow::Error> = async {
					let receipt = rollup
						.proveTransactionBatch(pi_commitment.into(), sol_proof)
						.send()
						.await
						.map_err(|e| {
							anyhow::anyhow!(
								"proveTransactionBatch send failed: {}",
								humanize_bridge_revert(&e)
							)
						})?
						.with_required_confirmations(1)
						.with_timeout(Some(RECEIPT_TIMEOUT))
						.get_receipt()
						.await
						.map_err(|e| anyhow::anyhow!("proveTransactionBatch receipt error: {e}"))?;
					anyhow::ensure!(
						receipt.status(),
						"proveTransactionBatch reverted (batch_id={batch_id}, tx={:?})",
						receipt.transaction_hash
					);
					Ok(receipt)
				}
				.await;

				match confirm_result {
					Err(e) => {
						error!(batch_id, error = %e, "on-chain proveTransactionBatch failed");
						self.pending_batches.remove(&batch_id);
						return Ok(());
					},
					Ok(receipt) => {
						// Extract new root from TransactionBatchProven event.
						let new_root_u256 = receipt.inner.logs().iter().find_map(|log| {
							log.log_decode::<ITesseraRollupV2::TransactionBatchProven>()
								.ok()
								.map(|d| d.inner.newTreeRoot)
						});

						if let Some(root_u256) = new_root_u256 {
							match contract::u256_le_to_hash(root_u256) {
								Ok(new_root) => {
									self.confirmed_root = new_root;
									self.confirmed_root_history.insert(new_root);
									info!(
										batch_id,
										new_root = ?root_u256,
										tx_hash = ?receipt.transaction_hash,
										"batch proven; confirmed_root updated"
									);
								},
								Err(e) => {
									warn!(batch_id, error = %e, "could not decode new root from event");
								},
							}
						} else {
							warn!(
								batch_id,
								"TransactionBatchProven event not found in receipt"
							);
						}
					},
				}

				self.pending_batches.remove(&batch_id);
				self.log_pool_status("batch proven and confirmed");
			},
		}
		Ok(())
	}
}

// ---------------------------------------------------------------------------
// Consume (deposit-batch) pipeline
// ---------------------------------------------------------------------------

impl Sequencer {
	/// Submit a consume prove request with unlimited exponential-backoff retries.
	pub(super) fn submit_consume_request_with_retry(
		&self,
		request: ConsumeProveRequest,
	) -> anyhow::Result<()> {
		let Some(client) = self.prover_client.clone() else {
			return Err(anyhow::anyhow!("prover client not initialized"));
		};
		let Some(result_tx) = self.consume_result_tx.clone() else {
			return Err(anyhow::anyhow!("consume result channel not initialized"));
		};
		let batch_id = request.batch_id;

		tokio::spawn(async move {
			let mut attempts: u64 = 0;
			loop {
				match client.prove_consume(request.clone()).await {
					Ok(outcome) => {
						let _ = result_tx.send(outcome).await;
						break;
					},
					Err(e) => {
						attempts = attempts.saturating_add(1);
						warn!(
							batch_id,
							attempts,
							error = %e,
							"consume prover unavailable; retrying"
						);
						tokio::select! {
							_ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {},
							_ = result_tx.closed() => {
								warn!(batch_id, "sequencer shutting down; abandoning consume retry");
								break;
							},
						}
					},
				}
			}
		});
		Ok(())
	}

	/// Finalize the consume batch builder, submit on-chain, and return `(batch_id,
	/// pi_commitment, prove_request)`. Does **not** call the prover — the caller decides the
	/// proof path (real prover vs. test zero-proof).
	pub(super) async fn submit_consume_batch_on_chain<P: Provider + Clone>(
		&mut self,
		provider: &P,
	) -> anyhow::Result<(u64, [u8; 32], ConsumeProveRequest)> {
		let cb = self.consume_batch_builder.take().ok_or_else(|| {
			anyhow::anyhow!("submit_consume_batch_on_chain called with no consume batch builder")
		})?;
		self.consume_batch_pending_since = None;

		debug!(notes = cb.len(), "flushing consume batch");

		let finalized = cb.finalize();

		let rollup =
			ITesseraRollupV2::ITesseraRollupV2Instance::new(self.config.bridge_address, provider);
		let pool_cfg_root: [u8; 32] = rollup.poolConfigRoot().call().await?.into();

		let root = contract::hash_to_u256_le(&self.confirmed_root);
		let batch_poseidon_root = contract::hash_to_u256_le(&finalized.batch_poseidon_root);

		let deposit_note_commitments: Vec<alloy::primitives::FixedBytes<32>> = finalized
			.deposit_note_commitments
			.iter()
			.map(|b| alloy::primitives::FixedBytes::<32>::from(*b))
			.collect();

		let batch = ITesseraRollupV2::DepositBatch {
			root,
			mainPoolConfigRoot: pool_cfg_root.into(),
			depositNoteCommitments: deposit_note_commitments,
			batchPoseidonRoot: batch_poseidon_root,
			confirmed: false,
		};

		let receipt = rollup
			.submitDepositBatch(batch)
			.send()
			.await
			.map_err(|e| {
				anyhow::anyhow!(
					"submitDepositBatch reverted: {}",
					humanize_bridge_revert(&e)
				)
			})?
			.with_required_confirmations(1)
			.with_timeout(Some(RECEIPT_TIMEOUT))
			.get_receipt()
			.await
			.map_err(|e| anyhow::anyhow!("submitDepositBatch receipt error: {e}"))?;

		anyhow::ensure!(
			receipt.status(),
			"submitDepositBatch reverted on-chain (tx={:?})",
			receipt.transaction_hash
		);

		let pi_commitment: [u8; 32] = receipt
			.inner
			.logs()
			.iter()
			.find_map(|log| {
				log.log_decode::<ITesseraRollupV2::DepositBatchSubmitted>()
					.ok()
					.map(|d| d.inner.piCommitment.into())
			})
			.ok_or_else(|| anyhow::anyhow!("DepositBatchSubmitted event not found in receipt"))?;

		let batch_id = self.next_consume_batch_id;
		self.next_consume_batch_id = self.next_consume_batch_id.saturating_add(1);

		info!(
			batch_id,
			pi_commitment = hex::encode(pi_commitment),
			real_notes = finalized.consume_proofs_by_slot.len(),
			"consume batch submitted on-chain"
		);

		let prove_request =
			finalized.into_prove_request(batch_id, self.confirmed_root, pool_cfg_root);

		Ok((batch_id, pi_commitment, prove_request))
	}

	/// Finalize the consume batch builder, submit on-chain, and dispatch a prove request.
	pub(super) async fn flush_consume_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
	) -> anyhow::Result<()> {
		let (batch_id, pi_commitment, prove_request) =
			self.submit_consume_batch_on_chain(provider).await?;
		self.pending_consume_batches.insert(
			batch_id,
			ConsumeBatchV2 {
				pi_commitment,
			},
		);
		self.submit_consume_request_with_retry(prove_request)?;
		Ok(())
	}

	/// Process a completed [`ConsumeOutcome`] from the remote prover.
	pub(super) async fn handle_consume_outcome<P: Provider + Clone>(
		&mut self,
		provider: &P,
		outcome: ConsumeOutcome,
	) -> anyhow::Result<()> {
		self.confirm_consume_batch(provider, outcome).await
	}

	/// On consume proof success, call `proveDepositBatch` on-chain.
	pub(super) async fn confirm_consume_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
		outcome: ConsumeOutcome,
	) -> anyhow::Result<()> {
		match outcome {
			ConsumeOutcome::Failure {
				batch_id,
				error,
			} => {
				self.pending_consume_batches.remove(&batch_id);
				return Err(anyhow::anyhow!(
					"consume prover failure for batch {batch_id}: {error}"
				));
			},

			ConsumeOutcome::Success {
				batch_id,
				batch_poseidon_root: _,
				solidity_proof,
				super_pi_commitment,
			} => {
				let Some(pending) = self.pending_consume_batches.get(&batch_id) else {
					warn!(
						batch_id,
						"consume proof arrived for unknown/already-confirmed batch; skipping"
					);
					return Ok(());
				};
				let pi_commitment = pending.pi_commitment;

				let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(
					self.config.bridge_address,
					provider,
				);

				let sol_proof = ITesseraRollupV2::Proof {
					proof: solidity_proof.proof,
					commitments: solidity_proof.commitments,
					commitmentPok: solidity_proof.commitment_pok,
				};

				info!(
					batch_id,
					pi_commitment = hex::encode(pi_commitment),
					prover_commitment = hex::encode(super_pi_commitment),
					"submitting proveDepositBatch"
				);

				let confirm_result: Result<_, anyhow::Error> = async {
					let receipt = rollup
						.proveDepositBatch(pi_commitment.into(), sol_proof)
						.send()
						.await
						.map_err(|e| {
							anyhow::anyhow!(
								"proveDepositBatch send failed: {}",
								humanize_bridge_revert(&e)
							)
						})?
						.with_required_confirmations(1)
						.with_timeout(Some(RECEIPT_TIMEOUT))
						.get_receipt()
						.await
						.map_err(|e| anyhow::anyhow!("proveDepositBatch receipt error: {e}"))?;
					anyhow::ensure!(
						receipt.status(),
						"proveDepositBatch reverted (batch_id={batch_id}, tx={:?})",
						receipt.transaction_hash
					);
					Ok(receipt)
				}
				.await;

				match confirm_result {
					Err(e) => {
						error!(
							batch_id,
							error = %e,
							"on-chain proveDepositBatch failed"
						);
						self.pending_consume_batches.remove(&batch_id);
						return Ok(());
					},
					Ok(receipt) => {
						let new_root_u256 = receipt.inner.logs().iter().find_map(|log| {
							log.log_decode::<ITesseraRollupV2::DepositBatchProven>()
								.ok()
								.map(|d| d.inner.newTreeRoot)
						});

						if let Some(root_u256) = new_root_u256 {
							match contract::u256_le_to_hash(root_u256) {
								Ok(new_root) => {
									self.confirmed_root = new_root;
									self.confirmed_root_history.insert(new_root);
									info!(
										batch_id,
										new_root = ?root_u256,
										tx_hash = ?receipt.transaction_hash,
										"consume batch proven; confirmed_root updated"
									);
								},
								Err(e) => {
									warn!(
										batch_id,
										error = %e,
										"could not decode new root from DepositBatchProven event"
									);
								},
							}
						} else {
							warn!(batch_id, "DepositBatchProven event not found in receipt");
						}
					},
				}

				self.pending_consume_batches.remove(&batch_id);
				info!(batch_id, "consume batch proven and confirmed");
			},
		}
		Ok(())
	}
}
