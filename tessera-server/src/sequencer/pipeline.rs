use tracing::{debug, error, info, warn};

use super::*;
use crate::{
	contract::{self, ITesseraRollupV2},
	sequencer::revert::humanize_bridge_revert,
	types::{ProveOutcome, ProveRequest},
};

impl Sequencer {
	/// Submit a V2 prove request to the remote prover with unlimited exponential-backoff retries.
	pub(super) fn submit_prove_request_v2_with_retry(
		&self,
		request: ProveRequest,
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
				match client.prove_tx(request.clone()).await {
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

	/// Finalize the batch builder, submit on-chain, and return `(batch_id, pi_commitment,
	/// prove_request)`. Does **not** call the prover — the caller decides the proof path
	/// (real prover vs. test zero-proof).
	pub(super) async fn submit_tx_batch_on_chain<P: Provider + Clone>(
		&mut self,
		provider: &P,
	) -> anyhow::Result<(u64, [u8; 32], ProveRequest)> {
		let bb = self.batch_builder.take().ok_or_else(|| {
			anyhow::anyhow!("submit_tx_batch_on_chain called with no batch builder")
		})?;
		self.batch_pending_since = None;

		debug!(slots = bb.len(), "flushing V2 batch");

		let finalized = bb.finalize();

		// Fetch current pool config root (uint256 = LE-packed Goldilocks hash).
		let rollup =
			ITesseraRollupV2::ITesseraRollupV2Instance::new(self.config.bridge_address, provider);
		let pool_cfg_root_u256 = rollup.poolConfigRoot().call().await?;
		// Convert to GL-preimage bytes32 (matches what the contract expects in the batch
		// and what the prover expects as main_pool_cfg_root witness).
		let pool_cfg_root_hash = contract::u256_le_to_hash(pool_cfg_root_u256)?;
		let pool_cfg_root_preimage: alloy::primitives::B256 =
			contract::hash_to_preimage_bytes32(&pool_cfg_root_hash);

		// Build the batch preimage bytes.
		// Layout: [batchPoseidonRoot(32B)][root(32B)][mainPoolConfigRoot(32B)]
		//         then n_slots × 520B:
		//           [notFakeTx:8B][accinNull:32B][accoutComm:32B][noteInNull×7:224B][noteOutComm×7:224B]
		//
		// GL-preimage encoding per field: [lo_u32_BE4][hi_u32_BE4].
		// nc_leaves/nn_leaves stride = NOTE_BATCH + 1 (7 NC + 1 AC per slot).
		let n_slots = finalized.ac_leaves.len();
		let stride = tessera_client::NOTE_BATCH + 1; // = 8

		let mut batch_preimage: Vec<u8> =
			Vec::with_capacity(96 + n_slots * (8 + 32 + 32 + 7 * 32 + 7 * 32));

		// Header (96B)
		batch_preimage
			.extend_from_slice(contract::hash_to_preimage_bytes32(&finalized.batch_poseidon_root).as_slice());
		batch_preimage
			.extend_from_slice(contract::hash_to_preimage_bytes32(&self.confirmed_root).as_slice());
		batch_preimage.extend_from_slice(pool_cfg_root_preimage.as_slice());

		// Per-slot data
		for s in 0..n_slots {
			// 8B: notFakeTx as GL field [lo_BE4][hi_BE4]
			let nft: u64 = if finalized.tx_proofs_by_slot.contains_key(&s) { 1 } else { 0 };
			batch_preimage.extend_from_slice(&(nft as u32).to_be_bytes()); // lo
			batch_preimage.extend_from_slice(&0u32.to_be_bytes()); // hi

			// 32B: accinNullifier (AN leaf)
			batch_preimage
				.extend_from_slice(contract::raw_to_preimage_bytes32(&finalized.an_leaves[s]).as_slice());
			// 32B: accoutCommitment (AC leaf)
			batch_preimage
				.extend_from_slice(contract::raw_to_preimage_bytes32(&finalized.ac_leaves[s]).as_slice());

			let base = s * stride;
			// 7×32B: noteInNullifiers (NN leaves)
			for j in 0..tessera_client::NOTE_BATCH {
				batch_preimage.extend_from_slice(
					contract::raw_to_preimage_bytes32(&finalized.nn_leaves[base + j]).as_slice(),
				);
			}
			// 7×32B: noteOutCommitments (NC leaves)
			for j in 0..tessera_client::NOTE_BATCH {
				batch_preimage.extend_from_slice(
					contract::raw_to_preimage_bytes32(&finalized.nc_leaves[base + j]).as_slice(),
				);
			}
		}

		// Submit on-chain (phase 1) — preimage bytes are in calldata (on-chain DA).
		let receipt = rollup
			.submitTransactionBatch(batch_preimage.clone().into())
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

		// Extract piCommitment from the TransactionBatchSubmitted event (for logging).
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
		// main_pool_cfg_root is GL-preimage [u8;32] — same format the proof witness expects.
		let prove_request = finalized.into_prove_request_v2(
			batch_id,
			self.confirmed_root,
			pool_cfg_root_preimage.into(),
		);

		Ok((batch_id, batch_preimage, prove_request))
	}

	/// Finalize the batch builder, submit on-chain, and dispatch a prove request.
	pub(super) async fn flush_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
	) -> anyhow::Result<()> {
		let (batch_id, batch_preimage, prove_request) =
			self.submit_tx_batch_on_chain(provider).await?;
		self.pending_batches.insert(
			batch_id,
			SolidityTransactionBatchCommitment {
				batch_preimage,
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
		outcome: ProveOutcome,
	) -> anyhow::Result<()> {
		self.confirm_tx_batch(provider, outcome).await
	}

	/// On proof success, call `proveTransactionBatch` on-chain and update state.
	pub(super) async fn confirm_tx_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
		outcome: ProveOutcome,
	) -> anyhow::Result<()> {
		match outcome {
			ProveOutcome::Failure {
				batch_id,
				error,
			} => {
				error!(
					batch_id,
					error, "prover failure; batch will not be confirmed"
				);
				self.pending_batches.remove(&batch_id);
			},

			ProveOutcome::Success {
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
				let batch_preimage = pending.batch_preimage.clone();
				let pi_commitment: [u8; 32] =
					alloy::primitives::keccak256(&batch_preimage).into();

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
						.proveTransactionBatch(batch_preimage.into(), sol_proof)
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
