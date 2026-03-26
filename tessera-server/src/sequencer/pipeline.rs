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

		// Fetch current pool config root.
		let rollup =
			ITesseraRollupV2::ITesseraRollupV2Instance::new(self.config.bridge_address, provider);
		let pool_cfg_root: [u8; 32] = rollup.poolConfigRoot().call().await?.into();

		// Build the on-chain TransactionBatch struct.
		// Per-slot layout: 7 NC + 1 AC, 7 NN + 1 AN.
		// The piCommitment factors out the common root/config/poseidon fields
		// and lists all 64 ACs, ANs, 7×64 NCs, 7×64 NNs.
		let n_slots = finalized.ac_leaves.len();

		// noteCommitments: 7 per slot (skip AC at position NOTE_BATCH=7), LE-packed.
		let stride = tessera_client::NOTE_BATCH + 1; // 8 entries per slot in nc/nn_leaves
		let mut note_commitments = Vec::with_capacity(n_slots * tessera_client::NOTE_BATCH);
		for s in 0..n_slots {
			let nc_base = s * stride;
			for j in 0..tessera_client::NOTE_BATCH {
				note_commitments.push(contract::bytes32_be_to_u256_le(
					&finalized.nc_leaves[nc_base + j],
				));
			}
		}

		// accountCommitments: all 64 slots, LE-packed.
		let account_commitments: Vec<alloy::primitives::U256> = finalized
			.ac_leaves
			.iter()
			.map(contract::bytes32_be_to_u256_le)
			.collect();

		// Nullifiers: only from real TX slots (padding slots have no nullifiers).
		let mut note_nullifiers = Vec::new();
		let mut account_nullifiers = Vec::new();
		for s in 0..n_slots {
			if !finalized.tx_proofs_by_slot.contains_key(&s) {
				continue;
			}
			let nn_base = s * stride;
			for j in 0..tessera_client::NOTE_BATCH {
				note_nullifiers.push(contract::bytes32_be_to_u256_le(
					&finalized.nn_leaves[nn_base + j],
				));
			}
			account_nullifiers.push(contract::bytes32_be_to_u256_le(
				&finalized.an_leaves[s],
			));
		}

		let batch_poseidon_root = contract::hash_to_u256_le(&finalized.batch_poseidon_root);
		let root = contract::hash_to_u256_le(&self.confirmed_root);

		let batch = ITesseraRollupV2::TransactionBatch {
			root,
			mainPoolConfigRoot: pool_cfg_root.into(),
			noteCommitments: note_commitments,
			noteNullifiers: note_nullifiers,
			accountCommitments: account_commitments,
			accountNullifiers: account_nullifiers,
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

		// DEBUG: decode and print the Solidity TX preimage
		if let Some(debug) = receipt
			.inner
			.logs()
			.iter()
			.find_map(|log| log.log_decode::<ITesseraRollupV2::DebugTxPreimage>().ok())
		{
			let pre = &debug.inner.preimage;
			eprintln!("[TX-CONTRACT] preimage len     : {}", pre.len());
			if pre.len() >= 192 {
				eprintln!(
					"[TX-CONTRACT] root             : {}",
					hex::encode(&pre[..32])
				);
				eprintln!(
					"[TX-CONTRACT] root (dup)        : {}",
					hex::encode(&pre[32..64])
				);
				eprintln!(
					"[TX-CONTRACT] mainPoolCfgRoot   : {}",
					hex::encode(&pre[64..96])
				);
				eprintln!(
					"[TX-CONTRACT] batchPoseidonRoot : {}",
					hex::encode(&pre[96..128])
				);
				eprintln!(
					"[TX-CONTRACT] accountCommitment : {}",
					hex::encode(&pre[128..160])
				);
				eprintln!(
					"[TX-CONTRACT] accountNullifier  : {}",
					hex::encode(&pre[160..192])
				);
				let rest = &pre[192..];
				let n_u256 = rest.len() / 32;
				let half = n_u256 / 2;
				eprintln!("[TX-CONTRACT] noteCommitments  : {} values", half);
				for i in 0..half.min(3) {
					eprintln!(
						"[TX-CONTRACT] nc[{:>3}]           : {}",
						i,
						hex::encode(&rest[i * 32..(i + 1) * 32])
					);
				}
				eprintln!("[TX-CONTRACT] noteNullifiers   : {} values", n_u256 - half);
				for i in 0..((n_u256 - half).min(3)) {
					let off = (half + i) * 32;
					eprintln!(
						"[TX-CONTRACT] nn[{:>3}]           : {}",
						i,
						hex::encode(&rest[off..off + 32])
					);
				}
			}
			eprintln!(
				"[TX-CONTRACT] result           : {}",
				hex::encode(debug.inner.result)
			);
		}

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
			SolidityTransactionBatchCommitment {
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
