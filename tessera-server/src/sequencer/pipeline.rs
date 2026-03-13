use tracing::{debug, error, info, warn};

use super::*;
use crate::sequencer::{
	batch::is_sorted_u256, recovery::commit_tree_batch, revert::humanize_bridge_revert,
};

impl Sequencer {
	/// Submit a prove request to the remote prover with unlimited exponential-backoff retries.
	///
	/// Spawns a Tokio task that loops, calling the HTTP prover client.  On success the
	/// [`ProveOutcome`] is forwarded through `result_tx`.  On failure the task sleeps 5 s
	/// and retries; it exits early if `result_tx` is closed (sequencer shutdown).
	pub(super) fn submit_prove_request_with_retry(
		&self,
		request: crate::types::ProveRequest,
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
				match client.prove(request.clone()).await {
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
							"prover unavailable; keeping batch pending and retrying"
						);
						tokio::select! {
							_ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {},
							_ = result_tx.closed() => {
								warn!(batch_id, "sequencer shutting down; abandoning prover retry");
								break;
							},
						}
					},
				}
			}
		});
		Ok(())
	}

	/// Query the bridge contract and return `true` if `note` can be consumed as a
	/// commitment (status is `Pending` or `None`).
	pub(super) async fn is_note_available<P: Provider + Clone>(
		&self,
		provider: &P,
		note: &[u8; 32],
	) -> bool {
		let bridge = IDepositsRollupBridge::IDepositsRollupBridgeInstance::new(
			self.config.bridge_address,
			provider,
		);
		let note = alloy::primitives::FixedBytes::<32>::from(*note);
		match bridge.getDepositStatus(note).call().await {
			Ok(status) => {
				matches!(
					status,
					IDepositsRollupBridge::DepositStatus::Pending
						| IDepositsRollupBridge::DepositStatus::None
				)
			},
			Err(e) => {
				warn!("failed to fetch note status: {e}");
				false
			},
		}
	}

	/// Evaluate the batch builder and flush when it is full or has timed out.
	///
	/// Returns immediately if:
	/// - No batch builder exists (nothing to flush).
	/// - The pending-batch registry is at capacity.
	pub(super) async fn maybe_flush_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
		account_batch_size: usize,
		batch_timeout: std::time::Duration,
	) -> anyhow::Result<()> {
		if self.registered_pending_batches.len() >= MAX_PENDING_BATCHES {
			return Ok(());
		}
		let Some(bb) = &self.batch_builder else {
			return Ok(());
		};
		self.log_pool_status("batch scheduling tick");

		let should_flush = bb.is_full()
			|| self
				.batch_pending_since
				.is_some_and(|since| since.elapsed() >= batch_timeout);

		if should_flush {
			self.flush_batch(provider, account_batch_size).await?;
		}
		Ok(())
	}

	/// Finalize the current batch builder, register on-chain, advance trees,
	/// and submit the prove request.
	///
	/// Steps:
	/// 1. Take and finalize the `BatchBuilder` (pads, sorts, builds leaf arrays).
	/// 2. Assert sort order on AN/NN (defensive).
	/// 3. Preflight: verify all four on-chain roots match local state.
	/// 4. Build native tree proofs from the finalized leaf arrays.
	/// 5. Call `registerTransactionBatchUpdate` on-chain; extract the `batchId`.
	/// 6. Apply inserts to the real local trees (advance roots).
	/// 7. Submit a `ProveRequest` via `submit_prove_request_with_retry`.
	/// 8. Store a `TxBatch` record for confirmation tracking.
	async fn flush_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
		account_batch_size: usize,
	) -> anyhow::Result<()> {
		let bb = self
			.batch_builder
			.take()
			.ok_or_else(|| anyhow::anyhow!("flush_batch called with no batch builder"))?;
		self.batch_pending_since = None;

		debug!(slots = bb.len(), account_batch_size, "flushing batch");

		// 1. Finalize: pad, sort, build leaf arrays.
		let finalized = bb.finalize();

		// 2. Assert sort order (defensive check at sequencer exit point).
		anyhow::ensure!(
			is_sorted_u256(&finalized.an_sorted),
			"AN leaves not sorted after finalize"
		);
		anyhow::ensure!(
			is_sorted_u256(&finalized.nn_sorted),
			"NN leaves not sorted after finalize"
		);

		// 3. Preflight: all four on-chain roots must match local state.
		let bridge = IDepositsRollupBridge::IDepositsRollupBridgeInstance::new(
			self.config.bridge_address,
			provider,
		);
		let on_chain_nc = bridge.notesCommitmentRoot().call().await?;
		let local_nc = contract::hash_to_bytes32(&self.notes_commitment_state.current_root());
		anyhow::ensure!(
			on_chain_nc == local_nc,
			"preflight failed: notesCommitmentRoot mismatch (on-chain={on_chain_nc:?}, local={local_nc:?})"
		);
		let on_chain_nn = bridge.notesNullifierRoot().call().await?;
		let local_nn = contract::hash_to_bytes32(&self.notes_nullifier_state.current_root());
		anyhow::ensure!(
			on_chain_nn == local_nn,
			"preflight failed: notesNullifierRoot mismatch (on-chain={on_chain_nn:?}, local={local_nn:?})"
		);
		let on_chain_ac = bridge.accountsCommitmentRoot().call().await?;
		let local_ac = contract::hash_to_bytes32(&self.accounts_commitment_state.current_root());
		anyhow::ensure!(
			on_chain_ac == local_ac,
			"preflight failed: accountsCommitmentRoot mismatch (on-chain={on_chain_ac:?}, local={local_ac:?})"
		);
		let on_chain_an = bridge.accountsNullifierRoot().call().await?;
		let local_an = contract::hash_to_bytes32(&self.accounts_nullifier_state.current_root());
		anyhow::ensure!(
			on_chain_an == local_an,
			"preflight failed: accountsNullifierRoot mismatch (on-chain={on_chain_an:?}, local={local_an:?})"
		);

		// 4. Build native tree proofs and assemble ProveRequest.
		let prove_request = finalized.into_prove_request(
			0, // batch_id placeholder — replaced after on-chain registration
			&self.accounts_commitment_state.tree,
			&self.accounts_nullifier_state.tree,
			&self.notes_commitment_state.tree,
			&self.notes_nullifier_state.tree,
		)?;

		let new_nc_root = contract::hash_to_bytes32(&prove_request.notes_commitment_proof.root_new);
		let new_nn_root = contract::hash_to_bytes32(&prove_request.notes_nullifier_proof.new_root);
		let new_ac_root =
			contract::hash_to_bytes32(&prove_request.accounts_commitment_proof.root_new);
		let new_an_root =
			contract::hash_to_bytes32(&prove_request.accounts_nullifier_proof.new_root);

		// 5. Register on-chain.
		let pending = bridge
			.registerTransactionBatchUpdate(
				new_nc_root,
				finalized.nc_fixed(),
				new_nn_root,
				finalized.nn_fixed(),
				new_ac_root,
				finalized.ac_fixed(),
				new_an_root,
				finalized.an_fixed(),
			)
			.send()
			.await
			.map_err(|e| {
				anyhow::anyhow!(
					"registerTransactionBatchUpdate reverted: {}",
					humanize_bridge_revert(&e)
				)
			})?;
		let receipt = pending
			.with_required_confirmations(1)
			.with_timeout(Some(RECEIPT_TIMEOUT))
			.get_receipt()
			.await
			.map_err(|e| anyhow::anyhow!("register receipt timeout/error: {e}"))?;
		anyhow::ensure!(
			receipt.status(),
			"registerTransactionBatchUpdate reverted on-chain (tx={:?})",
			receipt.transaction_hash
		);

		let batch_id: u64 = receipt
			.inner
			.logs()
			.iter()
			.find_map(|log| {
				log.log_decode::<IDepositsRollupBridge::TransactionBatchRegistered>()
					.ok()
					.and_then(|d| d.inner.batchId.try_into().ok())
			})
			.ok_or_else(|| {
				anyhow::anyhow!("TransactionBatchRegistered event not found in receipt")
			})?;

		info!(
			batch_id,
			real_slots = finalized.tx_proofs_by_slot.len(),
			total_slots = account_batch_size,
			"batch registered on-chain"
		);

		// 6. Apply inserts to real local trees (advance roots for subsequent batches).
		let nc_hashes = contract::bytes_slice_to_hashes(&finalized.nc_leaves)?;
		let nn_hashes = contract::bytes_slice_to_hashes(&finalized.nn_sorted)?;
		let ac_hashes = contract::bytes_slice_to_hashes(&finalized.ac_leaves)?;
		let an_hashes = contract::bytes_slice_to_hashes(&finalized.an_sorted)?;
		self.notes_commitment_state.tree.insert_batch(nc_hashes)?;
		self.notes_nullifier_state.tree.insert_batch(nn_hashes)?;
		self.accounts_commitment_state
			.tree
			.insert_batch(ac_hashes)?;
		self.accounts_nullifier_state.tree.insert_batch(an_hashes)?;

		// 7. Submit ProveRequest with the real batch_id.
		let mut prove_request = prove_request;
		prove_request.batch_id = batch_id;
		self.submit_prove_request_with_retry(prove_request)?;

		// 8. Store TxBatch for confirmation tracking / WAL commit / requeue.
		self.registered_pending_batches.insert(
			batch_id,
			TxBatch {
				batch_id,
				private_tx_reqs: Vec::new(), // TODO: store for requeue if needed
				deposit_notes: Vec::new(),   // TODO: store for requeue if needed
				nc_padded: finalized.nc_leaves,
				nn_padded: finalized.nn_sorted,
				ac_padded: finalized.ac_leaves,
				an_padded: finalized.an_sorted,
			},
		);
		self.log_pool_status("batch moved to pending");
		Ok(())
	}

	/// Process a completed [`ProveOutcome`] from the remote prover.
	pub(super) async fn handle_prove_outcome<P: Provider + Clone>(
		&mut self,
		provider: &P,
		outcome: ProveOutcome,
	) -> anyhow::Result<()> {
		self.confirm_tx_batch(provider, outcome).await
	}

	/// Confirm a registered batch by verifying the SuperAggregator Groth16 proof on-chain.
	///
	/// On **Failure**: logs the error and removes the batch from `registered_pending_batches`.
	///
	/// On **Success**:
	/// 1. Calls `confirmBatch` on-chain with the Groth16 proof.
	/// 2. Commits all four trees' padded batches to their WAL/snapshot stores.
	/// 3. Removes the batch from `registered_pending_batches`.
	async fn confirm_tx_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
		outcome: ProveOutcome,
	) -> anyhow::Result<()> {
		match outcome {
			ProveOutcome::Failure {
				batch_id,
				error,
			} => {
				tracing::error!(
					batch_id,
					error,
					"prover failure for batch; batch will not be confirmed"
				);
				self.registered_pending_batches.remove(&batch_id);
			},
			ProveOutcome::Success {
				batch_id,
				notes_new_root: _,
				nullifier_notes_new_root: _,
				accounts_new_root: _,
				nullifier_accounts_new_root: _,
				solidity_proof,
				super_pi_commitment,
			} => {
				if !self.registered_pending_batches.contains_key(&batch_id) {
					warn!(
						batch_id,
						"proof arrived for unknown/already-confirmed batch; skipping"
					);
					return Ok(());
				}

				let bridge = IDepositsRollupBridge::IDepositsRollupBridgeInstance::new(
					self.config.bridge_address,
					provider,
				);
				let sol_proof = IDepositsRollupBridge::Proof {
					proof: solidity_proof.proof,
					commitments: solidity_proof.commitments,
					commitmentPok: solidity_proof.commitment_pok,
				};

				// --- Pre-confirmBatch debug checks ---
				let batch_id_u256 = alloy::primitives::U256::from(batch_id);
				{
					match bridge.getBatchDebugInfo(batch_id_u256).call().await {
						Ok(info) => {
							let on_chain_hex = hex::encode(info.superPiCommitment.as_slice());
							let prover_hex = hex::encode(super_pi_commitment);
							let match_status = if on_chain_hex == prover_hex {
								"MATCH"
							} else {
								"MISMATCH"
							};
							info!(
								batch_id,
								on_chain_commitment = %on_chain_hex,
								prover_commitment = %prover_hex,
								status = match_status,
								"[DEBUG] commitment comparison"
							);
						},
						Err(e) => {
							warn!(
								batch_id,
								error = %e,
								"[DEBUG] getBatchDebugInfo call failed"
							);
						},
					}
				}

				let confirm_result: Result<_, anyhow::Error> = async {
					let receipt = bridge
						.confirmBatch(batch_id_u256, sol_proof)
						.send()
						.await
						.map_err(|e| {
							anyhow::anyhow!(
								"confirmBatch send failed: {}",
								humanize_bridge_revert(&e)
							)
						})?
						.with_required_confirmations(1)
						.with_timeout(Some(RECEIPT_TIMEOUT))
						.get_receipt()
						.await
						.map_err(|e| anyhow::anyhow!("confirmBatch receipt error: {e}"))?;
					anyhow::ensure!(
						receipt.status(),
						"confirmBatch reverted on-chain (batch_id={batch_id}, tx={:?})",
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
							"on-chain confirmBatch failed"
						);
						self.registered_pending_batches.remove(&batch_id);
						return Ok(());
					},
					Ok(receipt) => {
						info!(
							batch_id,
							tx_hash = ?receipt.transaction_hash,
							"batch confirmed on-chain"
						);
					},
				}

				let batch = self
					.registered_pending_batches
					.remove(&batch_id)
					.expect("batch was present above");

				// Commit all four trees' WAL entries now that on-chain confirmation succeeded.
				commit_tree_batch(
					&self.notes_commitment_state,
					&mut self.notes_commitment_store,
					&mut self.notes_commitment_meta,
					batch.nc_padded,
				)?;
				commit_tree_batch(
					&self.notes_nullifier_state,
					&mut self.notes_nullifier_store,
					&mut self.notes_nullifier_meta,
					batch.nn_padded,
				)?;
				commit_tree_batch(
					&self.accounts_commitment_state,
					&mut self.accounts_commitment_store,
					&mut self.accounts_commitment_meta,
					batch.ac_padded,
				)?;
				commit_tree_batch(
					&self.accounts_nullifier_state,
					&mut self.accounts_nullifier_store,
					&mut self.accounts_nullifier_meta,
					batch.an_padded,
				)?;

				self.log_pool_status("batch confirmed and committed locally");
			},
		}
		Ok(())
	}
}
