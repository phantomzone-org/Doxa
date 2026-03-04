use alloy::primitives::FixedBytes;
use tracing::{debug, info, warn};

use super::*;
use crate::sequencer::{recovery::commit_tree_batch, revert::humanize_bridge_revert};

impl Sequencer {
	/// Submit a prove request to the remote prover with unlimited exponential-backoff retries.
	///
	/// Spawns a Tokio task that loops, calling the HTTP prover client.  On success the
	/// [`ProveOutcome`] is forwarded through `result_tx`.  On failure the task sleeps 5 s
	/// and retries; it exits early if `result_tx` is closed (sequencer shutdown).
	///
	/// # Parameters
	/// - `request`: the fully assembled [`ProveRequest`] to send.
	///
	/// # Returns
	/// `Ok(())` once the task has been spawned (not once proving completes).
	///
	/// # Errors
	/// Returns `Err` immediately if the prover client or result channel has not been
	/// initialised on `self`.
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

	/// Query the bridge contract and return `true` if `note` can be consumed as a
	/// nullifier (status is `Validated` or `None`).
	pub(super) async fn is_note_validated<P: Provider + Clone>(
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
					IDepositsRollupBridge::DepositStatus::Validated
						| IDepositsRollupBridge::DepositStatus::None
				)
			},
			Err(e) => {
				warn!("failed to fetch note status: {e}");
				false
			},
		}
	}

	/// Evaluate all four pending queues and start a batch when any is ready.
	///
	/// A queue is "ready" when [`should_flush_pool`] returns `true`.
	/// When any queue is ready, a unified batch covering all four trees is started:
	/// real leaves from the ready queues, dummy-padded leaves for the others.
	///
	/// Returns immediately if the pending-batch registry is at capacity.
	pub(super) async fn maybe_start_next_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
		note_batch_size: usize,
		account_batch_size: usize,
		batch_timeout: std::time::Duration,
	) -> anyhow::Result<()> {
		if self.registered_pending_batches.len() >= MAX_PENDING_BATCHES {
			return Ok(());
		}
		self.refresh_pending_timers();
		self.log_pool_status("batch scheduling tick");

		let any_ready = Self::should_flush_pool(
			self.notes_commitment_state.pending_requests.len(),
			note_batch_size,
			self.notes_commitment_pending_since,
			batch_timeout,
		) || Self::should_flush_pool(
			self.notes_nullifier_state.pending_requests.len(),
			note_batch_size,
			self.notes_nullifier_pending_since,
			batch_timeout,
		) || Self::should_flush_pool(
			self.accounts_commitment_state.pending_requests.len(),
			account_batch_size,
			self.accounts_commitment_pending_since,
			batch_timeout,
		) || Self::should_flush_pool(
			self.accounts_nullifier_state.pending_requests.len(),
			account_batch_size,
			self.accounts_nullifier_pending_since,
			batch_timeout,
		);

		if any_ready {
			self.start_batch(provider, note_batch_size, account_batch_size)
				.await?;
		}
		Ok(())
	}

	/// Decide whether a pending queue should be flushed immediately.
	///
	/// Returns `true` if:
	/// - `pending_len >= batch_size` (queue is full), **or**
	/// - `pending_len > 0` and the queue has been waiting since `pending_since` for at least
	///   `batch_timeout`.
	///
	/// Returns `false` if `pending_len == 0` regardless of the other parameters.
	fn should_flush_pool(
		pending_len: usize,
		batch_size: usize,
		pending_since: Option<std::time::Instant>,
		batch_timeout: std::time::Duration,
	) -> bool {
		if pending_len == 0 {
			return false;
		}
		if pending_len >= batch_size {
			return true;
		}
		pending_since
			.map(|since| since.elapsed() >= batch_timeout)
			.unwrap_or(false)
	}

	/// Start a unified batch covering all four trees simultaneously.
	///
	/// Steps:
	/// 1. Pop up to `batch_size` real leaves from each pending queue (empty = all dummies).
	/// 2. Preflight: verify all four on-chain roots match local state.
	/// 3. Validate deposit status for real NC/NN leaves; check AC membership for AN leaves.
	/// 4. Pad each tree to its batch_size with deterministic dummy leaves.
	/// 5. Compute native batch proofs from tree clones.
	/// 6. Call `registerTransactionBatchUpdate` on-chain; extract the assigned `batchId`.
	/// 7. Apply padded inserts to the real local trees (advance roots for subsequent batches).
	/// 8. Submit a single [`ProveRequest`] via [`submit_prove_request_with_retry`].
	/// 9. Store a [`TxBatch`] record in `registered_pending_batches`.
	///
	/// # Errors
	/// Returns `Err` on root mismatch, invalid leaf status, native proof failure, or
	/// on-chain registration failure.
	///
	/// # Side effects
	/// Mutates all four tree states (pops from pending queues; advances tree roots).
	/// Spawns an async prove task.
	async fn start_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
		note_batch_size: usize,
		account_batch_size: usize,
	) -> anyhow::Result<()> {
		let bridge = IDepositsRollupBridge::IDepositsRollupBridgeInstance::new(
			self.config.bridge_address,
			provider,
		);
		debug!(
			nc_pending = self.notes_commitment_state.pending_requests.len(),
			nn_pending = self.notes_nullifier_state.pending_requests.len(),
			ac_pending = self.accounts_commitment_state.pending_requests.len(),
			an_pending = self.accounts_nullifier_state.pending_requests.len(),
			"starting unified batch preflight"
		);

		// 1. Pop from all queues (empty vec if none available).
		let nc_requests = self
			.notes_commitment_state
			.pop_next_up_to(note_batch_size)
			.unwrap_or_default();
		let nn_requests = self
			.notes_nullifier_state
			.pop_next_up_to(note_batch_size)
			.unwrap_or_default();
		let ac_requests = self
			.accounts_commitment_state
			.pop_next_up_to(account_batch_size)
			.unwrap_or_default();
		let an_requests = self
			.accounts_nullifier_state
			.pop_next_up_to(account_batch_size)
			.unwrap_or_default();
		self.refresh_pending_timers();

		// 2. Preflight: all four on-chain roots must match local state.
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

		// 3. Per-leaf validation for real leaves.
		for req in &nc_requests {
			let note = FixedBytes::<32>::from(req.commitment);
			let status =
				bridge.getDepositStatus(note).call().await.map_err(|e| {
					anyhow::anyhow!("preflight: failed to fetch NC note status: {e}")
				})?;
			anyhow::ensure!(
				matches!(
					status,
					IDepositsRollupBridge::DepositStatus::Pending
						| IDepositsRollupBridge::DepositStatus::None
				),
				"preflight failed: NC note {:?} not Pending/None",
				note
			);
		}
		for req in &nn_requests {
			let note = FixedBytes::<32>::from(req.commitment);
			let status =
				bridge.getDepositStatus(note).call().await.map_err(|e| {
					anyhow::anyhow!("preflight: failed to fetch NN note status: {e}")
				})?;
			anyhow::ensure!(
				matches!(
					status,
					IDepositsRollupBridge::DepositStatus::Validated
						| IDepositsRollupBridge::DepositStatus::None
				),
				"preflight failed: NN note {:?} not Validated/None",
				note
			);
		}
		for req in &an_requests {
			let commitment_hash =
				contract::bytes32_to_hash(&alloy::primitives::B256::from(req.commitment))?;
			anyhow::ensure!(
				self.accounts_commitment_state
					.tree
					.contains_leaf(&commitment_hash),
				"preflight failed: AN leaf {:?} not found in accounts commitment tree",
				alloy::primitives::B256::from(req.commitment)
			);
		}

		// 4 & 5. Build padded batches and compute native proofs.
		let nc_real: Vec<[u8; 32]> = nc_requests.iter().map(|r| r.commitment).collect();
		let nc_start = self.notes_commitment_state.tree.num_leaves();
		let (nc_padded_bytes, nc_hashes) = build_proving_commitments(
			DummyTreeType::NotesCommitment,
			nc_start,
			note_batch_size,
			&nc_real,
		)?;
		let mut nc_tmp = self.notes_commitment_state.tree.clone();
		let nc_proof = nc_tmp.insert_batch(nc_hashes.clone())?;
		anyhow::ensure!(nc_proof.verify(), "NC native proof verification failed");

		let nn_real: Vec<[u8; 32]> = nn_requests.iter().map(|r| r.commitment).collect();
		let nn_start = self.notes_nullifier_state.tree.num_leaves();
		let (nn_padded_bytes, nn_hashes) = build_proving_commitments(
			DummyTreeType::NotesNullifier,
			nn_start,
			note_batch_size,
			&nn_real,
		)?;
		let mut nn_tmp = self.notes_nullifier_state.tree.clone();
		let nn_proof = nn_tmp.insert_chained(nn_hashes.clone())?;
		anyhow::ensure!(nn_proof.verify(), "NN native proof verification failed");

		let ac_real: Vec<[u8; 32]> = ac_requests.iter().map(|r| r.commitment).collect();
		let ac_start = self.accounts_commitment_state.tree.num_leaves();
		let (ac_padded_bytes, ac_hashes) = build_proving_commitments(
			DummyTreeType::AccountsCommitment,
			ac_start,
			account_batch_size,
			&ac_real,
		)?;
		let mut ac_tmp = self.accounts_commitment_state.tree.clone();
		let ac_proof = ac_tmp.insert_batch(ac_hashes.clone())?;
		anyhow::ensure!(ac_proof.verify(), "AC native proof verification failed");

		let an_real: Vec<[u8; 32]> = an_requests.iter().map(|r| r.commitment).collect();
		let an_start = self.accounts_nullifier_state.tree.num_leaves();
		let (an_padded_bytes, an_hashes) = build_proving_commitments(
			DummyTreeType::AccountsNullifier,
			an_start,
			account_batch_size,
			&an_real,
		)?;
		let mut an_tmp = self.accounts_nullifier_state.tree.clone();
		let an_proof = an_tmp.insert_chained(an_hashes.clone())?;
		anyhow::ensure!(an_proof.verify(), "AN native proof verification failed");

		let new_nc_root = contract::hash_to_bytes32(&nc_proof.root_new);
		let new_nn_root = contract::hash_to_bytes32(
			&nn_proof
				.proofs
				.last()
				.ok_or_else(|| anyhow::anyhow!("NN proof is empty"))?
				.new_root,
		);
		let new_ac_root = contract::hash_to_bytes32(&ac_proof.root_new);
		let new_an_root = contract::hash_to_bytes32(
			&an_proof
				.proofs
				.last()
				.ok_or_else(|| anyhow::anyhow!("AN proof is empty"))?
				.new_root,
		);

		let nc_out: Vec<FixedBytes<32>> =
			nc_real.iter().map(|b| FixedBytes::<32>::from(*b)).collect();
		let nn_in: Vec<FixedBytes<32>> =
			nn_real.iter().map(|b| FixedBytes::<32>::from(*b)).collect();
		let ac_out: Vec<FixedBytes<32>> =
			ac_real.iter().map(|b| FixedBytes::<32>::from(*b)).collect();
		let an_in: Vec<FixedBytes<32>> =
			an_real.iter().map(|b| FixedBytes::<32>::from(*b)).collect();
		// 6. Register on-chain.
		let pending = bridge
			.registerTransactionBatchUpdate(
				new_nc_root,
				nc_out,
				new_nn_root,
				nn_in,
				new_ac_root,
				ac_out,
				new_an_root,
				an_in,
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
			nc_leaves = nc_real.len(),
			nn_leaves = nn_real.len(),
			ac_leaves = ac_real.len(),
			an_leaves = an_real.len(),
			"batch registered on-chain"
		);

		// 7. Apply inserts to real local trees (advance roots for subsequent batches).
		self.notes_commitment_state
			.tree
			.insert_batch(nc_hashes.clone())?;
		self.notes_nullifier_state
			.tree
			.insert_chained(nn_hashes.clone())?;
		self.accounts_commitment_state
			.tree
			.insert_batch(ac_hashes.clone())?;
		self.accounts_nullifier_state
			.tree
			.insert_chained(an_hashes.clone())?;

		// 8. Submit single ProveRequest.
		self.submit_prove_request_with_retry(crate::types::ProveRequest {
			batch_id,
			notes_commitment_proof: nc_proof,
			notes_nullifier_proof: nn_proof,
			accounts_commitment_proof: ac_proof,
			accounts_nullifier_proof: an_proof,
			associated_tx_proofs: vec![DUMMY_ASSOCIATED_INPUT_PROOF.to_vec(); account_batch_size],
		})?;

		// 9. Store TxBatch in the pending map.
		self.registered_pending_batches.insert(
			batch_id,
			TxBatch {
				batch_id,
				nc_requests,
				nn_requests,
				ac_requests,
				an_requests,
				nc_batch: TxPerTreeBatch {
					real_commitments_bytes: nc_real,
					proving_commitments_bytes: nc_padded_bytes,
					proving_commitments_hash: nc_hashes,
				},
				nn_batch: TxPerTreeBatch {
					real_commitments_bytes: nn_real,
					proving_commitments_bytes: nn_padded_bytes,
					proving_commitments_hash: nn_hashes,
				},
				ac_batch: TxPerTreeBatch {
					real_commitments_bytes: ac_real,
					proving_commitments_bytes: ac_padded_bytes,
					proving_commitments_hash: ac_hashes,
				},
				an_batch: TxPerTreeBatch {
					real_commitments_bytes: an_real,
					proving_commitments_bytes: an_padded_bytes,
					proving_commitments_hash: an_hashes,
				},
			},
		);
		self.log_pool_status("batch moved to pending");
		Ok(())
	}

	/// Process a completed [`ProveOutcome`] from the remote prover.
	///
	/// Routes all outcomes to [`confirm_tx_batch`].
	///
	/// # Errors
	/// Propagates any error from [`confirm_tx_batch`].
	pub(super) async fn handle_prove_outcome<P: Provider + Clone>(
		&mut self,
		provider: &P,
		outcome: ProveOutcome,
	) -> anyhow::Result<()> {
		self.confirm_tx_batch(provider, outcome).await
	}

	/// Confirm a registered batch by verifying the SuperAggregator Groth16 proof on-chain.
	///
	/// On **Failure**: re-queues the batch's pending requests into their respective pools
	/// and removes the batch from `registered_pending_batches`.
	///
	/// On **Success**:
	/// 1. Calls `confirmBatch` on-chain with the Groth16 proof.
	/// 2. Commits all four trees' padded batches to their WAL/snapshot stores.
	/// 3. Removes the batch from `registered_pending_batches`.
	///
	/// # Errors
	/// Returns `Err` on fatal conditions (on-chain revert, local store failure).
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
					"prover failure for batch; re-queueing requests"
				);
				if let Some(batch) = self.registered_pending_batches.remove(&batch_id) {
					self.notes_commitment_state
						.reinsert_batch(batch.nc_requests);
					self.notes_nullifier_state.reinsert_batch(batch.nn_requests);
					self.accounts_commitment_state
						.reinsert_batch(batch.ac_requests);
					self.accounts_nullifier_state
						.reinsert_batch(batch.an_requests);
				}
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
					// Step 1: Query on-chain stored commitment for this batch.
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
								"[DEBUG] Step 1: commitment comparison"
							);
							// Log derived public inputs
							let pub_inputs_hex: Vec<String> = info
								.pubInputs
								.iter()
								.map(|v| format!("{:#010x}", v.as_limbs()[0] as u32))
								.collect();
							info!(
								batch_id,
								pub_inputs = ?pub_inputs_hex,
								"[DEBUG] Step 2: derived pubInputs from on-chain commitment"
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

					// Step 3: Dry-run verifier with on-chain stored commitment.
					let on_chain_commitment = alloy::primitives::FixedBytes::from(
						<[u8; 32]>::try_from(
							bridge
								.getBatchDebugInfo(batch_id_u256)
								.call()
								.await
								.map(|r| r.superPiCommitment.0.to_vec())
								.unwrap_or_default()
								.as_slice(),
						)
						.unwrap_or([0u8; 32]),
					);
					match bridge
						.verifyProofDry(on_chain_commitment, sol_proof.clone())
						.call()
						.await
					{
						Ok(result) => {
							info!(
								batch_id,
								verifier_accepts = result,
								"[DEBUG] Step 3: dry-run verifier with ON-CHAIN commitment"
							);
						},
						Err(e) => {
							warn!(
								batch_id,
								error = %e,
								"[DEBUG] Step 3: verifyProofDry (on-chain commitment) call failed"
							);
						},
					}

					// Step 4: Dry-run verifier with prover's own commitment.
					let prover_commitment =
						alloy::primitives::FixedBytes::from(super_pi_commitment);
					match bridge
						.verifyProofDry(prover_commitment, sol_proof.clone())
						.call()
						.await
					{
						Ok(result) => {
							info!(
								batch_id,
								verifier_accepts = result,
								"[DEBUG] Step 4: dry-run verifier with PROVER commitment"
							);
						},
						Err(e) => {
							warn!(
								batch_id,
								error = %e,
								"[DEBUG] Step 4: verifyProofDry (prover commitment) call failed"
							);
						},
					}
				}

				let receipt = bridge
					.confirmBatch(batch_id_u256, sol_proof)
					.send()
					.await
					.map_err(|e| {
						anyhow::anyhow!("confirmBatch send failed: {}", humanize_bridge_revert(&e))
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
				info!(
					batch_id,
					tx_hash = ?receipt.transaction_hash,
					"batch confirmed on-chain"
				);

				let batch = self
					.registered_pending_batches
					.remove(&batch_id)
					.expect("batch was present above");

				// Commit all four trees' WAL entries now that on-chain confirmation succeeded.
				// Note: the trees were already advanced (insert_batch / insert_chained) at
				// registration time; here we only persist to the WAL/snapshot store.
				commit_tree_batch(
					&self.notes_commitment_state,
					&mut self.notes_commitment_store,
					&mut self.notes_commitment_meta,
					batch.nc_batch.proving_commitments_bytes,
				)?;
				commit_tree_batch(
					&self.notes_nullifier_state,
					&mut self.notes_nullifier_store,
					&mut self.notes_nullifier_meta,
					batch.nn_batch.proving_commitments_bytes,
				)?;
				commit_tree_batch(
					&self.accounts_commitment_state,
					&mut self.accounts_commitment_store,
					&mut self.accounts_commitment_meta,
					batch.ac_batch.proving_commitments_bytes,
				)?;
				commit_tree_batch(
					&self.accounts_nullifier_state,
					&mut self.accounts_nullifier_store,
					&mut self.accounts_nullifier_meta,
					batch.an_batch.proving_commitments_bytes,
				)?;

				self.log_pool_status("batch confirmed and committed locally");
			},
		}
		Ok(())
	}

	/// Register a private transaction as an optimistic two-phase batch.
	///
	/// Steps:
	/// 1. Guard against a full pending-batch queue.
	/// 2. For each of the four trees: pad real leaves to `batch_size` and compute the native batch
	///    proof from a tree clone.
	/// 3. Call `registerTransactionBatchUpdate` on-chain; extract the assigned `batchId`.
	/// 4. Apply the padded inserts to the real local trees.
	/// 5. Submit a single [`ProveRequest`] containing all four tree proofs and the TX leaf proofs.
	/// 6. Store a [`TxBatch`] record.
	#[allow(clippy::too_many_arguments)]
	pub(super) async fn register_tx_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
		request: PrivateTxRequest,
		note_batch_size: usize,
		account_batch_size: usize,
	) -> anyhow::Result<()> {
		if self.registered_pending_batches.len() >= MAX_PENDING_BATCHES {
			warn!(
				tx_id = request.tx_id.as_deref().unwrap_or("unknown"),
				"optimistic register queue full; dropping private tx"
			);
			return Err(anyhow::anyhow!("PendingQueueFull"));
		}
		let tx_id = request.tx_id.clone().unwrap_or_else(|| "unknown".into());
		debug!(tx_id = %tx_id, "starting optimistic register for private tx");

		// --- Notes Commitment ---
		let nc_real = request.output_notes;
		let (nc_padded, nc_hashes) = build_proving_commitments(
			DummyTreeType::NotesCommitment,
			self.notes_commitment_state.tree.num_leaves(),
			note_batch_size,
			&nc_real,
		)?;
		let mut nc_tmp = self.notes_commitment_state.tree.clone();
		let nc_proof = nc_tmp.insert_batch(nc_hashes.clone())?;
		anyhow::ensure!(nc_proof.verify(), "NC native proof failed (private tx)");

		// --- Notes Nullifier ---
		let nn_real = request.input_notes;
		let (nn_padded, nn_hashes) = build_proving_commitments(
			DummyTreeType::NotesNullifier,
			self.notes_nullifier_state.tree.num_leaves(),
			note_batch_size,
			&nn_real,
		)?;
		let mut nn_tmp = self.notes_nullifier_state.tree.clone();
		let nn_proof = nn_tmp.insert_chained(nn_hashes.clone())?;
		anyhow::ensure!(nn_proof.verify(), "NN native proof failed (private tx)");
		let new_nn_root = contract::hash_to_bytes32(
			&nn_proof
				.proofs
				.last()
				.ok_or_else(|| anyhow::anyhow!("NN proof is empty"))?
				.new_root,
		);

		// --- Accounts Commitment ---
		let ac_real = vec![request.output_account_leaf];
		let (ac_padded, ac_hashes) = build_proving_commitments(
			DummyTreeType::AccountsCommitment,
			self.accounts_commitment_state.tree.num_leaves(),
			account_batch_size,
			&ac_real,
		)?;
		let mut ac_tmp = self.accounts_commitment_state.tree.clone();
		let ac_proof = ac_tmp.insert_batch(ac_hashes.clone())?;
		anyhow::ensure!(ac_proof.verify(), "AC native proof failed (private tx)");

		// --- Accounts Nullifier ---
		let an_real = vec![request.input_account_leaf];
		let (an_padded, an_hashes) = build_proving_commitments(
			DummyTreeType::AccountsNullifier,
			self.accounts_nullifier_state.tree.num_leaves(),
			account_batch_size,
			&an_real,
		)?;
		let mut an_tmp = self.accounts_nullifier_state.tree.clone();
		let an_proof = an_tmp.insert_chained(an_hashes.clone())?;
		anyhow::ensure!(an_proof.verify(), "AN native proof failed (private tx)");
		let new_an_root = contract::hash_to_bytes32(
			&an_proof
				.proofs
				.last()
				.ok_or_else(|| anyhow::anyhow!("AN proof is empty"))?
				.new_root,
		);

		let new_nc_root = contract::hash_to_bytes32(&nc_proof.root_new);
		let new_ac_root = contract::hash_to_bytes32(&ac_proof.root_new);

		// Build calldata arrays.
		let nc_out: Vec<FixedBytes<32>> =
			nc_real.iter().map(|b| FixedBytes::<32>::from(*b)).collect();
		let nn_in: Vec<FixedBytes<32>> =
			nn_real.iter().map(|b| FixedBytes::<32>::from(*b)).collect();
		let ac_out: Vec<FixedBytes<32>> =
			ac_real.iter().map(|b| FixedBytes::<32>::from(*b)).collect();
		let an_in: Vec<FixedBytes<32>> =
			an_real.iter().map(|b| FixedBytes::<32>::from(*b)).collect();
		// Register on-chain.
		let bridge = IDepositsRollupBridge::IDepositsRollupBridgeInstance::new(
			self.config.bridge_address,
			provider,
		);
		let pending = bridge
			.registerTransactionBatchUpdate(
				new_nc_root,
				nc_out,
				new_nn_root,
				nn_in,
				new_ac_root,
				ac_out,
				new_an_root,
				an_in,
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
			tx_id = %tx_id,
			batch_id,
			nc_root = ?new_nc_root,
			nn_root = ?new_nn_root,
			ac_root = ?new_ac_root,
			an_root = ?new_an_root,
			"private tx batch registered on-chain"
		);

		// Apply inserts to real local trees.
		self.notes_commitment_state
			.tree
			.insert_batch(nc_hashes.clone())?;
		self.notes_nullifier_state
			.tree
			.insert_chained(nn_hashes.clone())?;
		self.accounts_commitment_state
			.tree
			.insert_batch(ac_hashes.clone())?;
		self.accounts_nullifier_state
			.tree
			.insert_chained(an_hashes.clone())?;

		// Build and submit single ProveRequest.
		// TX leaf proofs: place the real tx_proof in the active slots, dummy elsewhere.
		let n_active = nc_real
			.len()
			.div_ceil(8)
			.max(nn_real.len().div_ceil(8))
			.max(1);
		let mut associated_tx_proofs = vec![request.tx_proof; n_active];
		associated_tx_proofs.resize(account_batch_size, DUMMY_ASSOCIATED_INPUT_PROOF.to_vec());

		self.submit_prove_request_with_retry(crate::types::ProveRequest {
			batch_id,
			notes_commitment_proof: nc_proof,
			notes_nullifier_proof: nn_proof,
			accounts_commitment_proof: ac_proof,
			accounts_nullifier_proof: an_proof,
			associated_tx_proofs,
		})?;

		// Store TxBatch.
		self.registered_pending_batches.insert(
			batch_id,
			TxBatch {
				batch_id,
				nc_requests: vec![],
				nn_requests: vec![],
				ac_requests: vec![],
				an_requests: vec![],
				nc_batch: TxPerTreeBatch {
					real_commitments_bytes: nc_real,
					proving_commitments_bytes: nc_padded,
					proving_commitments_hash: nc_hashes,
				},
				nn_batch: TxPerTreeBatch {
					real_commitments_bytes: nn_real,
					proving_commitments_bytes: nn_padded,
					proving_commitments_hash: nn_hashes,
				},
				ac_batch: TxPerTreeBatch {
					real_commitments_bytes: ac_real,
					proving_commitments_bytes: ac_padded,
					proving_commitments_hash: ac_hashes,
				},
				an_batch: TxPerTreeBatch {
					real_commitments_bytes: an_real,
					proving_commitments_bytes: an_padded,
					proving_commitments_hash: an_hashes,
				},
			},
		);
		info!(
			batch_id,
			queue = self.registered_pending_batches.len(),
			"prove job submitted for registered private-tx batch"
		);
		Ok(())
	}
}
