use super::*;
use crate::sequencer::revert::humanize_bridge_revert;
use tracing::{debug, info, warn};

impl Sequencer {
	fn submit_prove_request_with_retry(
		&self,
		request: crate::types::ProveRequest,
		job: TreeJob,
	) -> anyhow::Result<()> {
		let Some(client) = self.prover_client.clone() else {
			return Err(anyhow::anyhow!("prover client not initialized"));
		};
		let Some(result_tx) = self.result_tx.clone() else {
			return Err(anyhow::anyhow!("prover result channel not initialized"));
		};

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
							job = ?job,
							attempts,
							error = %e,
							"prover unavailable; keeping batch pending and retrying"
						);
						// Sleep before retrying, but exit immediately if the sequencer
						// shuts down (result_rx dropped → channel closed).
						tokio::select! {
							_ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {},
							_ = result_tx.closed() => {
								warn!(job = ?job, "sequencer shutting down; abandoning prover retry");
								break;
							},
						}
					},
				}
			}
		});
		Ok(())
	}

	pub(super) async fn is_note_available<P: Provider + Clone>(&self, provider: &P, note: &[u8; 32]) -> bool {
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
			}
		}
	}

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
			}
		}
	}

	pub(super) async fn maybe_start_next_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
		batch_size: usize,
		in_flight: &mut Option<InFlightBatch>,
	) -> anyhow::Result<()> {
		if in_flight.is_some() {
			return Ok(());
		}
		self.log_pool_status("batch scheduling tick");

		if self.notes_commitment_state.pending_requests.len() >= batch_size {
			return self.start_notes_commitment_batch(provider, batch_size, in_flight).await;
		}
		if self.notes_nullifier_state.pending_requests.len() >= batch_size {
			return self.start_notes_nullifier_batch(provider, batch_size, in_flight).await;
		}
		if self.accounts_commitment_state.pending_requests.len() >= batch_size {
			return self
				.start_accounts_commitment_batch(provider, batch_size, in_flight)
				.await;
		}
		if self.accounts_nullifier_state.pending_requests.len() >= batch_size {
			return self
				.start_accounts_nullifier_batch(provider, batch_size, in_flight)
				.await;
		}
		Ok(())
	}

	async fn start_notes_commitment_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
		batch_size: usize,
		in_flight: &mut Option<InFlightBatch>,
	) -> anyhow::Result<()> {
		let bridge = IDepositsRollupBridge::IDepositsRollupBridgeInstance::new(
			self.config.bridge_address,
			provider,
		);
		debug!(
			pending = self.notes_commitment_state.pending_requests.len(),
			batch_size,
			"starting notes commitment batch preflight"
		);

		let batch = self
			.notes_commitment_state
			.pop_next_batch(batch_size)
			.ok_or_else(|| anyhow::anyhow!("batch requested but pending queue had insufficient size"))?;

		let on_chain_root = bridge.notesCommitmentRoot().call().await?;
		let local_root = contract::hash_to_bytes32(&self.notes_commitment_state.current_root());
		anyhow::ensure!(
			on_chain_root == local_root,
			"preflight failed: notesCommitmentRoot mismatch (on-chain={on_chain_root:?}, local={local_root:?})"
		);

		for req in &batch {
			let note = alloy::primitives::FixedBytes::<32>::from(req.commitment);
			let status = bridge
				.getDepositStatus(note)
				.call()
				.await
				.map_err(|e| anyhow::anyhow!("preflight failed: unable to fetch note status: {e}"))?;
			anyhow::ensure!(
				matches!(
					status,
					IDepositsRollupBridge::DepositStatus::Pending
						| IDepositsRollupBridge::DepositStatus::None
				),
				"preflight failed: existing bridge note not Pending/None"
			);
		}
		debug!(
			batch = batch.len(),
			on_chain_root = ?on_chain_root,
			local_root = ?local_root,
			"notes commitment preflight passed"
		);

		let commitments_bytes: Vec<[u8; 32]> = batch.iter().map(|r| r.commitment).collect();
		let commitments_hash: Vec<Hash> = contract::bytes_slice_to_hashes(&commitments_bytes)?;

		let mut tmp_tree = self.notes_commitment_state.tree.clone();
		let batch_proof = tmp_tree.insert_batch(commitments_hash.clone())?;
		anyhow::ensure!(batch_proof.verify(), "native commitment proof verification failed");

		self.submit_prove_request_with_retry(
			crate::types::ProveRequest::Commitment { batch_proof },
			TreeJob::NotesCommitment,
		)?;

		*in_flight = Some(InFlightBatch {
			job: TreeJob::NotesCommitment,
			requests: batch,
			commitments_bytes,
			commitments_hash,
		});
		info!(batch_size, "notes commitment batch sent to prover");
		self.log_pool_status("notes commitment batch moved in-flight");
		Ok(())
	}

	async fn start_notes_nullifier_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
		batch_size: usize,
		in_flight: &mut Option<InFlightBatch>,
	) -> anyhow::Result<()> {
		let bridge = IDepositsRollupBridge::IDepositsRollupBridgeInstance::new(
			self.config.bridge_address,
			provider,
		);
		debug!(
			pending = self.notes_nullifier_state.pending_requests.len(),
			batch_size,
			"starting notes nullifier batch preflight"
		);

		let batch = self
			.notes_nullifier_state
			.pop_next_batch(batch_size)
			.ok_or_else(|| anyhow::anyhow!("batch requested but pending queue had insufficient size"))?;

		let on_chain_root = bridge.notesNullifierRoot().call().await?;
		let local_root = contract::hash_to_bytes32(&self.notes_nullifier_state.current_root());
		anyhow::ensure!(
			on_chain_root == local_root,
			"preflight failed: notesNullifierRoot mismatch (on-chain={on_chain_root:?}, local={local_root:?})"
		);

		for req in &batch {
			let note = alloy::primitives::FixedBytes::<32>::from(req.commitment);
			let status = bridge
				.getDepositStatus(note)
				.call()
				.await
				.map_err(|e| anyhow::anyhow!("preflight failed: unable to fetch note status: {e}"))?;
			anyhow::ensure!(
				matches!(
					status,
					IDepositsRollupBridge::DepositStatus::Validated
						| IDepositsRollupBridge::DepositStatus::None
				),
				"preflight failed: existing bridge note not Validated/None"
			);
		}
		debug!(
			batch = batch.len(),
			on_chain_root = ?on_chain_root,
			local_root = ?local_root,
			"notes nullifier preflight passed"
		);

		let commitments_bytes: Vec<[u8; 32]> = batch.iter().map(|r| r.commitment).collect();
		let commitments_hash: Vec<Hash> = contract::bytes_slice_to_hashes(&commitments_bytes)?;

		let mut tmp_tree = self.notes_nullifier_state.tree.clone();
		let batch_proof = tmp_tree.insert_chained(commitments_hash.clone())?;
		anyhow::ensure!(batch_proof.verify(), "native nullifier proof verification failed");

		self.submit_prove_request_with_retry(
			crate::types::ProveRequest::Nullifier { batch_proof },
			TreeJob::NotesNullifier,
		)?;

		*in_flight = Some(InFlightBatch {
			job: TreeJob::NotesNullifier,
			requests: batch,
			commitments_bytes,
			commitments_hash,
		});
		info!(batch_size, "notes nullifier batch sent to prover");
		self.log_pool_status("notes nullifier batch moved in-flight");
		Ok(())
	}

	async fn start_accounts_commitment_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
		batch_size: usize,
		in_flight: &mut Option<InFlightBatch>,
	) -> anyhow::Result<()> {
		let bridge = IDepositsRollupBridge::IDepositsRollupBridgeInstance::new(
			self.config.bridge_address,
			provider,
		);
		debug!(
			pending = self.accounts_commitment_state.pending_requests.len(),
			batch_size,
			"starting accounts commitment batch preflight"
		);

		let batch = self
			.accounts_commitment_state
			.pop_next_batch(batch_size)
			.ok_or_else(|| anyhow::anyhow!("batch requested but pending queue had insufficient size"))?;

		let on_chain_root = bridge.accountsCommitmentRoot().call().await?;
		let local_root = contract::hash_to_bytes32(&self.accounts_commitment_state.current_root());
		anyhow::ensure!(
			on_chain_root == local_root,
			"preflight failed: accountsCommitmentRoot mismatch (on-chain={on_chain_root:?}, local={local_root:?})"
		);

		let commitments_bytes: Vec<[u8; 32]> = batch.iter().map(|r| r.commitment).collect();
		debug!(
			batch = batch.len(),
			on_chain_root = ?on_chain_root,
			local_root = ?local_root,
			"accounts commitment preflight passed"
		);
		let commitments_hash: Vec<Hash> = contract::bytes_slice_to_hashes(&commitments_bytes)?;

		let mut tmp_tree = self.accounts_commitment_state.tree.clone();
		let batch_proof = tmp_tree.insert_batch(commitments_hash.clone())?;
		anyhow::ensure!(batch_proof.verify(), "native commitment proof verification failed");

		self.submit_prove_request_with_retry(
			crate::types::ProveRequest::Commitment { batch_proof },
			TreeJob::AccountsCommitment,
		)?;

		*in_flight = Some(InFlightBatch {
			job: TreeJob::AccountsCommitment,
			requests: batch,
			commitments_bytes,
			commitments_hash,
		});
		info!(batch_size, "accounts commitment batch sent to prover");
		self.log_pool_status("accounts commitment batch moved in-flight");
		Ok(())
	}

	async fn start_accounts_nullifier_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
		batch_size: usize,
		in_flight: &mut Option<InFlightBatch>,
	) -> anyhow::Result<()> {
		let bridge = IDepositsRollupBridge::IDepositsRollupBridgeInstance::new(
			self.config.bridge_address,
			provider,
		);
		debug!(
			pending = self.accounts_nullifier_state.pending_requests.len(),
			batch_size,
			"starting accounts nullifier batch preflight"
		);

		let batch = self
			.accounts_nullifier_state
			.pop_next_batch(batch_size)
			.ok_or_else(|| anyhow::anyhow!("batch requested but pending queue had insufficient size"))?;

		let on_chain_root = bridge.accountsNullifierRoot().call().await?;
		let local_root = contract::hash_to_bytes32(&self.accounts_nullifier_state.current_root());
		anyhow::ensure!(
			on_chain_root == local_root,
			"preflight failed: accountsNullifierRoot mismatch (on-chain={on_chain_root:?}, local={local_root:?})"
		);

		// Verify each leaf-to-be-nullified was previously committed to the accounts commitment tree.
		for req in &batch {
			let commitment_hash =
				contract::bytes32_to_hash(&alloy::primitives::B256::from(req.commitment))?;
			anyhow::ensure!(
				self.accounts_commitment_state.tree.contains_leaf(&commitment_hash),
				"preflight failed: accounts nullifier leaf {:?} not found in accounts commitment tree",
				alloy::primitives::B256::from(req.commitment)
			);
		}

		let commitments_bytes: Vec<[u8; 32]> = batch.iter().map(|r| r.commitment).collect();
		debug!(
			batch = batch.len(),
			on_chain_root = ?on_chain_root,
			local_root = ?local_root,
			"accounts nullifier preflight passed"
		);
		let commitments_hash: Vec<Hash> = contract::bytes_slice_to_hashes(&commitments_bytes)?;

		let mut tmp_tree = self.accounts_nullifier_state.tree.clone();
		let batch_proof = tmp_tree.insert_chained(commitments_hash.clone())?;
		anyhow::ensure!(batch_proof.verify(), "native nullifier proof verification failed");

		self.submit_prove_request_with_retry(
			crate::types::ProveRequest::Nullifier { batch_proof },
			TreeJob::AccountsNullifier,
		)?;

		*in_flight = Some(InFlightBatch {
			job: TreeJob::AccountsNullifier,
			requests: batch,
			commitments_bytes,
			commitments_hash,
		});
		info!(batch_size, "accounts nullifier batch sent to prover");
		self.log_pool_status("accounts nullifier batch moved in-flight");
		Ok(())
	}

	pub(super) async fn handle_prove_outcome<P: Provider + Clone>(
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
			ProveOutcome::Failure { error } => {
				warn!(job = ?batch.job, "prover returned failure, re-queueing batch");
				match batch.job {
					TreeJob::NotesCommitment => self.notes_commitment_state.reinsert_batch(batch.requests),
					TreeJob::NotesNullifier => self.notes_nullifier_state.reinsert_batch(batch.requests),
					TreeJob::AccountsCommitment => self.accounts_commitment_state.reinsert_batch(batch.requests),
					TreeJob::AccountsNullifier => self.accounts_nullifier_state.reinsert_batch(batch.requests),
				}
				warn!(job = ?batch.job, error, "proof generation failed; batch requeued");
				self.log_pool_status("batch requeued after prover failure");
				return Ok(());
			},
			ProveOutcome::Success { new_root, solidity_proof } => {
				info!(
					job = ?batch.job,
					requests = batch.requests.len(),
					"prover returned success"
				);
				let commitments_vec: Vec<alloy::primitives::FixedBytes<32>> = batch
					.commitments_bytes
					.iter()
					.map(|b| alloy::primitives::FixedBytes::<32>::from(*b))
					.collect();
				let sol_proof = IDepositsRollupBridge::Proof {
					proof: solidity_proof.proof,
					commitments: solidity_proof.commitments,
					commitmentPok: solidity_proof.commitment_pok,
				};
				let new_root_hash = new_root;
				let new_root_bytes = contract::hash_to_bytes32(&new_root_hash);
				// Phase A: PI-validity proof path is wired in the contract API, but
				// sequencer currently sends a dummy Groth16 proof and relies on the
				// dev dummy verifier contract for acceptance.
				let zero = alloy::primitives::U256::ZERO;
				let aggregated_input_proof = IDepositsRollupBridge::Proof {
					proof: [zero; 8],
					commitments: [zero; 2],
					commitmentPok: [zero; 2],
				};

				let receipt_result: anyhow::Result<_> = match batch.job {
					TreeJob::NotesCommitment => {
						let pending = bridge
							.recordNotesCommitmentTreeUpdate(
								new_root_bytes,
								commitments_vec,
								sol_proof,
								aggregated_input_proof.clone(),
							)
							.send()
							.await
							.map_err(|e| anyhow::anyhow!(
								"recordNotesCommitmentTreeUpdate reverted: {}",
								humanize_bridge_revert(&e)
							))?;
						pending
							.with_required_confirmations(1)
							.with_timeout(Some(RECEIPT_TIMEOUT))
							.get_receipt()
							.await
							.map_err(|e| anyhow::anyhow!("receipt timeout/error: {e}"))
					},
					TreeJob::NotesNullifier => {
						let pending = bridge
							.recordNotesNullifierTreeUpdate(
								new_root_bytes,
								commitments_vec,
								sol_proof,
								aggregated_input_proof.clone(),
							)
							.send()
							.await
							.map_err(|e| anyhow::anyhow!(
								"recordNotesNullifierTreeUpdate reverted: {}",
								humanize_bridge_revert(&e)
							))?;
						pending
							.with_required_confirmations(1)
							.with_timeout(Some(RECEIPT_TIMEOUT))
							.get_receipt()
							.await
							.map_err(|e| anyhow::anyhow!("receipt timeout/error: {e}"))
					},
					TreeJob::AccountsCommitment => {
						let pending = bridge
							.recordAccountsCommitmentTreeUpdate(
								new_root_bytes,
								commitments_vec,
								sol_proof,
								aggregated_input_proof.clone(),
							)
							.send()
							.await
							.map_err(|e| anyhow::anyhow!(
								"recordAccountsCommitmentTreeUpdate reverted: {}",
								humanize_bridge_revert(&e)
							))?;
						pending
							.with_required_confirmations(1)
							.with_timeout(Some(RECEIPT_TIMEOUT))
							.get_receipt()
							.await
							.map_err(|e| anyhow::anyhow!("receipt timeout/error: {e}"))
					},
					TreeJob::AccountsNullifier => {
						let pending = bridge
							.recordAccountsNullifierTreeUpdate(
								new_root_bytes,
								commitments_vec,
								sol_proof,
								aggregated_input_proof,
							)
							.send()
							.await
							.map_err(|e| anyhow::anyhow!(
								"recordAccountsNullifierTreeUpdate reverted: {}",
								humanize_bridge_revert(&e)
							))?;
						pending
							.with_required_confirmations(1)
							.with_timeout(Some(RECEIPT_TIMEOUT))
							.get_receipt()
							.await
							.map_err(|e| anyhow::anyhow!("receipt timeout/error: {e}"))
					},
				};
				// Receipt timeout/error is non-fatal: requeue the batch so it can be retried.
				// The tx may still be in flight; chain recovery on next startup will reconcile.
				let receipt = match receipt_result {
					Ok(r) => r,
					Err(e) => {
						warn!(
							job = ?batch.job,
							error = %e,
							"receipt polling failed; requeueing batch for retry"
						);
						match batch.job {
							TreeJob::NotesCommitment => self.notes_commitment_state.reinsert_batch(batch.requests),
							TreeJob::NotesNullifier => self.notes_nullifier_state.reinsert_batch(batch.requests),
							TreeJob::AccountsCommitment => self.accounts_commitment_state.reinsert_batch(batch.requests),
							TreeJob::AccountsNullifier => self.accounts_nullifier_state.reinsert_batch(batch.requests),
						}
						return Ok(());
					},
				};
				anyhow::ensure!(
					receipt.status(),
					"tree update reverted on-chain (tx_hash={:?})",
					receipt.transaction_hash
				);
				info!(
					tx_hash = ?receipt.transaction_hash,
					updated = batch.requests.len(),
					job = ?batch.job,
					"tree update confirmed"
				);

				match batch.job {
					TreeJob::NotesCommitment => {
						let proof_local = self.notes_commitment_state.tree.insert_batch(batch.commitments_hash)?;
						anyhow::ensure!(proof_local.root_new == new_root_hash, "local root mismatch after confirm");
						if let (Some(store), Some(meta)) = (
							self.notes_commitment_store.as_mut(),
							self.notes_commitment_meta.as_mut(),
						) {
							store.commit_batch(&self.notes_commitment_state.tree, meta, batch.commitments_bytes)?;
						}
					},
					TreeJob::NotesNullifier => {
						let proof_local = self.notes_nullifier_state.tree.insert_chained(batch.commitments_hash)?;
						anyhow::ensure!(
							proof_local.proofs.last().unwrap().new_root == new_root_hash,
							"local root mismatch after confirm"
						);
						if let (Some(store), Some(meta)) = (
							self.notes_nullifier_store.as_mut(),
							self.notes_nullifier_meta.as_mut(),
						) {
							store.commit_batch(&self.notes_nullifier_state.tree, meta, batch.commitments_bytes)?;
						}
					},
					TreeJob::AccountsCommitment => {
						let proof_local = self.accounts_commitment_state.tree.insert_batch(batch.commitments_hash)?;
						anyhow::ensure!(proof_local.root_new == new_root_hash, "local root mismatch after confirm");
						if let (Some(store), Some(meta)) = (
							self.accounts_commitment_store.as_mut(),
							self.accounts_commitment_meta.as_mut(),
						) {
							store.commit_batch(&self.accounts_commitment_state.tree, meta, batch.commitments_bytes)?;
						}
					},
					TreeJob::AccountsNullifier => {
						let proof_local = self.accounts_nullifier_state.tree.insert_chained(batch.commitments_hash)?;
						anyhow::ensure!(
							proof_local.proofs.last().unwrap().new_root == new_root_hash,
							"local root mismatch after confirm"
						);
						if let (Some(store), Some(meta)) = (
							self.accounts_nullifier_store.as_mut(),
							self.accounts_nullifier_meta.as_mut(),
						) {
							store.commit_batch(&self.accounts_nullifier_state.tree, meta, batch.commitments_bytes)?;
						}
					},
				}
				self.log_pool_status("batch finalized and committed locally");
			},
		}

		Ok(())
	}
}
