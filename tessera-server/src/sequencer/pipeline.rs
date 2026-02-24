use alloy::primitives::FixedBytes;
use tessera_trees::{
	plonky2_gadgets::keccak256::utils::keccak256_field_elements_native,
	tree::hasher::CommitmentPreimage, F,
};
use tracing::{debug, info, warn};

use super::*;
use crate::{
	dummy::{self, DummyTreeType},
	sequencer::revert::humanize_bridge_revert,
};

const DUMMY_ASSOCIATED_INPUT_PROOF: &[u8] = &[0x01];

impl Sequencer {
	pub(super) fn submit_prove_request_with_retry(
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

	pub(super) async fn maybe_start_next_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
		batch_size: usize,
		batch_timeout: std::time::Duration,
		in_flight: &mut Option<InFlightBatch>,
	) -> anyhow::Result<()> {
		if in_flight.is_some() {
			return Ok(());
		}
		self.refresh_pending_timers();
		self.log_pool_status("batch scheduling tick");

		if Self::should_flush_pool(
			self.notes_commitment_state.pending_requests.len(),
			batch_size,
			self.notes_commitment_pending_since,
			batch_timeout,
		) {
			return self
				.start_notes_commitment_batch(provider, batch_size, in_flight)
				.await;
		}
		if Self::should_flush_pool(
			self.notes_nullifier_state.pending_requests.len(),
			batch_size,
			self.notes_nullifier_pending_since,
			batch_timeout,
		) {
			return self
				.start_notes_nullifier_batch(provider, batch_size, in_flight)
				.await;
		}
		if Self::should_flush_pool(
			self.accounts_commitment_state.pending_requests.len(),
			batch_size,
			self.accounts_commitment_pending_since,
			batch_timeout,
		) {
			return self
				.start_accounts_commitment_batch(provider, batch_size, in_flight)
				.await;
		}
		if Self::should_flush_pool(
			self.accounts_nullifier_state.pending_requests.len(),
			batch_size,
			self.accounts_nullifier_pending_since,
			batch_timeout,
		) {
			return self
				.start_accounts_nullifier_batch(provider, batch_size, in_flight)
				.await;
		}
		Ok(())
	}

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
			batch_size, "starting notes commitment batch preflight"
		);

		let batch = self
			.notes_commitment_state
			.pop_next_up_to(batch_size)
			.ok_or_else(|| anyhow::anyhow!("batch requested but pending queue was empty"))?;
		self.refresh_pending_timers();

		let on_chain_root = bridge.notesCommitmentRoot().call().await?;
		let local_root = contract::hash_to_bytes32(&self.notes_commitment_state.current_root());
		anyhow::ensure!(
			on_chain_root == local_root,
			"preflight failed: notesCommitmentRoot mismatch (on-chain={on_chain_root:?}, local={local_root:?})"
		);

		for req in &batch {
			let note = alloy::primitives::FixedBytes::<32>::from(req.commitment);
			let status = bridge.getDepositStatus(note).call().await.map_err(|e| {
				anyhow::anyhow!("preflight failed: unable to fetch note status: {e}")
			})?;
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

		let real_commitments_bytes: Vec<[u8; 32]> = batch.iter().map(|r| r.commitment).collect();
		let batch_start_index = self.notes_commitment_state.tree.num_leaves();
		let proving_commitments_bytes = dummy::pad_leaves(
			DummyTreeType::NotesCommitment,
			batch_start_index,
			batch_size,
			&real_commitments_bytes,
		)?;
		let proving_commitments_hash: Vec<Hash> =
			contract::bytes_slice_to_hashes(&proving_commitments_bytes)?;
		let mut associated_input_proofs: Vec<Vec<u8>> = batch
			.iter()
			.map(|r| {
				r.associated_input_proof.clone().ok_or_else(|| {
					anyhow::anyhow!(
						"missing associated input proof for notes commitment leaf {:?}",
						alloy::primitives::B256::from(r.commitment)
					)
				})
			})
			.collect::<anyhow::Result<_>>()?;
		associated_input_proofs.resize(batch_size, DUMMY_ASSOCIATED_INPUT_PROOF.to_vec());

		let mut tmp_tree = self.notes_commitment_state.tree.clone();
		let batch_proof = tmp_tree.insert_batch(proving_commitments_hash.clone())?;
		anyhow::ensure!(
			batch_proof.verify(),
			"native commitment proof verification failed"
		);

		self.submit_prove_request_with_retry(
			crate::types::ProveRequest::Commitment {
				batch_id: 0,
				tree_index: crate::types::TREE_NOTES_COMMITMENT,
				batch_proof,
				associated_input_proofs,
			},
			TreeJob::NotesCommitment,
		)?;

		let real_count = batch.len();
		*in_flight = Some(InFlightBatch {
			job: TreeJob::NotesCommitment,
			requests: batch,
			real_commitments_bytes,
			proving_commitments_bytes,
			proving_commitments_hash,
		});
		info!(
			batch_size,
			real_leaves = real_count,
			"notes commitment batch sent to prover"
		);
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
			batch_size, "starting notes nullifier batch preflight"
		);

		let batch = self
			.notes_nullifier_state
			.pop_next_up_to(batch_size)
			.ok_or_else(|| anyhow::anyhow!("batch requested but pending queue was empty"))?;
		self.refresh_pending_timers();

		let on_chain_root = bridge.notesNullifierRoot().call().await?;
		let local_root = contract::hash_to_bytes32(&self.notes_nullifier_state.current_root());
		anyhow::ensure!(
			on_chain_root == local_root,
			"preflight failed: notesNullifierRoot mismatch (on-chain={on_chain_root:?}, local={local_root:?})"
		);

		for req in &batch {
			let note = alloy::primitives::FixedBytes::<32>::from(req.commitment);
			let status = bridge.getDepositStatus(note).call().await.map_err(|e| {
				anyhow::anyhow!("preflight failed: unable to fetch note status: {e}")
			})?;
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

		let real_commitments_bytes: Vec<[u8; 32]> = batch.iter().map(|r| r.commitment).collect();
		let batch_start_index = self.notes_nullifier_state.tree.num_leaves();
		let proving_commitments_bytes = dummy::pad_leaves(
			DummyTreeType::NotesNullifier,
			batch_start_index,
			batch_size,
			&real_commitments_bytes,
		)?;
		let proving_commitments_hash: Vec<Hash> =
			contract::bytes_slice_to_hashes(&proving_commitments_bytes)?;
		let associated_input_proofs = vec![DUMMY_ASSOCIATED_INPUT_PROOF.to_vec(); batch_size];

		let mut tmp_tree = self.notes_nullifier_state.tree.clone();
		let batch_proof = tmp_tree.insert_chained(proving_commitments_hash.clone())?;
		anyhow::ensure!(
			batch_proof.verify(),
			"native nullifier proof verification failed"
		);

		self.submit_prove_request_with_retry(
			crate::types::ProveRequest::Nullifier {
				batch_id: 0,
				tree_index: crate::types::TREE_NOTES_NULLIFIER,
				batch_proof,
				associated_input_proofs,
			},
			TreeJob::NotesNullifier,
		)?;

		let real_count = batch.len();
		*in_flight = Some(InFlightBatch {
			job: TreeJob::NotesNullifier,
			requests: batch,
			real_commitments_bytes,
			proving_commitments_bytes,
			proving_commitments_hash,
		});
		info!(
			batch_size,
			real_leaves = real_count,
			"notes nullifier batch sent to prover"
		);
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
			batch_size, "starting accounts commitment batch preflight"
		);

		let batch = self
			.accounts_commitment_state
			.pop_next_up_to(batch_size)
			.ok_or_else(|| anyhow::anyhow!("batch requested but pending queue was empty"))?;
		self.refresh_pending_timers();

		let on_chain_root = bridge.accountsCommitmentRoot().call().await?;
		let local_root = contract::hash_to_bytes32(&self.accounts_commitment_state.current_root());
		anyhow::ensure!(
			on_chain_root == local_root,
			"preflight failed: accountsCommitmentRoot mismatch (on-chain={on_chain_root:?}, local={local_root:?})"
		);

		let real_commitments_bytes: Vec<[u8; 32]> = batch.iter().map(|r| r.commitment).collect();
		debug!(
			batch = batch.len(),
			on_chain_root = ?on_chain_root,
			local_root = ?local_root,
			"accounts commitment preflight passed"
		);
		let batch_start_index = self.accounts_commitment_state.tree.num_leaves();
		let proving_commitments_bytes = dummy::pad_leaves(
			DummyTreeType::AccountsCommitment,
			batch_start_index,
			batch_size,
			&real_commitments_bytes,
		)?;
		let proving_commitments_hash: Vec<Hash> =
			contract::bytes_slice_to_hashes(&proving_commitments_bytes)?;
		let associated_input_proofs = vec![DUMMY_ASSOCIATED_INPUT_PROOF.to_vec(); batch_size];

		let mut tmp_tree = self.accounts_commitment_state.tree.clone();
		let batch_proof = tmp_tree.insert_batch(proving_commitments_hash.clone())?;
		anyhow::ensure!(
			batch_proof.verify(),
			"native commitment proof verification failed"
		);

		self.submit_prove_request_with_retry(
			crate::types::ProveRequest::Commitment {
				batch_id: 0,
				tree_index: crate::types::TREE_ACCOUNTS_COMMITMENT,
				batch_proof,
				associated_input_proofs,
			},
			TreeJob::AccountsCommitment,
		)?;

		let real_count = batch.len();
		*in_flight = Some(InFlightBatch {
			job: TreeJob::AccountsCommitment,
			requests: batch,
			real_commitments_bytes,
			proving_commitments_bytes,
			proving_commitments_hash,
		});
		info!(
			batch_size,
			real_leaves = real_count,
			"accounts commitment batch sent to prover"
		);
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
			batch_size, "starting accounts nullifier batch preflight"
		);

		let batch = self
			.accounts_nullifier_state
			.pop_next_up_to(batch_size)
			.ok_or_else(|| anyhow::anyhow!("batch requested but pending queue was empty"))?;
		self.refresh_pending_timers();

		let on_chain_root = bridge.accountsNullifierRoot().call().await?;
		let local_root = contract::hash_to_bytes32(&self.accounts_nullifier_state.current_root());
		anyhow::ensure!(
			on_chain_root == local_root,
			"preflight failed: accountsNullifierRoot mismatch (on-chain={on_chain_root:?}, local={local_root:?})"
		);

		// Verify each leaf-to-be-nullified was previously committed to the accounts commitment
		// tree.
		for req in &batch {
			let commitment_hash =
				contract::bytes32_to_hash(&alloy::primitives::B256::from(req.commitment))?;
			anyhow::ensure!(
				self.accounts_commitment_state.tree.contains_leaf(&commitment_hash),
				"preflight failed: accounts nullifier leaf {:?} not found in accounts commitment tree",
				alloy::primitives::B256::from(req.commitment)
			);
		}

		let real_commitments_bytes: Vec<[u8; 32]> = batch.iter().map(|r| r.commitment).collect();
		debug!(
			batch = batch.len(),
			on_chain_root = ?on_chain_root,
			local_root = ?local_root,
			"accounts nullifier preflight passed"
		);
		let batch_start_index = self.accounts_nullifier_state.tree.num_leaves();
		let proving_commitments_bytes = dummy::pad_leaves(
			DummyTreeType::AccountsNullifier,
			batch_start_index,
			batch_size,
			&real_commitments_bytes,
		)?;
		let proving_commitments_hash: Vec<Hash> =
			contract::bytes_slice_to_hashes(&proving_commitments_bytes)?;
		let associated_input_proofs = vec![DUMMY_ASSOCIATED_INPUT_PROOF.to_vec(); batch_size];

		let mut tmp_tree = self.accounts_nullifier_state.tree.clone();
		let batch_proof = tmp_tree.insert_chained(proving_commitments_hash.clone())?;
		anyhow::ensure!(
			batch_proof.verify(),
			"native nullifier proof verification failed"
		);

		self.submit_prove_request_with_retry(
			crate::types::ProveRequest::Nullifier {
				batch_id: 0,
				tree_index: crate::types::TREE_ACCOUNTS_NULLIFIER,
				batch_proof,
				associated_input_proofs,
			},
			TreeJob::AccountsNullifier,
		)?;

		let real_count = batch.len();
		*in_flight = Some(InFlightBatch {
			job: TreeJob::AccountsNullifier,
			requests: batch,
			real_commitments_bytes,
			proving_commitments_bytes,
			proving_commitments_hash,
		});
		info!(
			batch_size,
			real_leaves = real_count,
			"accounts nullifier batch sent to prover"
		);
		self.log_pool_status("accounts nullifier batch moved in-flight");
		Ok(())
	}

	pub(super) async fn handle_prove_outcome<P: Provider + Clone>(
		&mut self,
		provider: &P,
		outcome: ProveOutcome,
		in_flight: &mut Option<InFlightBatch>,
	) -> anyhow::Result<()> {
		// Two-phase path: batch_id != 0 means this outcome belongs to a
		// registered TxBatch; route to the confirm pipeline.
		let outcome_batch_id = match &outcome {
			ProveOutcome::Success {
				batch_id, ..
			}
			| ProveOutcome::Failure {
				batch_id, ..
			} => *batch_id,
		};
		if outcome_batch_id != 0 {
			return self.confirm_tx_batch_tree(provider, outcome).await;
		}

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
				batch_id: _,
				tree_index: _,
				error,
			} => {
				warn!(job = ?batch.job, "prover returned failure, re-queueing batch");
				match batch.job {
					TreeJob::NotesCommitment => {
						self.notes_commitment_state.reinsert_batch(batch.requests)
					},
					TreeJob::NotesNullifier => {
						self.notes_nullifier_state.reinsert_batch(batch.requests)
					},
					TreeJob::AccountsCommitment => self
						.accounts_commitment_state
						.reinsert_batch(batch.requests),
					TreeJob::AccountsNullifier => {
						self.accounts_nullifier_state.reinsert_batch(batch.requests)
					},
				}
				warn!(job = ?batch.job, error, "proof generation failed; batch requeued");
				self.log_pool_status("batch requeued after prover failure");
				return Ok(());
			},
			ProveOutcome::Success {
				batch_id: _,
				tree_index: _,
				new_root,
				solidity_proof,
				aggregated_input_solidity_proof,
			} => {
				info!(
					job = ?batch.job,
					requests = batch.requests.len(),
					"prover returned success"
				);
				let commitments_vec: Vec<alloy::primitives::FixedBytes<32>> = batch
					.real_commitments_bytes
					.iter()
					.map(|b| alloy::primitives::FixedBytes::<32>::from(*b))
					.collect();
				let sol_proof = IDepositsRollupBridge::Proof {
					proof: solidity_proof.proof,
					commitments: solidity_proof.commitments,
					commitmentPok: solidity_proof.commitment_pok,
				};
				let aggregated_input_proof = IDepositsRollupBridge::Proof {
					proof: aggregated_input_solidity_proof.proof,
					commitments: aggregated_input_solidity_proof.commitments,
					commitmentPok: aggregated_input_solidity_proof.commitment_pok,
				};
				let new_root_hash = new_root;
				let new_root_bytes = contract::hash_to_bytes32(&new_root_hash);

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
							.map_err(|e| {
								anyhow::anyhow!(
									"recordNotesCommitmentTreeUpdate reverted: {}",
									humanize_bridge_revert(&e)
								)
							})?;
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
							.map_err(|e| {
								anyhow::anyhow!(
									"recordNotesNullifierTreeUpdate reverted: {}",
									humanize_bridge_revert(&e)
								)
							})?;
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
							.map_err(|e| {
								anyhow::anyhow!(
									"recordAccountsCommitmentTreeUpdate reverted: {}",
									humanize_bridge_revert(&e)
								)
							})?;
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
							.map_err(|e| {
								anyhow::anyhow!(
									"recordAccountsNullifierTreeUpdate reverted: {}",
									humanize_bridge_revert(&e)
								)
							})?;
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
							TreeJob::NotesCommitment => {
								self.notes_commitment_state.reinsert_batch(batch.requests)
							},
							TreeJob::NotesNullifier => {
								self.notes_nullifier_state.reinsert_batch(batch.requests)
							},
							TreeJob::AccountsCommitment => self
								.accounts_commitment_state
								.reinsert_batch(batch.requests),
							TreeJob::AccountsNullifier => {
								self.accounts_nullifier_state.reinsert_batch(batch.requests)
							},
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
					updated_real = batch.requests.len(),
					job = ?batch.job,
					"tree update confirmed"
				);

				match batch.job {
					TreeJob::NotesCommitment => {
						let proof_local = self
							.notes_commitment_state
							.tree
							.insert_batch(batch.proving_commitments_hash)?;
						anyhow::ensure!(
							proof_local.root_new == new_root_hash,
							"local root mismatch after confirm"
						);
						if let (Some(store), Some(meta)) = (
							self.notes_commitment_store.as_mut(),
							self.notes_commitment_meta.as_mut(),
						) {
							store.commit_batch(
								&self.notes_commitment_state.tree,
								meta,
								batch.proving_commitments_bytes,
							)?;
						}
					},
					TreeJob::NotesNullifier => {
						let proof_local = self
							.notes_nullifier_state
							.tree
							.insert_chained(batch.proving_commitments_hash)?;
						anyhow::ensure!(
							proof_local.proofs.last().unwrap().new_root == new_root_hash,
							"local root mismatch after confirm"
						);
						if let (Some(store), Some(meta)) = (
							self.notes_nullifier_store.as_mut(),
							self.notes_nullifier_meta.as_mut(),
						) {
							store.commit_batch(
								&self.notes_nullifier_state.tree,
								meta,
								batch.proving_commitments_bytes,
							)?;
						}
					},
					TreeJob::AccountsCommitment => {
						let proof_local = self
							.accounts_commitment_state
							.tree
							.insert_batch(batch.proving_commitments_hash)?;
						anyhow::ensure!(
							proof_local.root_new == new_root_hash,
							"local root mismatch after confirm"
						);
						if let (Some(store), Some(meta)) = (
							self.accounts_commitment_store.as_mut(),
							self.accounts_commitment_meta.as_mut(),
						) {
							store.commit_batch(
								&self.accounts_commitment_state.tree,
								meta,
								batch.proving_commitments_bytes,
							)?;
						}
					},
					TreeJob::AccountsNullifier => {
						let proof_local = self
							.accounts_nullifier_state
							.tree
							.insert_chained(batch.proving_commitments_hash)?;
						anyhow::ensure!(
							proof_local.proofs.last().unwrap().new_root == new_root_hash,
							"local root mismatch after confirm"
						);
						if let (Some(store), Some(meta)) = (
							self.accounts_nullifier_store.as_mut(),
							self.accounts_nullifier_meta.as_mut(),
						) {
							store.commit_batch(
								&self.accounts_nullifier_state.tree,
								meta,
								batch.proving_commitments_bytes,
							)?;
						}
					},
				}
				self.log_pool_status("batch finalized and committed locally");
			},
		}

		Ok(())
	}

	/// Register a private transaction as an optimistic two-phase batch.
	///
	/// Steps:
	/// 1. Guard against a full pending-batch queue.
	/// 2. For each of the four trees: pad real leaves to `batch_size`, compute the native batch
	///    proof from a tree clone, and derive the PI commitment.
	/// 3. Call `registerTransactionBatchUpdate` on-chain; extract the assigned `batchId` from the
	///    emitted `TransactionBatchRegistered` event.
	/// 4. Apply the padded inserts to the real local trees (advancing their roots so subsequent
	///    registrations can build on top).
	/// 5. Store a `TxBatch` record and submit four async prove jobs.
	pub(super) async fn register_tx_batch<P: Provider + Clone>(
		&mut self,
		provider: &P,
		request: PrivateTxRequest,
		batch_size: usize,
	) -> anyhow::Result<()> {
		// 1. Queue-full guard.
		if self.registered_pending_batches.len() >= MAX_PENDING_BATCHES {
			warn!(
				tx_id = request.tx_id.as_deref().unwrap_or("unknown"),
				"optimistic register queue full; dropping private tx"
			);
			return Err(anyhow::anyhow!("PendingQueueFull"));
		}
		let tx_id = request.tx_id.clone().unwrap_or_else(|| "unknown".into());

		debug!(tx_id = %tx_id, "starting optimistic register for private tx");

		// 2. Pad + compute native proofs from clones.

		// --- Notes Commitment (TREE_NOTES_COMMITMENT = 0) ---
		let nc_real = request.output_notes;
		let nc_start = self.notes_commitment_state.tree.num_leaves();
		let nc_padded = dummy::pad_leaves(
			DummyTreeType::NotesCommitment,
			nc_start,
			batch_size,
			&nc_real,
		)?;
		let nc_hashes: Vec<Hash> = crate::contract::bytes_slice_to_hashes(&nc_padded)?;
		let mut nc_tmp = self.notes_commitment_state.tree.clone();
		let nc_proof = nc_tmp.insert_batch(nc_hashes.clone())?;
		anyhow::ensure!(nc_proof.verify(), "NC native proof failed (private tx)");
		let nc_pi = {
			let mut pre: Vec<F> = Vec::new();
			nc_proof.write_preimage(&mut pre);
			u32x8_to_bytes32(keccak256_field_elements_native(&pre))
		};
		let mut nc_assoc: Vec<Vec<u8>> = nc_real.iter().map(|_| request.tx_proof.clone()).collect();
		nc_assoc.resize(batch_size, DUMMY_ASSOCIATED_INPUT_PROOF.to_vec());

		// --- Notes Nullifier (TREE_NOTES_NULLIFIER = 1) ---
		let nn_real = request.input_notes;
		let nn_start = self.notes_nullifier_state.tree.num_leaves();
		let nn_padded = dummy::pad_leaves(
			DummyTreeType::NotesNullifier,
			nn_start,
			batch_size,
			&nn_real,
		)?;
		let nn_hashes: Vec<Hash> = crate::contract::bytes_slice_to_hashes(&nn_padded)?;
		let mut nn_tmp = self.notes_nullifier_state.tree.clone();
		let nn_proof = nn_tmp.insert_chained(nn_hashes.clone())?;
		anyhow::ensure!(nn_proof.verify(), "NN native proof failed (private tx)");
		let new_nn_root = crate::contract::hash_to_bytes32(
			&nn_proof
				.proofs
				.last()
				.ok_or_else(|| anyhow::anyhow!("notes nullifier proof is empty"))?
				.new_root,
		);
		let nn_pi = {
			let mut pre: Vec<F> = Vec::new();
			nn_proof.write_preimage(&mut pre);
			u32x8_to_bytes32(keccak256_field_elements_native(&pre))
		};
		let nn_assoc = vec![DUMMY_ASSOCIATED_INPUT_PROOF.to_vec(); batch_size];

		// --- Accounts Commitment (TREE_ACCOUNTS_COMMITMENT = 2) ---
		let ac_real = vec![request.output_account_leaf];
		let ac_start = self.accounts_commitment_state.tree.num_leaves();
		let ac_padded = dummy::pad_leaves(
			DummyTreeType::AccountsCommitment,
			ac_start,
			batch_size,
			&ac_real,
		)?;
		let ac_hashes: Vec<Hash> = crate::contract::bytes_slice_to_hashes(&ac_padded)?;
		let mut ac_tmp = self.accounts_commitment_state.tree.clone();
		let ac_proof = ac_tmp.insert_batch(ac_hashes.clone())?;
		anyhow::ensure!(ac_proof.verify(), "AC native proof failed (private tx)");
		let ac_pi = {
			let mut pre: Vec<F> = Vec::new();
			ac_proof.write_preimage(&mut pre);
			u32x8_to_bytes32(keccak256_field_elements_native(&pre))
		};
		let ac_assoc = vec![DUMMY_ASSOCIATED_INPUT_PROOF.to_vec(); batch_size];

		// --- Accounts Nullifier (TREE_ACCOUNTS_NULLIFIER = 3) ---
		let an_real = vec![request.input_account_leaf];
		let an_start = self.accounts_nullifier_state.tree.num_leaves();
		let an_padded = dummy::pad_leaves(
			DummyTreeType::AccountsNullifier,
			an_start,
			batch_size,
			&an_real,
		)?;
		let an_hashes: Vec<Hash> = crate::contract::bytes_slice_to_hashes(&an_padded)?;
		let mut an_tmp = self.accounts_nullifier_state.tree.clone();
		let an_proof = an_tmp.insert_chained(an_hashes.clone())?;
		anyhow::ensure!(an_proof.verify(), "AN native proof failed (private tx)");
		let new_an_root = crate::contract::hash_to_bytes32(
			&an_proof
				.proofs
				.last()
				.ok_or_else(|| anyhow::anyhow!("accounts nullifier proof is empty"))?
				.new_root,
		);
		let an_pi = {
			let mut pre: Vec<F> = Vec::new();
			an_proof.write_preimage(&mut pre);
			u32x8_to_bytes32(keccak256_field_elements_native(&pre))
		};
		let an_assoc = vec![DUMMY_ASSOCIATED_INPUT_PROOF.to_vec(); batch_size];

		// New roots for the two commitment trees.
		let new_nc_root = crate::contract::hash_to_bytes32(&nc_proof.root_new);
		let new_ac_root = crate::contract::hash_to_bytes32(&ac_proof.root_new);

		// 3. Build calldata arrays (real leaves only — contract doesn't receive padding).
		let nc_out: Vec<FixedBytes<32>> =
			nc_real.iter().map(|b| FixedBytes::<32>::from(*b)).collect();
		let nn_in: Vec<FixedBytes<32>> =
			nn_real.iter().map(|b| FixedBytes::<32>::from(*b)).collect();
		let ac_out: Vec<FixedBytes<32>> =
			ac_real.iter().map(|b| FixedBytes::<32>::from(*b)).collect();
		let an_in: Vec<FixedBytes<32>> =
			an_real.iter().map(|b| FixedBytes::<32>::from(*b)).collect();
		let pi_commitments: [FixedBytes<32>; 4] = [
			FixedBytes::<32>::from(nc_pi),
			FixedBytes::<32>::from(nn_pi),
			FixedBytes::<32>::from(ac_pi),
			FixedBytes::<32>::from(an_pi),
		];

		// 4. Call registerTransactionBatchUpdate on-chain.
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
				pi_commitments,
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

		// 5. Extract batchId from the TransactionBatchRegistered event.
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

		// 6. Apply inserts to real local trees (advance state for subsequent batches).
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

		// 7. Build prove requests (before moving data into TxBatch).
		let nc_prove = crate::types::ProveRequest::Commitment {
			batch_id,
			tree_index: crate::types::TREE_NOTES_COMMITMENT,
			batch_proof: nc_proof,
			associated_input_proofs: nc_assoc.clone(),
		};
		let nn_prove = crate::types::ProveRequest::Nullifier {
			batch_id,
			tree_index: crate::types::TREE_NOTES_NULLIFIER,
			batch_proof: nn_proof,
			associated_input_proofs: nn_assoc.clone(),
		};
		let ac_prove = crate::types::ProveRequest::Commitment {
			batch_id,
			tree_index: crate::types::TREE_ACCOUNTS_COMMITMENT,
			batch_proof: ac_proof,
			associated_input_proofs: ac_assoc.clone(),
		};
		let an_prove = crate::types::ProveRequest::Nullifier {
			batch_id,
			tree_index: crate::types::TREE_ACCOUNTS_NULLIFIER,
			batch_proof: an_proof,
			associated_input_proofs: an_assoc.clone(),
		};

		// 8. Store TxBatch in the pending map.
		self.registered_pending_batches.insert(
			batch_id,
			TxBatch {
				batch_id,
				pi_commitments: [nc_pi, nn_pi, ac_pi, an_pi],
				per_tree: [
					TxPerTreeBatch {
						real_commitments_bytes: nc_real,
						proving_commitments_bytes: nc_padded,
						proving_commitments_hash: nc_hashes,
						associated_input_proofs: nc_assoc,
					},
					TxPerTreeBatch {
						real_commitments_bytes: nn_real,
						proving_commitments_bytes: nn_padded,
						proving_commitments_hash: nn_hashes,
						associated_input_proofs: nn_assoc,
					},
					TxPerTreeBatch {
						real_commitments_bytes: ac_real,
						proving_commitments_bytes: ac_padded,
						proving_commitments_hash: ac_hashes,
						associated_input_proofs: ac_assoc,
					},
					TxPerTreeBatch {
						real_commitments_bytes: an_real,
						proving_commitments_bytes: an_padded,
						proving_commitments_hash: an_hashes,
						associated_input_proofs: an_assoc,
					},
				],
				local_confirmed_mask: 0,
			},
		);

		// 9. Submit 4 independent prove jobs.
		self.submit_prove_request_with_retry(nc_prove, TreeJob::NotesCommitment)?;
		self.submit_prove_request_with_retry(nn_prove, TreeJob::NotesNullifier)?;
		self.submit_prove_request_with_retry(ac_prove, TreeJob::AccountsCommitment)?;
		self.submit_prove_request_with_retry(an_prove, TreeJob::AccountsNullifier)?;

		info!(
			batch_id,
			queue = self.registered_pending_batches.len(),
			"4 prove jobs submitted for registered batch"
		);
		Ok(())
	}

	/// Confirm one tree's proof for a registered two-phase batch.
	///
	/// On success: calls `confirmTreeUpdate` on-chain, advances `local_confirmed_mask`.
	/// When all 4 trees are confirmed (`mask == 0xF`), removes the batch from the map.
	/// On failure: logs the error and leaves the batch in `registered_pending_batches`
	/// for operator recovery (Slice 6).
	async fn confirm_tx_batch_tree<P: Provider + Clone>(
		&mut self,
		provider: &P,
		outcome: ProveOutcome,
	) -> anyhow::Result<()> {
		match outcome {
			ProveOutcome::Failure {
				batch_id,
				tree_index,
				error,
			} => {
				tracing::error!(
					batch_id,
					tree_index,
					error,
					"prover failure for two-phase batch; batch stays pending"
				);
			},
			ProveOutcome::Success {
				batch_id,
				tree_index,
				solidity_proof,
				aggregated_input_solidity_proof,
				// new_root is not needed: the contract verifies it against the registered root.
				new_root: _,
			} => {
				if !self.registered_pending_batches.contains_key(&batch_id) {
					warn!(
						batch_id,
						tree_index, "proof arrived for unknown/already-confirmed batch; skipping"
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
				let inputs_proof = IDepositsRollupBridge::Proof {
					proof: aggregated_input_solidity_proof.proof,
					commitments: aggregated_input_solidity_proof.commitments,
					commitmentPok: aggregated_input_solidity_proof.commitment_pok,
				};

				let receipt_result = bridge
					.confirmTreeUpdate(
						alloy::primitives::U256::from(batch_id),
						tree_index,
						sol_proof,
						inputs_proof,
					)
					.send()
					.await
					.map_err(|e| {
						anyhow::anyhow!(
							"confirmTreeUpdate send failed: {}",
							humanize_bridge_revert(&e)
						)
					})?;

				let receipt = receipt_result
					.with_required_confirmations(1)
					.with_timeout(Some(RECEIPT_TIMEOUT))
					.get_receipt()
					.await
					.map_err(|e| anyhow::anyhow!("confirmTreeUpdate receipt timeout/error: {e}"))?;

				anyhow::ensure!(
					receipt.status(),
					"confirmTreeUpdate reverted on-chain (batch_id={batch_id}, tree_index={tree_index}, tx={:?})",
					receipt.transaction_hash
				);

				info!(
					batch_id,
					tree_index,
					tx_hash = ?receipt.transaction_hash,
					"tree confirmed on-chain"
				);

				if let Some(tx_batch) = self.registered_pending_batches.get_mut(&batch_id) {
					tx_batch.local_confirmed_mask |= 1u8 << tree_index;
					if tx_batch.local_confirmed_mask == 0xF {
						info!(batch_id, "all 4 trees confirmed; batch complete");
						self.registered_pending_batches.remove(&batch_id);
					}
				}
			},
		}
		Ok(())
	}
}

/// Pack a keccak-256 digest `[u32; 8]` (big-endian word order) into raw bytes.
fn u32x8_to_bytes32(digest: [u32; 8]) -> [u8; 32] {
	let mut bytes = [0u8; 32];
	for (i, word) in digest.iter().enumerate() {
		bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
	}
	bytes
}
