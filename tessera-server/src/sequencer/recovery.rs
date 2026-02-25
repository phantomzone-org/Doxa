use alloy::{
	consensus::Transaction as _,
	primitives::U256,
	rpc::types::{Filter, Log},
	sol_types::{SolCall, SolEvent},
};
use tracing::{debug, info, warn};

use super::*;
use crate::dummy::{self, DummyTreeType};

impl Sequencer {
	/// Maximum block range per `eth_getLogs` call.
	/// Nodes commonly limit responses to ~2 000–10 000 blocks; 1 000 is conservative.
	const LOG_FETCH_CHUNK_BLOCKS: u64 = 1_000;

	pub(super) fn load_other_trees(&mut self) -> anyhow::Result<()> {
		{
			let mut store = TreeStore::<NullifierTree<Hash>>::open(
				&self.config.tree_store_path,
				TreeId::NotesNullifier,
				self.config.snapshot_every_batches,
			)?;
			let (mut tree, meta0) = store.load_or_init(|| NullifierTree::new(TREE_DEPTH))?;
			let (wal_pos, replayed) =
				store.replay_wal_since_snapshot(&mut tree, &meta0, |t, vals| {
					let values: Vec<Hash> = contract::bytes_slice_to_hashes(&vals)?;
					let proof = t.insert_chained(values)?;
					anyhow::ensure!(proof.verify(), "WAL replay produced invalid proof");
					Ok(())
				})?;
			let mut meta = meta0.clone();
			meta.wal_pos = wal_pos;
			meta.committed_batches = meta.committed_batches.saturating_add(replayed);
			info!(
				tree = "notes_nullifier",
				replayed_batches = replayed,
				wal_pos,
				last_block = meta.last_block,
				last_tx_index = meta.last_tx_index,
				last_log_index = meta.last_log_index,
				"loaded local tree state from snapshot/WAL"
			);

			self.notes_nullifier_state.tree = tree;
			self.notes_nullifier_store = Some(store);
			self.notes_nullifier_meta = Some(meta);
		}

		{
			let mut store = TreeStore::<CommitmentTree<Hash>>::open(
				&self.config.tree_store_path,
				TreeId::AccountsCommitment,
				self.config.snapshot_every_batches,
			)?;
			let (mut tree, meta0) = store.load_or_init(|| CommitmentTree::new(TREE_DEPTH))?;
			let (wal_pos, replayed) =
				store.replay_wal_since_snapshot(&mut tree, &meta0, |t, vals| {
					let leaves: Vec<Hash> = contract::bytes_slice_to_hashes(&vals)?;
					let proof = t.insert_batch(leaves)?;
					anyhow::ensure!(proof.verify(), "WAL replay produced invalid proof");
					Ok(())
				})?;
			// Backward compatibility for legacy snapshots that predate CommitmentTree::leaf_counts.
			if meta0.snapshot_version < 2 {
				tree.rebuild_leaf_counts();
			}
			let mut meta = meta0.clone();
			meta.wal_pos = wal_pos;
			meta.committed_batches = meta.committed_batches.saturating_add(replayed);
			info!(
				tree = "accounts_commitment",
				replayed_batches = replayed,
				wal_pos,
				last_block = meta.last_block,
				last_tx_index = meta.last_tx_index,
				last_log_index = meta.last_log_index,
				"loaded local tree state from snapshot/WAL"
			);

			self.accounts_commitment_state.tree = tree;
			self.accounts_commitment_store = Some(store);
			self.accounts_commitment_meta = Some(meta);
		}

		{
			let mut store = TreeStore::<NullifierTree<Hash>>::open(
				&self.config.tree_store_path,
				TreeId::AccountsNullifier,
				self.config.snapshot_every_batches,
			)?;
			let (mut tree, meta0) = store.load_or_init(|| NullifierTree::new(TREE_DEPTH))?;
			let (wal_pos, replayed) =
				store.replay_wal_since_snapshot(&mut tree, &meta0, |t, vals| {
					let values: Vec<Hash> = contract::bytes_slice_to_hashes(&vals)?;
					let proof = t.insert_chained(values)?;
					anyhow::ensure!(proof.verify(), "WAL replay produced invalid proof");
					Ok(())
				})?;
			let mut meta = meta0.clone();
			meta.wal_pos = wal_pos;
			meta.committed_batches = meta.committed_batches.saturating_add(replayed);
			info!(
				tree = "accounts_nullifier",
				replayed_batches = replayed,
				wal_pos,
				last_block = meta.last_block,
				last_tx_index = meta.last_tx_index,
				last_log_index = meta.last_log_index,
				"loaded local tree state from snapshot/WAL"
			);

			self.accounts_nullifier_state.tree = tree;
			self.accounts_nullifier_store = Some(store);
			self.accounts_nullifier_meta = Some(meta);
		}

		Ok(())
	}

	pub(super) async fn recover_missing_chain_updates<P: Provider + Clone>(
		&mut self,
		provider: &P,
		on_chain_notes_commitment_root: &alloy::primitives::FixedBytes<32>,
		on_chain_notes_nullifier_root: &alloy::primitives::FixedBytes<32>,
		on_chain_accounts_commitment_root: &alloy::primitives::FixedBytes<32>,
		on_chain_accounts_nullifier_root: &alloy::primitives::FixedBytes<32>,
	) -> anyhow::Result<()> {
		let local_notes_commitment_root =
			contract::hash_to_bytes32(&self.notes_commitment_state.current_root());
		let local_notes_nullifier_root =
			contract::hash_to_bytes32(&self.notes_nullifier_state.current_root());
		let local_accounts_commitment_root =
			contract::hash_to_bytes32(&self.accounts_commitment_state.current_root());
		let local_accounts_nullifier_root =
			contract::hash_to_bytes32(&self.accounts_nullifier_state.current_root());

		if local_notes_commitment_root == *on_chain_notes_commitment_root
			&& local_notes_nullifier_root == *on_chain_notes_nullifier_root
			&& local_accounts_commitment_root == *on_chain_accounts_commitment_root
			&& local_accounts_nullifier_root == *on_chain_accounts_nullifier_root
		{
			info!("local tree roots already match chain; no chain recovery needed");
			return Ok(());
		}
		info!(
			local_notes_commitment_root = ?local_notes_commitment_root,
			local_notes_nullifier_root = ?local_notes_nullifier_root,
			local_accounts_commitment_root = ?local_accounts_commitment_root,
			local_accounts_nullifier_root = ?local_accounts_nullifier_root,
			on_chain_notes_commitment_root = ?on_chain_notes_commitment_root,
			on_chain_notes_nullifier_root = ?on_chain_notes_nullifier_root,
			on_chain_accounts_commitment_root = ?on_chain_accounts_commitment_root,
			on_chain_accounts_nullifier_root = ?on_chain_accounts_nullifier_root,
			"local state behind chain, starting chain recovery replay"
		);

		let from_block = [
			self.notes_commitment_meta
				.as_ref()
				.map(|m| m.last_block)
				.unwrap_or(0),
			self.notes_nullifier_meta
				.as_ref()
				.map(|m| m.last_block)
				.unwrap_or(0),
			self.accounts_commitment_meta
				.as_ref()
				.map(|m| m.last_block)
				.unwrap_or(0),
			self.accounts_nullifier_meta
				.as_ref()
				.map(|m| m.last_block)
				.unwrap_or(0),
		]
		.into_iter()
		.min()
		.unwrap_or(0);

		// Paginate eth_getLogs to avoid hitting node response-size limits.
		// Many public nodes cap results to ~2 000–10 000 blocks per call.
		let to_block = provider.get_block_number().await?;
		let mut validated_logs: Vec<alloy::rpc::types::Log> = Vec::new();
		let mut chunk_start = from_block;
		while chunk_start <= to_block {
			let chunk_end = (chunk_start + Self::LOG_FETCH_CHUNK_BLOCKS - 1).min(to_block);
			let filter = Filter::new()
				.address(self.config.bridge_address)
				.event_signature(IDepositsRollupBridge::ValidatedBatchFinalized::SIGNATURE_HASH)
				.from_block(chunk_start)
				.to_block(chunk_end);
			let chunk = provider.get_logs(&filter).await?;
			debug!(
				from = chunk_start,
				to = chunk_end,
				count = chunk.len(),
				"fetched ValidatedBatchFinalized log page"
			);
			validated_logs.extend(chunk);
			chunk_start = chunk_end + 1;
		}
		validated_logs.sort_by_key(log_order_key);
		info!(
			from_block,
			to_block,
			logs = validated_logs.len(),
			"fetched ValidatedBatchFinalized logs for recovery"
		);

		let mut processed_any = false;
		let mut processed_count: u64 = 0;
		for log in validated_logs {
			let key = log_order_key(&log);
			let decoded = log.log_decode::<IDepositsRollupBridge::ValidatedBatchFinalized>()?;

			// Determine tree type directly from the event discriminator — no calldata guessing.
			let job = match decoded.inner.treeType {
				contract::IDepositsRollupBridge::TreeType::NotesCommitment => {
					TreeJob::NotesCommitment
				},
				contract::IDepositsRollupBridge::TreeType::NotesNullifier => {
					TreeJob::NotesNullifier
				},
				contract::IDepositsRollupBridge::TreeType::AccountsCommitment => {
					TreeJob::AccountsCommitment
				},
				contract::IDepositsRollupBridge::TreeType::AccountsNullifier => {
					TreeJob::AccountsNullifier
				},
				contract::IDepositsRollupBridge::TreeType::__Invalid => {
					warn!("unknown TreeType in ValidatedBatchFinalized event; skipping");
					continue;
				},
			};

			let tx_hash = log.transaction_hash.ok_or_else(|| {
				anyhow::anyhow!("ValidatedBatchFinalized log missing transaction hash")
			})?;
			let tx = provider
				.get_transaction_by_hash(tx_hash)
				.await?
				.ok_or_else(|| anyhow::anyhow!("transaction not found for hash {tx_hash:?}"))?;
			let Some(commitments_bytes) =
				Self::decode_leaves_from_tx_input(tx.input().as_ref(), job)?
			else {
				warn!(tx_hash = ?tx_hash, job = ?job, "could not decode leaves from tx calldata for ValidatedBatchFinalized; skipping");
				continue;
			};
			debug!(
				tx_hash = ?tx_hash,
				job = ?job,
				leaves = commitments_bytes.len(),
				log_key = ?key,
				"decoded recovered batch from on-chain tx input"
			);

			let changed = self.apply_recovered_batch(
				job,
				decoded.inner.oldRoot,
				decoded.inner.newRoot,
				decoded
					.inner
					.effectiveBatchSize
					.try_into()
					.map_err(|_| anyhow::anyhow!("effectiveBatchSize too large in event"))?,
				commitments_bytes,
				key,
			)?;
			processed_any |= changed;
			if changed {
				processed_count = processed_count.saturating_add(1);
			}
		}
		info!(
			processed_batches = processed_count,
			"chain recovery replay pass completed"
		);

		let local_notes_commitment_root =
			contract::hash_to_bytes32(&self.notes_commitment_state.current_root());
		anyhow::ensure!(
			*on_chain_notes_commitment_root == local_notes_commitment_root,
			"notesCommitmentRoot mismatch after replay: on-chain={on_chain_notes_commitment_root:?}, local={local_notes_commitment_root:?}"
		);
		let local_notes_nullifier_root =
			contract::hash_to_bytes32(&self.notes_nullifier_state.current_root());
		anyhow::ensure!(
			*on_chain_notes_nullifier_root == local_notes_nullifier_root,
			"notesNullifierRoot mismatch after replay: on-chain={on_chain_notes_nullifier_root:?}, local={local_notes_nullifier_root:?}"
		);
		let local_accounts_commitment_root =
			contract::hash_to_bytes32(&self.accounts_commitment_state.current_root());
		anyhow::ensure!(
			*on_chain_accounts_commitment_root == local_accounts_commitment_root,
			"accountsCommitmentRoot mismatch after replay: on-chain={on_chain_accounts_commitment_root:?}, local={local_accounts_commitment_root:?}"
		);
		let local_accounts_nullifier_root =
			contract::hash_to_bytes32(&self.accounts_nullifier_state.current_root());
		anyhow::ensure!(
			*on_chain_accounts_nullifier_root == local_accounts_nullifier_root,
			"accountsNullifierRoot mismatch after replay: on-chain={on_chain_accounts_nullifier_root:?}, local={local_accounts_nullifier_root:?}"
		);

		if processed_any {
			if let (Some(store), Some(meta)) = (
				self.notes_commitment_store.as_ref(),
				self.notes_commitment_meta.as_ref(),
			) {
				store.force_checkpoint(&self.notes_commitment_state.tree, meta)?;
			}
			if let (Some(store), Some(meta)) = (
				self.notes_nullifier_store.as_ref(),
				self.notes_nullifier_meta.as_ref(),
			) {
				store.force_checkpoint(&self.notes_nullifier_state.tree, meta)?;
			}
			if let (Some(store), Some(meta)) = (
				self.accounts_commitment_store.as_ref(),
				self.accounts_commitment_meta.as_ref(),
			) {
				store.force_checkpoint(&self.accounts_commitment_state.tree, meta)?;
			}
			if let (Some(store), Some(meta)) = (
				self.accounts_nullifier_store.as_ref(),
				self.accounts_nullifier_meta.as_ref(),
			) {
				store.force_checkpoint(&self.accounts_nullifier_state.tree, meta)?;
			}
		}
		info!(
			notes_commitment_root = ?contract::hash_to_bytes32(&self.notes_commitment_state.current_root()),
			notes_nullifier_root = ?contract::hash_to_bytes32(&self.notes_nullifier_state.current_root()),
			accounts_commitment_root = ?contract::hash_to_bytes32(&self.accounts_commitment_state.current_root()),
			accounts_nullifier_root = ?contract::hash_to_bytes32(&self.accounts_nullifier_state.current_root()),
			"chain recovery completed and local roots reconciled"
		);

		Ok(())
	}

	/// Decode leaf commitments from tx calldata for the given tree job.
	///
	/// Uses the `treeType` discriminator already decoded from the `ValidatedBatchFinalized`
	/// event so we only attempt the one matching ABI selector.
	fn decode_leaves_from_tx_input(
		input: &[u8],
		job: TreeJob,
	) -> anyhow::Result<Option<Vec<[u8; 32]>>> {
		match job {
			TreeJob::NotesCommitment => {
				if let Ok(call) =
					IDepositsRollupBridge::recordNotesCommitmentTreeUpdateCall::abi_decode(input)
				{
					return Ok(Some(
						call.noteCommitments.into_iter().map(Into::into).collect(),
					));
				}
				Ok(None)
			},
			TreeJob::NotesNullifier => {
				match IDepositsRollupBridge::recordNotesNullifierTreeUpdateCall::abi_decode(input) {
					Ok(call) => Ok(Some(
						call.noteCommitments.into_iter().map(Into::into).collect(),
					)),
					Err(_) => Ok(None),
				}
			},
			TreeJob::AccountsCommitment => {
				match IDepositsRollupBridge::recordAccountsCommitmentTreeUpdateCall::abi_decode(
					input,
				) {
					Ok(call) => Ok(Some(
						call.accountCommitments
							.into_iter()
							.map(Into::into)
							.collect(),
					)),
					Err(_) => Ok(None),
				}
			},
			TreeJob::AccountsNullifier => {
				match IDepositsRollupBridge::recordAccountsNullifierTreeUpdateCall::abi_decode(
					input,
				) {
					Ok(call) => Ok(Some(
						call.accountCommitments
							.into_iter()
							.map(Into::into)
							.collect(),
					)),
					Err(_) => Ok(None),
				}
			},
		}
	}

	fn apply_recovered_batch(
		&mut self,
		job: TreeJob,
		old_root: alloy::primitives::FixedBytes<32>,
		new_root: alloy::primitives::FixedBytes<32>,
		batch_size: usize,
		real_commitments_bytes: Vec<[u8; 32]>,
		log_key: (u64, u64, u64),
	) -> anyhow::Result<bool> {
		match job {
			TreeJob::NotesCommitment => {
				let Some(meta) = self.notes_commitment_meta.as_mut() else {
					return Err(anyhow::anyhow!("notes commitment metadata not initialized"));
				};
				if !is_log_after_cursor(log_key, meta) {
					debug!(job = ?job, log_key = ?log_key, "skipping already applied recovered batch");
					return Ok(false);
				}
				let current_root =
					contract::hash_to_bytes32(&self.notes_commitment_state.current_root());
				if current_root != new_root {
					anyhow::ensure!(
						current_root == old_root,
						"notes commitment replay divergence at log {:?}: local={:?} old={:?} new={:?}",
						log_key,
						current_root,
						old_root,
						new_root
					);
					let batch_start_index = self.notes_commitment_state.tree.num_leaves();
					let commitments_bytes = dummy::pad_leaves(
						DummyTreeType::NotesCommitment,
						batch_start_index,
						batch_size,
						&real_commitments_bytes,
					)?;
					let commitments_hash: Vec<Hash> =
						contract::bytes_slice_to_hashes(&commitments_bytes)?;
					let proof = self
						.notes_commitment_state
						.tree
						.insert_batch(commitments_hash)?;
					anyhow::ensure!(
						proof.verify(),
						"recovered notes commitment proof verification failed"
					);
					anyhow::ensure!(
						proof.root_new == contract::bytes32_to_hash(&new_root)?,
						"recovered notes commitment root mismatch after apply"
					);
					meta.last_block = log_key.0;
					meta.last_tx_index = log_key.1;
					meta.last_log_index = log_key.2;
					if let Some(store) = self.notes_commitment_store.as_mut() {
						store.commit_batch(
							&self.notes_commitment_state.tree,
							meta,
							commitments_bytes,
						)?;
					}
				} else {
					meta.last_block = log_key.0;
					meta.last_tx_index = log_key.1;
					meta.last_log_index = log_key.2;
				}
			},
			TreeJob::NotesNullifier => {
				let Some(meta) = self.notes_nullifier_meta.as_mut() else {
					return Err(anyhow::anyhow!("notes nullifier metadata not initialized"));
				};
				if !is_log_after_cursor(log_key, meta) {
					debug!(job = ?job, log_key = ?log_key, "skipping already applied recovered batch");
					return Ok(false);
				}
				let current_root =
					contract::hash_to_bytes32(&self.notes_nullifier_state.current_root());
				if current_root != new_root {
					anyhow::ensure!(
						current_root == old_root,
						"notes nullifier replay divergence at log {:?}: local={:?} old={:?} new={:?}",
						log_key,
						current_root,
						old_root,
						new_root
					);
					let batch_start_index = self.notes_nullifier_state.tree.num_leaves();
					let commitments_bytes = dummy::pad_leaves(
						DummyTreeType::NotesNullifier,
						batch_start_index,
						batch_size,
						&real_commitments_bytes,
					)?;
					let commitments_hash: Vec<Hash> =
						contract::bytes_slice_to_hashes(&commitments_bytes)?;
					let proof = self
						.notes_nullifier_state
						.tree
						.insert_chained(commitments_hash)?;
					anyhow::ensure!(
						proof.verify(),
						"recovered notes nullifier proof verification failed"
					);
					anyhow::ensure!(
						proof.proofs.last().map(|p| p.new_root)
							== Some(contract::bytes32_to_hash(&new_root)?),
						"recovered notes nullifier root mismatch after apply"
					);
					meta.last_block = log_key.0;
					meta.last_tx_index = log_key.1;
					meta.last_log_index = log_key.2;
					if let Some(store) = self.notes_nullifier_store.as_mut() {
						store.commit_batch(
							&self.notes_nullifier_state.tree,
							meta,
							commitments_bytes,
						)?;
					}
				} else {
					meta.last_block = log_key.0;
					meta.last_tx_index = log_key.1;
					meta.last_log_index = log_key.2;
				}
			},
			TreeJob::AccountsCommitment => {
				let Some(meta) = self.accounts_commitment_meta.as_mut() else {
					return Err(anyhow::anyhow!(
						"accounts commitment metadata not initialized"
					));
				};
				if !is_log_after_cursor(log_key, meta) {
					debug!(job = ?job, log_key = ?log_key, "skipping already applied recovered batch");
					return Ok(false);
				}
				let current_root =
					contract::hash_to_bytes32(&self.accounts_commitment_state.current_root());
				if current_root != new_root {
					anyhow::ensure!(
						current_root == old_root,
						"accounts commitment replay divergence at log {:?}: local={:?} old={:?} new={:?}",
						log_key,
						current_root,
						old_root,
						new_root
					);
					let batch_start_index = self.accounts_commitment_state.tree.num_leaves();
					let commitments_bytes = dummy::pad_leaves(
						DummyTreeType::AccountsCommitment,
						batch_start_index,
						batch_size,
						&real_commitments_bytes,
					)?;
					let commitments_hash: Vec<Hash> =
						contract::bytes_slice_to_hashes(&commitments_bytes)?;
					let proof = self
						.accounts_commitment_state
						.tree
						.insert_batch(commitments_hash)?;
					anyhow::ensure!(
						proof.verify(),
						"recovered accounts commitment proof verification failed"
					);
					anyhow::ensure!(
						proof.root_new == contract::bytes32_to_hash(&new_root)?,
						"recovered accounts commitment root mismatch after apply"
					);
					meta.last_block = log_key.0;
					meta.last_tx_index = log_key.1;
					meta.last_log_index = log_key.2;
					if let Some(store) = self.accounts_commitment_store.as_mut() {
						store.commit_batch(
							&self.accounts_commitment_state.tree,
							meta,
							commitments_bytes,
						)?;
					}
				} else {
					meta.last_block = log_key.0;
					meta.last_tx_index = log_key.1;
					meta.last_log_index = log_key.2;
				}
			},
			TreeJob::AccountsNullifier => {
				let Some(meta) = self.accounts_nullifier_meta.as_mut() else {
					return Err(anyhow::anyhow!(
						"accounts nullifier metadata not initialized"
					));
				};
				if !is_log_after_cursor(log_key, meta) {
					debug!(job = ?job, log_key = ?log_key, "skipping already applied recovered batch");
					return Ok(false);
				}
				let current_root =
					contract::hash_to_bytes32(&self.accounts_nullifier_state.current_root());
				if current_root != new_root {
					anyhow::ensure!(
						current_root == old_root,
						"accounts nullifier replay divergence at log {:?}: local={:?} old={:?} new={:?}",
						log_key,
						current_root,
						old_root,
						new_root
					);
					let batch_start_index = self.accounts_nullifier_state.tree.num_leaves();
					let commitments_bytes = dummy::pad_leaves(
						DummyTreeType::AccountsNullifier,
						batch_start_index,
						batch_size,
						&real_commitments_bytes,
					)?;
					let commitments_hash: Vec<Hash> =
						contract::bytes_slice_to_hashes(&commitments_bytes)?;
					let proof = self
						.accounts_nullifier_state
						.tree
						.insert_chained(commitments_hash)?;
					anyhow::ensure!(
						proof.verify(),
						"recovered accounts nullifier proof verification failed"
					);
					anyhow::ensure!(
						proof.proofs.last().map(|p| p.new_root)
							== Some(contract::bytes32_to_hash(&new_root)?),
						"recovered accounts nullifier root mismatch after apply"
					);
					meta.last_block = log_key.0;
					meta.last_tx_index = log_key.1;
					meta.last_log_index = log_key.2;
					if let Some(store) = self.accounts_nullifier_store.as_mut() {
						store.commit_batch(
							&self.accounts_nullifier_state.tree,
							meta,
							commitments_bytes,
						)?;
					}
				} else {
					meta.last_block = log_key.0;
					meta.last_tx_index = log_key.1;
					meta.last_log_index = log_key.2;
				}
			},
		}
		Ok(true)
	}

	pub(super) async fn recover_pending_requests<P: Provider + Clone>(
		&mut self,
		provider: &P,
		note_batch_size: usize,
		account_batch_size: usize,
	) -> anyhow::Result<()> {
		let to_block = provider.get_block_number().await?;

		// Fetch all TransactionBatchRegistered events (paginated).
		let mut all_logs: Vec<Log> = Vec::new();
		let mut chunk_start = 0u64;
		while chunk_start <= to_block {
			let chunk_end = (chunk_start + Self::LOG_FETCH_CHUNK_BLOCKS - 1).min(to_block);
			let filter = Filter::new()
				.address(self.config.bridge_address)
				.event_signature(IDepositsRollupBridge::TransactionBatchRegistered::SIGNATURE_HASH)
				.from_block(chunk_start)
				.to_block(chunk_end);
			let logs = provider.get_logs(&filter).await?;
			debug!(
				from = chunk_start,
				to = chunk_end,
				count = logs.len(),
				"fetched TransactionBatchRegistered log page"
			);
			all_logs.extend(logs);
			chunk_start = chunk_end + 1;
		}
		all_logs.sort_by_key(log_order_key);

		if all_logs.is_empty() {
			info!("no TransactionBatchRegistered events found; nothing to recover");
			return Ok(());
		}
		info!(
			count = all_logs.len(),
			"fetched TransactionBatchRegistered events for pending-batch recovery"
		);

		let bridge = IDepositsRollupBridge::IDepositsRollupBridgeInstance::new(
			self.config.bridge_address,
			provider,
		);

		let mut recovered_pending = 0usize;
		let mut recovered_confirmed = 0usize;

		for log in &all_logs {
			let event = log.log_decode::<IDepositsRollupBridge::TransactionBatchRegistered>()?;
			let batch_id: u64 =
				event.inner.batchId.try_into().map_err(|_| {
					anyhow::anyhow!("batchId overflow in TransactionBatchRegistered")
				})?;

			// Query the on-chain slot to check if the batch is already confirmed.
			// If slot.batchId != batch_id the slot was freed (batch already confirmed).
			let slot_index = U256::from(batch_id % MAX_PENDING_BATCHES as u64);
			let slot = bridge.pendingBatches(slot_index).call().await?;
			let slot_batch_id: u64 = slot.batchId.try_into().unwrap_or(0);
			let confirmed: bool = slot_batch_id != batch_id || slot.confirmed;

			// Decode the registerTransactionBatchUpdate calldata to recover leaf data.
			let tx_hash = log.transaction_hash.ok_or_else(|| {
				anyhow::anyhow!("TransactionBatchRegistered log missing tx hash (batch {batch_id})")
			})?;
			let tx = provider
				.get_transaction_by_hash(tx_hash)
				.await?
				.ok_or_else(|| anyhow::anyhow!("tx not found: {tx_hash:?}"))?;
			let call = IDepositsRollupBridge::registerTransactionBatchUpdateCall::abi_decode(
				tx.input().as_ref(),
			)
			.map_err(|e| {
				anyhow::anyhow!(
					"abi_decode registerTransactionBatchUpdate for batch {batch_id}: {e}"
				)
			})?;

			let nc_real: Vec<[u8; 32]> = call
				.noteCommitmentsOut
				.into_iter()
				.map(Into::into)
				.collect();
			let nn_real: Vec<[u8; 32]> =
				call.noteNullifiersIn.into_iter().map(Into::into).collect();
			let ac_real: Vec<[u8; 32]> = call
				.accountCommitmentsOut
				.into_iter()
				.map(Into::into)
				.collect();
			let an_real: Vec<[u8; 32]> = call
				.accountNullifiersIn
				.into_iter()
				.map(Into::into)
				.collect();

			// Apply leaves to local trees (advancing state) and requeue prove jobs
			// for any trees not yet confirmed.  Confirmed batches are applied so that
			// subsequent pending batches build on the correct tree state.
			let is_pending = self.apply_and_requeue_pending_batch(
				batch_id,
				confirmed,
				nc_real,
				nn_real,
				ac_real,
				an_real,
				note_batch_size,
				account_batch_size,
			)?;

			if is_pending {
				recovered_pending += 1;
				info!(batch_id, confirmed, "recovered pending two-phase batch");
			} else {
				recovered_confirmed += 1;
				debug!(
					batch_id,
					"applied confirmed two-phase batch to advance local tree state"
				);
			}
		}

		info!(
			recovered_pending,
			recovered_confirmed, "two-phase batch recovery complete"
		);
		Ok(())
	}

	/// Apply the four trees' leaves for a registered two-phase batch to the local
	/// in-memory trees, advancing their roots.
	///
	/// If `confirmed` is `false` the batch is still pending: stores a `TxBatch`
	/// entry and submits a single [`ProveRequest`] covering all four trees.
	/// Returns `true` when the batch is pending, `false` when already fully confirmed.
	///
	/// **Note**: the original transaction proofs are not persisted across restarts.
	/// Recovered prove jobs use dummy proofs for all associated-input leaf slots.
	#[allow(clippy::too_many_arguments)]
	fn apply_and_requeue_pending_batch(
		&mut self,
		batch_id: u64,
		confirmed: bool,
		nc_real: Vec<[u8; 32]>,
		nn_real: Vec<[u8; 32]>,
		ac_real: Vec<[u8; 32]>,
		an_real: Vec<[u8; 32]>,
		note_batch_size: usize,
		account_batch_size: usize,
	) -> anyhow::Result<bool> {
		use crate::types::ProveRequest;

		// --- Notes commitment (tree 0) ---
		let nc_start = self.notes_commitment_state.tree.num_leaves();
		let nc_padded = dummy::pad_leaves(
			DummyTreeType::NotesCommitment,
			nc_start,
			note_batch_size,
			&nc_real,
		)?;
		let nc_hashes: Vec<Hash> = crate::contract::bytes_slice_to_hashes(&nc_padded)?;
		let nc_proof = self
			.notes_commitment_state
			.tree
			.insert_batch(nc_hashes.clone())?;
		anyhow::ensure!(
			nc_proof.verify(),
			"NC native proof failed during recovery (batch {batch_id})"
		);

		// --- Notes nullifier (tree 1) ---
		let nn_start = self.notes_nullifier_state.tree.num_leaves();
		let nn_padded = dummy::pad_leaves(
			DummyTreeType::NotesNullifier,
			nn_start,
			note_batch_size,
			&nn_real,
		)?;
		let nn_hashes: Vec<Hash> = crate::contract::bytes_slice_to_hashes(&nn_padded)?;
		let nn_proof = self
			.notes_nullifier_state
			.tree
			.insert_chained(nn_hashes.clone())?;
		anyhow::ensure!(
			nn_proof.verify(),
			"NN native proof failed during recovery (batch {batch_id})"
		);

		// --- Accounts commitment (tree 2) ---
		let ac_start = self.accounts_commitment_state.tree.num_leaves();
		let ac_padded = dummy::pad_leaves(
			DummyTreeType::AccountsCommitment,
			ac_start,
			account_batch_size,
			&ac_real,
		)?;
		let ac_hashes: Vec<Hash> = crate::contract::bytes_slice_to_hashes(&ac_padded)?;
		let ac_proof = self
			.accounts_commitment_state
			.tree
			.insert_batch(ac_hashes.clone())?;
		anyhow::ensure!(
			ac_proof.verify(),
			"AC native proof failed during recovery (batch {batch_id})"
		);

		// --- Accounts nullifier (tree 3) ---
		let an_start = self.accounts_nullifier_state.tree.num_leaves();
		let an_padded = dummy::pad_leaves(
			DummyTreeType::AccountsNullifier,
			an_start,
			account_batch_size,
			&an_real,
		)?;
		let an_hashes: Vec<Hash> = crate::contract::bytes_slice_to_hashes(&an_padded)?;
		let an_proof = self
			.accounts_nullifier_state
			.tree
			.insert_chained(an_hashes.clone())?;
		anyhow::ensure!(
			an_proof.verify(),
			"AN native proof failed during recovery (batch {batch_id})"
		);

		// Fully confirmed — trees advanced; no prove jobs needed.
		if confirmed {
			return Ok(false);
		}

		// Store TxBatch with the new flat per-tree fields.
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

		// Submit a single ProveRequest covering all four trees.
		// The original tx_proof bytes are not persisted; use dummy proofs for all slots.
		let associated_tx_proofs = vec![DUMMY_ASSOCIATED_INPUT_PROOF.to_vec(); account_batch_size];
		self.submit_prove_request_with_retry(ProveRequest {
			batch_id,
			notes_commitment_proof: nc_proof,
			notes_nullifier_proof: nn_proof,
			accounts_commitment_proof: ac_proof,
			accounts_nullifier_proof: an_proof,
			associated_tx_proofs,
		})?;

		Ok(true)
	}
}

fn log_order_key(log: &Log) -> (u64, u64, u64) {
	let block = log.block_number.unwrap_or_default();
	let tx = log.transaction_index.unwrap_or_default();
	let idx = log.log_index.unwrap_or_default();
	(block, tx, idx)
}

fn is_log_after_cursor(log_key: (u64, u64, u64), meta: &StoreMeta) -> bool {
	log_key > (meta.last_block, meta.last_tx_index, meta.last_log_index)
}
