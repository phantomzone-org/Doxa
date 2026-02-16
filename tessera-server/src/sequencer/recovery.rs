use super::*;
use alloy::{
	consensus::Transaction as _,
	rpc::types::{Filter, Log},
	sol_types::{SolCall, SolEvent},
};
use tracing::{debug, info, warn};

impl Sequencer {
	pub(super) fn load_other_trees(&mut self) -> anyhow::Result<()> {
		{
			let mut store = TreeStore::<NullifierTree<Hash>>::open(
				&self.config.tree_store_path,
				TreeId::NotesNullifier,
				self.config.snapshot_every_batches,
			)?;
			let (mut tree, meta0) = store.load_or_init(|| NullifierTree::new(TREE_DEPTH))?;
			let (wal_pos, replayed) = store.replay_wal_since_snapshot(&mut tree, &meta0, |t, vals| {
				let values: Vec<Hash> = vals
					.into_iter()
					.map(|b| contract::bytes32_to_hash(&alloy::primitives::B256::from(b)))
					.collect();
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
			let (wal_pos, replayed) = store.replay_wal_since_snapshot(&mut tree, &meta0, |t, vals| {
				let leaves: Vec<Hash> = vals
					.into_iter()
					.map(|b| contract::bytes32_to_hash(&alloy::primitives::B256::from(b)))
					.collect();
				let proof = t.insert_batch(leaves)?;
				anyhow::ensure!(proof.verify(), "WAL replay produced invalid proof");
				Ok(())
			})?;
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
			let (wal_pos, replayed) = store.replay_wal_since_snapshot(&mut tree, &meta0, |t, vals| {
				let values: Vec<Hash> = vals
					.into_iter()
					.map(|b| contract::bytes32_to_hash(&alloy::primitives::B256::from(b)))
					.collect();
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

		let validated_filter = Filter::new()
			.address(self.config.bridge_address)
			.event_signature(IDepositsRollupBridge::ValidatedBatchFinalized::SIGNATURE_HASH)
			.from_block(from_block);
		let mut validated_logs = provider.get_logs(&validated_filter).await?;
		validated_logs.sort_by_key(log_order_key);
		info!(
			from_block,
			logs = validated_logs.len(),
			"fetched ValidatedBatchFinalized logs for recovery"
		);

		let mut processed_any = false;
		let mut processed_count: u64 = 0;
		for log in validated_logs {
			let key = log_order_key(&log);
			let decoded = log.log_decode::<IDepositsRollupBridge::ValidatedBatchFinalized>()?;

			let tx_hash = log
				.transaction_hash
				.ok_or_else(|| anyhow::anyhow!("ValidatedBatchFinalized log missing transaction hash"))?;
			let tx = provider
				.get_transaction_by_hash(tx_hash)
				.await?
				.ok_or_else(|| anyhow::anyhow!("transaction not found for hash {tx_hash:?}"))?;
			let Some((job, commitments_bytes)) =
				self.decode_tree_job_from_tx_input(tx.input().as_ref())?
			else {
				warn!(tx_hash = ?tx_hash, "unrecognized tx calldata for ValidatedBatchFinalized; skipping");
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

	fn decode_tree_job_from_tx_input(
		&self,
		input: &[u8],
	) -> anyhow::Result<Option<(TreeJob, Vec<[u8; 32]>)>> {
		if let Ok(call) = IDepositsRollupBridge::executeValidateDepositBatchCall::abi_decode(input)
		{
			let leaves = call.noteCommitments.into_iter().map(Into::into).collect();
			return Ok(Some((TreeJob::NotesCommitment, leaves)));
		}
		if let Ok(call) = IDepositsRollupBridge::validateDepositBatchCall::abi_decode(input) {
			let leaves = call.noteCommitments.into_iter().map(Into::into).collect();
			return Ok(Some((TreeJob::NotesCommitment, leaves)));
		}
		if let Ok(call) = IDepositsRollupBridge::recordNotesNullifierTreeUpdateCall::abi_decode(input)
		{
			let leaves = call.noteCommitments.into_iter().map(Into::into).collect();
			return Ok(Some((TreeJob::NotesNullifier, leaves)));
		}
		if let Ok(call) =
			IDepositsRollupBridge::recordAccountsCommitmentTreeUpdateCall::abi_decode(input)
		{
			let leaves = call.accountCommitments.into_iter().map(Into::into).collect();
			return Ok(Some((TreeJob::AccountsCommitment, leaves)));
		}
		if let Ok(call) =
			IDepositsRollupBridge::recordAccountsNullifierTreeUpdateCall::abi_decode(input)
		{
			let leaves = call.accountCommitments.into_iter().map(Into::into).collect();
			return Ok(Some((TreeJob::AccountsNullifier, leaves)));
		}
		Ok(None)
	}

	fn apply_recovered_batch(
		&mut self,
		job: TreeJob,
		old_root: alloy::primitives::FixedBytes<32>,
		new_root: alloy::primitives::FixedBytes<32>,
		commitments_bytes: Vec<[u8; 32]>,
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
				let current_root = contract::hash_to_bytes32(&self.notes_commitment_state.current_root());
				if current_root != new_root {
					anyhow::ensure!(
						current_root == old_root,
						"notes commitment replay divergence at log {:?}: local={:?} old={:?} new={:?}",
						log_key,
						current_root,
						old_root,
						new_root
					);
					let commitments_hash: Vec<Hash> = commitments_bytes
						.iter()
						.map(|b| contract::bytes32_to_hash(&alloy::primitives::B256::from(*b)))
						.collect();
					let proof = self.notes_commitment_state.tree.insert_batch(commitments_hash)?;
					anyhow::ensure!(proof.verify(), "recovered notes commitment proof verification failed");
					anyhow::ensure!(
						proof.root_new == contract::bytes32_to_hash(&new_root),
						"recovered notes commitment root mismatch after apply"
					);
					meta.last_block = log_key.0;
					meta.last_tx_index = log_key.1;
					meta.last_log_index = log_key.2;
					if let Some(store) = self.notes_commitment_store.as_mut() {
						store.commit_batch(&self.notes_commitment_state.tree, meta, commitments_bytes)?;
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
				let current_root = contract::hash_to_bytes32(&self.notes_nullifier_state.current_root());
				if current_root != new_root {
					anyhow::ensure!(
						current_root == old_root,
						"notes nullifier replay divergence at log {:?}: local={:?} old={:?} new={:?}",
						log_key,
						current_root,
						old_root,
						new_root
					);
					let commitments_hash: Vec<Hash> = commitments_bytes
						.iter()
						.map(|b| contract::bytes32_to_hash(&alloy::primitives::B256::from(*b)))
						.collect();
					let proof = self.notes_nullifier_state.tree.insert_chained(commitments_hash)?;
					anyhow::ensure!(proof.verify(), "recovered notes nullifier proof verification failed");
					anyhow::ensure!(
						proof.proofs.last().map(|p| p.new_root) == Some(contract::bytes32_to_hash(&new_root)),
						"recovered notes nullifier root mismatch after apply"
					);
					meta.last_block = log_key.0;
					meta.last_tx_index = log_key.1;
					meta.last_log_index = log_key.2;
					if let Some(store) = self.notes_nullifier_store.as_mut() {
						store.commit_batch(&self.notes_nullifier_state.tree, meta, commitments_bytes)?;
					}
				} else {
					meta.last_block = log_key.0;
					meta.last_tx_index = log_key.1;
					meta.last_log_index = log_key.2;
				}
			},
			TreeJob::AccountsCommitment => {
				let Some(meta) = self.accounts_commitment_meta.as_mut() else {
					return Err(anyhow::anyhow!("accounts commitment metadata not initialized"));
				};
				if !is_log_after_cursor(log_key, meta) {
					debug!(job = ?job, log_key = ?log_key, "skipping already applied recovered batch");
					return Ok(false);
				}
				let current_root = contract::hash_to_bytes32(&self.accounts_commitment_state.current_root());
				if current_root != new_root {
					anyhow::ensure!(
						current_root == old_root,
						"accounts commitment replay divergence at log {:?}: local={:?} old={:?} new={:?}",
						log_key,
						current_root,
						old_root,
						new_root
					);
					let commitments_hash: Vec<Hash> = commitments_bytes
						.iter()
						.map(|b| contract::bytes32_to_hash(&alloy::primitives::B256::from(*b)))
						.collect();
					let proof = self.accounts_commitment_state.tree.insert_batch(commitments_hash)?;
					anyhow::ensure!(proof.verify(), "recovered accounts commitment proof verification failed");
					anyhow::ensure!(
						proof.root_new == contract::bytes32_to_hash(&new_root),
						"recovered accounts commitment root mismatch after apply"
					);
					meta.last_block = log_key.0;
					meta.last_tx_index = log_key.1;
					meta.last_log_index = log_key.2;
					if let Some(store) = self.accounts_commitment_store.as_mut() {
						store.commit_batch(&self.accounts_commitment_state.tree, meta, commitments_bytes)?;
					}
				} else {
					meta.last_block = log_key.0;
					meta.last_tx_index = log_key.1;
					meta.last_log_index = log_key.2;
				}
			},
			TreeJob::AccountsNullifier => {
				let Some(meta) = self.accounts_nullifier_meta.as_mut() else {
					return Err(anyhow::anyhow!("accounts nullifier metadata not initialized"));
				};
				if !is_log_after_cursor(log_key, meta) {
					debug!(job = ?job, log_key = ?log_key, "skipping already applied recovered batch");
					return Ok(false);
				}
				let current_root = contract::hash_to_bytes32(&self.accounts_nullifier_state.current_root());
				if current_root != new_root {
					anyhow::ensure!(
						current_root == old_root,
						"accounts nullifier replay divergence at log {:?}: local={:?} old={:?} new={:?}",
						log_key,
						current_root,
						old_root,
						new_root
					);
					let commitments_hash: Vec<Hash> = commitments_bytes
						.iter()
						.map(|b| contract::bytes32_to_hash(&alloy::primitives::B256::from(*b)))
						.collect();
					let proof = self.accounts_nullifier_state.tree.insert_chained(commitments_hash)?;
					anyhow::ensure!(proof.verify(), "recovered accounts nullifier proof verification failed");
					anyhow::ensure!(
						proof.proofs.last().map(|p| p.new_root) == Some(contract::bytes32_to_hash(&new_root)),
						"recovered accounts nullifier root mismatch after apply"
					);
					meta.last_block = log_key.0;
					meta.last_tx_index = log_key.1;
					meta.last_log_index = log_key.2;
					if let Some(store) = self.accounts_nullifier_store.as_mut() {
						store.commit_batch(&self.accounts_nullifier_state.tree, meta, commitments_bytes)?;
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
		_provider: &P,
		_batch_size: usize,
	) -> anyhow::Result<()> {
		Ok(())
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
