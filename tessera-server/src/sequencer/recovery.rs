use std::path::Path;

use alloy::{
	consensus::Transaction as _,
	primitives::U256,
	rpc::types::{Filter, Log},
	sol_types::{SolCall, SolEvent},
};
use serde::{Deserialize, Serialize};
use tessera_trees::tree::hasher::HashOutput;
use tracing::{debug, info, warn};

use super::*;
use crate::{
	contract,
	dummy::{self, DummyTreeType},
	states::{SequencerTree, TreeState},
	tree_store::{StoreMeta, TreeId, TreeStore},
};

// ---------------------------------------------------------------------------
// Generic helpers (usable across pipeline.rs and recovery.rs)
// ---------------------------------------------------------------------------

/// Load one tree from its WAL + snapshot store, replaying any pending entries.
///
/// Unifies the repeated open → load → replay → fixup pattern used for all
/// four trees at startup.
pub(super) fn load_tree_from_store<T>(
	tree_store_path: &Path,
	tree_id: TreeId,
	tree_name: &str,
	snapshot_every_batches: u64,
	batch_size: usize,
) -> anyhow::Result<(T, TreeStore<T>, StoreMeta)>
where
	T: SequencerTree + Serialize + for<'de> Deserialize<'de> + Clone,
{
	let mut store = TreeStore::<T>::open(tree_store_path, tree_id, snapshot_every_batches)?;
	let (mut tree, meta0) = store.load_or_init(|| T::new_padded(TREE_DEPTH, batch_size))?;
	let (wal_pos, replayed) = store.replay_wal_since_snapshot(&mut tree, &meta0, |t, vals| {
		let hashes = contract::bytes_slice_to_hashes(&vals)?;
		t.insert_verified(hashes)?;
		Ok(())
	})?;
	tree.fixup_legacy_snapshot(meta0.snapshot_version);
	let mut meta = meta0.clone();
	meta.wal_pos = wal_pos;
	meta.committed_batches = meta.committed_batches.saturating_add(replayed);
	info!(
		tree = tree_name,
		replayed_batches = replayed,
		wal_pos,
		last_block = meta.last_block,
		last_tx_index = meta.last_tx_index,
		last_log_index = meta.last_log_index,
		"loaded local tree state from snapshot/WAL"
	);
	Ok((tree, store, meta))
}

/// Apply a recovered batch to one tree, verifying root transitions.
///
/// Replaces the four nearly-identical match arms previously in
/// `apply_recovered_batch`.
#[allow(clippy::too_many_arguments)]
fn apply_recovered_batch_for_tree<T>(
	state: &mut TreeState<T>,
	store: &mut Option<TreeStore<T>>,
	meta: &mut Option<StoreMeta>,
	dummy_type: DummyTreeType,
	tree_name: &str,
	old_root: alloy::primitives::FixedBytes<32>,
	new_root: alloy::primitives::FixedBytes<32>,
	batch_size: usize,
	real_commitments_bytes: &[[u8; 32]],
	log_key: (u64, u64, u64),
) -> anyhow::Result<bool>
where
	T: SequencerTree + Serialize + for<'de> Deserialize<'de> + Clone,
{
	let Some(meta) = meta.as_mut() else {
		return Err(anyhow::anyhow!("{tree_name} metadata not initialized"));
	};
	if !is_log_after_cursor(log_key, meta) {
		debug!(tree = tree_name, log_key = ?log_key, "skipping already applied recovered batch");
		return Ok(false);
	}
	let current_root = contract::hash_to_bytes32(&state.current_root());
	if current_root != new_root {
		anyhow::ensure!(
			current_root == old_root,
			"{tree_name} replay divergence at log {log_key:?}: \
			 local={current_root:?} old={old_root:?} new={new_root:?}"
		);
		let batch_start_index = state.tree.num_leaves();
		let commitments_bytes = dummy::pad_leaves(
			dummy_type,
			batch_start_index,
			batch_size,
			real_commitments_bytes,
		)?;
		let commitments_hash: Vec<HashOutput> =
			contract::bytes_slice_to_hashes(&commitments_bytes)?;
		let actual_root = state.tree.insert_verified(commitments_hash)?;
		anyhow::ensure!(
			actual_root == contract::bytes32_to_hash(&new_root)?,
			"recovered {tree_name} root mismatch after apply"
		);
		update_meta_cursor(meta, log_key);
		if let Some(store) = store.as_mut() {
			store.commit_batch(&state.tree, meta, commitments_bytes)?;
		}
	} else {
		update_meta_cursor(meta, log_key);
	}
	Ok(true)
}

/// Commit one tree's batch to its WAL/snapshot store.
pub(super) fn commit_tree_batch<T>(
	state: &TreeState<T>,
	store: &mut Option<TreeStore<T>>,
	meta: &mut Option<StoreMeta>,
	values: Vec<[u8; 32]>,
) -> anyhow::Result<()>
where
	T: SequencerTree + Serialize + for<'de> Deserialize<'de> + Clone,
{
	if let (Some(store), Some(meta)) = (store.as_mut(), meta.as_mut()) {
		store.commit_batch(&state.tree, meta, values)?;
	}
	Ok(())
}

/// Force a checkpoint for one tree's store.
pub(super) fn checkpoint_tree<T>(
	state: &TreeState<T>,
	store: &Option<TreeStore<T>>,
	meta: &Option<StoreMeta>,
) -> anyhow::Result<()>
where
	T: SequencerTree + Serialize + for<'de> Deserialize<'de> + Clone,
{
	if let (Some(store), Some(meta)) = (store.as_ref(), meta.as_ref()) {
		store.force_checkpoint(&state.tree, meta)?;
	}
	Ok(())
}

fn update_meta_cursor(meta: &mut StoreMeta, log_key: (u64, u64, u64)) {
	meta.last_block = log_key.0;
	meta.last_tx_index = log_key.1;
	meta.last_log_index = log_key.2;
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

// ---------------------------------------------------------------------------
// Sequencer recovery methods
// ---------------------------------------------------------------------------

impl Sequencer {
	/// Maximum block range per `eth_getLogs` call.
	const LOG_FETCH_CHUNK_BLOCKS: u64 = 1_000;

	pub(super) fn load_other_trees(
		&mut self,
		note_batch_size: usize,
		account_batch_size: usize,
	) -> anyhow::Result<()> {
		let (tree, store, meta) = load_tree_from_store::<NullifierTree<HashOutput>>(
			&self.config.tree_store_path,
			TreeId::NotesNullifier,
			"notes_nullifier",
			self.config.snapshot_every_batches,
			note_batch_size,
		)?;
		self.notes_nullifier_state.tree = tree;
		self.notes_nullifier_store = Some(store);
		self.notes_nullifier_meta = Some(meta);

		let (tree, store, meta) = load_tree_from_store::<CommitmentTree<HashOutput>>(
			&self.config.tree_store_path,
			TreeId::AccountsCommitment,
			"accounts_commitment",
			self.config.snapshot_every_batches,
			account_batch_size,
		)?;
		self.accounts_commitment_state.tree = tree;
		self.accounts_commitment_store = Some(store);
		self.accounts_commitment_meta = Some(meta);

		let (tree, store, meta) = load_tree_from_store::<NullifierTree<HashOutput>>(
			&self.config.tree_store_path,
			TreeId::AccountsNullifier,
			"accounts_nullifier",
			self.config.snapshot_every_batches,
			account_batch_size,
		)?;
		self.accounts_nullifier_state.tree = tree;
		self.accounts_nullifier_store = Some(store);
		self.accounts_nullifier_meta = Some(meta);

		Ok(())
	}

	pub(super) async fn recover_missing_chain_updates<P: Provider + Clone>(
		&mut self,
		provider: &P,
		on_chain_nc_root: &alloy::primitives::FixedBytes<32>,
		on_chain_nn_root: &alloy::primitives::FixedBytes<32>,
		on_chain_ac_root: &alloy::primitives::FixedBytes<32>,
		on_chain_an_root: &alloy::primitives::FixedBytes<32>,
	) -> anyhow::Result<()> {
		let local_nc = contract::hash_to_bytes32(&self.notes_commitment_state.current_root());
		let local_nn = contract::hash_to_bytes32(&self.notes_nullifier_state.current_root());
		let local_ac = contract::hash_to_bytes32(&self.accounts_commitment_state.current_root());
		let local_an = contract::hash_to_bytes32(&self.accounts_nullifier_state.current_root());

		if local_nc == *on_chain_nc_root
			&& local_nn == *on_chain_nn_root
			&& local_ac == *on_chain_ac_root
			&& local_an == *on_chain_an_root
		{
			info!("local tree roots already match chain; no chain recovery needed");
			return Ok(());
		}
		info!(
			?local_nc,
			?local_nn,
			?local_ac,
			?local_an,
			?on_chain_nc_root,
			?on_chain_nn_root,
			?on_chain_ac_root,
			?on_chain_an_root,
			"local state behind chain, starting chain recovery replay"
		);

		let from_block = [
			self.notes_commitment_meta.as_ref(),
			self.notes_nullifier_meta.as_ref(),
			self.accounts_commitment_meta.as_ref(),
			self.accounts_nullifier_meta.as_ref(),
		]
		.iter()
		.filter_map(|m| m.map(|m| m.last_block))
		.min()
		.unwrap_or(0);

		let to_block = provider.get_block_number().await?;
		let validated_logs = self
			.fetch_paginated_logs(
				provider,
				IDepositsRollupBridge::ValidatedBatchFinalized::SIGNATURE_HASH,
				from_block,
				to_block,
				"ValidatedBatchFinalized",
			)
			.await?;
		info!(
			from_block,
			to_block,
			logs = validated_logs.len(),
			"fetched ValidatedBatchFinalized logs for recovery"
		);

		let mut processed_count: u64 = 0;
		let mut processed_any = false;
		for log in validated_logs {
			let key = log_order_key(&log);
			let decoded = log.log_decode::<IDepositsRollupBridge::ValidatedBatchFinalized>()?;

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
				warn!(tx_hash = ?tx_hash, job = ?job, "could not decode leaves from tx calldata; skipping");
				continue;
			};
			debug!(
				tx_hash = ?tx_hash,
				job = ?job,
				leaves = commitments_bytes.len(),
				log_key = ?key,
				"decoded recovered batch from on-chain tx input"
			);

			let batch_size: usize = decoded
				.inner
				.effectiveBatchSize
				.try_into()
				.map_err(|_| anyhow::anyhow!("effectiveBatchSize too large in event"))?;

			let changed = self.apply_recovered_batch(
				job,
				decoded.inner.oldRoot,
				decoded.inner.newRoot,
				batch_size,
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

		// Verify all four local roots match chain after replay.
		let verify = |name: &str,
		              on_chain: &alloy::primitives::FixedBytes<32>,
		              local: alloy::primitives::FixedBytes<32>|
		 -> anyhow::Result<()> {
			anyhow::ensure!(
				*on_chain == local,
				"{name} mismatch after replay: on-chain={on_chain:?}, local={local:?}"
			);
			Ok(())
		};
		verify(
			"notesCommitmentRoot",
			on_chain_nc_root,
			contract::hash_to_bytes32(&self.notes_commitment_state.current_root()),
		)?;
		verify(
			"notesNullifierRoot",
			on_chain_nn_root,
			contract::hash_to_bytes32(&self.notes_nullifier_state.current_root()),
		)?;
		verify(
			"accountsCommitmentRoot",
			on_chain_ac_root,
			contract::hash_to_bytes32(&self.accounts_commitment_state.current_root()),
		)?;
		verify(
			"accountsNullifierRoot",
			on_chain_an_root,
			contract::hash_to_bytes32(&self.accounts_nullifier_state.current_root()),
		)?;

		if processed_any {
			checkpoint_tree(
				&self.notes_commitment_state,
				&self.notes_commitment_store,
				&self.notes_commitment_meta,
			)?;
			checkpoint_tree(
				&self.notes_nullifier_state,
				&self.notes_nullifier_store,
				&self.notes_nullifier_meta,
			)?;
			checkpoint_tree(
				&self.accounts_commitment_state,
				&self.accounts_commitment_store,
				&self.accounts_commitment_meta,
			)?;
			checkpoint_tree(
				&self.accounts_nullifier_state,
				&self.accounts_nullifier_store,
				&self.accounts_nullifier_meta,
			)?;
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
			TreeJob::NotesCommitment => apply_recovered_batch_for_tree(
				&mut self.notes_commitment_state,
				&mut self.notes_commitment_store,
				&mut self.notes_commitment_meta,
				DummyTreeType::NotesCommitment,
				"notes_commitment",
				old_root,
				new_root,
				batch_size,
				&real_commitments_bytes,
				log_key,
			),
			TreeJob::NotesNullifier => apply_recovered_batch_for_tree(
				&mut self.notes_nullifier_state,
				&mut self.notes_nullifier_store,
				&mut self.notes_nullifier_meta,
				DummyTreeType::NotesNullifier,
				"notes_nullifier",
				old_root,
				new_root,
				batch_size,
				&real_commitments_bytes,
				log_key,
			),
			TreeJob::AccountsCommitment => apply_recovered_batch_for_tree(
				&mut self.accounts_commitment_state,
				&mut self.accounts_commitment_store,
				&mut self.accounts_commitment_meta,
				DummyTreeType::AccountsCommitment,
				"accounts_commitment",
				old_root,
				new_root,
				batch_size,
				&real_commitments_bytes,
				log_key,
			),
			TreeJob::AccountsNullifier => apply_recovered_batch_for_tree(
				&mut self.accounts_nullifier_state,
				&mut self.accounts_nullifier_store,
				&mut self.accounts_nullifier_meta,
				DummyTreeType::AccountsNullifier,
				"accounts_nullifier",
				old_root,
				new_root,
				batch_size,
				&real_commitments_bytes,
				log_key,
			),
		}
	}

	pub(super) async fn recover_pending_requests<P: Provider + Clone>(
		&mut self,
		provider: &P,
		note_batch_size: usize,
		account_batch_size: usize,
	) -> anyhow::Result<()> {
		let to_block = provider.get_block_number().await?;

		let all_logs = self
			.fetch_paginated_logs(
				provider,
				IDepositsRollupBridge::TransactionBatchRegistered::SIGNATURE_HASH,
				0,
				to_block,
				"TransactionBatchRegistered",
			)
			.await?;

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

			let slot_index = U256::from(batch_id % MAX_PENDING_BATCHES as u64);
			let slot = bridge.pendingBatches(slot_index).call().await?;
			let slot_batch_id: u64 = slot.batchId.try_into().unwrap_or(0);
			let confirmed: bool = slot_batch_id != batch_id || slot.confirmed;

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

		let (mut nc_padded, _) = build_proving_commitments(
			DummyTreeType::NotesCommitment,
			self.notes_commitment_state.tree.num_leaves(),
			note_batch_size,
			&nc_real,
		)?;
		nc_padded.sort();
		let nc_hashes = contract::bytes_slice_to_hashes(&nc_padded)?;
		let nc_proof = self
			.notes_commitment_state
			.tree
			.insert_batch(nc_hashes.clone())?;
		anyhow::ensure!(
			nc_proof.verify(),
			"NC native proof failed during recovery (batch {batch_id})"
		);

		let (mut nn_padded, _) = build_proving_commitments(
			DummyTreeType::NotesNullifier,
			self.notes_nullifier_state.tree.num_leaves(),
			note_batch_size,
			&nn_real,
		)?;
		nn_padded.sort();
		let nn_hashes = contract::bytes_slice_to_hashes(&nn_padded)?;
		let nn_proof = self
			.notes_nullifier_state
			.tree
			.insert_batch(nn_hashes.clone())?;
		anyhow::ensure!(
			nn_proof.verify(),
			"NN native proof failed during recovery (batch {batch_id})"
		);

		let (mut ac_padded, _) = build_proving_commitments(
			DummyTreeType::AccountsCommitment,
			self.accounts_commitment_state.tree.num_leaves(),
			account_batch_size,
			&ac_real,
		)?;
		ac_padded.sort();
		let ac_hashes = contract::bytes_slice_to_hashes(&ac_padded)?;
		let ac_proof = self
			.accounts_commitment_state
			.tree
			.insert_batch(ac_hashes.clone())?;
		anyhow::ensure!(
			ac_proof.verify(),
			"AC native proof failed during recovery (batch {batch_id})"
		);

		let (mut an_padded, _) = build_proving_commitments(
			DummyTreeType::AccountsNullifier,
			self.accounts_nullifier_state.tree.num_leaves(),
			account_batch_size,
			&an_real,
		)?;
		an_padded.sort();
		let an_hashes = contract::bytes_slice_to_hashes(&an_padded)?;
		let an_proof = self
			.accounts_nullifier_state
			.tree
			.insert_batch(an_hashes.clone())?;
		anyhow::ensure!(
			an_proof.verify(),
			"AN native proof failed during recovery (batch {batch_id})"
		);

		// Fully confirmed — trees advanced; no prove jobs needed.
		if confirmed {
			return Ok(false);
		}

		// Store TxBatch and submit prove job.
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

		self.submit_prove_request_with_retry(ProveRequest {
			batch_id,
			notes_commitment_proof: nc_proof,
			notes_nullifier_proof: nn_proof,
			accounts_commitment_proof: ac_proof,
			accounts_nullifier_proof: an_proof,
			nc_sorted_leaves: self.registered_pending_batches[&batch_id]
				.nc_batch
				.proving_commitments_bytes
				.clone(),
			nn_sorted_leaves: self.registered_pending_batches[&batch_id]
				.nn_batch
				.proving_commitments_bytes
				.clone(),
			ac_sorted_leaves: self.registered_pending_batches[&batch_id]
				.ac_batch
				.proving_commitments_bytes
				.clone(),
			an_sorted_leaves: self.registered_pending_batches[&batch_id]
				.an_batch
				.proving_commitments_bytes
				.clone(),
			real_account_slots: vec![], // recovery: treat all as dummy
			tx_proofs_by_slot: std::collections::HashMap::new(),
		})?;

		Ok(true)
	}

	/// Fetch paginated event logs for a given event signature.
	async fn fetch_paginated_logs<P: Provider + Clone>(
		&self,
		provider: &P,
		event_sig: alloy::primitives::B256,
		from_block: u64,
		to_block: u64,
		event_name: &str,
	) -> anyhow::Result<Vec<Log>> {
		let mut all_logs: Vec<Log> = Vec::new();
		let mut chunk_start = from_block;
		while chunk_start <= to_block {
			let chunk_end = (chunk_start + Self::LOG_FETCH_CHUNK_BLOCKS - 1).min(to_block);
			let filter = Filter::new()
				.address(self.config.bridge_address)
				.event_signature(event_sig)
				.from_block(chunk_start)
				.to_block(chunk_end);
			let chunk = provider.get_logs(&filter).await?;
			debug!(
				from = chunk_start,
				to = chunk_end,
				count = chunk.len(),
				event = event_name,
				"fetched log page"
			);
			all_logs.extend(chunk);
			chunk_start = chunk_end + 1;
		}
		all_logs.sort_by_key(log_order_key);
		Ok(all_logs)
	}
}
