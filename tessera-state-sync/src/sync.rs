use std::collections::HashMap;

use alloy::{
	primitives::{Address, B256},
	providers::Provider,
	rpc::types::{Filter, Log},
	sol_types::SolEvent,
};
use anyhow::Context;
use plonky2_field::types::Field;
use tessera_utils::hasher::{HashOutput, MerkleHash};
use tracing::{debug, info, warn};

use crate::{
	constants::*,
	contract::{self, ITesseraRollupV2},
	state::*,
};

// ── StateSyncService impl (public API) ────────────────────────────────────────

impl StateSyncService {
	/// Build a StateSyncService by replaying every confirmed batch from genesis to latest block.
	pub async fn sync_from_genesis<P: Provider + Clone>(
		provider: P,
		address: Address,
		chunk_blocks: u64,
	) -> anyhow::Result<Self> {
		let genesis_block: u64 = std::env::var("TESSERA_GENESIS_BLOCK")
			.ok()
			.and_then(|s| s.parse().ok())
			.unwrap_or(0);

		let latest_block = provider
			.get_block_number()
			.await
			.context("failed to get latest block number")?;

		info!(
			"Starting genesis sync from block {} to {}",
			genesis_block, latest_block
		);

		// Fetch tree parameters
		let tree_depth = fetch_tree_depth(&provider, address).await?;
		let config_tree_depth = fetch_config_tree_depth(&provider, address).await?;
		info!(
			"Tree depths: state={}, config={}",
			tree_depth, config_tree_depth
		);
		anyhow::ensure!(
			config_tree_depth == tessera_client::MAIN_POOL_CONFIG_DEPTH,
			"on-chain configTreeDepth={} != MAIN_POOL_CONFIG_DEPTH={}",
			config_tree_depth,
			tessera_client::MAIN_POOL_CONFIG_DEPTH
		);

		let service = Self::new(tree_depth);

		// Process submissions and proven batches using consistent approach
		process_new_submissions(
			&provider,
			address,
			genesis_block,
			latest_block,
			chunk_blocks,
			&service,
		)
		.await?;

		// Collect and replay proven batches
		let mut proven_batches = collect_proven_batches(
			&provider,
			address,
			genesis_block,
			latest_block,
			chunk_blocks,
		)
		.await?;
		proven_batches.sort_by_key(|b| b.leaf_index);

		info!(
			total_proven_batches = proven_batches.len(),
			"Replaying proven batches"
		);

		for entry in &proven_batches {
			// Check if preimage is already in state from a previous submission event
			let preimage_known = service.with_state(|s| {
				s.pending_tx_batches.contains_key(&entry.pi_commitment.0)
					|| s.pending_bridge_tx_batches
						.contains_key(&entry.pi_commitment.0)
			});

			if !preimage_known {
				// Fallback: submission was in an earlier block window; do targeted search
				let tx_hash = find_submission_tx_hash(
					&provider,
					address,
					match entry.kind {
						BatchKind::Transaction => {
							ITesseraRollupV2::TransactionBatchSubmitted::SIGNATURE_HASH
						},
						BatchKind::BridgeTx => {
							ITesseraRollupV2::BridgeTxBatchSubmitted::SIGNATURE_HASH
						},
					},
					entry.pi_commitment,
					genesis_block,
					latest_block,
					chunk_blocks,
					match entry.kind {
						BatchKind::Transaction => "TransactionBatchSubmitted",
						BatchKind::BridgeTx => "BridgeTxBatchSubmitted",
					},
				)
				.await?;
				let input = fetch_transaction_input(&provider, tx_hash).await?;
				match entry.kind {
					BatchKind::Transaction => {
						let preimage = decode_tx_batch_calldata(&input)?;
						apply_tx_preimage(&preimage, entry.pi_commitment.0, &service)?;
					},
					BatchKind::BridgeTx => {
						let preimage = decode_bridge_batch_calldata(&input)?;
						apply_bridge_preimage(&preimage, entry.pi_commitment.0, &service)?;
					},
				}
			}

			// Confirm the batch
			let batch_root = service
				.with_state(|s| {
					let batches = match entry.kind {
						BatchKind::Transaction => &s.pending_tx_batches,
						BatchKind::BridgeTx => &s.pending_bridge_tx_batches,
					};
					batches
						.get(&entry.pi_commitment.0)
						.map(|p| extract_batch_root_from_preimage(p, entry.kind))
				})
				.transpose()?;

			if let Some(batch_root) = batch_root {
				service.with_state_mut(|s| {
					s.confirm_batch(entry.pi_commitment.0, batch_root, entry.new_tree_root)
				})?;
			}
		}

		// Sync config tree
		sync_config_tree(
			&provider,
			address,
			genesis_block,
			latest_block,
			chunk_blocks,
			&service,
			genesis_block,
		)
		.await?;

		// Sync deposits
		sync_deposits(
			&provider,
			address,
			genesis_block,
			latest_block,
			chunk_blocks,
			&service,
		)
		.await?;

		// Update last synced block
		service.with_state_mut(|state| {
			state.last_synced_block = latest_block;
		});

		verify_leaf_count(&provider, address, &service).await;

		Ok(service)
	}

	/// Poll for new events and apply them to the state.
	pub async fn poll_sync<P: Provider + Clone>(
		&self,
		provider: P,
		address: Address,
		chunk_blocks: u64,
	) -> anyhow::Result<()> {
		let genesis_block: u64 = std::env::var("TESSERA_GENESIS_BLOCK")
			.ok()
			.and_then(|s| s.parse().ok())
			.unwrap_or(0);
		let from_block = self.with_state(|state| state.last_synced_block);
		let to_block = provider
			.get_block_number()
			.await
			.context("failed to get latest block number")?;

		if to_block <= from_block {
			return Ok(()); // No new blocks
		}

		debug!("Polling sync from block {} to {}", from_block + 1, to_block);

		// Step 1: process new submission events immediately
		process_new_submissions(
			&provider,
			address,
			from_block + 1,
			to_block,
			chunk_blocks,
			self,
		)
		.await?;

		// Step 2: collect and apply proven batches
		let mut proven =
			collect_proven_batches(&provider, address, from_block + 1, to_block, chunk_blocks)
				.await?;
		proven.sort_by_key(|b| b.leaf_index);

		for entry in &proven {
			// Check if preimage is already in state from a previous submission event
			let preimage_known = self.with_state(|s| {
				s.pending_tx_batches.contains_key(&entry.pi_commitment.0)
					|| s.pending_bridge_tx_batches
						.contains_key(&entry.pi_commitment.0)
			});

			if !preimage_known {
				// Fallback: submission was in an earlier block window; do targeted search
				let tx_hash = find_submission_tx_hash(
					&provider,
					address,
					match entry.kind {
						BatchKind::Transaction => {
							ITesseraRollupV2::TransactionBatchSubmitted::SIGNATURE_HASH
						},
						BatchKind::BridgeTx => {
							ITesseraRollupV2::BridgeTxBatchSubmitted::SIGNATURE_HASH
						},
					},
					entry.pi_commitment,
					genesis_block,
					from_block,
					chunk_blocks,
					match entry.kind {
						BatchKind::Transaction => "TransactionBatchSubmitted",
						BatchKind::BridgeTx => "BridgeTxBatchSubmitted",
					},
				)
				.await?;
				let input = fetch_transaction_input(&provider, tx_hash).await?;
				match entry.kind {
					BatchKind::Transaction => {
						let preimage = decode_tx_batch_calldata(&input)?;
						apply_tx_preimage(&preimage, entry.pi_commitment.0, self)?;
					},
					BatchKind::BridgeTx => {
						let preimage = decode_bridge_batch_calldata(&input)?;
						apply_bridge_preimage(&preimage, entry.pi_commitment.0, self)?;
					},
				}
			}

			// Confirm the batch
			let batch_root = self
				.with_state(|s| {
					let batches = match entry.kind {
						BatchKind::Transaction => &s.pending_tx_batches,
						BatchKind::BridgeTx => &s.pending_bridge_tx_batches,
					};
					batches
						.get(&entry.pi_commitment.0)
						.map(|p| extract_batch_root_from_preimage(p, entry.kind))
				})
				.transpose()?;

			if let Some(batch_root) = batch_root {
				self.with_state_mut(|s| {
					s.confirm_batch(entry.pi_commitment.0, batch_root, entry.new_tree_root)
				})?;
			}
		}

		// Step 3: config tree and deposits
		sync_config_tree(
			&provider,
			address,
			from_block + 1,
			to_block,
			chunk_blocks,
			self,
			0,
		)
		.await?;
		sync_deposits(
			&provider,
			address,
			from_block + 1,
			to_block,
			chunk_blocks,
			self,
		)
		.await?;

		self.with_state_mut(|s| s.last_synced_block = to_block);
		Ok(())
	}
}

// ── Internal types ────────────────────────────────────────────────────────────

pub struct ProvenBatchEntry {
	pub pi_commitment: B256,
	pub new_tree_root: HashOutput,
	pub leaf_index: u64,
	pub kind: BatchKind,
}

// ── Genesis / poll orchestration helpers ────────────────────────────────────────

async fn process_new_submissions<P: Provider + Clone>(
	provider: &P,
	address: Address,
	from_block: u64,
	to_block: u64,
	chunk_blocks: u64,
	service: &StateSyncService,
) -> anyhow::Result<()> {
	let tx_submit_map =
		build_tx_submit_map(provider, address, from_block, to_block, chunk_blocks).await?;
	let bridge_submit_map =
		build_bridge_submit_map(provider, address, from_block, to_block, chunk_blocks).await?;

	for (pi_commitment, tx_hash) in &tx_submit_map {
		let already_known = service.with_state(|s| {
			s.pending_tx_batches.contains_key(&pi_commitment.0)
				|| s.confirmed_tx_batches.contains(&pi_commitment.0)
		});
		if already_known {
			continue;
		}
		let input = fetch_transaction_input(provider, *tx_hash).await?;
		let preimage = decode_tx_batch_calldata(&input)?;
		apply_tx_preimage(&preimage, pi_commitment.0, service)?;
	}
	for (pi_commitment, tx_hash) in &bridge_submit_map {
		let already_known = service.with_state(|s| {
			s.pending_bridge_tx_batches.contains_key(&pi_commitment.0)
				|| s.confirmed_bridge_tx_batches.contains(&pi_commitment.0)
		});
		if already_known {
			continue;
		}
		let input = fetch_transaction_input(provider, *tx_hash).await?;
		let preimage = decode_bridge_batch_calldata(&input)?;
		apply_bridge_preimage(&preimage, pi_commitment.0, service)?;
	}
	Ok(())
}

async fn collect_proven_batches<P: Provider + Clone>(
	provider: &P,
	address: Address,
	from_block: u64,
	to_block: u64,
	chunk_blocks: u64,
) -> anyhow::Result<Vec<ProvenBatchEntry>> {
	let tx_proven_logs = fetch_logs(
		provider,
		address,
		ITesseraRollupV2::TransactionBatchProven::SIGNATURE_HASH,
		from_block,
		to_block,
		chunk_blocks,
		"TransactionBatchProven",
	)
	.await?;

	let bridge_proven_logs = fetch_logs(
		provider,
		address,
		ITesseraRollupV2::BridgeTxBatchProven::SIGNATURE_HASH,
		from_block,
		to_block,
		chunk_blocks,
		"BridgeTxBatchProven",
	)
	.await?;

	let mut entries = Vec::with_capacity(tx_proven_logs.len() + bridge_proven_logs.len());

	for log in &tx_proven_logs {
		match decode_tx_proven_log(log) {
			Ok(entry) => entries.push(entry),
			Err(e) => warn!(error = %e, "failed to decode TransactionBatchProven log; skipping"),
		}
	}
	for log in &bridge_proven_logs {
		match decode_bridge_proven_log(log) {
			Ok(entry) => entries.push(entry),
			Err(e) => warn!(error = %e, "failed to decode BridgeTxBatchProven log; skipping"),
		}
	}

	Ok(entries)
}

async fn sync_config_tree<P: Provider + Clone>(
	provider: &P,
	address: Address,
	from_block: u64,
	to_block: u64,
	chunk_blocks: u64,
	service: &StateSyncService,
	genesis_block: u64,
) -> anyhow::Result<()> {
	// Fetch SubpoolOwnerAssigned events
	let assigned_logs = fetch_logs(
		provider,
		address,
		ITesseraRollupV2::SubpoolOwnerAssigned::SIGNATURE_HASH,
		from_block,
		to_block,
		chunk_blocks,
		"SubpoolOwnerAssigned",
	)
	.await?;

	// Fetch SubpoolRootUpdated events
	let updated_logs = fetch_logs(
		provider,
		address,
		ITesseraRollupV2::SubpoolRootUpdated::SIGNATURE_HASH,
		from_block,
		to_block,
		chunk_blocks,
		"SubpoolRootUpdated",
	)
	.await?;

	// Process assigned events first (they establish the ordering)
	for log in &assigned_logs {
		if let Ok(decoded) = log.log_decode::<ITesseraRollupV2::SubpoolOwnerAssigned>() {
			let event = SubpoolAssignedEvent {
				subpool_id: decoded.inner.subpoolId,
				owner: decoded.inner.owner,
				block_number: log.block_number.unwrap_or_default(),
				log_index: log.log_index.unwrap_or_default(),
			};

			service.with_state_mut(|state| {
				if event.subpool_id == state.next_expected_subpool_id {
					state
						.subpool_roots
						.entry(event.subpool_id)
						.or_insert(HashOutput::ZERO);
					state.next_expected_subpool_id += 1;
					while let Some(buffered_event) = state
						.pending_subpool_assignments
						.remove(&state.next_expected_subpool_id)
					{
						state
							.subpool_roots
							.entry(buffered_event.subpool_id)
							.or_insert(HashOutput::ZERO);
						state.next_expected_subpool_id += 1;
					}
				} else if event.subpool_id > state.next_expected_subpool_id {
					state
						.pending_subpool_assignments
						.insert(event.subpool_id, event);
				}
			});
		}
	}

	// For initial sync: fetch current on-chain roots for all registered subpools
	if from_block == genesis_block {
		let registered_subpool_ids: Vec<u64> =
			service.with_state(|s| (1..s.next_expected_subpool_id).collect());
		for subpool_id in registered_subpool_ids {
			let instance = ITesseraRollupV2::ITesseraRollupV2Instance::new(address, provider);
			let root_u256 = instance
				.subpoolRoots(subpool_id)
				.call()
				.await
				.with_context(|| format!("subpoolRoots({subpool_id})"))?;
			let root = contract::u256_le_to_hash(root_u256)?;
			service.with_state_mut(|s| s.subpool_roots.insert(subpool_id, root));
		}
		// Rebuild config tree from fetched roots
		service.with_state_mut(|s| {
			s.config_tree = tessera_client::pool_config::MainPoolConfigTree::new();
			let mut sorted: Vec<_> = s.subpool_roots.iter().map(|(&id, &r)| (id, r)).collect();
			sorted.sort_by_key(|(id, _)| *id);
			for (subpool_id, subpool_root) in sorted {
				use tessera_client::SubpoolId;
				use tessera_utils::F;
				let sid = SubpoolId(F::from_canonical_u64(subpool_id));
				s.config_tree
					.insert_subpool_at_position(sid, subpool_root)
					.expect("config tree rebuild should not fail");
			}
		});
	} else {
		// Poll-sync: rebuild config tree to incorporate any newly assigned zero-root subpools.
		service.with_state_mut(|s| {
			s.config_tree = tessera_client::pool_config::MainPoolConfigTree::new();
			let mut sorted: Vec<_> = s.subpool_roots.iter().map(|(&id, &r)| (id, r)).collect();
			sorted.sort_by_key(|(id, _)| *id);
			for (subpool_id, subpool_root) in sorted {
				use tessera_client::SubpoolId;
				use tessera_utils::F;
				let sid = SubpoolId(F::from_canonical_u64(subpool_id));
				s.config_tree
					.insert_subpool_at_position(sid, subpool_root)
					.expect("config tree rebuild should not fail");
			}
		});
	}

	// Process root updates
	for log in &updated_logs {
		if let Ok(decoded) = log.log_decode::<ITesseraRollupV2::SubpoolRootUpdated>() {
			let subpool_id = decoded.inner.subpoolId;
			let new_root = contract::u256_le_to_hash(decoded.inner.newSubpoolRoot)?;

			service.with_state_mut(|state| state.update_subpool_root(subpool_id, new_root))?;
		}
	}

	// Add warning when buffered subpool events remain after processing
	service.with_state(|s| {
		if !s.pending_subpool_assignments.is_empty() {
			tracing::warn!(
				buffered = s.pending_subpool_assignments.len(),
				"subpool assignments are buffered awaiting predecessor subpool_id"
			);
		}
	});

	Ok(())
}

async fn sync_deposits<P: Provider + Clone>(
	provider: &P,
	address: Address,
	from_block: u64,
	to_block: u64,
	chunk_blocks: u64,
	service: &StateSyncService,
) -> anyhow::Result<()> {
	let deposit_available_logs = fetch_logs(
		provider,
		address,
		ITesseraRollupV2::DepositAvailable::SIGNATURE_HASH,
		from_block,
		to_block,
		chunk_blocks,
		"DepositAvailable",
	)
	.await?;

	let deposit_validated_logs = fetch_logs(
		provider,
		address,
		ITesseraRollupV2::DepositValidated::SIGNATURE_HASH,
		from_block,
		to_block,
		chunk_blocks,
		"DepositValidated",
	)
	.await?;

	let deposit_withdrawn_logs = fetch_logs(
		provider,
		address,
		ITesseraRollupV2::DepositWithdrawn::SIGNATURE_HASH,
		from_block,
		to_block,
		chunk_blocks,
		"DepositWithdrawn",
	)
	.await?;

	// Process DepositAvailable events
	for log in &deposit_available_logs {
		if let Ok(decoded) = log.log_decode::<ITesseraRollupV2::DepositAvailable>() {
			let note_commitment = decoded.inner.noteCommitment.0;
			let record = DepositRecord {
				note_commitment, // Store note_commitment in record
				value: decoded.inner.value,
				recipient: decoded.inner.recipient,
				status: DepositStatus::Pending,
				deposit_block: log.block_number.unwrap_or_default(),
				asset_id: decoded.inner.assetId,
			};

			service.with_state_mut(|state| {
				state.deposits.insert(note_commitment, record);
			});
		}
	}

	// Process DepositValidated events
	for log in &deposit_validated_logs {
		if let Ok(decoded) = log.log_decode::<ITesseraRollupV2::DepositValidated>() {
			let note_commitment = decoded.inner.noteCommitment.0;

			service.with_state_mut(|state| {
				if let Some(record) = state.deposits.get_mut(&note_commitment) {
					record.status = DepositStatus::Validated;
				}
			});
		}
	}

	// Process DepositWithdrawn events
	for log in &deposit_withdrawn_logs {
		if let Ok(decoded) = log.log_decode::<ITesseraRollupV2::DepositWithdrawn>() {
			let note_commitment = decoded.inner.noteCommitment.0;

			service.with_state_mut(|state| {
				if let Some(record) = state.deposits.get_mut(&note_commitment) {
					record.status = DepositStatus::Withdrawn;
				}
			});
		}
	}

	Ok(())
}

// ── Replay / confirm helpers ────────────────────────────────────────────────────

fn apply_tx_preimage(
	preimage: &[u8],
	pi_commitment: [u8; 32],
	service: &StateSyncService,
) -> anyhow::Result<()> {
	validate_tx_preimage_len(preimage)?;

	service.with_state_mut(|state| {
		// Extract and add commitments with correct subtree indices
		for s in 0..PRIV_TX_BATCH_SIZE {
			let slot_off = TX_HEADER_SIZE + s * TX_SLOT_SIZE;
			// no read_gl_bool check here — all slots contribute to the subtree

			// leaf s*8+0 = accOutComm
			let acc_comm = read_gl_b32(preimage, slot_off + TX_ACCOUT_COMM_OFF);
			state.add_pending_commitment(bytes_to_hash(&acc_comm), pi_commitment, s * 8);

			// leaves s*8+1 .. s*8+7 = noteOutComm[0..6]
			for j in 0..NOTE_BATCH {
				let note_comm = read_gl_b32(preimage, slot_off + TX_NOTE_OUT_OFF + j * 32);
				state.add_pending_commitment(
					bytes_to_hash(&note_comm),
					pi_commitment,
					s * 8 + j + 1,
				);
			}
		}

		// Extract and add nullifiers
		for s in 0..PRIV_TX_BATCH_SIZE {
			let slot_off = TX_HEADER_SIZE + s * TX_SLOT_SIZE;
			if !read_gl_bool(preimage, slot_off) {
				continue;
			}

			// Account input nullifier
			let acc_null = read_gl_b32(preimage, slot_off + TX_ACCIN_NULL_OFF);
			state.add_pending_nullifier(bytes_to_hash(&acc_null), pi_commitment);

			// Note input nullifiers
			for j in 0..NOTE_BATCH {
				let note_null = read_gl_b32(preimage, slot_off + TX_NOTE_IN_OFF + j * 32);
				state.add_pending_nullifier(bytes_to_hash(&note_null), pi_commitment);
			}
		}

		// Store pending batch
		state.pending_tx_batches.insert(
			pi_commitment,
			alloy::primitives::Bytes::from(preimage.to_vec()),
		);
	});

	Ok(())
}

fn apply_bridge_preimage(
	preimage: &[u8],
	pi_commitment: [u8; 32],
	service: &StateSyncService,
) -> anyhow::Result<()> {
	validate_bridge_preimage_len(preimage)?;

	service.with_state_mut(|state| {
		// Withdraw: slot s → leaf s
		for s in 0..BRIDGE_TX_HALF_SIZE {
			let w_off = TX_HEADER_SIZE + s * W_SLOT_SIZE;
			// no read_gl_bool check here — all slots contribute to the subtree
			let acc_comm = read_gl_b32(preimage, w_off + W_ACCOUT_COMM_OFF);
			state.add_pending_commitment(bytes_to_hash(&acc_comm), pi_commitment, s);

			// Withdraw nullifiers
			if !read_gl_bool(preimage, w_off) {
				continue;
			}
			let acc_null = read_gl_b32(preimage, w_off + W_ACCIN_NULL_OFF);
			state.add_pending_nullifier(bytes_to_hash(&acc_null), pi_commitment);
		}

		// Deposit: slot s → leaf 256+s
		for s in 0..BRIDGE_TX_HALF_SIZE {
			let d_off = D_SECTION_OFF + s * D_SLOT_SIZE;
			// no read_gl_bool check here — all slots contribute to the subtree
			let acc_comm = read_gl_b32(preimage, d_off + D_ACCOUT_COMM_OFF);
			state.add_pending_commitment(bytes_to_hash(&acc_comm), pi_commitment, 256 + s);

			// Deposit nullifiers
			if !read_gl_bool(preimage, d_off) {
				continue;
			}
			let acc_null = read_gl_b32(preimage, d_off + D_ACCIN_NULL_OFF);
			state.add_pending_nullifier(bytes_to_hash(&acc_null), pi_commitment);
		}

		// Store pending batch
		state.pending_bridge_tx_batches.insert(
			pi_commitment,
			alloy::primitives::Bytes::from(preimage.to_vec()),
		);
	});

	Ok(())
}

fn bytes_to_hash(b: &[u8; 32]) -> tessera_utils::hasher::HashOutput {
	contract::bytes32_to_hash(&alloy::primitives::B256::from(*b))
		.expect("bytes32_to_hash cannot fail for valid 32-byte array")
}

// ── Log decoding helpers ────────────────────────────────────────────────────────

fn decode_tx_submitted_log(log: &Log) -> anyhow::Result<(B256, B256)> {
	let decoded = log
		.log_decode::<ITesseraRollupV2::TransactionBatchSubmitted>()
		.context("decode TransactionBatchSubmitted")?;
	let tx_hash = log
		.transaction_hash
		.context("TransactionBatchSubmitted log missing transaction_hash")?;
	Ok((decoded.inner.piCommitment, tx_hash))
}

fn decode_bridge_submitted_log(log: &Log) -> anyhow::Result<(B256, B256)> {
	let decoded = log
		.log_decode::<ITesseraRollupV2::BridgeTxBatchSubmitted>()
		.context("decode BridgeTxBatchSubmitted")?;
	let tx_hash = log
		.transaction_hash
		.context("BridgeTxBatchSubmitted log missing transaction_hash")?;
	Ok((decoded.inner.piCommitment, tx_hash))
}

fn decode_tx_proven_log(log: &Log) -> anyhow::Result<ProvenBatchEntry> {
	let decoded = log
		.log_decode::<ITesseraRollupV2::TransactionBatchProven>()
		.context("decode TransactionBatchProven")?;
	let inner = &decoded.inner;
	Ok(ProvenBatchEntry {
		pi_commitment: inner.piCommitment,
		new_tree_root: contract::u256_le_to_hash(inner.newTreeRoot)?,
		leaf_index: inner
			.leafIndex
			.try_into()
			.context("leafIndex overflows u64")?,
		kind: BatchKind::Transaction,
	})
}

fn decode_bridge_proven_log(log: &Log) -> anyhow::Result<ProvenBatchEntry> {
	let decoded = log
		.log_decode::<ITesseraRollupV2::BridgeTxBatchProven>()
		.context("decode BridgeTxBatchProven")?;
	let inner = &decoded.inner;
	Ok(ProvenBatchEntry {
		pi_commitment: inner.piCommitment,
		new_tree_root: contract::u256_le_to_hash(inner.newTreeRoot)?,
		leaf_index: inner
			.leafIndex
			.try_into()
			.context("leafIndex overflows u64")?,
		kind: BatchKind::BridgeTx,
	})
}

// ── Calldata decoding helpers ────────────────────────────────────────────────────

fn decode_tx_batch_calldata(
	input: &alloy::primitives::Bytes,
) -> anyhow::Result<alloy::primitives::Bytes> {
	use alloy::sol_types::SolCall;
	let call = ITesseraRollupV2::submitTransactionBatchCall::abi_decode(input)?;
	Ok(call.batchPreimage)
}

fn decode_bridge_batch_calldata(
	input: &alloy::primitives::Bytes,
) -> anyhow::Result<alloy::primitives::Bytes> {
	use alloy::sol_types::SolCall;
	let call = ITesseraRollupV2::submitBridgeTxBatchCall::abi_decode(input)?;
	Ok(call.batchPreimage)
}

fn extract_batch_root_from_preimage(
	preimage: &[u8],
	_kind: BatchKind,
) -> anyhow::Result<HashOutput> {
	// Batch root is the first 32 bytes (batchPoseidonRoot)
	if preimage.len() < 32 {
		anyhow::bail!("preimage too short for batch root");
	}
	let batch_root_bytes = read_gl_b32(preimage, 0);
	Ok(bytes_to_hash(&batch_root_bytes))
}

// ── Preimage parsing helpers ────────────────────────────────────────────────────

fn read_gl_b32(preimage: &[u8], off: usize) -> [u8; 32] {
	let b: alloy::primitives::B256 = preimage[off..off + 32]
		.try_into()
		.expect("slice always 32 bytes");
	contract::preimage_bytes32_to_raw(&b)
}

fn read_gl_bool(preimage: &[u8], off: usize) -> bool {
	let lo = u32::from_be_bytes(preimage[off..off + 4].try_into().unwrap());
	let hi = u32::from_be_bytes(preimage[off + 4..off + 8].try_into().unwrap());
	lo != 0 || hi != 0
}

fn validate_tx_preimage_len(preimage: &[u8]) -> anyhow::Result<()> {
	anyhow::ensure!(
		preimage.len() >= TX_PREIMAGE_LEN,
		"tx batch preimage too short: got {} bytes, expected at least {}",
		preimage.len(),
		TX_PREIMAGE_LEN
	);
	Ok(())
}

fn validate_bridge_preimage_len(preimage: &[u8]) -> anyhow::Result<()> {
	anyhow::ensure!(
		preimage.len() >= BRIDGE_TX_PREIMAGE_LEN,
		"bridge tx batch preimage too short: got {} bytes, expected at least {}",
		preimage.len(),
		BRIDGE_TX_PREIMAGE_LEN
	);
	Ok(())
}

// ── RPC helpers ────────────────────────────────────────────────────────────────

async fn build_tx_submit_map<P: Provider + Clone>(
	provider: &P,
	address: Address,
	from_block: u64,
	to_block: u64,
	chunk_blocks: u64,
) -> anyhow::Result<HashMap<B256, B256>> {
	let logs = fetch_logs(
		provider,
		address,
		ITesseraRollupV2::TransactionBatchSubmitted::SIGNATURE_HASH,
		from_block,
		to_block,
		chunk_blocks,
		"TransactionBatchSubmitted",
	)
	.await?;

	let mut map = HashMap::with_capacity(logs.len());
	for log in &logs {
		match decode_tx_submitted_log(log) {
			Ok((pi, tx_hash)) => {
				map.insert(pi, tx_hash);
			},
			Err(e) => {
				warn!(error = %e, "failed to decode TransactionBatchSubmitted log; skipping");
			},
		}
	}
	Ok(map)
}

async fn build_bridge_submit_map<P: Provider + Clone>(
	provider: &P,
	address: Address,
	from_block: u64,
	to_block: u64,
	chunk_blocks: u64,
) -> anyhow::Result<HashMap<B256, B256>> {
	let logs = fetch_logs(
		provider,
		address,
		ITesseraRollupV2::BridgeTxBatchSubmitted::SIGNATURE_HASH,
		from_block,
		to_block,
		chunk_blocks,
		"BridgeTxBatchSubmitted",
	)
	.await?;

	let mut map = HashMap::with_capacity(logs.len());
	for log in &logs {
		match decode_bridge_submitted_log(log) {
			Ok((pi, tx_hash)) => {
				map.insert(pi, tx_hash);
			},
			Err(e) => {
				warn!(error = %e, "failed to decode BridgeTxBatchSubmitted log; skipping");
			},
		}
	}
	Ok(map)
}

async fn find_submission_tx_hash<P: Provider + Clone>(
	provider: &P,
	address: Address,
	event_sig: B256,
	pi_commitment: B256,
	from_block: u64,
	to_block: u64,
	chunk_blocks: u64,
	event_name: &str,
) -> anyhow::Result<B256> {
	let mut chunk_start = from_block;

	while chunk_start <= to_block {
		let chunk_end = (chunk_start + chunk_blocks - 1).min(to_block);

		let filter = Filter::new()
			.address(address)
			.event_signature(event_sig)
			.topic1(pi_commitment)
			.from_block(chunk_start)
			.to_block(chunk_end);

		let logs = provider
            .get_logs(&filter)
            .await
            .with_context(|| {
                format!(
                    "eth_getLogs({event_name}, {chunk_start}..{chunk_end}, piCommitment={pi_commitment:?})"
                )
            })?;

		if let Some(log) = logs.first() {
			let tx_hash = log
				.transaction_hash
				.context("submission log missing transaction_hash")?;
			return Ok(tx_hash);
		}

		chunk_start = chunk_end + 1;
	}

	anyhow::bail!(
        "no {event_name} log found for piCommitment {pi_commitment:?} in blocks {from_block}..{to_block}"
    );
}

async fn fetch_transaction_input<P: Provider + Clone>(
	provider: &P,
	tx_hash: B256,
) -> anyhow::Result<alloy::primitives::Bytes> {
	use alloy::consensus::Transaction as _;

	let tx = provider
		.get_transaction_by_hash(tx_hash)
		.await
		.with_context(|| format!("eth_getTransactionByHash({tx_hash:?})"))?
		.with_context(|| format!("transaction {tx_hash:?} not found"))?;

	Ok(tx.inner.input().clone())
}

async fn fetch_tree_depth<P: Provider + Clone>(
	provider: &P,
	address: Address,
) -> anyhow::Result<usize> {
	let instance = ITesseraRollupV2::ITesseraRollupV2Instance::new(address, provider);
	let depth = instance.treeDepth().call().await.context("treeDepth()")?;
	depth.try_into().context("treeDepth overflows usize")
}

async fn fetch_config_tree_depth<P: Provider + Clone>(
	provider: &P,
	address: Address,
) -> anyhow::Result<usize> {
	let instance = ITesseraRollupV2::ITesseraRollupV2Instance::new(address, provider);
	let depth = instance
		.configTreeDepth()
		.call()
		.await
		.context("configTreeDepth()")?;
	depth.try_into().context("configTreeDepth overflows usize")
}

async fn verify_leaf_count<P: Provider + Clone>(
	provider: &P,
	address: Address,
	service: &StateSyncService,
) {
	match fetch_on_chain_leaf_count(provider, address).await {
		Ok(on_chain) => {
			let local_count = service.with_state(|state| state.state_tree.num_leaves()) as u64;
			if local_count == on_chain {
				info!(
					leaf_count = local_count,
					"local tree matches on-chain leaf count"
				);
			} else {
				warn!(
					local = local_count,
					on_chain, "local leaf count differs from on-chain leafCount()"
				);
			}
		},
		Err(e) => warn!(error = %e, "could not fetch on-chain leafCount() for sanity check"),
	}
}

async fn fetch_on_chain_leaf_count<P: Provider + Clone>(
	provider: &P,
	address: Address,
) -> anyhow::Result<u64> {
	let instance = ITesseraRollupV2::ITesseraRollupV2Instance::new(address, provider);
	let count = instance
		.imtLeafCount()
		.call()
		.await
		.context("imtLeafCount()")?;
	count.try_into().context("leafCount overflows u64")
}

async fn fetch_logs<P: Provider + Clone>(
	provider: &P,
	address: Address,
	event_sig: B256,
	from_block: u64,
	to_block: u64,
	chunk_blocks: u64,
	event_name: &str,
) -> anyhow::Result<Vec<Log>> {
	let mut all_logs: Vec<Log> = Vec::new();
	let mut chunk_start = from_block;

	while chunk_start <= to_block {
		let chunk_end = (chunk_start + chunk_blocks - 1).min(to_block);

		let filter = Filter::new()
			.address(address)
			.event_signature(event_sig)
			.from_block(chunk_start)
			.to_block(chunk_end);

		let chunk = provider
			.get_logs(&filter)
			.await
			.with_context(|| format!("eth_getLogs({event_name}, {chunk_start}..{chunk_end})"))?;

		debug!(
			event = event_name,
			from = chunk_start,
			to = chunk_end,
			count = chunk.len(),
			"fetched log page"
		);

		all_logs.extend(chunk);
		chunk_start = chunk_end + 1;
	}

	Ok(all_logs)
}
