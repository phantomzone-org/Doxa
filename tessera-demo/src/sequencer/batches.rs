use std::sync::Arc;

use alloy::primitives::{B256, U256};
use plonky2::field::types::{Field, PrimeField64};
use tessera_client::NOTE_BATCH;
use tessera_server::{
	contract::{self, hash_to_u256_le, ITesseraRollupV2},
	proof_aggregation::SubtreeRootCircuit,
	sequencer::revert::humanize_bridge_revert,
};
use tessera_utils::hasher::HashOutput;
use tracing::{error, info};

use super::{
	helpers::random_proof,
	state::{DemoProvider, SharedState},
};

// ---------------------------------------------------------------------------
// Transaction batches
// ---------------------------------------------------------------------------

pub(crate) async fn flush_tx_batch(
	state: &SharedState,
	provider: &Arc<DemoProvider>,
) -> anyhow::Result<()> {
	let (rollup_addr, bb, prove_delay, confirmed_root) = {
		let mut st = state.lock().await;
		let bb = match st.tx_batch_builder.take() {
			Some(bb) => bb,
			None => return Ok(()),
		};
		st.tx_batch_pending_since = None;
		(st.rollup_addr, bb, st.prove_delay, st.confirmed_root)
	};

	let finalized = bb.finalize();

	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(rollup_addr, provider.as_ref());
	let pool_cfg_root: [u8; 32] = rollup.poolConfigRoot().call().await?.into();

	let n_slots = finalized.ac_leaves.len();
	let stride = NOTE_BATCH + 1; // 8 entries per slot in nc/nn_leaves

	// All slots contribute commitments (including padding — they go into the NCT).
	let mut note_commitments = Vec::with_capacity(n_slots * NOTE_BATCH);
	for s in 0..n_slots {
		let nc_base = s * stride;
		for j in 0..NOTE_BATCH {
			note_commitments.push(contract::bytes32_be_to_u256_le(
				&finalized.nc_leaves[nc_base + j],
			));
		}
	}
	let account_commitments: Vec<U256> = finalized
		.ac_leaves
		.iter()
		.map(contract::bytes32_be_to_u256_le)
		.collect();

	// Only real TX slots contribute nullifiers — padding slots have no nullifiers.
	let mut note_nullifiers = Vec::new();
	let mut account_nullifiers = Vec::new();
	for s in 0..n_slots {
		if !finalized.tx_proofs_by_slot.contains_key(&s) {
			continue;
		}
		let nn_base = s * stride;
		for j in 0..NOTE_BATCH {
			note_nullifiers.push(contract::bytes32_be_to_u256_le(
				&finalized.nn_leaves[nn_base + j],
			));
		}
		account_nullifiers.push(contract::bytes32_be_to_u256_le(&finalized.an_leaves[s]));
	}

	let batch_poseidon_root = hash_to_u256_le(&finalized.batch_poseidon_root);

	let batch = ITesseraRollupV2::TransactionBatch {
		root: confirmed_root,
		mainPoolConfigRoot: pool_cfg_root.into(),
		noteCommitments: note_commitments,
		noteNullifiers: note_nullifiers,
		accountCommitments: account_commitments,
		accountNullifiers: account_nullifiers,
		batchPoseidonRoot: batch_poseidon_root,
		confirmed: false,
	};

	info!(
		real_slots = finalized.tx_proofs_by_slot.len(),
		note_commitments = batch.noteCommitments.len(),
		account_commitments = batch.accountCommitments.len(),
		"submitting TX batch on-chain"
	);

	let call = rollup.submitTransactionBatch(batch);
	let gas_estimate = call.estimate_gas().await;
	info!(gas_estimate = ?gas_estimate, "TX batch gas estimate");

	let receipt = call
		.send()
		.await
		.map_err(|e| {
			anyhow::anyhow!(
				"submitTransactionBatch failed: {}",
				humanize_bridge_revert(&e)
			)
		})?
		.get_receipt()
		.await
		.map_err(|e| anyhow::anyhow!("submitTransactionBatch receipt: {e}"))?;

	anyhow::ensure!(receipt.status(), "submitTransactionBatch reverted");

	let pi_commitment: B256 = receipt
		.inner
		.logs()
		.iter()
		.find_map(|l| {
			l.log_decode::<ITesseraRollupV2::TransactionBatchSubmitted>()
				.ok()
				.map(|d| d.inner.piCommitment)
		})
		.ok_or_else(|| anyhow::anyhow!("TransactionBatchSubmitted event not found"))?;

	// Collect the 512 leaves (as HashOutput) for local tree insertion after prove.
	let batch_leaves: Vec<HashOutput> = finalized
		.nc_leaves
		.iter()
		.map(|c| HashOutput::from_encoded_fields_unchecked(*c))
		.collect();

	info!(
		pi_commitment = %pi_commitment,
		"TX batch submitted; scheduling proof in {}s",
		prove_delay.as_secs()
	);

	let state_clone = state.clone();
	let provider_clone = provider.clone();
	tokio::spawn(async move {
		tokio::time::sleep(prove_delay).await;
		if let Err(e) =
			prove_tx_batch(&state_clone, &provider_clone, pi_commitment, batch_leaves).await
		{
			error!("failed to prove TX batch: {e}");
		}
	});

	Ok(())
}

async fn prove_tx_batch(
	state: &SharedState,
	provider: &Arc<DemoProvider>,
	pi_commitment: B256,
	batch_leaves: Vec<HashOutput>,
) -> anyhow::Result<()> {
	let rollup_addr = state.lock().await.rollup_addr;
	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(rollup_addr, provider.as_ref());

	info!(%pi_commitment, "proving TX batch (zero proof)");

	let receipt = rollup
		.proveTransactionBatch(pi_commitment, random_proof())
		.send()
		.await
		.map_err(|e| {
			anyhow::anyhow!(
				"proveTransactionBatch failed: {}",
				humanize_bridge_revert(&e)
			)
		})?
		.get_receipt()
		.await
		.map_err(|e| anyhow::anyhow!("proveTransactionBatch receipt: {e}"))?;

	anyhow::ensure!(receipt.status(), "proveTransactionBatch reverted");

	let new_root = receipt
		.inner
		.logs()
		.iter()
		.find_map(|l| {
			l.log_decode::<ITesseraRollupV2::TransactionBatchProven>()
				.ok()
				.map(|d| d.inner.newTreeRoot)
		})
		.ok_or_else(|| anyhow::anyhow!("TransactionBatchProven event not found"))?;

	let mut st = state.lock().await;
	st.confirmed_root = new_root;
	st.confirmed_root_history.insert(new_root);

	// Capture base leaf index before insertion so we can record positions.
	let base_leaf = st.local_tree.num_leaves() as u64;

	// Insert all 512 batch leaves into the local tree.
	st.local_tree
		.insert_batch(batch_leaves.clone())
		.map_err(|e| anyhow::anyhow!("local tree insert_batch: {e}"))?;

	// Record NCT leaf positions for every non-zero leaf.
	let mut recorded = 0usize;
	for (offset, leaf) in batch_leaves.iter().enumerate() {
		if leaf.0.iter().all(|f| f.to_canonical_u64() == 0) {
			continue;
		}
		let hex_key = hash_output_to_hex(leaf);
		st.note_positions.insert(hex_key, base_leaf + offset as u64);
		recorded += 1;
	}

	let confirmed_roots = st.confirmed_root_history.len();
	info!(
		new_root = %new_root,
		confirmed_roots,
		local_tree_leaves = st.local_tree.num_leaves(),
		recorded_positions = recorded,
		"=== TX batch CONFIRMED ==="
	);

	Ok(())
}

// ---------------------------------------------------------------------------
// Deposit batches
// ---------------------------------------------------------------------------

pub(crate) async fn flush_deposit_batch(
	state: &SharedState,
	provider: &Arc<DemoProvider>,
) -> anyhow::Result<()> {
	let (rollup_addr, deposits, prove_delay, confirmed_root) = {
		let mut st = state.lock().await;
		if st.deposit_queue.is_empty() {
			return Ok(());
		}
		let deposits = std::mem::take(&mut st.deposit_queue);
		st.deposit_batch_pending_since = None;
		(st.rollup_addr, deposits, st.prove_delay, st.confirmed_root)
	};

	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(rollup_addr, provider.as_ref());
	let pool_cfg_root: [u8; 32] = rollup.poolConfigRoot().call().await?.into();

	let deposit_nc_hashes: Vec<HashOutput> = deposits
		.iter()
		.map(|nc| HashOutput::from_encoded_fields_unchecked(nc.0))
		.collect();

	const DEPOSIT_BATCH_SIZE: usize = 512;
	let mut padded = deposit_nc_hashes;
	padded.resize(
		DEPOSIT_BATCH_SIZE,
		HashOutput::new([tessera_utils::F::ZERO; 4]),
	);
	let batch_poseidon_root = SubtreeRootCircuit::compute_root_native(&padded);
	let batch_poseidon_root_u256 = hash_to_u256_le(&batch_poseidon_root);

	let deposit_batch = ITesseraRollupV2::DepositBatch {
		root: confirmed_root,
		mainPoolConfigRoot: pool_cfg_root.into(),
		depositNoteCommitments: deposits.clone(),
		batchPoseidonRoot: batch_poseidon_root_u256,
		confirmed: false,
	};

	info!(
		deposits = deposits.len(),
		"submitting deposit batch on-chain"
	);

	let receipt = rollup
		.submitDepositBatch(deposit_batch)
		.send()
		.await
		.map_err(|e| anyhow::anyhow!("submitDepositBatch failed: {}", humanize_bridge_revert(&e)))?
		.get_receipt()
		.await
		.map_err(|e| anyhow::anyhow!("submitDepositBatch receipt: {e}"))?;

	anyhow::ensure!(receipt.status(), "submitDepositBatch reverted");

	let pi_commitment: B256 = receipt
		.inner
		.logs()
		.iter()
		.find_map(|l| {
			l.log_decode::<ITesseraRollupV2::DepositBatchSubmitted>()
				.ok()
				.map(|d| d.inner.piCommitment)
		})
		.ok_or_else(|| anyhow::anyhow!("DepositBatchSubmitted event not found"))?;

	// Collect deposit leaves (as HashOutput) for local tree insertion after prove.
	let deposit_leaves: Vec<HashOutput> = padded;

	info!(
		%pi_commitment,
		"deposit batch submitted; scheduling proof in {}s",
		prove_delay.as_secs()
	);

	let state_clone = state.clone();
	let provider_clone = provider.clone();
	tokio::spawn(async move {
		tokio::time::sleep(prove_delay).await;
		if let Err(e) =
			prove_deposit_batch(&state_clone, &provider_clone, pi_commitment, deposit_leaves).await
		{
			error!("failed to prove deposit batch: {e}");
		}
	});

	Ok(())
}

async fn prove_deposit_batch(
	state: &SharedState,
	provider: &Arc<DemoProvider>,
	pi_commitment: B256,
	deposit_leaves: Vec<HashOutput>,
) -> anyhow::Result<()> {
	let rollup_addr = state.lock().await.rollup_addr;
	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(rollup_addr, provider.as_ref());

	info!(%pi_commitment, "proving deposit batch (zero proof)");

	let receipt = rollup
		.proveDepositBatch(pi_commitment, random_proof())
		.send()
		.await
		.map_err(|e| anyhow::anyhow!("proveDepositBatch failed: {}", humanize_bridge_revert(&e)))?
		.get_receipt()
		.await
		.map_err(|e| anyhow::anyhow!("proveDepositBatch receipt: {e}"))?;

	anyhow::ensure!(receipt.status(), "proveDepositBatch reverted");

	let new_root = receipt
		.inner
		.logs()
		.iter()
		.find_map(|l| {
			l.log_decode::<ITesseraRollupV2::DepositBatchProven>()
				.ok()
				.map(|d| d.inner.newTreeRoot)
		})
		.ok_or_else(|| anyhow::anyhow!("DepositBatchProven event not found"))?;

	let mut st = state.lock().await;
	st.confirmed_root = new_root;
	st.confirmed_root_history.insert(new_root);

	// Capture base leaf index before insertion so we can record positions.
	let base_leaf = st.local_tree.num_leaves() as u64;

	// Insert deposit leaves into the local tree.
	st.local_tree
		.insert_batch(deposit_leaves.clone())
		.map_err(|e| anyhow::anyhow!("local tree insert_batch (deposit): {e}"))?;

	// Record NCT leaf positions for every non-zero deposit leaf.
	let mut recorded = 0usize;
	for (offset, leaf) in deposit_leaves.iter().enumerate() {
		if leaf.0.iter().all(|f| f.to_canonical_u64() == 0) {
			continue;
		}
		let hex_key = hash_output_to_hex(leaf);
		st.note_positions.insert(hex_key, base_leaf + offset as u64);
		recorded += 1;
	}

	let confirmed_roots = st.confirmed_root_history.len();
	info!(
		new_root = %new_root,
		confirmed_roots,
		local_tree_leaves = st.local_tree.num_leaves(),
		recorded_positions = recorded,
		"=== Deposit batch CONFIRMED ==="
	);

	Ok(())
}

/// Encode a `HashOutput` (4 × Goldilocks field elements) as a 64-char hex string.
/// Uses the same big-endian u64 encoding as the operator's `hash_to_hex`.
fn hash_output_to_hex(h: &HashOutput) -> String {
	let mut out = [0u8; 32];
	for (i, f) in h.0.iter().enumerate() {
		out[i * 8..(i + 1) * 8].copy_from_slice(&f.to_canonical_u64().to_le_bytes());
	}
	hex::encode(out)
}
