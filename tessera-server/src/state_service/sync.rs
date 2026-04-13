use std::collections::HashMap;

use alloy::{
	primitives::{Address, B256},
	providers::Provider,
	rpc::types::{Filter, Log},
	sol_types::SolEvent,
};
use anyhow::Context;
use tessera_utils::hasher::HashOutput;
use tracing::{debug, info, warn};

use super::state::StateSnapshot;
use crate::contract::{self, ITesseraRollupV2};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum block range per `eth_getLogs` call.
///
/// Matches the chunk size used by the sequencer's `recovery` module.
pub(super) const LOG_FETCH_CHUNK_BLOCKS: u64 = 1_000;

// ---------------------------------------------------------------------------
// High-level sync entry point
// ---------------------------------------------------------------------------

/// Build a [`StateSnapshot`] by replaying every confirmed batch from genesis
/// to `to_block`.
///
/// Steps:
/// 1. Fetch `TransactionBatchSubmitted` / `DepositBatchSubmitted` events to map each `piCommitment`
///    to its submission transaction hash.
/// 2. Fetch `TransactionBatchProven` / `DepositBatchProven` events to obtain the `leafIndex` and
///    confirmed root for each proven batch.
/// 3. Merge both proven-event lists and sort by `leafIndex` (ascending) to recover the canonical
///    leaf-insertion order.
/// 4. For each batch, decode the original submission calldata, extract leaves and nullifiers, and
///    apply them to the snapshot.
/// 5. Record every proven root as confirmed.
/// 6. Sanity-check local leaf count against `leafCount()` on the contract.
///
/// # Errors
/// Propagates any RPC or decoding error.
pub async fn sync_from_genesis<P: Provider + Clone>(
	provider: &P,
	address: Address,
	chunk_blocks: u64,
	to_block: u64,
) -> anyhow::Result<StateSnapshot> {
	let depth = fetch_tree_depth(provider, address).await?;
	let mut state = StateSnapshot::new(depth);

	// The root of the empty tree is always a valid confirmed root: it is the
	// value the contract publishes as `currentRoot()` before any batch is
	// proven.  Seed the set here so that clients can submit TXs against the
	// genesis root even when no batches have ever been proven.
	let genesis_root = state.root();
	state.confirm_root(genesis_root);

	// Build submission maps: piCommitment → tx hash.
	let tx_submit_map = build_tx_submit_map(provider, address, 0, to_block, chunk_blocks).await?;
	let dep_submit_map =
		build_deposit_submit_map(provider, address, 0, to_block, chunk_blocks).await?;

	// Collect proven batches sorted by leafIndex.
	let mut ordered_batches =
		collect_proven_batches(provider, address, 0, to_block, chunk_blocks).await?;
	ordered_batches.sort_by_key(|b| b.leaf_index);

	info!(
		total_proven_batches = ordered_batches.len(),
		"replaying proven batches into local tree"
	);

	for batch_entry in &ordered_batches {
		replay_batch(
			provider,
			batch_entry,
			&tx_submit_map,
			&dep_submit_map,
			&mut state,
		)
		.await?;
	}

	verify_leaf_count(provider, address, &state).await;

	Ok(state)
}

/// Fetch and apply every proven batch in `(from_block, to_block]` to an
/// already-initialised snapshot.
///
/// Called by the service's polling loop after genesis sync to incorporate new
/// confirmed batches without replaying from genesis.
///
/// # Errors
/// Propagates any RPC or decoding error.
pub async fn sync_range<P: Provider + Clone>(
	provider: &P,
	address: Address,
	chunk_blocks: u64,
	from_block: u64,
	to_block: u64,
	state: &mut StateSnapshot,
) -> anyhow::Result<()> {
	let mut tx_submit_map =
		build_tx_submit_map(provider, address, from_block, to_block, chunk_blocks).await?;
	let mut dep_submit_map =
		build_deposit_submit_map(provider, address, from_block, to_block, chunk_blocks).await?;

	let mut ordered_batches =
		collect_proven_batches(provider, address, from_block, to_block, chunk_blocks).await?;
	ordered_batches.sort_by_key(|b| b.leaf_index);

	// Proven batches often refer to submissions from earlier blocks. If the
	// submission isn't in the current polling window, look it up explicitly
	// by piCommitment so we can still replay the batch.
	fill_missing_submission_txs(
		provider,
		address,
		&ordered_batches,
		&mut tx_submit_map,
		&mut dep_submit_map,
		to_block,
		chunk_blocks,
	)
	.await?;

	for batch_entry in &ordered_batches {
		replay_batch(
			provider,
			batch_entry,
			&tx_submit_map,
			&dep_submit_map,
			state,
		)
		.await?;
	}

	Ok(())
}

// ---------------------------------------------------------------------------
// Internal batch descriptor
// ---------------------------------------------------------------------------

/// Whether a proven batch is a private-transaction batch or a deposit batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BatchKind {
	Transaction,
	Deposit,
}

/// Metadata about a single proven batch, extracted from a `*BatchProven` event.
pub(super) struct ProvenBatchEntry {
	/// Identifies the submission transaction that carries this batch's leaves.
	pub pi_commitment: B256,
	/// New tree root produced by this batch; recorded as a confirmed root.
	pub new_tree_root: HashOutput,
	/// Tree-insertion position of the first leaf this batch added.
	pub leaf_index: u64,
	/// Discriminant: TX or deposit batch.
	pub kind: BatchKind,
}

// ---------------------------------------------------------------------------
// Submission-map construction
// ---------------------------------------------------------------------------

/// Build a `piCommitment → submission tx hash` map from
/// `TransactionBatchSubmitted` events in `[from_block, to_block]`.
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

/// Build a `piCommitment → submission tx hash` map from
/// `DepositBatchSubmitted` events in `[from_block, to_block]`.
async fn build_deposit_submit_map<P: Provider + Clone>(
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
		match decode_deposit_submitted_log(log) {
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

// ---------------------------------------------------------------------------
// Submission lookup by piCommitment (fallback for polling window gaps)
// ---------------------------------------------------------------------------

async fn fill_missing_submission_txs<P: Provider + Clone>(
	provider: &P,
	address: Address,
	ordered_batches: &[ProvenBatchEntry],
	tx_submit_map: &mut HashMap<B256, B256>,
	dep_submit_map: &mut HashMap<B256, B256>,
	to_block: u64,
	chunk_blocks: u64,
) -> anyhow::Result<()> {
	for entry in ordered_batches {
		let (map, sig, name): (&mut HashMap<B256, B256>, _, &str) = match entry.kind {
			BatchKind::Transaction => (
				tx_submit_map,
				ITesseraRollupV2::TransactionBatchSubmitted::SIGNATURE_HASH,
				"TransactionBatchSubmitted",
			),
			BatchKind::Deposit => (
				dep_submit_map,
				ITesseraRollupV2::BridgeTxBatchSubmitted::SIGNATURE_HASH,
				"BridgeTxBatchSubmitted",
			),
		};

		if map.contains_key(&entry.pi_commitment) {
			continue;
		}

		let tx_hash = find_submission_tx_hash(
			provider,
			address,
			sig,
			entry.pi_commitment,
			0,
			to_block,
			chunk_blocks,
			name,
		)
		.await?;

		map.insert(entry.pi_commitment, tx_hash);
	}

	Ok(())
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

/// Decode a `TransactionBatchSubmitted` log and return
/// `(piCommitment, transaction_hash)`.
fn decode_tx_submitted_log(log: &Log) -> anyhow::Result<(B256, B256)> {
	let decoded = log
		.log_decode::<ITesseraRollupV2::TransactionBatchSubmitted>()
		.context("decode TransactionBatchSubmitted")?;
	let tx_hash = log
		.transaction_hash
		.context("TransactionBatchSubmitted log missing transaction_hash")?;
	Ok((decoded.inner.piCommitment, tx_hash))
}

/// Decode a `BridgeTxBatchSubmitted` log and return
/// `(piCommitment, transaction_hash)`.
fn decode_deposit_submitted_log(log: &Log) -> anyhow::Result<(B256, B256)> {
	let decoded = log
		.log_decode::<ITesseraRollupV2::BridgeTxBatchSubmitted>()
		.context("decode BridgeTxBatchSubmitted")?;
	let tx_hash = log
		.transaction_hash
		.context("BridgeTxBatchSubmitted log missing transaction_hash")?;
	Ok((decoded.inner.piCommitment, tx_hash))
}

// ---------------------------------------------------------------------------
// Proven-batch collection
// ---------------------------------------------------------------------------

/// Fetch `TransactionBatchProven` and `DepositBatchProven` events and return
/// them as an unsorted list of [`ProvenBatchEntry`] values.
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

	let dep_proven_logs = fetch_logs(
		provider,
		address,
		ITesseraRollupV2::BridgeTxBatchProven::SIGNATURE_HASH,
		from_block,
		to_block,
		chunk_blocks,
		"BridgeTxBatchProven",
	)
	.await?;

	let mut entries = Vec::with_capacity(tx_proven_logs.len() + dep_proven_logs.len());

	for log in &tx_proven_logs {
		match decode_tx_proven_log(log) {
			Ok(entry) => entries.push(entry),
			Err(e) => warn!(error = %e, "failed to decode TransactionBatchProven log; skipping"),
		}
	}
	for log in &dep_proven_logs {
		match decode_deposit_proven_log(log) {
			Ok(entry) => entries.push(entry),
			Err(e) => warn!(error = %e, "failed to decode DepositBatchProven log; skipping"),
		}
	}

	Ok(entries)
}

/// Decode a single `TransactionBatchProven` log into a [`ProvenBatchEntry`].
fn decode_tx_proven_log(log: &Log) -> anyhow::Result<ProvenBatchEntry> {
	let decoded = log
		.log_decode::<ITesseraRollupV2::TransactionBatchProven>()
		.context("decode TransactionBatchProven")?;
	let inner = &decoded.inner;
	Ok(ProvenBatchEntry {
		pi_commitment: inner.piCommitment,
		new_tree_root: contract::u256_le_to_hash(inner.newTreeRoot)
			.context("newTreeRoot is not a valid Goldilocks hash")?,
		leaf_index: inner
			.leafIndex
			.try_into()
			.context("leafIndex overflows u64")?,
		kind: BatchKind::Transaction,
	})
}

/// Decode a single `BridgeTxBatchProven` log into a [`ProvenBatchEntry`].
fn decode_deposit_proven_log(log: &Log) -> anyhow::Result<ProvenBatchEntry> {
	let decoded = log
		.log_decode::<ITesseraRollupV2::BridgeTxBatchProven>()
		.context("decode BridgeTxBatchProven")?;
	let inner = &decoded.inner;
	Ok(ProvenBatchEntry {
		pi_commitment: inner.piCommitment,
		new_tree_root: contract::u256_le_to_hash(inner.newTreeRoot)
			.context("newTreeRoot is not a valid Goldilocks hash")?,
		leaf_index: inner
			.leafIndex
			.try_into()
			.context("leafIndex overflows u64")?,
		kind: BatchKind::Deposit,
	})
}

// ---------------------------------------------------------------------------
// Batch replay
// ---------------------------------------------------------------------------

/// Apply a single proven batch to `state`.
///
/// Resolves the submission tx hash from the appropriate map, fetches the
/// transaction, decodes its calldata, and delegates to the correct apply
/// function.  Also records the proven root.
async fn replay_batch<P: Provider + Clone>(
	provider: &P,
	entry: &ProvenBatchEntry,
	tx_submit_map: &HashMap<B256, B256>,
	dep_submit_map: &HashMap<B256, B256>,
	state: &mut StateSnapshot,
) -> anyhow::Result<()> {
	let submit_map = match entry.kind {
		BatchKind::Transaction => tx_submit_map,
		BatchKind::Deposit => dep_submit_map,
	};

	let tx_hash = submit_map
		.get(&entry.pi_commitment)
		.copied()
		.with_context(|| {
			format!(
				"no submission tx found for piCommitment {:?} ({:?}); \
             the submission may be outside the synced block range",
				entry.pi_commitment, entry.kind
			)
		})?;

	let input = fetch_transaction_input(provider, tx_hash).await?;

	match entry.kind {
		BatchKind::Transaction => {
			let preimage = decode_tx_batch_calldata(&input)
				.context("decode submitTransactionBatch calldata")?;
			apply_tx_preimage(&preimage, state)?;
		},
		BatchKind::Deposit => {
			let preimage = decode_bridge_tx_batch_calldata(&input)
				.context("decode submitBridgeTxBatch calldata")?;
			apply_bridge_tx_preimage(&preimage, state)?;
		},
	}

	state.confirm_root(entry.new_tree_root);

	debug!(
		leaf_index = entry.leaf_index,
		local_leaf_count = state.leaf_count(),
		kind = ?entry.kind,
		"replayed proven batch"
	);

	Ok(())
}

// ---------------------------------------------------------------------------
// Transaction fetching
// ---------------------------------------------------------------------------

/// Fetch the calldata (`input`) of the transaction identified by `tx_hash`.
///
/// # Errors
/// Returns `Err` if the provider returns no transaction for the given hash.
async fn fetch_transaction_input<P: Provider + Clone>(
	provider: &P,
	tx_hash: B256,
) -> anyhow::Result<alloy::primitives::Bytes> {
	// Bring the consensus Transaction trait into scope so that `.input()` is
	// available on the inner transaction envelope via Deref.
	use alloy::consensus::Transaction as _;

	let tx = provider
		.get_transaction_by_hash(tx_hash)
		.await
		.with_context(|| format!("eth_getTransactionByHash({tx_hash:?})"))?
		.with_context(|| format!("transaction {tx_hash:?} not found"))?;

	Ok(tx.inner.input().clone())
}

// ---------------------------------------------------------------------------
// Calldata decoding
// ---------------------------------------------------------------------------

/// ABI-decode the calldata of a `submitTransactionBatch` transaction and
/// return the raw preimage bytes.
fn decode_tx_batch_calldata(
	input: &alloy::primitives::Bytes,
) -> anyhow::Result<alloy::primitives::Bytes> {
	use alloy::sol_types::SolCall;
	let call = ITesseraRollupV2::submitTransactionBatchCall::abi_decode(input)
		.context("ABI decode submitTransactionBatch")?;
	Ok(call.batchPreimage)
}

/// ABI-decode the calldata of a `submitBridgeTxBatch` transaction and
/// return the raw preimage bytes.
fn decode_bridge_tx_batch_calldata(
	input: &alloy::primitives::Bytes,
) -> anyhow::Result<alloy::primitives::Bytes> {
	use alloy::sol_types::SolCall;
	let call = ITesseraRollupV2::submitBridgeTxBatchCall::abi_decode(input)
		.context("ABI decode submitBridgeTxBatch")?;
	Ok(call.batchPreimage)
}

// ---------------------------------------------------------------------------
// Preimage parsing constants (must match TesseraContract.sol)
// ---------------------------------------------------------------------------

/// TX batch: header size in bytes (batchPoseidonRoot + root + mainPoolConfigRoot).
const TX_HEADER_SIZE: usize = 96;
/// TX batch: per-slot size = notFakeTx(8) + accinNull(32) + accoutComm(32) + noteInNull(7×32) + noteOutComm(7×32).
const TX_SLOT_SIZE: usize = 8 + 32 + 32 + 7 * 32 + 7 * 32; // 520
/// TX batch: byte offset of accinNullifier within a slot.
const TX_ACCIN_NULL_OFF: usize = 8;
/// TX batch: byte offset of the first noteInNullifier within a slot.
const TX_NOTE_IN_OFF: usize = 8 + 32 + 32; // 72
/// Number of private-TX slots per batch.
const PRIV_TX_BATCH_SIZE: usize = 64;
/// Note nullifiers per TX slot.
const NOTE_BATCH: usize = 7;
/// TX batch: total preimage length in bytes.
const TX_PREIMAGE_LEN: usize = TX_HEADER_SIZE + PRIV_TX_BATCH_SIZE * TX_SLOT_SIZE;

/// Bridge TX: per-withdraw-slot size.
const W_SLOT_SIZE: usize = 8 + 32 + 32 + 7 * 8 + 7 * 64 + 40; // 616
/// Bridge TX: per-deposit-slot size.
const D_SLOT_SIZE: usize = 8 + 32 + 32 + 32 + 40 + 64 + 8; // 216
/// Bridge TX: byte offset where the deposit section begins.
const D_SECTION_OFF: usize = 96 + 256 * W_SLOT_SIZE; // 157792
/// Bridge TX: half-batch size (256 withdraw + 256 deposit slots).
const BRIDGE_TX_HALF_SIZE: usize = 256;
/// Bridge TX: byte offset of accinNullifier within a withdraw slot.
const W_ACCIN_NULL_OFF: usize = 8;
/// Bridge TX: byte offset of accinNullifier within a deposit slot.
const D_ACCIN_NULL_OFF: usize = 8;
/// Bridge TX: total preimage length in bytes.
const BRIDGE_TX_PREIMAGE_LEN: usize =
	D_SECTION_OFF + BRIDGE_TX_HALF_SIZE * D_SLOT_SIZE;

// ---------------------------------------------------------------------------
// Preimage validation
// ---------------------------------------------------------------------------

fn validate_tx_preimage_len(preimage: &[u8]) -> anyhow::Result<()> {
	anyhow::ensure!(
		preimage.len() >= TX_PREIMAGE_LEN,
		"tx batch preimage too short: got {} bytes, expected at least {}",
		preimage.len(),
		TX_PREIMAGE_LEN
	);
	Ok(())
}

fn validate_bridge_tx_preimage_len(preimage: &[u8]) -> anyhow::Result<()> {
	anyhow::ensure!(
		preimage.len() >= BRIDGE_TX_PREIMAGE_LEN,
		"bridge tx batch preimage too short: got {} bytes, expected at least {}",
		preimage.len(),
		BRIDGE_TX_PREIMAGE_LEN
	);
	Ok(())
}

// ---------------------------------------------------------------------------
// Preimage parsing helpers
// ---------------------------------------------------------------------------

/// Read a GL-preimage-encoded bytes32 at `off` in `preimage` and return it as
/// the raw `[u8; 32]` format used by `StateSnapshot` / `hash_to_bytes32`.
///
/// GL-preimage layout:  [lo0_BE4][hi0_BE4][lo1_BE4][hi1_BE4]...
/// hash_to_bytes32 layout: [hi0_BE4][lo0_BE4][hi1_BE4][lo1_BE4]...
/// → swap the two 4-byte halves per field element (symmetric — same as
///   `raw_to_preimage_bytes32` / `preimage_bytes32_to_raw`).
fn read_gl_b32(preimage: &[u8], off: usize) -> [u8; 32] {
	let b: alloy::primitives::B256 =
		preimage[off..off + 32].try_into().expect("slice always 32 bytes");
	contract::preimage_bytes32_to_raw(&b)
}

/// Read the 8-byte GL-field at `off` and return `true` iff the value is
/// non-zero (lo_u32 or hi_u32 non-zero).
fn read_gl_bool(preimage: &[u8], off: usize) -> bool {
	let lo = u32::from_be_bytes(preimage[off..off + 4].try_into().unwrap());
	let hi = u32::from_be_bytes(preimage[off + 4..off + 8].try_into().unwrap());
	lo != 0 || hi != 0
}

// ---------------------------------------------------------------------------
// Leaf / nullifier extraction from preimage
// ---------------------------------------------------------------------------

/// Extract the single batch leaf (batchPoseidonRoot) from a TX or bridge-TX
/// preimage.  Each proven batch appends exactly one leaf — the batchPoseidonRoot
/// at offset 0 in the preimage.
fn leaf_from_preimage(preimage: &[u8]) -> [u8; 32] {
	read_gl_b32(preimage, 0)
}

/// Extract all nullifiers committed by a TX-batch preimage.
///
/// Only real slots (`notFakeTx` non-zero) contribute nullifiers.
/// Per real slot: 1 account nullifier + 7 note-in nullifiers.
fn nullifiers_from_tx_preimage(preimage: &[u8]) -> Vec<[u8; 32]> {
	let mut out = Vec::new();
	for s in 0..PRIV_TX_BATCH_SIZE {
		let slot_off = TX_HEADER_SIZE + s * TX_SLOT_SIZE;
		if !read_gl_bool(preimage, slot_off) {
			continue;
		}
		out.push(read_gl_b32(preimage, slot_off + TX_ACCIN_NULL_OFF));
		for j in 0..NOTE_BATCH {
			out.push(read_gl_b32(preimage, slot_off + TX_NOTE_IN_OFF + j * 32));
		}
	}
	out
}

/// Extract all nullifiers committed by a bridge-TX-batch preimage.
///
/// Real withdraw slots contribute 1 account nullifier each.
/// Real deposit slots contribute 1 account nullifier each.
/// (No per-note nullifiers in bridge TX slots.)
fn nullifiers_from_bridge_tx_preimage(preimage: &[u8]) -> Vec<[u8; 32]> {
	let mut out = Vec::new();
	for s in 0..BRIDGE_TX_HALF_SIZE {
		let w_off = 96 + s * W_SLOT_SIZE;
		if read_gl_bool(preimage, w_off) {
			out.push(read_gl_b32(preimage, w_off + W_ACCIN_NULL_OFF));
		}
		let d_off = D_SECTION_OFF + s * D_SLOT_SIZE;
		if read_gl_bool(preimage, d_off) {
			out.push(read_gl_b32(preimage, d_off + D_ACCIN_NULL_OFF));
		}
	}
	out
}

// ---------------------------------------------------------------------------
// State application
// ---------------------------------------------------------------------------

/// Apply a proven TX-batch preimage to `state`:
///   - Insert the batchPoseidonRoot as a tree leaf (confirmed state).
///   - Insert all nullifiers from real slots (confirmed state).
fn apply_tx_preimage(preimage: &[u8], state: &mut StateSnapshot) -> anyhow::Result<()> {
	validate_tx_preimage_len(preimage)?;
	state.insert_leaf(leaf_from_preimage(preimage))?;
	for nullifier in nullifiers_from_tx_preimage(preimage) {
		state.insert_nullifier(nullifier);
	}
	Ok(())
}

/// Apply a proven bridge-TX-batch preimage to `state`:
///   - Insert the batchPoseidonRoot as a tree leaf.
///   - Insert account nullifiers from all real withdraw and deposit slots.
fn apply_bridge_tx_preimage(preimage: &[u8], state: &mut StateSnapshot) -> anyhow::Result<()> {
	validate_bridge_tx_preimage_len(preimage)?;
	state.insert_leaf(leaf_from_preimage(preimage))?;
	for nullifier in nullifiers_from_bridge_tx_preimage(preimage) {
		state.insert_nullifier(nullifier);
	}
	Ok(())
}

// ---------------------------------------------------------------------------
// On-chain sanity helpers
// ---------------------------------------------------------------------------

/// Compare the local leaf count in `state` against the contract's
/// `leafCount()`.  Logs a warning on mismatch; does not return an error so
/// that a temporary discrepancy (e.g. a batch submitted but not yet proven)
/// does not abort the sync.
async fn verify_leaf_count<P: Provider + Clone>(
	provider: &P,
	address: Address,
	state: &StateSnapshot,
) {
	match fetch_on_chain_leaf_count(provider, address).await {
		Ok(on_chain) => {
			if state.leaf_count() as u64 == on_chain {
				info!(
					leaf_count = state.leaf_count(),
					"local tree matches on-chain leaf count"
				);
			} else {
				warn!(
					local = state.leaf_count(),
					on_chain, "local leaf count differs from on-chain leafCount()"
				);
			}
		},
		Err(e) => warn!(error = %e, "could not fetch on-chain leafCount() for sanity check"),
	}
}

/// Call `leafCount()` on the contract and return the result as `u64`.
pub(super) async fn fetch_on_chain_leaf_count<P: Provider + Clone>(
	provider: &P,
	address: Address,
) -> anyhow::Result<u64> {
	let instance = ITesseraRollupV2::ITesseraRollupV2Instance::new(address, provider);
	let count = instance.leafCount().call().await.context("leafCount()")?;
	count.try_into().context("leafCount overflows u64")
}

/// Call `treeDepth()` on the contract and return the result as `usize`.
///
/// Used at startup to allocate the local [`MerkleTree`] with the correct
/// depth without hard-coding the value.
async fn fetch_tree_depth<P: Provider + Clone>(
	provider: &P,
	address: Address,
) -> anyhow::Result<usize> {
	let instance = ITesseraRollupV2::ITesseraRollupV2Instance::new(address, provider);
	let depth = instance.treeDepth().call().await.context("treeDepth()")?;
	depth.try_into().context("treeDepth overflows usize")
}

// ---------------------------------------------------------------------------
// Paginated log fetching
// ---------------------------------------------------------------------------

/// Fetch all logs matching `event_sig` emitted by `address` between
/// `from_block` and `to_block`, paged in chunks of `chunk_blocks` blocks.
///
/// Paging avoids hitting provider range limits (typically 10 000 blocks per
/// `eth_getLogs` call on public nodes).
pub(super) async fn fetch_logs<P: Provider + Clone>(
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
