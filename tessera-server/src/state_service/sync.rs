use std::collections::HashMap;

use alloy::{
	primitives::{Address, B256, U256},
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
	let tx_submit_map =
		build_tx_submit_map(provider, address, from_block, to_block, chunk_blocks).await?;
	let dep_submit_map =
		build_deposit_submit_map(provider, address, from_block, to_block, chunk_blocks).await?;

	let mut ordered_batches =
		collect_proven_batches(provider, address, from_block, to_block, chunk_blocks).await?;
	ordered_batches.sort_by_key(|b| b.leaf_index);

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
		ITesseraRollupV2::DepositBatchSubmitted::SIGNATURE_HASH,
		from_block,
		to_block,
		chunk_blocks,
		"DepositBatchSubmitted",
	)
	.await?;

	let mut map = HashMap::with_capacity(logs.len());
	for log in &logs {
		match decode_deposit_submitted_log(log) {
			Ok((pi, tx_hash)) => {
				map.insert(pi, tx_hash);
			},
			Err(e) => {
				warn!(error = %e, "failed to decode DepositBatchSubmitted log; skipping");
			},
		}
	}
	Ok(map)
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

/// Decode a `DepositBatchSubmitted` log and return
/// `(piCommitment, transaction_hash)`.
fn decode_deposit_submitted_log(log: &Log) -> anyhow::Result<(B256, B256)> {
	let decoded = log
		.log_decode::<ITesseraRollupV2::DepositBatchSubmitted>()
		.context("decode DepositBatchSubmitted")?;
	let tx_hash = log
		.transaction_hash
		.context("DepositBatchSubmitted log missing transaction_hash")?;
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
		ITesseraRollupV2::DepositBatchProven::SIGNATURE_HASH,
		from_block,
		to_block,
		chunk_blocks,
		"DepositBatchProven",
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

/// Decode a single `DepositBatchProven` log into a [`ProvenBatchEntry`].
fn decode_deposit_proven_log(log: &Log) -> anyhow::Result<ProvenBatchEntry> {
	let decoded = log
		.log_decode::<ITesseraRollupV2::DepositBatchProven>()
		.context("decode DepositBatchProven")?;
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
			let call = decode_tx_batch_calldata(&input)
				.context("decode submitTransactionBatch calldata")?;
			apply_tx_batch(&call.batch, state)?;
		},
		BatchKind::Deposit => {
			let call = decode_deposit_batch_calldata(&input)
				.context("decode submitDepositBatch calldata")?;
			apply_deposit_batch(&call.batch, state)?;
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

/// ABI-decode the calldata of a `submitTransactionBatch` transaction.
///
/// # Errors
/// Returns `Err` if the bytes cannot be decoded as the expected 4-byte
/// selector followed by an ABI-encoded `TransactionBatch`.
fn decode_tx_batch_calldata(
	input: &alloy::primitives::Bytes,
) -> anyhow::Result<ITesseraRollupV2::submitTransactionBatchCall> {
	use alloy::sol_types::SolCall;
	ITesseraRollupV2::submitTransactionBatchCall::abi_decode(input)
		.context("ABI decode submitTransactionBatch")
}

/// ABI-decode the calldata of a `submitDepositBatch` transaction.
///
/// # Errors
/// Returns `Err` if the bytes cannot be decoded as the expected 4-byte
/// selector followed by an ABI-encoded `DepositBatch`.
fn decode_deposit_batch_calldata(
	input: &alloy::primitives::Bytes,
) -> anyhow::Result<ITesseraRollupV2::submitDepositBatchCall> {
	use alloy::sol_types::SolCall;
	ITesseraRollupV2::submitDepositBatchCall::abi_decode(input)
		.context("ABI decode submitDepositBatch")
}

// ---------------------------------------------------------------------------
// Commitment encoding helpers
// ---------------------------------------------------------------------------

/// Convert an on-chain `uint256` commitment to the canonical `[u8; 32]`
/// byte representation used by the sequencer and prover.
///
/// On-chain commitments are stored as LE-packed Goldilocks uint256 values
/// (see [`contract::hash_to_u256_le`]).  The sequencer represents the same
/// commitment as `[u8; 32]` with each of the four Goldilocks limbs in
/// big-endian byte order (see [`contract::hash_to_bytes32`]).
///
/// This function applies the correct inverse:
///   `limbs[i]` → `u64::to_be_bytes()` at offset `i * 8`.
///
/// # Errors
/// Returns `Err` if any 64-bit limb is ≥ `GOLDILOCKS_PRIME`.
fn u256_commitment_to_bytes32(v: U256) -> anyhow::Result<[u8; 32]> {
	let h = contract::u256_le_to_hash(v)?;
	Ok(contract::hash_to_bytes32(&h).0)
}

// ---------------------------------------------------------------------------
// Leaf / nullifier extraction
// ---------------------------------------------------------------------------

/// Extract the leaf commitments from a TX batch in tree-insertion order.
///
/// The on-chain IMT appends note commitments before account commitments,
/// matching the order the SubtreeRootCircuit processes them.
///
/// # Errors
/// Returns `Err` if any commitment limb is out of Goldilocks range.
fn leaves_from_tx_batch(
	batch: &ITesseraRollupV2::TransactionBatch,
) -> anyhow::Result<Vec<[u8; 32]>> {
	batch
		.noteCommitments
		.iter()
		.chain(batch.accountCommitments.iter())
		.map(|&v| u256_commitment_to_bytes32(v))
		.collect()
}

/// Extract the nullifiers from a TX batch.
///
/// Note nullifiers are followed by account nullifiers.
///
/// # Errors
/// Returns `Err` if any nullifier limb is out of Goldilocks range.
fn nullifiers_from_tx_batch(
	batch: &ITesseraRollupV2::TransactionBatch,
) -> anyhow::Result<Vec<[u8; 32]>> {
	batch
		.noteNullifiers
		.iter()
		.chain(batch.accountNullifiers.iter())
		.map(|&v| u256_commitment_to_bytes32(v))
		.collect()
}

/// Extract the leaf commitments from a deposit batch in tree-insertion order.
///
/// Deposit note commitments are stored on-chain as raw `bytes32` values,
/// matching the sequencer's `[u8; 32]` representation directly.
fn leaves_from_deposit_batch(batch: &ITesseraRollupV2::DepositBatch) -> Vec<[u8; 32]> {
	batch.depositNoteCommitments.iter().map(|b| b.0).collect()
}

// ---------------------------------------------------------------------------
// State application
// ---------------------------------------------------------------------------

/// Insert all leaves and nullifiers from a TX batch into `state`.
///
/// Leaves are inserted in the order returned by [`leaves_from_tx_batch`].
///
/// # Errors
/// Propagates any commitment-encoding or tree-insertion error.
fn apply_tx_batch(
	batch: &ITesseraRollupV2::TransactionBatch,
	state: &mut StateSnapshot,
) -> anyhow::Result<()> {
	for leaf in leaves_from_tx_batch(batch)? {
		state.insert_leaf(leaf)?;
	}
	for nullifier in nullifiers_from_tx_batch(batch)? {
		state.insert_nullifier(nullifier);
	}
	Ok(())
}

/// Insert all deposit note commitments from a deposit batch into `state`.
///
/// Deposit batches carry no nullifiers.
///
/// # Errors
/// Propagates any tree-insertion error.
fn apply_deposit_batch(
	batch: &ITesseraRollupV2::DepositBatch,
	state: &mut StateSnapshot,
) -> anyhow::Result<()> {
	for leaf in leaves_from_deposit_batch(batch) {
		state.insert_leaf(leaf)?;
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
