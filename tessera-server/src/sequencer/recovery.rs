use std::collections::BTreeSet;

use alloy::{
	providers::Provider,
	rpc::types::{Filter, Log},
	sol_types::SolEvent,
};
use tessera_utils::hasher::HashOutput;
use tracing::{debug, info};

use crate::contract::{self, ITesseraRollupV2};

/// Maximum block range per `eth_getLogs` call.
const LOG_FETCH_CHUNK_BLOCKS: u64 = 1_000;

/// Fetch all `TransactionBatchProven` and `DepositBatchProven` events between
/// `from_block` and `to_block`, extract their `newTreeRoot` fields, and insert
/// each decoded root into `history`.
pub(super) async fn load_confirmed_roots<P: Provider + Clone>(
	provider: &P,
	address: alloy::primitives::Address,
	from_block: u64,
	to_block: u64,
	history: &mut BTreeSet<HashOutput>,
) -> anyhow::Result<()> {
	// Fetch TransactionBatchProven events.
	let tx_proven_logs = fetch_paginated_logs(
		provider,
		address,
		ITesseraRollupV2::TransactionBatchProven::SIGNATURE_HASH,
		from_block,
		to_block,
		"TransactionBatchProven",
	)
	.await?;

	// Fetch DepositBatchProven events.
	let dep_proven_logs = fetch_paginated_logs(
		provider,
		address,
		ITesseraRollupV2::DepositBatchProven::SIGNATURE_HASH,
		from_block,
		to_block,
		"DepositBatchProven",
	)
	.await?;

	let mut inserted = 0usize;

	for log in tx_proven_logs.iter().chain(dep_proven_logs.iter()) {
		// Try decoding as TransactionBatchProven first, then DepositBatchProven.
		let new_root_u256 =
			if let Ok(d) = log.log_decode::<ITesseraRollupV2::TransactionBatchProven>() {
				d.inner.newTreeRoot
			} else if let Ok(d) = log.log_decode::<ITesseraRollupV2::DepositBatchProven>() {
				d.inner.newTreeRoot
			} else {
				continue;
			};

		match contract::u256_le_to_hash(new_root_u256) {
			Ok(root) => {
				if history.insert(root) {
					inserted += 1;
				}
			},
			Err(e) => {
				tracing::warn!(error = %e, "could not decode newTreeRoot from event; skipping");
			},
		}
	}

	info!(
		tx_proven = tx_proven_logs.len(),
		dep_proven = dep_proven_logs.len(),
		inserted,
		"loaded confirmed root history from on-chain events"
	);

	Ok(())
}

/// Fetch all matching logs for `event_sig` from `from_block` to `to_block`,
/// paged in chunks of `LOG_FETCH_CHUNK_BLOCKS`.
async fn fetch_paginated_logs<P: Provider + Clone>(
	provider: &P,
	address: alloy::primitives::Address,
	event_sig: alloy::primitives::B256,
	from_block: u64,
	to_block: u64,
	event_name: &str,
) -> anyhow::Result<Vec<Log>> {
	let mut all_logs: Vec<Log> = Vec::new();
	let mut chunk_start = from_block;
	while chunk_start <= to_block {
		let chunk_end = (chunk_start + LOG_FETCH_CHUNK_BLOCKS - 1).min(to_block);
		let filter = Filter::new()
			.address(address)
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
	Ok(all_logs)
}
