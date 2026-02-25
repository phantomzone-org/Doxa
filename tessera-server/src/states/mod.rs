mod commitment_state;
mod nullifier_state;

pub use commitment_state::*;
pub use nullifier_state::*;

/// Canonical sort key for sequencing on-chain events in arrival order.
///
/// Three-level sort (block → tx → log) matches the EVM log ordering guarantee:
/// events within a block are ordered by transaction position, and within a
/// transaction by log emission order.
///
/// On the API path (no on-chain event), `block_number` and `transaction_index`
/// are set to 0 and `log_index` is filled from a monotonically-increasing
/// counter (`api_order_counter`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventOrderKey {
	pub block_number: u64,
	pub transaction_index: u64,
	pub log_index: u64,
}

/// A leaf that has been accepted but not yet included in a proving batch.
///
/// Stored in `pending_requests` (keyed by [`EventOrderKey`]) and mirrored in
/// `pending_commitments` for O(1) duplicate detection.
#[derive(Debug, Clone)]
pub struct PendingRequest {
	pub order_key: EventOrderKey,
	pub commitment: [u8; 32],
}
