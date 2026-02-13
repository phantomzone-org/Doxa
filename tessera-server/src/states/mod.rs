mod commitment_state;
mod nullifier_state;

pub use commitment_state::*;
pub use nullifier_state::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventOrderKey {
	pub block_number: u64,
	pub transaction_index: u64,
	pub log_index: u64,
}

#[derive(Debug, Clone)]
pub struct PendingRequest {
	pub order_key: EventOrderKey,
	pub commitment: [u8; 32],
}
