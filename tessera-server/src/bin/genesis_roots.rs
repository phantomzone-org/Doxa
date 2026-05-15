//! Print the local (empty tree) genesis roots used by the sequencer.
//!
//! These roots must match the genesis roots configured at bridge deployment time.
//! If they don't match, the sequencer will refuse to run because proofs and on-chain
//! state would be inconsistent.
//!
//! Usage:
//!   TESSERA_NOTE_BATCH_SIZE=1024 cargo run --bin genesis_roots --release

use tessera_server::{contract, states::CommitmentTreeState};

fn main() {
	let note_batch_size: usize = std::env::var("TESSERA_NOTE_BATCH_SIZE")
		.unwrap_or_else(|_| "1024".to_string())
		.parse()
		.expect("TESSERA_NOTE_BATCH_SIZE must be a valid usize");

	let commitment = contract::hash_to_bytes32(&CommitmentTreeState::genesis_root(note_batch_size));

	println!("commitment_genesis_root={commitment:?}");
}
