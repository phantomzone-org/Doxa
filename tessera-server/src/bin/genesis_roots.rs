//! Print the local (empty tree) genesis roots used by the sequencer.
//!
//! These roots must match the genesis roots configured at bridge deployment time.
//! If they don't match, the sequencer will refuse to run because proofs and on-chain
//! state would be inconsistent.
//!
//! Nullifier trees are pre-padded to `batch_size` alignment, so the genesis root
//! depends on the batch size.
//!
//! Usage:
//!   TESSERA_NOTE_BATCH_SIZE=1024 TESSERA_ACCOUNT_BATCH_SIZE=128 \
//!   cargo run --bin genesis_roots --release

use tessera_server::{
	contract,
	states::{CommitmentTreeState, NullifierTreeState},
};

fn main() {
	let note_batch_size: usize = std::env::var("TESSERA_NOTE_BATCH_SIZE")
		.unwrap_or_else(|_| "1024".to_string())
		.parse()
		.expect("TESSERA_NOTE_BATCH_SIZE must be a valid usize");
	let account_batch_size: usize = std::env::var("TESSERA_ACCOUNT_BATCH_SIZE")
		.unwrap_or_else(|_| "128".to_string())
		.parse()
		.expect("TESSERA_ACCOUNT_BATCH_SIZE must be a valid usize");

	let commitment = contract::hash_to_bytes32(&CommitmentTreeState::genesis_root(note_batch_size));
	let notes_nullifier =
		contract::hash_to_bytes32(&NullifierTreeState::genesis_root(note_batch_size));
	let accounts_nullifier =
		contract::hash_to_bytes32(&NullifierTreeState::genesis_root(account_batch_size));

	println!("commitment_genesis_root={commitment:?}");
	println!("notes_nullifier_genesis_root (batch_size={note_batch_size})={notes_nullifier:?}");
	println!(
		"accounts_nullifier_genesis_root (batch_size={account_batch_size})={accounts_nullifier:?}"
	);
}
