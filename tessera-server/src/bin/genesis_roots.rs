//! Print the local (empty tree) genesis roots used by the sequencer.
//!
//! These roots must match the genesis roots configured at bridge deployment time.
//! If they don't match, the sequencer will refuse to run because proofs and on-chain
//! state would be inconsistent.
//!
//! Usage:
//!   cargo run --bin genesis_roots --release

use tessera_server::{
	contract,
	states::{CommitmentTreeState, NullifierTreeState},
};

fn main() {
	let commitment = contract::hash_to_bytes32(&CommitmentTreeState::genesis_root());
	let nullifier = contract::hash_to_bytes32(&NullifierTreeState::genesis_root());

	println!("commitment_genesis_root={commitment:?}");
	println!("nullifier_genesis_root={nullifier:?}");
}

