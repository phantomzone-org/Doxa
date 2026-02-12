//! Print the genesis root (empty Merkle tree root) as a hex-encoded bytes32.
//!
//! The sequencer starts with an empty depth-32 Poseidon Merkle tree. The
//! on-chain `DepositsRollupBridge` contract must be deployed with this exact
//! value as the `_genesisRoot` constructor argument.
//!
//! Usage:
//!   cargo run -p tessera-server --example genesis_root --release

use tessera_server::{contract, state::SequencerState};

fn main() {
	let root = SequencerState::genesis_root();
	let root_bytes32 = contract::hash_to_bytes32(&root);
	println!("{root_bytes32}");
}
