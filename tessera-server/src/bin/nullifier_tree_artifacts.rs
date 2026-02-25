//! Generate native Plonky2 artifacts for the nullifier trees.
//!
//! Produces two sets of native circuit data (no BN128/Groth16 wrapping):
//!   - `artifacts/nullifier-tree/notes/native_circuit_data.bin`    (notes,
//!     `TESSERA_NOTE_BATCH_SIZE` leaves)
//!   - `artifacts/nullifier-tree/accounts/native_circuit_data.bin` (accounts,
//!     `TESSERA_ACCOUNT_BATCH_SIZE` leaves)
//!
//! The SuperAggregator artifact builder loads these files to embed the inner
//! circuit's `CommonCircuitData` and `VerifierOnlyCircuitData` as constants.
//!
//! Usage:
//!   TESSERA_NOTE_BATCH_SIZE=128 TESSERA_ACCOUNT_BATCH_SIZE=16 \
//!   cargo run --bin nullifier_tree_artifacts --release

use std::{fs, path::PathBuf};

use anyhow::{ensure, Result};
use plonky2::util::serialization::DefaultGateSerializer;
use tessera_server::sample_batch_nullifier_tree_proof;
use tessera_trees::groth::TesseraGeneratorSerializer;

fn generate_nullifier_artifacts(dir_name: &str, batch_size: usize) -> Result<()> {
	let artifacts_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifacts");
	let out_dir = artifacts_root.join(dir_name);
	fs::create_dir_all(&out_dir)?;

	println!("{dir_name}: batch_size={batch_size}");

	let (circuit_data, proof, _, _) = sample_batch_nullifier_tree_proof([0u8; 32], batch_size)?;

	// Verify the proof to confirm the circuit is sound.
	circuit_data.verify(proof)?;

	// Serialize native circuit data — loaded by super_aggregator_artifacts to bake
	// inner CommonCircuitData / VerifierOnlyCircuitData into the SuperAggregator.
	let gate_ser = DefaultGateSerializer;
	let native_bytes = circuit_data
		.to_bytes(&gate_ser, &TesseraGeneratorSerializer)
		.map_err(|_| {
			anyhow::anyhow!(
				"serialize native circuit failed for {dir_name}. \
				 If a new custom generator was added, register it in \
				 tessera-trees/src/groth/serializer.rs."
			)
		})?;

	let out_path = out_dir.join("native_circuit_data.bin");
	fs::write(&out_path, native_bytes)?;
	println!("  wrote: {}", out_path.display());

	Ok(())
}

fn main() -> Result<()> {
	let note_batch_size: usize = std::env::var("TESSERA_NOTE_BATCH_SIZE")
		.unwrap_or_else(|_| "128".to_string())
		.parse()
		.expect("TESSERA_NOTE_BATCH_SIZE must be a valid usize");
	let account_batch_size: usize = std::env::var("TESSERA_ACCOUNT_BATCH_SIZE")
		.unwrap_or_else(|_| "16".to_string())
		.parse()
		.expect("TESSERA_ACCOUNT_BATCH_SIZE must be a valid usize");

	ensure!(
		note_batch_size == account_batch_size * 8,
		"TESSERA_NOTE_BATCH_SIZE ({note_batch_size}) must be exactly 8 × TESSERA_ACCOUNT_BATCH_SIZE ({account_batch_size})"
	);

	println!("=== notes-nullifier-tree (batch_size={note_batch_size}) ===");
	generate_nullifier_artifacts("nullifier-tree/notes", note_batch_size)?;

	println!("\n=== accounts-nullifier-tree (batch_size={account_batch_size}) ===");
	generate_nullifier_artifacts("nullifier-tree/accounts", account_batch_size)?;

	Ok(())
}
