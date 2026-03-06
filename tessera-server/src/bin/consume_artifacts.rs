//! Generate consume-circuit artifacts for `/consume-request` proof validation.
//!
//! Produces a trivial 4-PI Plonky2 circuit (one `bytes32` note commitment
//! encoded as 4 Goldilocks u64 fields) and saves three files to
//! `tessera-server/artifacts/consume/`:
//!
//! | File               | Content                     | Used by           |
//! |--------------------|-----------------------------|-------------------|
//! | `leaf_common.bin`  | `CommonCircuitData`         | sequencer verifier |
//! | `leaf_verifier.bin`| `VerifierOnlyCircuitData`   | sequencer verifier |
//! | `leaf_prover.bin`  | full `CircuitData`          | client prover      |
//!
//! Usage:
//!   cargo run --bin consume_artifacts --release

use std::{fs, path::PathBuf};

use anyhow::Result;
use plonky2::{
	iop::target::Target,
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::{CircuitConfig, CircuitData},
	},
	util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use tessera_trees::{ConfigNative, D, F};

const N_PI: usize = 4;

fn main() -> Result<()> {
	let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("artifacts")
		.join("consume");

	fs::create_dir_all(&out_dir)?;
	println!("consume artifacts: {}", out_dir.display());

	let (circuit, _targets) = build_leaf_circuit();

	let gate_ser = DefaultGateSerializer;
	let gen_ser = DefaultGeneratorSerializer::<ConfigNative, D>::default();

	let common_bytes = circuit
		.common
		.to_bytes(&gate_ser)
		.map_err(|_| anyhow::anyhow!("serialize leaf_common failed"))?;
	fs::write(out_dir.join("leaf_common.bin"), &common_bytes)?;
	println!("  wrote: leaf_common.bin");

	let verifier_bytes = circuit
		.verifier_only
		.to_bytes()
		.map_err(|_| anyhow::anyhow!("serialize leaf_verifier failed"))?;
	fs::write(out_dir.join("leaf_verifier.bin"), &verifier_bytes)?;
	println!("  wrote: leaf_verifier.bin");

	let prover_bytes = circuit
		.to_bytes(&gate_ser, &gen_ser)
		.map_err(|_| anyhow::anyhow!("serialize leaf_prover failed"))?;
	fs::write(out_dir.join("leaf_prover.bin"), &prover_bytes)?;
	println!("  wrote: leaf_prover.bin");

	Ok(())
}

fn build_leaf_circuit() -> (CircuitData<F, ConfigNative, D>, Vec<Target>) {
	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, D>::new(config);
	let targets: Vec<Target> = (0..N_PI).map(|_| builder.add_virtual_target()).collect();
	for &t in &targets {
		builder.register_public_input(t);
	}
	(builder.build::<ConfigNative>(), targets)
}
