//! Generate Aggregator artifacts for the [`PrivateTx`].
//!
//! Produces a native Plonky2 `GenericAggregator` (ARITY=2, DEPTH=7,
//! [`ReducerKind::None`]) that aggregates 128 leaf proofs and exposes their
//! 9344 raw public inputs (128×73) as the root proof's public inputs.
//! Each TX leaf has 73 fields: is_real(1) + 8 note nullifiers + 8 note commitments +
//! 1 account nullifier + 1 account commitment (4 Goldilocks fields each).
//! No BN128/Groth16 wrapping is done here — the SuperAggregator wraps all 5
//! inner proofs together.
//!
//! Usage:
//!   TESSERA_DEBUG=1 cargo run --bin aggregator_artifacts --release

use std::{fs, path::PathBuf, time::Instant};

use anyhow::Result;
use num::pow;
use plonky2::{
	field::types::Field,
	iop::{
		target::{BoolTarget, Target},
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::{CircuitConfig, CircuitData},
		proof::ProofWithPublicInputs,
	},
	util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use tessera_trees::{
	proof_aggregation::{GenericAggregator, GenericAggregatorConfig, ReducerKind},
	ConfigNative, D, F,
};

fn debug_enabled() -> bool {
	std::env::var("TESSERA_DEBUG")
		.map(|v| v == "1")
		.unwrap_or(false)
}

fn debug_log(msg: &str) {
	if debug_enabled() {
		println!("{msg}");
	}
}

const ARITY: usize = 2;
const DEPTH: usize = 7;
const TX_DATA_PI: usize = 72; // 8 nullifiers + 8 commitments + 1+1 accounts (×4)
const TX_LEAF_PI: usize = TX_DATA_PI + 1; // +1 for is_real boolean at PI[0]

fn main() -> Result<()> {
	let tmp_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("artifacts")
		.join("associated-input-aggregator");

	fs::create_dir_all(&tmp_dir)?;

	println!("aggregator artifacts: {}", tmp_dir.display());

	debug_log("Instantiate GenericAggregator");
	let config = GenericAggregatorConfig {
		arity: ARITY,
		depth: DEPTH,
		reducer: ReducerKind::None,
	};

	let (leaf_circuit, is_real_t, targets) = build_leaf_circuit(TX_DATA_PI);

	let prover_bytes = leaf_circuit
		.to_bytes(
			&DefaultGateSerializer,
			&DefaultGeneratorSerializer::<ConfigNative, D>::default(),
		)
		.map_err(|_| anyhow::anyhow!("serialize leaf_prover failed"))?;
	fs::write(tmp_dir.join("leaf_prover.bin"), &prover_bytes)?;
	println!("  wrote: leaf_prover.bin");

	let agg = GenericAggregator::new(
		config,
		leaf_circuit.common.clone(),
		leaf_circuit.verifier_only.clone(),
	)?;

	debug_log("Store GenericAggregator");
	agg.store_artifacts(&tmp_dir)?;

	// --- Sample leaf proofs for E2E test scripts ---
	//
	// Scripts look up $NOTE.hex from this directory to supply a real plonky2
	// leaf proof with each consume-request / private-tx submission.  One
	// distinct proof per note index ensures each slot in the 128-leaf
	// aggregation tree carries unique public inputs.
	//
	// 256 entries covers the default TOTAL_DEPOSITS=256 in the test scripts.
	// The trivial circuit proves in < 1 ms each, so this adds negligible time.
	const N_SAMPLE_PROOFS: usize = 256;
	let leaf_proofs_dir = tmp_dir.join("leaf_proofs");
	fs::create_dir_all(&leaf_proofs_dir)?;
	for i in 1..=N_SAMPLE_PROOFS {
		let note_hex = format!("0x{:064x}", i);
		let proof_path = leaf_proofs_dir.join(format!("{}.hex", note_hex));
		if proof_path.exists() {
			continue;
		}
		// TX_DATA_PI fields per leaf: 8×note_null (32f) + 8×note_comm (32f) + acct_null (4f) +
		// acct_comm (4f). Use a simple deterministic fill: field[k] = base + k, base = i * 1000.
		let base = i as u64 * 1000;
		let vals: Vec<u64> = (0..TX_DATA_PI).map(|k| base + k as u64).collect();
		let proof = prove_leaf(&leaf_circuit, is_real_t, &targets, true, &vals)?;
		let hex_str = format!("0x{}", hex::encode(proof.to_bytes()));
		fs::write(&proof_path, hex_str)?;
	}
	println!(
		"wrote {N_SAMPLE_PROOFS} sample leaf proofs to {}",
		leaf_proofs_dir.display()
	);

	debug_log("Generate Dummy Root Proof");
	let n_leaves: usize = pow(ARITY, DEPTH);

	let leaf_values: Vec<Vec<u64>> = (0..n_leaves as u64)
		.map(|i| (0..TX_DATA_PI as u64).map(|k| i * 1000 + k).collect())
		.collect();
	let proofs: Vec<_> = leaf_values
		.iter()
		.map(|vals| prove_leaf(&leaf_circuit, is_real_t, &targets, true, vals))
		.collect::<Result<_>>()?;

	let now = Instant::now();
	let root = agg.aggregate(proofs)?;
	println!("Aggregation took: {:?}", now.elapsed());
	agg.verify_root(&root.proof)?;

	// With ReducerKind::None the root proof passes all leaf PIs through unchanged:
	// n_leaves × TX_LEAF_PI = 128 × 73 = 9344 raw Goldilocks field elements.
	assert_eq!(
		root.proof.public_inputs.len(),
		n_leaves * TX_LEAF_PI,
		"ReducerKind::None root must have exactly n_leaves × TX_LEAF_PI = {} public inputs",
		n_leaves * TX_LEAF_PI,
	);

	Ok(())
}

fn build_leaf_circuit(
	n_data_pi: usize,
) -> (CircuitData<F, ConfigNative, D>, BoolTarget, Vec<Target>) {
	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, D>::new(config);
	// PI[0] = is_real boolean
	let is_real = builder.add_virtual_bool_target_safe();
	builder.register_public_input(is_real.target);
	// PI[1..] = data fields
	let targets: Vec<Target> = (0..n_data_pi)
		.map(|_| builder.add_virtual_target())
		.collect();
	for &t in &targets {
		builder.register_public_input(t);
	}
	(builder.build::<ConfigNative>(), is_real, targets)
}

fn prove_leaf(
	circuit: &CircuitData<F, ConfigNative, D>,
	is_real_t: BoolTarget,
	targets: &[Target],
	is_real: bool,
	values: &[u64],
) -> Result<ProofWithPublicInputs<F, ConfigNative, D>> {
	assert_eq!(targets.len(), values.len());
	let mut pw = PartialWitness::new();
	pw.set_bool_target(is_real_t, is_real)?;
	for (&t, &v) in targets.iter().zip(values.iter()) {
		pw.set_target(t, F::from_canonical_u64(v))?;
	}
	circuit.prove(pw)
}
