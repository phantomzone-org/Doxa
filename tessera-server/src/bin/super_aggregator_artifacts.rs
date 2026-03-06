//! Generate artifacts for the SuperAggregator.
//!
//! Must run AFTER `commitment_tree_artifacts`, `nullifier_tree_artifacts`, and
//! `aggregator_artifacts` have completed successfully.
//!
//! Inner PI counts (for reference):
//!   TX aggregator root: 16 × 73 = 1168 fields (ARITY=2, DEPTH=4, ReducerKind::None)
//!     Each TX leaf: is_real(1) + 72 data fields
//!   NC / NN tree:  (2 + note_batch_size) × 4    fields  (default: 520 with batch_size=128)
//!   AC / AN tree:  (2 + account_batch_size) × 4  fields  (default:  72 with batch_size=16)
//!   SuperAggregator Keccak preimage: 1184 fields (TX PIs enforced in-circuit, not hashed)
//!   SuperAggregator output: 8 fields (Keccak-256 digest as 8 × u32)
//!
//! Produces:
//!   - `artifacts/super-aggregator/`                (SuperAggregator Plonky2 circuit + inner data)
//!   - `artifacts/super-aggregator/plonky2-proof/`  (BN128 wrapper circuit data)
//!   - `artifacts/super-aggregator/groth-artifacts/` (Groth16 proving/verifying keys)
//!
//! Usage:
//!   TESSERA_NOTE_BATCH_SIZE=128 TESSERA_ACCOUNT_BATCH_SIZE=16 \
//!   cargo run --bin super_aggregator_artifacts --release

use std::{fs, path::PathBuf, time::Instant};

use anyhow::{ensure, Result};
use plonky2::{
	iop::{
		target::Target,
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
	util::serialization::DefaultGateSerializer,
};
use tessera_server::{sample_batch_commitment_tree_proof, sample_batch_nullifier_tree_proof};
use tessera_trees::{
	groth::{BN128Wrapper, Groth16Wrapper, TesseraGeneratorSerializer},
	proof_aggregation::{GenericAggregator, SuperAggregator, SuperAggregatorCircuitData},
	CircuitDataNative, ConfigNative, ProofBN128, ProofNative, D, F,
};

const TX_ARITY: usize = 2;
const TX_DEPTH: usize = 4;

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

fn load_native_circuit_data(path: &std::path::Path) -> Result<CircuitDataNative> {
	let gate_ser = DefaultGateSerializer;
	let bytes =
		fs::read(path).map_err(|e| anyhow::anyhow!("failed to read '{}': {e}", path.display()))?;
	CircuitDataNative::from_bytes(&bytes, &gate_ser, &TesseraGeneratorSerializer).map_err(|_| {
		anyhow::anyhow!(
			"deserialize native circuit from '{}' failed. \
			 Delete the artifacts directory and re-run the tree artifact binaries.",
			path.display()
		)
	})
}

/// Build a TX-leaf circuit instance and prove it with specific 72-field data PI values.
///
/// The circuit geometry matches `aggregator_leaf_circuit` (TX_LEAF_PI=73,
/// standard_recursion_config): PI[0]=is_real (set to `true`), PI[1..73]=data.
/// Used when leaf PI values must be derived from tree proof public inputs.
fn prove_tx_leaf(data_values: &[F]) -> Result<ProofNative> {
	const TX_DATA_PI: usize = 72;
	assert_eq!(
		data_values.len(),
		TX_DATA_PI,
		"TX leaf must have exactly 72 data PI fields"
	);
	let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
	// PI[0] = is_real boolean (always true for real TX proofs)
	let is_real = builder.add_virtual_bool_target_safe();
	builder.register_public_input(is_real.target);
	// PI[1..73] = data fields
	let targets: Vec<Target> = (0..TX_DATA_PI)
		.map(|_| builder.add_virtual_target())
		.collect();
	for &t in &targets {
		builder.register_public_input(t);
	}
	let cd = builder.build::<ConfigNative>();
	let mut pw = PartialWitness::new();
	pw.set_bool_target(is_real, true)?;
	for (&t, &v) in targets.iter().zip(data_values.iter()) {
		pw.set_target(t, v)?;
	}
	cd.prove(pw)
}

/// Generate one complete set of 5 inner proofs and prove the SuperAggregator.
///
/// TX leaf proofs are constructed with PI values matching the corresponding
/// tree leaf PIs, satisfying the in-circuit cross-check constraints.
///
/// PI layout constants:
///   NC/AC (commitment tree): [old_root(4), new_root(4), leaves(...)] → leaves at offset 8
///   NN/AN (nullifier tree):  [old_root(4), new_node_path(1), values(...)] → values at offset 5
fn prove_super(
	super_agg: &SuperAggregator,
	tx_agg: &GenericAggregator<F, ConfigNative, D>,
	note_batch_size: usize,
	account_batch_size: usize,
	seed: [u8; 32],
) -> Result<ProofNative> {
	let (_, nc_proof, _, _) = sample_batch_commitment_tree_proof(seed, note_batch_size)?;
	let (_, nn_proof, _, _) = sample_batch_nullifier_tree_proof(seed, note_batch_size)?;
	let (_, ac_proof, _, _) = sample_batch_commitment_tree_proof(seed, account_batch_size)?;
	let (_, an_proof, _, _) = sample_batch_nullifier_tree_proof(seed, account_batch_size)?;

	let n_tx_slots = TX_ARITY.pow(TX_DEPTH as u32); // = 16
	let notes_per_slot = note_batch_size / n_tx_slots; // = 8

	// Leaf offsets within each tree's public_inputs:
	//   NC/AC: old_root[4] + new_root[4]       → leaves at 8
	//   NN/AN: [old_root(4), new_node_path(1), values[0..N-2](4 each), new_root(4), value[N-1](4)]
	//          → values[0..N-2] at offset 5; value[N-1] at nn_len-4 (after new_root)
	const NC_LEAF_OFFSET: usize = 8;
	const NN_LEAF_OFFSET: usize = 5;
	let nn_len = nn_proof.public_inputs.len();
	let an_len = an_proof.public_inputs.len();

	// Build one TX leaf proof per slot with PI values matching the tree leaf PIs.
	// TX leaf layout (72 fields per slot):
	//   [0 ..31] = note_nullifiers[0..8]  (from NN values)
	//   [32..63] = note_commitments[0..8] (from NC leaves)
	//   [64..67] = account_nullifier       (from AN values)
	//   [68..71] = account_commitment      (from AC leaves)
	let leaf_proofs: Vec<ProofNative> = (0..n_tx_slots)
		.map(|s| {
			let mut vals = Vec::with_capacity(72);
			// note nullifiers [0..32]: from NN values
			// values[0..N-2] at offset 5; value[N-1] at nn_len-4 (after new_root)
			for j in 0..notes_per_slot {
				let leaf_idx = s * notes_per_slot + j;
				let nn_val_base = if leaf_idx < note_batch_size - 1 {
					NN_LEAF_OFFSET + leaf_idx * 4
				} else {
					nn_len - 4
				};
				for k in 0..4 {
					vals.push(nn_proof.public_inputs[nn_val_base + k]);
				}
			}
			// note commitments [32..64]: from NC leaves
			for j in 0..notes_per_slot {
				for k in 0..4 {
					vals.push(
						nc_proof.public_inputs[NC_LEAF_OFFSET + (s * notes_per_slot + j) * 4 + k],
					);
				}
			}
			// account nullifier [64..68]: from AN values
			// value[N-1] at an_len-4 (after new_root)
			let an_val_base = if s < account_batch_size - 1 {
				NN_LEAF_OFFSET + s * 4
			} else {
				an_len - 4
			};
			for k in 0..4 {
				vals.push(an_proof.public_inputs[an_val_base + k]);
			}
			// account commitment [68..72]: from AC leaves
			for k in 0..4 {
				vals.push(ac_proof.public_inputs[NC_LEAF_OFFSET + s * 4 + k]);
			}
			prove_tx_leaf(&vals)
		})
		.collect::<Result<_>>()?;

	let tx_result = tx_agg.aggregate(leaf_proofs)?;

	let now = Instant::now();
	let proof = super_agg.prove(nc_proof, nn_proof, ac_proof, an_proof, tx_result.proof)?;
	println!("  SuperAggregator prove: {:?}", now.elapsed());
	Ok(proof)
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

	let artifacts_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifacts");
	let super_dir = artifacts_root.join("super-aggregator");
	let plonky2_path = super_dir.join("plonky2-proof");
	let groth_path = super_dir.join("groth-artifacts");

	println!("super-aggregator dir:    {}", super_dir.display());
	println!("plonky2 artifacts:       {}", plonky2_path.display());
	println!("groth16 artifacts:       {}", groth_path.display());

	// --- Load inner circuit data ---
	println!("\nLoading inner circuit data...");
	let nc_cd = load_native_circuit_data(
		&artifacts_root.join("commitment-tree/notes/native_circuit_data.bin"),
	)?;
	let nn_cd = load_native_circuit_data(
		&artifacts_root.join("nullifier-tree/notes/native_circuit_data.bin"),
	)?;
	let ac_cd = load_native_circuit_data(
		&artifacts_root.join("commitment-tree/accounts/native_circuit_data.bin"),
	)?;
	let an_cd = load_native_circuit_data(
		&artifacts_root.join("nullifier-tree/accounts/native_circuit_data.bin"),
	)?;

	let tx_agg: GenericAggregator<F, ConfigNative, D> =
		GenericAggregator::from_artifacts(&artifacts_root.join("associated-input-aggregator"))?;
	let tx_root = tx_agg.level_circuit(TX_DEPTH - 1)?;

	// --- Build SuperAggregator ---
	println!("\nBuilding SuperAggregator circuit...");
	let now = Instant::now();
	let inner = SuperAggregatorCircuitData {
		nc_common: nc_cd.common.clone(),
		nc_verifier: nc_cd.verifier_only.clone(),
		nn_common: nn_cd.common.clone(),
		nn_verifier: nn_cd.verifier_only.clone(),
		ac_common: ac_cd.common.clone(),
		ac_verifier: ac_cd.verifier_only.clone(),
		an_common: an_cd.common.clone(),
		an_verifier: an_cd.verifier_only.clone(),
		tx_common: tx_root.circuit_data.common.clone(),
		tx_verifier: tx_root.circuit_data.verifier_only.clone(),
	};
	let super_agg = SuperAggregator::build(inner)?;
	println!("  circuit built: {:?}", now.elapsed());

	// --- Initial prove (needed for BN128 circuit derivation and artifact storage) ---
	println!("\nGenerating dummy inner proofs (seed=0)...");
	let dummy_proof = prove_super(
		&super_agg,
		&tx_agg,
		note_batch_size,
		account_batch_size,
		[0u8; 32],
	)?;
	super_agg.circuit_data.verify(dummy_proof.clone())?;
	assert_eq!(
		dummy_proof.public_inputs.len(),
		8,
		"SuperAggregator root must have exactly 8 public inputs"
	);
	println!("  root proof verified ok");

	// --- Store SuperAggregator Plonky2 artifacts ---
	fs::create_dir_all(&super_dir)?;
	super_agg.store_artifacts(&super_dir)?;
	println!("stored SuperAggregator artifacts: {}", super_dir.display());

	// --- BN128 wrap ---
	debug_log("Instantiate BN128Wrapper");
	let bn128_wrapper = BN128Wrapper::new(super_agg.circuit_data.clone(), dummy_proof)?;

	if !BN128Wrapper::has_full_artifacts(&plonky2_path) {
		println!("writing plonky2 circuit data");
		fs::create_dir_all(&plonky2_path)?;
		bn128_wrapper.store_full_circuit_data(&plonky2_path)?;
	}

	// --- Groth16 trusted setup ---
	if !groth_path.is_dir() {
		println!("generating groth16 trusted setup");
		let result = Groth16Wrapper::trusted_setup(&plonky2_path, &groth_path);
		debug_log(&format!("trusted_setup result: {result}"));
	}

	let result: String = Groth16Wrapper::init(&plonky2_path, &groth_path)?;
	debug_log(&format!("init result: {result}"));

	let result: String = Groth16Wrapper::check_init();
	debug_log(&format!("check_init result: {result}"));

	// --- Groth16 round-trip test ---
	println!("\nGenerating Groth16 proof (seed=1)...");
	let super_proof2 = prove_super(
		&super_agg,
		&tx_agg,
		note_batch_size,
		account_batch_size,
		[1u8; 32],
	)?;

	let start = Instant::now();
	let proof_bn128: ProofBN128 = bn128_wrapper.wrap_proof_to_bn128(super_proof2)?;
	debug_log(&format!("[TIME] bn128 wrap: {:?}", start.elapsed()));

	let start = Instant::now();
	let (g16_proof, g16_pub_inp) = Groth16Wrapper::prove(proof_bn128)?;
	debug_log(&format!("[TIME] groth16_prove: {:?}", start.elapsed()));

	Groth16Wrapper::verify(g16_proof.clone(), g16_pub_inp.clone())?;
	println!("  Groth16 verify ok");

	let solidity_json = Groth16Wrapper::proof_to_solidity_json(&g16_proof, &g16_pub_inp)?;
	let json_path = groth_path.join("proof_solidity.json");
	fs::write(&json_path, &solidity_json)?;
	println!("wrote proof: {}", json_path.display());
	debug_log(&format!(
		"\n(rust) Solidity proof JSON written to {:?}\n{}",
		json_path, solidity_json
	));

	Ok(())
}
