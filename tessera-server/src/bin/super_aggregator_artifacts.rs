//! Generate artifacts for the SuperAggregator.
//!
//! Must run AFTER `commitment_tree_artifacts`, `nullifier_tree_artifacts`, and
//! `aggregator_artifacts` have completed successfully.
//!
//! Inner PI counts (for reference):
//!   TX aggregator root: 128 × 75 = 9600 fields (ARITY=2, DEPTH=7, ReducerKind::None)
//!     Each TX leaf: subpool_id_in(1) + subpool_id_out(1) + is_real(1) + 72 data fields
//!   NC / NN tree:  (2 + note_batch_size) × 4    fields  (default: 4104 with batch_size=1024)
//!   AC / AN tree:  (2 + account_batch_size) × 4  fields  (default:  520 with batch_size=128)
//!   SuperAggregator Keccak preimage: 9248 fields (TX PIs enforced in-circuit, not hashed)
//!   SuperAggregator output: 8 fields (Keccak-256 digest as 8 × u32)
//!
//! Produces:
//!   - `artifacts/super-aggregator/`                (SuperAggregator Plonky2 circuit + inner data)
//!   - `artifacts/super-aggregator/plonky2-proof/`  (BN128 wrapper circuit data)
//!   - `artifacts/super-aggregator/groth-artifacts/` (Groth16 proving/verifying keys)
//!
//! Usage:
//!   TESSERA_NOTE_BATCH_SIZE=1024 TESSERA_ACCOUNT_BATCH_SIZE=128 \
//!   cargo run --bin super_aggregator_artifacts --release

use std::{fs, path::PathBuf, time::Instant};

use anyhow::{ensure, Result};
use plonky2::{
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::{CircuitConfig, VerifierCircuitTarget},
		proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
	},
	util::serialization::DefaultGateSerializer,
};
use tessera_server::{sample_batch_commitment_tree_proof, sample_batch_nullifier_tree_proof};
use tessera_trees::{
	groth::{BN128Wrapper, Groth16Wrapper, TesseraGeneratorSerializer},
	proof_aggregation::{GenericAggregator, SuperAggregator, SuperAggregatorCircuitData},
	CircuitDataNative, ConfigNative, ProofBN128, ProofNative, D, F,
};

const TX_ARITY: usize = 2;
const TX_DEPTH: usize = 7;

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

/// Build a recursive leaf circuit that verifies an inner PrivTx proof and forwards its PIs.
/// Returns the circuit, proof target, and verifier target.
fn build_recursive_leaf_circuit(
	inner_circuit: &CircuitDataNative,
) -> (
	CircuitDataNative,
	ProofWithPublicInputsTarget<D>,
	VerifierCircuitTarget,
) {
	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, D>::new(config);
	let inner_proof_target = builder.add_virtual_proof_with_pis(&inner_circuit.common);
	let inner_verifier_target = builder.constant_verifier_data(&inner_circuit.verifier_only);
	builder.verify_proof::<ConfigNative>(
		&inner_proof_target,
		&inner_verifier_target,
		&inner_circuit.common,
	);
	for &pi in &inner_proof_target.public_inputs {
		builder.register_public_input(pi);
	}
	let circuit = builder.build::<ConfigNative>();
	(circuit, inner_proof_target, inner_verifier_target)
}

/// Prove a recursive leaf by wrapping an inner PrivTx proof.
fn prove_recursive_leaf(
	leaf_circuit: &CircuitDataNative,
	inner_proof_target: &ProofWithPublicInputsTarget<D>,
	inner_verifier_target: &VerifierCircuitTarget,
	inner_circuit: &CircuitDataNative,
	inner_proof: &ProofWithPublicInputs<F, ConfigNative, D>,
) -> Result<ProofNative> {
	let mut pw = PartialWitness::new();
	pw.set_verifier_data_target(inner_verifier_target, &inner_circuit.verifier_only)?;
	pw.set_proof_with_pis_target(inner_proof_target, inner_proof)?;
	let proof = leaf_circuit.prove(pw)?;
	Ok(proof)
}

/// Generate one complete set of 5 inner proofs and prove the SuperAggregator.
///
/// TX leaf proofs use dummy inner PrivTx proofs (not_fake_tx=0) for all slots.
/// Since is_real=false for all dummy proofs, the SuperAggregator skips cross-check
/// constraints, making this valid for artifact generation and testing.
#[allow(clippy::too_many_arguments)]
fn prove_super(
	super_agg: &SuperAggregator,
	tx_agg: &GenericAggregator<F, ConfigNative, D>,
	inner_circuit: &CircuitDataNative,
	dummy_inner_proof: &ProofWithPublicInputs<F, ConfigNative, D>,
	leaf_circuit: &CircuitDataNative,
	inner_proof_target: &ProofWithPublicInputsTarget<D>,
	inner_verifier_target: &VerifierCircuitTarget,
	note_batch_size: usize,
	account_batch_size: usize,
	seed: [u8; 32],
) -> Result<ProofNative> {
	let (_, nc_proof, _, _) = sample_batch_commitment_tree_proof(seed, note_batch_size)?;
	let (_, nn_proof, _, _) = sample_batch_nullifier_tree_proof(seed, note_batch_size)?;
	let (_, ac_proof, _, _) = sample_batch_commitment_tree_proof(seed, account_batch_size)?;
	let (_, an_proof, _, _) = sample_batch_nullifier_tree_proof(seed, account_batch_size)?;

	let n_tx_slots = TX_ARITY.pow(TX_DEPTH as u32); // = 128

	// All TX leaf proofs wrap the dummy inner proof (not_fake_tx=0).
	let leaf_proofs: Vec<ProofNative> = (0..n_tx_slots)
		.map(|i| {
			let proof = prove_recursive_leaf(
				leaf_circuit,
				inner_proof_target,
				inner_verifier_target,
				inner_circuit,
				dummy_inner_proof,
			);
			if (i + 1) % 16 == 0 {
				println!("  proved recursive leaf {}/{}", i + 1, n_tx_slots);
			}
			proof
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
		.unwrap_or_else(|_| "1024".to_string())
		.parse()
		.expect("TESSERA_NOTE_BATCH_SIZE must be a valid usize");
	let account_batch_size: usize = std::env::var("TESSERA_ACCOUNT_BATCH_SIZE")
		.unwrap_or_else(|_| "128".to_string())
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

	// --- Build inner PrivTx circuit + dummy proof + recursive leaf circuit ---
	println!("\nBuilding inner PrivTx circuit + recursive leaf circuit...");
	let (inner_circuit, dummy_inner_proof) = tessera_client::build_circuit_and_dummy_proof();
	let (leaf_circuit, inner_proof_target, inner_verifier_target) =
		build_recursive_leaf_circuit(&inner_circuit);
	println!(
		"  inner PrivTx: {} PIs, degree_bits={}",
		inner_circuit.common.num_public_inputs,
		inner_circuit.common.degree_bits()
	);
	println!(
		"  recursive leaf: {} PIs, degree_bits={}",
		leaf_circuit.common.num_public_inputs,
		leaf_circuit.common.degree_bits()
	);

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
		&inner_circuit,
		&dummy_inner_proof,
		&leaf_circuit,
		&inner_proof_target,
		&inner_verifier_target,
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
		&inner_circuit,
		&dummy_inner_proof,
		&leaf_circuit,
		&inner_proof_target,
		&inner_verifier_target,
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
