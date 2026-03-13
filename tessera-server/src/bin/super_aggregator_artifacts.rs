//! Generate artifacts for the SuperAggregator.
//!
//! Must run AFTER `commitment_tree_artifacts`, `nullifier_tree_artifacts`, and
//! `aggregator_artifacts` have completed successfully.
//!
//! Inner PI counts (for reference):
//!   TX aggregator root: 128 × 77 = 9856 fields (ARITY=2, DEPTH=7, ReducerKind::None)
//!     Each TX leaf: 75 explicit PIs + 2 plonky2 lookup-table metadata
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
	iop::witness::PartialWitness,
	plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
};
use tessera_client::TesseraGateSerializer;
use tessera_server::dummy::pad_leaves;
use tessera_trees::{
	groth::{BN128Wrapper, Groth16Wrapper, TesseraGeneratorSerializer},
	proof_aggregation::{
		validate_ac_offcircuit, validate_an_offcircuit, validate_nc_offcircuit,
		validate_nn_offcircuit, GenericAggregator, SuperAggregator, SuperAggregatorCircuitData,
	},
	tree::{
		hasher::{HashOutput, MerkleHashCircuit},
		BatchCommitmentProofTargets, BatchNullifierInsertProofTargets, CommitmentTree,
		NullifierTree,
	},
	CircuitDataNative, ConfigNative, ProofBN128, ProofNative, D, F,
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

const TREE_DEPTH: usize = 32;
const NOTES_PER_SLOT: usize = tessera_client::NOTE_BATCH;

fn extract_hash(pis: &[F], offset: usize) -> [F; 4] {
	[
		pis[offset],
		pis[offset + 1],
		pis[offset + 2],
		pis[offset + 3],
	]
}

/// Convert a HashOutput to a 32-byte big-endian representation.
fn hash_to_bytes32(h: &HashOutput) -> [u8; 32] {
	let mut bytes = [0u8; 32];
	for i in 0..4 {
		bytes[i * 8..(i + 1) * 8].copy_from_slice(&h.0[i].0.to_be_bytes());
	}
	bytes
}

/// Convert a 32-byte big-endian representation to 4 Goldilocks field elements.
fn bytes32_to_f4(b: &[u8; 32]) -> [F; 4] {
	core::array::from_fn(|i| {
		let val = u64::from_be_bytes(b[i * 8..(i + 1) * 8].try_into().unwrap());
		plonky2::field::types::Field::from_canonical_u64(val)
	})
}

fn prove_commitment_tree(leaves: &[HashOutput], batch_size: usize) -> Result<ProofNative> {
	let mut tree = CommitmentTree::<HashOutput>::new(TREE_DEPTH);
	let batch_proof = tree.insert_batch(leaves.to_vec())?;
	assert!(batch_proof.verify(), "commitment tree native proof invalid");

	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, D>::new(config);
	let ctx = HashOutput::register_luts(&mut builder);
	let targets =
		BatchCommitmentProofTargets::new::<HashOutput, F, D>(&mut builder, TREE_DEPTH, batch_size);
	targets.connect::<HashOutput, F, D>(&mut builder, &ctx);
	let cd = builder.build::<ConfigNative>();
	let mut pw = PartialWitness::new();
	targets.set::<HashOutput, F, D, TREE_DEPTH>(&mut pw, &batch_proof)?;
	let proof = cd.prove(pw)?;
	cd.verify(proof.clone())?;
	Ok(proof)
}

fn prove_nullifier_tree(leaves: &[HashOutput], batch_size: usize) -> Result<ProofNative> {
	let mut tree = NullifierTree::<HashOutput>::new_with_padding(TREE_DEPTH, batch_size);
	let batch_proof = tree.insert_batch(leaves.to_vec())?;
	assert!(batch_proof.verify(), "nullifier tree native proof invalid");

	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, D>::new(config);
	let ctx = HashOutput::register_luts(&mut builder);
	let targets = BatchNullifierInsertProofTargets::new::<HashOutput, F, D>(
		&mut builder,
		TREE_DEPTH,
		batch_size,
	);
	targets.connect::<HashOutput, F, D>(&mut builder, &ctx);
	let cd = builder.build::<ConfigNative>();
	let mut pw = PartialWitness::new();
	targets.set::<HashOutput, F, D>(&mut pw, &batch_proof)?;
	let proof = cd.prove(pw)?;
	cd.verify(proof.clone())?;
	Ok(proof)
}

fn load_native_circuit_data(path: &std::path::Path) -> Result<CircuitDataNative> {
	let gate_ser = plonky2::util::serialization::DefaultGateSerializer;
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

	let tx_agg_dir = artifacts_root.join("associated-input-aggregator");
	let tx_agg: GenericAggregator<F, ConfigNative, D> =
		GenericAggregator::from_artifacts(&tx_agg_dir, &TesseraGateSerializer)?;
	let tx_root = tx_agg.level_circuit(tx_agg.config().depth - 1)?;

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

	// --- Generate all proofs from scratch (same flow as integration test) ---
	// 1. Build PrivTx circuit.
	println!("\nBuilding PrivTx circuit...");
	let now = Instant::now();
	let (priv_tx_cd, priv_tx_targets) = tessera_client::build_priv_tx_circuit();
	println!(
		"  PrivTx circuit: {} PIs [{:?}]",
		priv_tx_cd.common.num_public_inputs,
		now.elapsed()
	);

	// 2. Generate real PrivTx proofs.
	let n_real = 2;
	let n_tx = account_batch_size;
	println!("\nProving {n_real} real PrivTx proofs...");
	let now = Instant::now();
	let real_proofs: Vec<ProofNative> = (0..n_real)
		.map(|i| tessera_client::prove_real_priv_tx(&priv_tx_cd, &priv_tx_targets, 42 + i as u64))
		.collect();
	println!("  {n_real} real proofs [{:?}]", now.elapsed());

	// 3. Extract AN/NN from real proofs as bytes for dummy-leaf derivation. Offsets account for
	//    LUT_PI_COUNT auto-registered PIs at the start.
	use tessera_trees::proof_aggregation::TX_DATA_OFFSET;
	let an_off = TX_DATA_OFFSET;
	let ac_off = TX_DATA_OFFSET + 4;
	let nn_off = TX_DATA_OFFSET + 8;
	let nc_off = TX_DATA_OFFSET + 40;

	let an_real_bytes: Vec<[u8; 32]> = real_proofs
		.iter()
		.map(|p| hash_to_bytes32(&HashOutput::from(extract_hash(&p.public_inputs, an_off))))
		.collect();
	let nn_real_bytes: Vec<[u8; 32]> = real_proofs
		.iter()
		.flat_map(|p| {
			(0..NOTES_PER_SLOT).map(move |j| {
				hash_to_bytes32(&HashOutput::from(extract_hash(
					&p.public_inputs,
					nn_off + j * 4,
				)))
			})
		})
		.collect();

	// 4. Pad AN/NN to derive dummy override values.
	// Use empty nullifier tree roots for the new derivation (trees start empty in artifact gen).
	let an_empty_root = hash_to_bytes32(
		&NullifierTree::<HashOutput>::new_with_padding(TREE_DEPTH, account_batch_size).get_root(),
	);
	let nn_empty_root = hash_to_bytes32(
		&NullifierTree::<HashOutput>::new_with_padding(TREE_DEPTH, note_batch_size).get_root(),
	);
	let an_padded_bytes = pad_leaves(&an_empty_root, 0, n_tx, &an_real_bytes)?;
	let nn_padded_bytes = pad_leaves(&nn_empty_root, 0, note_batch_size, &nn_real_bytes)?;

	// 5. Generate dummy PrivTx proofs with AN/NN overrides.
	let n_dummy = n_tx - n_real;
	println!("Proving {n_dummy} dummy PrivTx proofs...");
	let now = Instant::now();
	let mut tx_proofs: Vec<ProofNative> = real_proofs;
	for s in n_real..n_tx {
		let override_an = bytes32_to_f4(&an_padded_bytes[s]);
		let override_nn: [[F; 4]; tessera_client::NOTE_BATCH] =
			core::array::from_fn(|j| bytes32_to_f4(&nn_padded_bytes[s * NOTES_PER_SLOT + j]));
		let proof = tessera_client::prove_dummy_priv_tx(
			&priv_tx_cd,
			&priv_tx_targets,
			s as u64,
			override_an,
			override_nn,
		);
		tx_proofs.push(proof);
	}
	println!("  {n_dummy} dummy proofs [{:?}]", now.elapsed());

	// 6. Extract ALL tree leaves directly from TX proof PIs. NC/AC: arrival order (positional
	//    cross-checks in SA). AN/NN: sorted (multiset equality in SA — order-independent).
	println!("Extracting leaves from TX PIs & building trees...");
	let nc_hashes: Vec<HashOutput> = tx_proofs
		.iter()
		.flat_map(|p| {
			(0..NOTES_PER_SLOT)
				.map(move |j| HashOutput::from(extract_hash(&p.public_inputs, nc_off + j * 4)))
		})
		.collect();
	let ac_hashes: Vec<HashOutput> = tx_proofs
		.iter()
		.map(|p| HashOutput::from(extract_hash(&p.public_inputs, ac_off)))
		.collect();
	let mut an_hashes: Vec<HashOutput> = tx_proofs
		.iter()
		.map(|p| HashOutput::from(extract_hash(&p.public_inputs, an_off)))
		.collect();
	let mut nn_hashes: Vec<HashOutput> = tx_proofs
		.iter()
		.flat_map(|p| {
			(0..NOTES_PER_SLOT)
				.map(move |j| HashOutput::from(extract_hash(&p.public_inputs, nn_off + j * 4)))
		})
		.collect();
	an_hashes.sort();
	nn_hashes.sort();

	// 7. Build tree proofs.
	println!("Proving tree circuits...");
	let now = Instant::now();
	let nc_proof = prove_commitment_tree(&nc_hashes, note_batch_size)?;
	println!("  NC [{:?}]", now.elapsed());
	let now = Instant::now();
	let ac_proof = prove_commitment_tree(&ac_hashes, account_batch_size)?;
	println!("  AC [{:?}]", now.elapsed());
	let now = Instant::now();
	let nn_proof = prove_nullifier_tree(&nn_hashes, note_batch_size)?;
	println!("  NN [{:?}]", now.elapsed());
	let now = Instant::now();
	let an_proof = prove_nullifier_tree(&an_hashes, account_batch_size)?;
	println!("  AN [{:?}]", now.elapsed());

	// 8. Aggregate TX proofs.
	println!("Aggregating {} TX proofs...", n_tx);
	let now = Instant::now();
	let agg_result = tx_agg.aggregate(tx_proofs)?;
	tx_agg.verify_root(&agg_result.proof)?;
	println!("  Aggregation [{:?}]", now.elapsed());

	// 9. Off-circuit PI cross-checks then prove SuperAggregator.
	let tx_pis = &agg_result.proof.public_inputs;
	validate_ac_offcircuit(&ac_proof.public_inputs, tx_pis, n_tx)?;
	validate_nc_offcircuit(&nc_proof.public_inputs, tx_pis, n_tx, NOTES_PER_SLOT)?;
	validate_an_offcircuit(&an_proof.public_inputs, tx_pis, n_tx)?;
	validate_nn_offcircuit(&nn_proof.public_inputs, tx_pis, n_tx, NOTES_PER_SLOT)?;
	println!("Off-circuit PI cross-checks passed");

	println!("Proving SuperAggregator...");
	let now = Instant::now();
	let dummy_proof = super_agg.prove(nc_proof, nn_proof, ac_proof, an_proof, agg_result.proof)?;
	println!("  SuperAggregator prove: {:?}", now.elapsed());

	super_agg.circuit_data.verify(dummy_proof.clone())?;
	assert_eq!(
		dummy_proof.public_inputs.len(),
		8,
		"SuperAggregator root must have exactly 8 public inputs"
	);
	println!("  root proof verified ok");

	// --- Store SuperAggregator Plonky2 artifacts + serialized proof ---
	fs::create_dir_all(&super_dir)?;
	super_agg.store_artifacts(&super_dir)?;
	let dummy_proof_bytes = dummy_proof.to_bytes();
	fs::write(super_dir.join("dummy_super_proof.bin"), &dummy_proof_bytes)?;
	println!(
		"stored SuperAggregator artifacts: {} (proof {} bytes)",
		super_dir.display(),
		dummy_proof_bytes.len()
	);

	// --- BN128 wrap ---
	debug_log("Instantiate BN128Wrapper");
	let bn128_wrapper = BN128Wrapper::new(super_agg.circuit_data.clone(), dummy_proof.clone())?;

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

	// --- Groth16 round-trip test (reuses the serialized dummy proof) ---
	println!("\nGroth16 round-trip test (reusing dummy proof)...");

	let start = Instant::now();
	let proof_bn128: ProofBN128 = bn128_wrapper.wrap_proof_to_bn128(dummy_proof)?;
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
