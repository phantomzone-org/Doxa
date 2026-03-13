//! Integration test: real PrivTx proofs → tree proofs → aggregation → SuperAggregator.
//!
//! Verifies the full proving pipeline with real (non-dummy) PrivTx proofs.
//! - `test_real_proof_pipeline_all_real`: minimal (2 TX, arity=2 depth=1).
//! - `test_real_proof_pipeline_128_tx`: production-size (128 TX, arity=2 depth=7).

use std::time::Instant;

use plonky2::{
	field::types::{Field, PrimeField64},
	iop::witness::PartialWitness,
	plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
};
use tessera_trees::{
	proof_aggregation::{
		validate_ac_offcircuit, validate_an_offcircuit, validate_nc_offcircuit,
		validate_nn_offcircuit, GenericAggregator, GenericAggregatorConfig, ReducerKind,
		SuperAggregator, SuperAggregatorCircuitData, IS_REAL_OFFSET, TX_DATA_OFFSET,
	},
	tree::{
		hasher::HashOutput, BatchCommitmentProofTargets, BatchNullifierInsertProofTargets,
		CommitmentTree, NullifierTree,
	},
	CircuitDataNative, ConfigNative, ProofNative, D, F,
};

const NOTES_PER_SLOT: usize = tessera_client::NOTE_BATCH; // 8
const TREE_DEPTH: usize = 32;

/// Extract 4-field hash from a proof's public inputs at the given offset.
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
		F::from_canonical_u64(val)
	})
}

/// Build a commitment-tree circuit, prove it, and return (circuit_data, proof).
fn prove_commitment_tree(
	batch_proof: &tessera_trees::tree::BatchCommitmentProof<HashOutput>,
	batch_size: usize,
) -> (CircuitDataNative, ProofNative) {
	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, D>::new(config);
	let targets = BatchCommitmentProofTargets::new::<F, D>(&mut builder, TREE_DEPTH, batch_size);
	targets.connect::<HashOutput, F, D>(&mut builder);
	let cd = builder.build::<ConfigNative>();
	let mut pw = PartialWitness::new();
	targets
		.set::<HashOutput, F, TREE_DEPTH>(&mut pw, batch_proof)
		.expect("commitment witness set failed");
	let proof = cd.prove(pw).expect("commitment tree prove failed");
	cd.verify(proof.clone())
		.expect("commitment tree verify failed");
	(cd, proof)
}

/// Build a nullifier-tree circuit, prove it, and return (circuit_data, proof).
fn prove_nullifier_tree(
	batch_proof: &tessera_trees::tree::BatchInsertProof<HashOutput>,
	batch_size: usize,
) -> (CircuitDataNative, ProofNative) {
	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, D>::new(config);
	let targets =
		BatchNullifierInsertProofTargets::new::<F, D>(&mut builder, TREE_DEPTH, batch_size);
	targets.connect::<HashOutput, F, D>(&mut builder);
	let cd = builder.build::<ConfigNative>();
	let mut pw = PartialWitness::new();
	targets
		.set::<HashOutput, F, TREE_DEPTH>(&mut pw, batch_proof)
		.expect("nullifier witness set failed");
	let proof = cd.prove(pw).expect("nullifier tree prove failed");
	cd.verify(proof.clone())
		.expect("nullifier tree verify failed");
	(cd, proof)
}

/// Full pipeline: 2 real PrivTx proofs → 4 tree proofs → aggregation → SuperAggregator.
#[test]
fn test_real_proof_pipeline_all_real() {
	let account_batch_size: usize = 2;
	let note_batch_size: usize = account_batch_size * NOTES_PER_SLOT;

	// ---------------------------------------------------------------
	// 1. Build PrivTx circuit and generate 2 real proofs (different seeds).
	// ---------------------------------------------------------------
	let t = Instant::now();
	println!("Building PrivTx circuit...");
	let (priv_tx_cd, priv_tx_targets) = tessera_client::build_priv_tx_circuit();
	let n_pi = priv_tx_cd.common.num_public_inputs;
	println!("  PrivTx circuit: {n_pi} PIs [{:.2?}]", t.elapsed());
	assert!(n_pi >= 75, "PrivTx must have at least 75 PIs, got {n_pi}");

	let t = Instant::now();
	println!("Proving PrivTx slot 0 (seed=42)...");
	let tx_proof_0 = tessera_client::prove_real_priv_tx(&priv_tx_cd, &priv_tx_targets, 42);
	println!("  [{:.2?}]", t.elapsed());

	let t = Instant::now();
	println!("Proving PrivTx slot 1 (seed=99)...");
	let tx_proof_1 = tessera_client::prove_real_priv_tx(&priv_tx_cd, &priv_tx_targets, 99);
	println!("  [{:.2?}]", t.elapsed());

	// ---------------------------------------------------------------
	// 2. Extract AN, AC, NN, NC from each proof's PIs.
	// ---------------------------------------------------------------
	let pis_0 = &tx_proof_0.public_inputs;
	let pis_1 = &tx_proof_1.public_inputs;

	assert_ne!(
		pis_0[IS_REAL_OFFSET],
		F::ZERO,
		"proof 0 must have is_real=1"
	);
	assert_ne!(
		pis_1[IS_REAL_OFFSET],
		F::ZERO,
		"proof 1 must have is_real=1"
	);

	let an_off = TX_DATA_OFFSET;
	let ac_off = TX_DATA_OFFSET + 4;
	let nn_off = TX_DATA_OFFSET + 8;
	let nc_off = TX_DATA_OFFSET + 40;

	let an_0 = extract_hash(pis_0, an_off);
	let an_1 = extract_hash(pis_1, an_off);
	let ac_0 = extract_hash(pis_0, ac_off);
	let ac_1 = extract_hash(pis_1, ac_off);

	let nn: Vec<HashOutput> = (0..2)
		.flat_map(|slot| {
			let pis = if slot == 0 { pis_0 } else { pis_1 };
			(0..NOTES_PER_SLOT).map(move |j| HashOutput::from(extract_hash(pis, nn_off + j * 4)))
		})
		.collect();

	let nc: Vec<HashOutput> = (0..2)
		.flat_map(|slot| {
			let pis = if slot == 0 { pis_0 } else { pis_1 };
			(0..NOTES_PER_SLOT).map(move |j| HashOutput::from(extract_hash(pis, nc_off + j * 4)))
		})
		.collect();

	let ac = vec![HashOutput::from(ac_0), HashOutput::from(ac_1)];
	let an = vec![HashOutput::from(an_0), HashOutput::from(an_1)];

	// ---------------------------------------------------------------
	// 3. Build trees, insert leaves, get native batch proofs.
	// ---------------------------------------------------------------
	let t = Instant::now();
	println!("Building NC tree...");
	let mut nc_tree = CommitmentTree::<HashOutput>::new(TREE_DEPTH);
	let nc_batch = nc_tree.insert_batch(nc.clone()).expect("NC insert failed");
	assert!(nc_batch.verify(), "NC native proof invalid");
	println!("  [{:.2?}]", t.elapsed());

	let t = Instant::now();
	println!("Building AC tree...");
	let mut ac_tree = CommitmentTree::<HashOutput>::new(TREE_DEPTH);
	let ac_batch = ac_tree.insert_batch(ac.clone()).expect("AC insert failed");
	assert!(ac_batch.verify(), "AC native proof invalid");
	println!("  [{:.2?}]", t.elapsed());

	let t = Instant::now();
	println!("Building NN tree...");
	let mut nn_tree = NullifierTree::<HashOutput>::new_with_padding(TREE_DEPTH, note_batch_size);
	let nn_batch = nn_tree.insert_batch(nn.clone()).expect("NN insert failed");
	assert!(nn_batch.verify(), "NN native proof invalid");
	println!("  [{:.2?}]", t.elapsed());

	let t = Instant::now();
	println!("Building AN tree...");
	let mut an_tree = NullifierTree::<HashOutput>::new_with_padding(TREE_DEPTH, account_batch_size);
	let an_batch = an_tree.insert_batch(an.clone()).expect("AN insert failed");
	assert!(an_batch.verify(), "AN native proof invalid");
	println!("  [{:.2?}]", t.elapsed());

	// ---------------------------------------------------------------
	// 4. Build tree circuits and prove.
	// ---------------------------------------------------------------
	let t = Instant::now();
	println!("Proving NC circuit...");
	let (nc_cd, nc_proof) = prove_commitment_tree(&nc_batch, note_batch_size);
	println!("  [{:.2?}]", t.elapsed());

	let t = Instant::now();
	println!("Proving AC circuit...");
	let (ac_cd, ac_proof) = prove_commitment_tree(&ac_batch, account_batch_size);
	println!("  [{:.2?}]", t.elapsed());

	let t = Instant::now();
	println!("Proving NN circuit...");
	let (nn_cd, nn_proof) = prove_nullifier_tree(&nn_batch, note_batch_size);
	println!("  [{:.2?}]", t.elapsed());

	let t = Instant::now();
	println!("Proving AN circuit...");
	let (an_cd, an_proof) = prove_nullifier_tree(&an_batch, account_batch_size);
	println!("  [{:.2?}]", t.elapsed());

	// ---------------------------------------------------------------
	// 5. Build GenericAggregator (arity=2, depth=1) and aggregate TX proofs.
	// ---------------------------------------------------------------
	let t = Instant::now();
	println!("Building TX aggregator (arity=2, depth=1)...");
	let agg_config = GenericAggregatorConfig {
		arity: 2,
		depth: 1,
		reducer: ReducerKind::None,
	};
	let agg = GenericAggregator::new(
		agg_config,
		priv_tx_cd.common.clone(),
		priv_tx_cd.verifier_only.clone(),
	)
	.expect("aggregator build failed");
	println!("  [{:.2?}]", t.elapsed());

	let t = Instant::now();
	println!("Aggregating 2 TX proofs...");
	let agg_result = agg
		.aggregate(vec![tx_proof_0, tx_proof_1])
		.expect("aggregation failed");
	agg.verify_root(&agg_result.proof)
		.expect("aggregation root verify failed");
	println!("  [{:.2?}]", t.elapsed());

	assert_eq!(agg_result.proof.public_inputs.len(), 2 * n_pi);

	// ---------------------------------------------------------------
	// 6. Build SuperAggregator and prove.
	// ---------------------------------------------------------------
	let agg_root_circuit = agg
		.level_circuit(0)
		.expect("aggregator has at least one level");

	let t = Instant::now();
	println!("Building SuperAggregator...");
	let sa_inner = SuperAggregatorCircuitData {
		nc_common: nc_cd.common.clone(),
		nc_verifier: nc_cd.verifier_only.clone(),
		nn_common: nn_cd.common.clone(),
		nn_verifier: nn_cd.verifier_only.clone(),
		ac_common: ac_cd.common.clone(),
		ac_verifier: ac_cd.verifier_only.clone(),
		an_common: an_cd.common.clone(),
		an_verifier: an_cd.verifier_only.clone(),
		tx_common: agg_root_circuit.circuit_data.common.clone(),
		tx_verifier: agg_root_circuit.circuit_data.verifier_only.clone(),
	};
	let sa = SuperAggregator::build(sa_inner).expect("SA build failed");
	println!("  [{:.2?}]", t.elapsed());

	// Off-circuit PI cross-checks (must pass before SA prove).
	let tx_pis = &agg_result.proof.public_inputs;
	validate_ac_offcircuit(&ac_proof.public_inputs, tx_pis, account_batch_size)
		.expect("off-circuit AC check failed");
	validate_nc_offcircuit(
		&nc_proof.public_inputs,
		tx_pis,
		account_batch_size,
		NOTES_PER_SLOT,
	)
	.expect("off-circuit NC check failed");
	validate_an_offcircuit(&an_proof.public_inputs, tx_pis, account_batch_size)
		.expect("off-circuit AN check failed");
	validate_nn_offcircuit(
		&nn_proof.public_inputs,
		tx_pis,
		account_batch_size,
		NOTES_PER_SLOT,
	)
	.expect("off-circuit NN check failed");

	let t = Instant::now();
	println!("Proving SuperAggregator...");
	let root = sa
		.prove(nc_proof, nn_proof, ac_proof, an_proof, agg_result.proof)
		.expect("SuperAggregator prove failed");
	println!("  [{:.2?}]", t.elapsed());

	assert_eq!(root.public_inputs.len(), 8);
	sa.circuit_data
		.verify(root)
		.expect("SuperAggregator verify failed");

	println!("SUCCESS: full real-proof pipeline (2 TX) passed");
}

/// Helper: run the full pipeline with `n_tx` slots, `n_real` real + rest dummy.
/// `agg_depth` must satisfy `2^agg_depth == n_tx`.
fn run_mixed_pipeline(tag: &str, n_tx: usize, n_real: usize, agg_depth: usize) {
	use tessera_server::dummy::pad_leaves;

	let account_batch_size = n_tx;
	let note_batch_size = n_tx * NOTES_PER_SLOT;
	let total_start = Instant::now();

	// 1. Build PrivTx circuit.
	let t = Instant::now();
	println!("[{tag}] Building PrivTx circuit...");
	let (priv_tx_cd, priv_tx_targets) = tessera_client::build_priv_tx_circuit();
	let n_pi = priv_tx_cd.common.num_public_inputs;
	println!("[{tag}]   PrivTx circuit: {n_pi} PIs [{:.2?}]", t.elapsed());

	// 2. Generate real proofs.
	let t = Instant::now();
	println!("[{tag}] Proving {n_real} real PrivTx proofs...");
	let real_proofs: Vec<ProofNative> = (0..n_real)
		.map(|i| tessera_client::prove_real_priv_tx(&priv_tx_cd, &priv_tx_targets, 42 + i as u64))
		.collect();
	println!("[{tag}]   {n_real} real proofs [{:.2?}]", t.elapsed());

	// 3. Extract AN/NN from real proofs as bytes for dummy-leaf derivation.
	let an_real_bytes: Vec<[u8; 32]> = real_proofs
		.iter()
		.map(|p| hash_to_bytes32(&HashOutput::from(extract_hash(&p.public_inputs, 3))))
		.collect();
	let nn_real_bytes: Vec<[u8; 32]> = real_proofs
		.iter()
		.flat_map(|p| {
			(0..NOTES_PER_SLOT).map(move |j| {
				hash_to_bytes32(&HashOutput::from(extract_hash(
					&p.public_inputs,
					11 + j * 4,
				)))
			})
		})
		.collect();

	// 4. Pad AN/NN batches to derive dummy override values.
	let t = Instant::now();
	println!("[{tag}] Padding AN/NN for dummy overrides...");
	// Use empty nullifier tree roots for dummy derivation (tests start from empty trees).
	let an_empty_root = hash_to_bytes32(
		&NullifierTree::<HashOutput>::new_with_padding(TREE_DEPTH, account_batch_size).get_root(),
	);
	let nn_empty_root = hash_to_bytes32(
		&NullifierTree::<HashOutput>::new_with_padding(TREE_DEPTH, note_batch_size).get_root(),
	);
	let an_padded_bytes =
		pad_leaves(&an_empty_root, 0, account_batch_size, &an_real_bytes).expect("AN pad failed");
	let nn_padded_bytes =
		pad_leaves(&nn_empty_root, 0, note_batch_size, &nn_real_bytes).expect("NN pad failed");
	println!("[{tag}]   Padding [{:.2?}]", t.elapsed());

	// 5. Generate dummy proofs with AN/NN overrides.
	let t = Instant::now();
	let n_dummy = n_tx - n_real;
	println!("[{tag}] Proving {n_dummy} dummy PrivTx proofs...");
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
	println!("[{tag}]   {n_dummy} dummy proofs [{:.2?}]", t.elapsed());

	// 6. Extract ALL tree leaves directly from TX proof PIs. This guarantees tree inputs exactly
	//    match what the SA circuit sees.
	//
	//    Ordering rules (must match production sequencer):
	//    - NC/AC: arrival order (positional cross-checks in SA).
	//    - NN/AN: sorted (multiset equality in SA — order-independent).
	//    TX proofs stay in arrival order; dummy overrides use unsorted AN/NN.
	let t = Instant::now();
	println!("[{tag}] Extracting leaves from TX PIs & building trees...");

	// NC/AC: arrival order — directly from TX proof PIs in slot order.
	let nc_hashes: Vec<HashOutput> = tx_proofs
		.iter()
		.flat_map(|p| {
			(0..NOTES_PER_SLOT)
				.map(move |j| HashOutput::from(extract_hash(&p.public_inputs, 43 + j * 4)))
		})
		.collect();
	let ac_hashes: Vec<HashOutput> = tx_proofs
		.iter()
		.map(|p| HashOutput::from(extract_hash(&p.public_inputs, 7)))
		.collect();

	// AN/NN: sorted for nullifier trees (multiset equality is order-independent).
	let mut an_hashes: Vec<HashOutput> = tx_proofs
		.iter()
		.map(|p| HashOutput::from(extract_hash(&p.public_inputs, 3)))
		.collect();
	let mut nn_hashes: Vec<HashOutput> = tx_proofs
		.iter()
		.flat_map(|p| {
			(0..NOTES_PER_SLOT)
				.map(move |j| HashOutput::from(extract_hash(&p.public_inputs, 11 + j * 4)))
		})
		.collect();
	an_hashes.sort();
	nn_hashes.sort();

	let mut nc_tree = CommitmentTree::<HashOutput>::new(TREE_DEPTH);
	let nc_batch = nc_tree.insert_batch(nc_hashes).expect("NC insert failed");
	assert!(nc_batch.verify(), "NC native proof invalid");

	let mut ac_tree = CommitmentTree::<HashOutput>::new(TREE_DEPTH);
	let ac_batch = ac_tree.insert_batch(ac_hashes).expect("AC insert failed");
	assert!(ac_batch.verify(), "AC native proof invalid");

	let mut nn_tree = NullifierTree::<HashOutput>::new_with_padding(TREE_DEPTH, note_batch_size);
	let nn_batch = nn_tree.insert_batch(nn_hashes).expect("NN insert failed");
	assert!(nn_batch.verify(), "NN native proof invalid");

	let mut an_tree = NullifierTree::<HashOutput>::new_with_padding(TREE_DEPTH, account_batch_size);
	let an_batch = an_tree.insert_batch(an_hashes).expect("AN insert failed");
	assert!(an_batch.verify(), "AN native proof invalid");
	println!("[{tag}]   Trees [{:.2?}]", t.elapsed());

	// 7. Tree circuit proofs.
	let t = Instant::now();
	println!("[{tag}] Proving NC circuit (batch={note_batch_size})...");
	let (nc_cd, nc_proof) = prove_commitment_tree(&nc_batch, note_batch_size);
	println!("[{tag}]   NC [{:.2?}]", t.elapsed());

	let t = Instant::now();
	println!("[{tag}] Proving AC circuit (batch={account_batch_size})...");
	let (ac_cd, ac_proof) = prove_commitment_tree(&ac_batch, account_batch_size);
	println!("[{tag}]   AC [{:.2?}]", t.elapsed());

	let t = Instant::now();
	println!("[{tag}] Proving NN circuit (batch={note_batch_size})...");
	let (nn_cd, nn_proof) = prove_nullifier_tree(&nn_batch, note_batch_size);
	println!("[{tag}]   NN [{:.2?}]", t.elapsed());

	let t = Instant::now();
	println!("[{tag}] Proving AN circuit (batch={account_batch_size})...");
	let (an_cd, an_proof) = prove_nullifier_tree(&an_batch, account_batch_size);
	println!("[{tag}]   AN [{:.2?}]", t.elapsed());

	// 8. Aggregation.
	let t = Instant::now();
	println!("[{tag}] Building TX aggregator (arity=2, depth={agg_depth})...");
	let agg_config = GenericAggregatorConfig {
		arity: 2,
		depth: agg_depth,
		reducer: ReducerKind::None,
	};
	let agg = GenericAggregator::new(
		agg_config,
		priv_tx_cd.common.clone(),
		priv_tx_cd.verifier_only.clone(),
	)
	.expect("aggregator build failed");
	println!("[{tag}]   Aggregator build [{:.2?}]", t.elapsed());

	let t = Instant::now();
	println!("[{tag}] Aggregating {n_tx} TX proofs...");
	let agg_result = agg.aggregate(tx_proofs).expect("aggregation failed");
	agg.verify_root(&agg_result.proof)
		.expect("aggregation root verify failed");
	println!("[{tag}]   Aggregation [{:.2?}]", t.elapsed());
	assert_eq!(agg_result.proof.public_inputs.len(), n_tx * n_pi);

	// 9. SuperAggregator.
	let agg_root_circuit = agg
		.level_circuit(agg_depth - 1)
		.expect("aggregator root level");

	let t = Instant::now();
	println!("[{tag}] Building SuperAggregator...");
	let sa_inner = SuperAggregatorCircuitData {
		nc_common: nc_cd.common.clone(),
		nc_verifier: nc_cd.verifier_only.clone(),
		nn_common: nn_cd.common.clone(),
		nn_verifier: nn_cd.verifier_only.clone(),
		ac_common: ac_cd.common.clone(),
		ac_verifier: ac_cd.verifier_only.clone(),
		an_common: an_cd.common.clone(),
		an_verifier: an_cd.verifier_only.clone(),
		tx_common: agg_root_circuit.circuit_data.common.clone(),
		tx_verifier: agg_root_circuit.circuit_data.verifier_only.clone(),
	};
	let sa = SuperAggregator::build(sa_inner).expect("SA build failed");
	println!("[{tag}]   SA build [{:.2?}]", t.elapsed());

	// Off-circuit PI cross-checks (must pass before SA prove).
	let tx_pis = &agg_result.proof.public_inputs;
	validate_ac_offcircuit(&ac_proof.public_inputs, tx_pis, n_tx)
		.expect("off-circuit AC check failed");
	validate_nc_offcircuit(&nc_proof.public_inputs, tx_pis, n_tx, NOTES_PER_SLOT)
		.expect("off-circuit NC check failed");
	validate_an_offcircuit(&an_proof.public_inputs, tx_pis, n_tx)
		.expect("off-circuit AN check failed");
	validate_nn_offcircuit(&nn_proof.public_inputs, tx_pis, n_tx, NOTES_PER_SLOT)
		.expect("off-circuit NN check failed");
	println!("[{tag}]   Off-circuit PI checks passed");

	let t = Instant::now();
	println!("[{tag}] Proving SuperAggregator...");
	let root = sa
		.prove(nc_proof, nn_proof, ac_proof, an_proof, agg_result.proof)
		.expect("SuperAggregator prove failed");
	println!("[{tag}]   SA prove [{:.2?}]", t.elapsed());

	assert_eq!(root.public_inputs.len(), 8);
	sa.circuit_data
		.verify(root)
		.expect("SuperAggregator verify failed");

	println!("[{tag}] SUCCESS [{:.2?}]", total_start.elapsed());
}

/// 4 TX: 2 real + 2 dummy → full pipeline.
#[test]
fn test_pipeline_4tx_2real_2dummy() {
	run_mixed_pipeline("4TX-2R", 4, 2, 2);
}

/// 4 TX: all dummy → full pipeline.
#[test]
fn test_pipeline_4tx_all_dummy() {
	run_mixed_pipeline("4TX-0R", 4, 0, 2);
}

/// 128 TX: 2 real + 126 dummy → full production-scale pipeline.
#[test]
#[ignore] // slow; run with: cargo test -p tessera-server --test real_proof_pipeline --release --
		  // test_pipeline_128tx --ignored --nocapture
fn test_pipeline_128tx() {
	run_mixed_pipeline("128TX-2R", 128, 2, 7);
}

/// SA Plonky2 proof via BatchBuilder path (no BN128/Groth16).
///
/// Exercises the full sequencer flow: BatchBuilder → FinalizedBatch →
/// sort permutation → dummy overrides → tree proofs → TX aggregation →
/// SuperAggregator Plonky2 prove. Catches permutation bugs that only
/// manifest when the sequencer sorts leaves.
#[test]
fn test_sa_plonky2_from_batch_builder() {
	use plonky2::plonk::proof::ProofWithPublicInputs;
	use tessera_server::sequencer::batch::BatchBuilder;

	let tag = "BB-4TX-2R";
	let account_batch_size: usize = 128;
	let note_batch_size = account_batch_size * NOTES_PER_SLOT;
	let agg_depth = 7; // arity=2, depth=2 → 4 leaves
	let total_start = Instant::now();

	// 1. Build PrivTx circuit + 2 real proofs.
	let t = Instant::now();
	println!("[{tag}] Building PrivTx circuit...");
	let (priv_tx_cd, priv_tx_targets) = tessera_client::build_priv_tx_circuit();
	let n_pi = priv_tx_cd.common.num_public_inputs;
	println!("[{tag}]   PrivTx circuit: {n_pi} PIs [{:.2?}]", t.elapsed());

	let t = Instant::now();
	println!("[{tag}] Proving 2 real PrivTx proofs...");
	let real_proofs: Vec<ProofNative> = (0..2)
		.map(|i| tessera_client::prove_real_priv_tx(&priv_tx_cd, &priv_tx_targets, 42 + i as u64))
		.collect();
	println!("[{tag}]   2 real proofs [{:.2?}]", t.elapsed());

	// 2. Build empty trees.
	let ac_tree = CommitmentTree::<HashOutput>::new(TREE_DEPTH);
	let an_tree = NullifierTree::<HashOutput>::new_with_padding(TREE_DEPTH, account_batch_size);
	let nc_tree = CommitmentTree::<HashOutput>::new(TREE_DEPTH);
	let nn_tree = NullifierTree::<HashOutput>::new_with_padding(TREE_DEPTH, note_batch_size);

	// 3. Build batch via BatchBuilder.
	let t = Instant::now();
	println!("[{tag}] Building batch via BatchBuilder...");
	let mut bb = BatchBuilder::new(account_batch_size, &ac_tree, &an_tree, &nc_tree, &nn_tree);
	let an_off = TX_DATA_OFFSET;
	let ac_off = TX_DATA_OFFSET + 4;
	let nn_off = TX_DATA_OFFSET + 8;
	let nc_off = TX_DATA_OFFSET + 40;
	for proof in &real_proofs {
		let pis = &proof.public_inputs;
		let an = hash_to_bytes32(&HashOutput::from(extract_hash(pis, an_off)));
		let ac = hash_to_bytes32(&HashOutput::from(extract_hash(pis, ac_off)));
		let nn: [[u8; 32]; 8] = core::array::from_fn(|j| {
			hash_to_bytes32(&HashOutput::from(extract_hash(pis, nn_off + j * 4)))
		});
		let nc: [[u8; 32]; 8] = core::array::from_fn(|j| {
			hash_to_bytes32(&HashOutput::from(extract_hash(pis, nc_off + j * 4)))
		});
		bb.add_private_tx(proof.to_bytes(), ac, an, nc, nn)
			.expect("add_private_tx failed");
	}
	let batch = bb.finalize();
	println!(
		"[{tag}]   BatchBuilder finalized: {} AC, {} NC, {} real slots [{:.2?}]",
		batch.ac_leaves.len(),
		batch.nc_leaves.len(),
		batch.tx_proofs_by_slot.len(),
		t.elapsed()
	);

	// 4. Build trees from FinalizedBatch arrays.
	let t = Instant::now();
	println!("[{tag}] Building trees from batch arrays...");
	let nc_hashes: Vec<HashOutput> = batch
		.nc_leaves
		.iter()
		.map(|b| HashOutput::from(bytes32_to_f4(b)))
		.collect();
	let ac_hashes: Vec<HashOutput> = batch
		.ac_leaves
		.iter()
		.map(|b| HashOutput::from(bytes32_to_f4(b)))
		.collect();
	let an_hashes: Vec<HashOutput> = batch
		.an_sorted
		.iter()
		.map(|b| HashOutput::from(bytes32_to_f4(b)))
		.collect();
	let nn_hashes: Vec<HashOutput> = batch
		.nn_sorted
		.iter()
		.map(|b| HashOutput::from(bytes32_to_f4(b)))
		.collect();

	let mut nc_tree = CommitmentTree::<HashOutput>::new(TREE_DEPTH);
	let nc_batch = nc_tree.insert_batch(nc_hashes).expect("NC insert failed");
	assert!(nc_batch.verify(), "NC native proof invalid");

	let mut ac_tree = CommitmentTree::<HashOutput>::new(TREE_DEPTH);
	let ac_batch = ac_tree.insert_batch(ac_hashes).expect("AC insert failed");
	assert!(ac_batch.verify(), "AC native proof invalid");

	let mut nn_tree = NullifierTree::<HashOutput>::new_with_padding(TREE_DEPTH, note_batch_size);
	let nn_batch = nn_tree.insert_batch(nn_hashes).expect("NN insert failed");
	assert!(nn_batch.verify(), "NN native proof invalid");

	let mut an_tree = NullifierTree::<HashOutput>::new_with_padding(TREE_DEPTH, account_batch_size);
	for (i, h) in an_hashes.iter().enumerate() {
		println!(
			"[{tag}]   AN tree sorted[{i}] = [{}, {}, {}, {}]",
			h.0[0].to_canonical_u64(),
			h.0[1].to_canonical_u64(),
			h.0[2].to_canonical_u64(),
			h.0[3].to_canonical_u64(),
		);
	}
	let an_batch = an_tree.insert_batch(an_hashes).expect("AN insert failed");
	assert!(an_batch.verify(), "AN native proof invalid");
	println!("[{tag}]   Trees [{:.2?}]", t.elapsed());

	// 5. Tree circuit proofs.
	let t = Instant::now();
	println!("[{tag}] Proving tree circuits...");
	let (nc_cd, nc_proof) = prove_commitment_tree(&nc_batch, note_batch_size);
	let (ac_cd, ac_proof) = prove_commitment_tree(&ac_batch, account_batch_size);
	let (nn_cd, nn_proof) = prove_nullifier_tree(&nn_batch, note_batch_size);
	let (an_cd, an_proof) = prove_nullifier_tree(&an_batch, account_batch_size);
	println!("[{tag}]   Tree proofs [{:.2?}]", t.elapsed());

	// 6. Build TX proofs using tx_pi() for dummy overrides.
	let t = Instant::now();
	println!("[{tag}] Building TX proofs (2 real + 2 dummy)...");
	let mut tx_proofs: Vec<ProofNative> = Vec::with_capacity(account_batch_size);
	for s in 0..account_batch_size {
		if let Some(proof_bytes) = batch.tx_proofs_by_slot.get(&s) {
			let proof: ProofNative =
				ProofWithPublicInputs::from_bytes(proof_bytes.clone(), &priv_tx_cd.common)
					.expect("real proof deser failed");
			let actual_an = extract_hash(&proof.public_inputs, an_off);
			let is_real = proof.public_inputs[IS_REAL_OFFSET].to_canonical_u64();
			println!(
				"[{tag}]   slot {s} (real): is_real={is_real} an=[{}, {}, {}, {}]",
				actual_an[0].to_canonical_u64(),
				actual_an[1].to_canonical_u64(),
				actual_an[2].to_canonical_u64(),
				actual_an[3].to_canonical_u64(),
			);
			tx_proofs.push(proof);
		} else {
			// Dummy: use tx_pi() to recover the correct override values.
			let slot_pi = batch.tx_pi(s);
			let override_an = bytes32_to_f4(&slot_pi.an);
			let override_nn: [[F; 4]; tessera_client::NOTE_BATCH] =
				core::array::from_fn(|j| bytes32_to_f4(&slot_pi.nn[j]));
			let proof = tessera_client::prove_dummy_priv_tx(
				&priv_tx_cd,
				&priv_tx_targets,
				s as u64,
				override_an,
				override_nn,
			);
			println!(
				"[{tag}]   slot {s} (dummy): override_an=[{}, {}, {}, {}]",
				override_an[0].to_canonical_u64(),
				override_an[1].to_canonical_u64(),
				override_an[2].to_canonical_u64(),
				override_an[3].to_canonical_u64(),
			);
			tx_proofs.push(proof);
		}
	}
	println!("[{tag}]   TX proofs [{:.2?}]", t.elapsed());

	// 7. Aggregation.
	let t = Instant::now();
	println!("[{tag}] Aggregating {account_batch_size} TX proofs (arity=2, depth={agg_depth})...");
	let agg_config = GenericAggregatorConfig {
		arity: 2,
		depth: agg_depth,
		reducer: ReducerKind::None,
	};
	let agg = GenericAggregator::new(
		agg_config,
		priv_tx_cd.common.clone(),
		priv_tx_cd.verifier_only.clone(),
	)
	.expect("aggregator build failed");
	let agg_result = agg.aggregate(tx_proofs).expect("aggregation failed");
	agg.verify_root(&agg_result.proof)
		.expect("aggregation root verify failed");
	println!("[{tag}]   Aggregation [{:.2?}]", t.elapsed());

	// 8. Off-circuit PI cross-checks.
	let tx_pis = &agg_result.proof.public_inputs;
	validate_ac_offcircuit(&ac_proof.public_inputs, tx_pis, account_batch_size)
		.expect("off-circuit AC check failed");
	validate_nc_offcircuit(
		&nc_proof.public_inputs,
		tx_pis,
		account_batch_size,
		NOTES_PER_SLOT,
	)
	.expect("off-circuit NC check failed");
	validate_an_offcircuit(&an_proof.public_inputs, tx_pis, account_batch_size)
		.expect("off-circuit AN check failed");
	validate_nn_offcircuit(
		&nn_proof.public_inputs,
		tx_pis,
		account_batch_size,
		NOTES_PER_SLOT,
	)
	.expect("off-circuit NN check failed");
	println!("[{tag}]   Off-circuit PI checks passed");

	// 9. SuperAggregator Plonky2 (no BN128/Groth16).
	let agg_root_circuit = agg
		.level_circuit(agg_depth - 1)
		.expect("aggregator root level");

	let t = Instant::now();
	println!("[{tag}] Building SuperAggregator...");
	let sa_inner = SuperAggregatorCircuitData {
		nc_common: nc_cd.common.clone(),
		nc_verifier: nc_cd.verifier_only.clone(),
		nn_common: nn_cd.common.clone(),
		nn_verifier: nn_cd.verifier_only.clone(),
		ac_common: ac_cd.common.clone(),
		ac_verifier: ac_cd.verifier_only.clone(),
		an_common: an_cd.common.clone(),
		an_verifier: an_cd.verifier_only.clone(),
		tx_common: agg_root_circuit.circuit_data.common.clone(),
		tx_verifier: agg_root_circuit.circuit_data.verifier_only.clone(),
	};
	let sa = SuperAggregator::build(sa_inner).expect("SA build failed");
	println!("[{tag}]   SA build [{:.2?}]", t.elapsed());

	let t = Instant::now();
	println!("[{tag}] Proving SuperAggregator (Plonky2 only)...");
	let root = sa
		.prove(nc_proof, nn_proof, ac_proof, an_proof, agg_result.proof)
		.expect("SuperAggregator prove failed");
	println!("[{tag}]   SA prove [{:.2?}]", t.elapsed());

	assert_eq!(root.public_inputs.len(), 8);
	sa.circuit_data
		.verify(root)
		.expect("SuperAggregator verify failed");

	println!("[{tag}] SUCCESS [{:.2?}]", total_start.elapsed());
}
