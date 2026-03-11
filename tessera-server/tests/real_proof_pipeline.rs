//! Integration test: real PrivTx proofs → tree proofs → aggregation → SuperAggregator.
//!
//! Verifies the full proving pipeline with real (non-dummy) PrivTx proofs.
//! - `test_real_proof_pipeline_all_real`: minimal (2 TX, arity=2 depth=1).
//! - `test_real_proof_pipeline_128_tx`: production-size (128 TX, arity=2 depth=7).

use std::time::Instant;

use plonky2::{
	field::types::Field,
	iop::witness::PartialWitness,
	plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
};
use tessera_trees::{
	proof_aggregation::{
		GenericAggregator, GenericAggregatorConfig, ReducerKind, SuperAggregator,
		SuperAggregatorCircuitData,
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

	assert_ne!(pis_0[2], F::ZERO, "proof 0 must have is_real=1");
	assert_ne!(pis_1[2], F::ZERO, "proof 1 must have is_real=1");

	let an_0 = extract_hash(pis_0, 3);
	let an_1 = extract_hash(pis_1, 3);
	let ac_0 = extract_hash(pis_0, 7);
	let ac_1 = extract_hash(pis_1, 7);

	let nn: Vec<HashOutput> = (0..2)
		.flat_map(|slot| {
			let pis = if slot == 0 { pis_0 } else { pis_1 };
			(0..NOTES_PER_SLOT).map(move |j| HashOutput::from(extract_hash(pis, 11 + j * 4)))
		})
		.collect();

	let nc: Vec<HashOutput> = (0..2)
		.flat_map(|slot| {
			let pis = if slot == 0 { pis_0 } else { pis_1 };
			(0..NOTES_PER_SLOT).map(move |j| HashOutput::from(extract_hash(pis, 43 + j * 4)))
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
	use tessera_server::dummy::{pad_leaves, DummyTreeType};

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

	// 3. Extract tree leaves from real proofs (as bytes).
	let an_real_bytes: Vec<[u8; 32]> = real_proofs
		.iter()
		.map(|p| hash_to_bytes32(&HashOutput::from(extract_hash(&p.public_inputs, 3))))
		.collect();
	let ac_real_bytes: Vec<[u8; 32]> = real_proofs
		.iter()
		.map(|p| hash_to_bytes32(&HashOutput::from(extract_hash(&p.public_inputs, 7))))
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
	let nc_real_bytes: Vec<[u8; 32]> = real_proofs
		.iter()
		.flat_map(|p| {
			(0..NOTES_PER_SLOT).map(move |j| {
				hash_to_bytes32(&HashOutput::from(extract_hash(
					&p.public_inputs,
					43 + j * 4,
				)))
			})
		})
		.collect();

	// 4. Pad batches.
	let t = Instant::now();
	println!("[{tag}] Padding batches...");
	let nc_padded = pad_leaves(
		DummyTreeType::NotesCommitment,
		0,
		note_batch_size,
		&nc_real_bytes,
	)
	.expect("NC pad failed");
	let ac_padded = pad_leaves(
		DummyTreeType::AccountsCommitment,
		0,
		account_batch_size,
		&ac_real_bytes,
	)
	.expect("AC pad failed");
	let mut nn_padded = pad_leaves(
		DummyTreeType::NotesNullifier,
		0,
		note_batch_size,
		&nn_real_bytes,
	)
	.expect("NN pad failed");
	nn_padded.sort();
	let mut an_padded = pad_leaves(
		DummyTreeType::AccountsNullifier,
		0,
		account_batch_size,
		&an_real_bytes,
	)
	.expect("AN pad failed");
	an_padded.sort();
	println!("[{tag}]   Padding [{:.2?}]", t.elapsed());

	// 5. Generate dummy proofs with overrides.
	let t = Instant::now();
	let n_dummy = n_tx - n_real;
	println!("[{tag}] Proving {n_dummy} dummy PrivTx proofs...");
	let mut tx_proofs: Vec<ProofNative> = real_proofs;
	for s in n_real..n_tx {
		let override_an = bytes32_to_f4(&an_padded[s]);
		let override_nn: [[F; 4]; tessera_client::NOTE_BATCH] =
			core::array::from_fn(|j| bytes32_to_f4(&nn_padded[s * NOTES_PER_SLOT + j]));
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

	// 6. Build trees.
	let t = Instant::now();
	println!("[{tag}] Building trees...");
	let nc_hashes: Vec<HashOutput> = nc_padded
		.iter()
		.map(|b| HashOutput::from(bytes32_to_f4(b)))
		.collect();
	let mut nc_tree = CommitmentTree::<HashOutput>::new(TREE_DEPTH);
	let nc_batch = nc_tree.insert_batch(nc_hashes).expect("NC insert failed");
	assert!(nc_batch.verify(), "NC native proof invalid");

	let ac_hashes: Vec<HashOutput> = ac_padded
		.iter()
		.map(|b| HashOutput::from(bytes32_to_f4(b)))
		.collect();
	let mut ac_tree = CommitmentTree::<HashOutput>::new(TREE_DEPTH);
	let ac_batch = ac_tree.insert_batch(ac_hashes).expect("AC insert failed");
	assert!(ac_batch.verify(), "AC native proof invalid");

	let nn_hashes: Vec<HashOutput> = nn_padded
		.iter()
		.map(|b| HashOutput::from(bytes32_to_f4(b)))
		.collect();
	let mut nn_tree = NullifierTree::<HashOutput>::new_with_padding(TREE_DEPTH, note_batch_size);
	let nn_batch = nn_tree.insert_batch(nn_hashes).expect("NN insert failed");
	assert!(nn_batch.verify(), "NN native proof invalid");

	let an_hashes: Vec<HashOutput> = an_padded
		.iter()
		.map(|b| HashOutput::from(bytes32_to_f4(b)))
		.collect();
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
