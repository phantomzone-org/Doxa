mod data_types;

pub mod aggregation_pipeline;
pub mod config;
pub mod contract;
pub mod dummy;
pub mod prover;
pub mod prover_client;
pub mod sequencer;
pub mod states;
pub mod tree_store;
pub mod types;

use std::time::Instant;

use anyhow::Result;
pub use data_types::*;
use plonky2::{
	field::types::Field,
	iop::{
		target::Target,
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::{CircuitConfig, CircuitData},
		proof::ProofWithPublicInputs,
	},
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use tessera_trees::{
	tree::{
		hasher::{Hash, NewRandom},
		BatchCommitmentProof, BatchCommitmentProofTargets, BatchInsertProof,
		BatchNullifierInsertProofTargets, CommitmentTree, NullifierTree,
	},
	CircuitDataNative, ConfigNative, ProofNative, D, F,
};

pub const TREE_DEPTH: usize = 32;

/// Build and prove a minimal TX-leaf circuit for aggregation testing.
///
/// Constructs a trivial plonky2 circuit whose 72 public inputs encode 18
/// random 256-bit hash values (8 note nullifiers, 8 note commitments,
/// 1 account nullifier, 1 account commitment — 4 Goldilocks u64 limbs each).
/// Returns the circuit data (for use as the aggregation tree's leaf circuit),
/// a concrete proof, and the raw field-element values that form the public inputs.
///
/// The `seed` parameter controls the PRNG so test vectors are deterministic
/// but distinct for different seeds.
pub fn aggregator_leaf_circuit(seed: [u8; 32]) -> Result<(CircuitDataNative, ProofNative, Vec<F>)> {
	fn build_leaf_circuit(n_pi: usize) -> (CircuitData<F, ConfigNative, D>, Vec<Target>) {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let targets: Vec<Target> = (0..n_pi).map(|_| builder.add_virtual_target()).collect();
		for &t in &targets {
			builder.register_public_input(t);
		}
		(builder.build::<ConfigNative>(), targets)
	}

	fn prove_leaf(
		circuit: &CircuitData<F, ConfigNative, D>,
		targets: &[Target],
		values: &[F],
	) -> Result<ProofWithPublicInputs<F, ConfigNative, D>> {
		let mut pw = PartialWitness::new();
		for (&t, &v) in targets.iter().zip(values.iter()) {
			pw.set_target(t, v)?;
		}
		circuit.prove(pw)
	}

	const N_PI: usize = 72;

	let mut values = Vec::with_capacity(N_PI);

	let mut rng: StdRng = StdRng::from_seed(seed);

	// Each of the 18 output values is a 256-bit hash → 4 Goldilocks u64 limbs.
	// Ordering: 8 note nullifiers, 8 note commitments, 1 acct nullifier, 1 acct commitment.
	for _ in 0..18 {
		for _ in 0..4 {
			values.push(F::from_noncanonical_u64(rng.next_u64()));
		}
	}

	let (circuit_data, targets) = build_leaf_circuit(N_PI);

	let proof = prove_leaf(&circuit_data, &targets, &values)?;

	Ok((circuit_data, proof, values.to_vec()))
}

/// Generate a sample batch commitment insertion proof for testing.
///
/// Creates 128 random deposits, inserts them into a depth-32 commitment
/// tree, builds and proves a plonky2 circuit (with Keccak-256 commitment),
/// and returns the circuit data, proof, batch proof (roots + leaves), and
/// raw deposits.
///
/// The `seed` parameter controls the PRNG, ensuring deterministic but
/// distinct test vectors across calls (e.g. seed `[0u8; 32]` for R1CS
/// shape, `[1u8; 32]` for the actual proof).
pub fn sample_batch_commitment_tree_proof(
	seed: [u8; 32],
	batch_size: usize,
) -> Result<(
	CircuitDataNative,
	ProofNative,
	BatchCommitmentProof<Hash>,
	Vec<Hash>,
)> {
	const DEPTH: usize = 32;

	print!("Alloc tree 2^{DEPTH}: ");
	let now = Instant::now();
	let mut tree: CommitmentTree<Hash> = CommitmentTree::new(TREE_DEPTH);
	println!("{:?}", now.elapsed());

	let mut rng: StdRng = StdRng::from_seed(seed);

	print!("Insert batch: ");
	let now: Instant = Instant::now();
	let mut batch: Vec<Hash> = Vec::with_capacity(batch_size);
	for _ in 0..batch_size {
		batch.push(Hash::new_random(&mut rng));
	}
	let batch_proof = tree.insert_batch(batch.clone())?;
	assert!(batch_proof.verify());
	println!("{:?}", now.elapsed());

	let config: CircuitConfig = CircuitConfig::standard_recursion_config();
	let mut builder: CircuitBuilder<F, D> = CircuitBuilder::<F, D>::new(config);

	print!("Alloc Targets: ");
	let now: Instant = Instant::now();
	let targets: BatchCommitmentProofTargets =
		BatchCommitmentProofTargets::new::<F, D>(&mut builder, DEPTH, batch_size);
	println!("{:?}", now.elapsed());

	print!("Connect: ");
	let now: Instant = Instant::now();
	targets.connect::<Hash, F, D>(&mut builder);
	println!("{:?}", now.elapsed());

	print!("Set Witnesses: ");
	let now: Instant = Instant::now();
	let mut pw: PartialWitness<F> = PartialWitness::new();
	targets.set::<Hash, F, DEPTH>(&mut pw, &batch_proof)?;
	println!("{:?}", now.elapsed());

	print!("Build: ");
	let now = Instant::now();
	let circuit_data: CircuitDataNative = builder.build::<ConfigNative>();
	println!("{:?}", now.elapsed());

	print!("Prove: ");
	let now = Instant::now();
	let proof = circuit_data.prove(pw)?;
	println!("{:?}", now.elapsed());

	println!("proof.pi: {}", proof.public_inputs.len());

	let bytes = proof.to_bytes();
	println!("size: {}KB", bytes.len() >> 10);

	circuit_data.verify(proof.clone())?;
	println!("{:?}", now.elapsed());

	Ok((circuit_data, proof, batch_proof, batch))
}

/// Generate a sample batch nullifier insertion proof for testing.
///
/// Creates 128 random deposits, inserts them into a depth-32 nullifier
/// tree, builds and proves a plonky2 circuit (with Keccak-256 commitment),
/// and returns the circuit data, proof, batch proof (roots + leaves), and
/// raw deposits.
///
/// The `seed` parameter controls the PRNG, ensuring deterministic but
/// distinct test vectors across calls (e.g. seed `[0u8; 32]` for R1CS
/// shape, `[1u8; 32]` for the actual proof).
pub fn sample_batch_nullifier_tree_proof(
	seed: [u8; 32],
	batch_size: usize,
) -> Result<(
	CircuitDataNative,
	ProofNative,
	BatchInsertProof<Hash>,
	Vec<Hash>,
)> {
	const DEPTH: usize = 32;

	print!("Alloc tree with padding (batch_size={batch_size}): ");
	let now = Instant::now();
	let mut tree = NullifierTree::new_with_padding(TREE_DEPTH, batch_size);
	println!("{:?}", now.elapsed());

	let mut rng: StdRng = StdRng::from_seed(seed);

	print!("Insert batch: ");
	let now = Instant::now();
	let mut batch: Vec<Hash> = Vec::with_capacity(batch_size);
	for _ in 0..batch_size {
		batch.push(Hash::new_random(&mut rng));
	}
	let batch_proof = tree.insert_batch(batch.clone())?;
	assert!(batch_proof.verify());
	println!("{:?}", now.elapsed());

	let config: CircuitConfig = CircuitConfig::standard_recursion_config();
	let mut builder: CircuitBuilder<F, D> = CircuitBuilder::<F, D>::new(config);

	print!("Alloc Targets: ");
	let now: Instant = Instant::now();
	let targets: BatchNullifierInsertProofTargets =
		BatchNullifierInsertProofTargets::new::<F, D>(&mut builder, DEPTH, batch_size);
	println!("{:?}", now.elapsed());

	print!("Connect: ");
	let now: Instant = Instant::now();
	targets.connect::<Hash, F, D>(&mut builder);
	println!("{:?}", now.elapsed());

	print!("Set Witnesses: ");
	let now: Instant = Instant::now();
	let mut pw: PartialWitness<F> = PartialWitness::new();
	targets.set::<Hash, F, DEPTH>(&mut pw, &batch_proof)?;
	println!("{:?}", now.elapsed());

	print!("Build: ");
	let now = Instant::now();
	let circuit_data: CircuitDataNative = builder.build::<ConfigNative>();
	println!("{:?}", now.elapsed());

	print!("Prove: ");
	let now = Instant::now();
	let proof = circuit_data.prove(pw)?;
	println!("{:?}", now.elapsed());

	println!("proof.pi: {}", proof.public_inputs.len());

	let bytes = proof.to_bytes();
	println!("size: {}KB", bytes.len() >> 10);

	circuit_data.verify(proof.clone())?;
	println!("{:?}", now.elapsed());

	Ok((circuit_data, proof, batch_proof, batch))
}
