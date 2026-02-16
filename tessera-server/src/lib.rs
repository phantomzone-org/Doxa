mod data_types;

pub mod config;
pub mod contract;
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
	iop::witness::PartialWitness,
	plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
};
use rand::{rngs::StdRng, SeedableRng};
use tessera_trees::{
	tree::{
		hasher::{Hash, NewRandom, Sha256Commitment},
		BatchCommitmentProof, BatchCommitmentProofTargets, ChainedInsertProofTargets,
		CommitmentTree, NullifierChainedInsertProof, NullifierTree,
	},
	CircuitDataNative, ConfigNative, ProofNative, D, F,
};

pub const TREE_DEPTH: usize = 32;

/// Generate a sample batch commitment insertion proof for testing.
///
/// Creates 128 random deposits, hashes each via SHA-256 to derive Merkle
/// leaves, inserts them into a depth-32 commitment tree, builds and proves
/// a plonky2 circuit (with SHA-256 commitment), and returns the circuit
/// data, proof, batch proof (roots + leaves), and raw deposits.
///
/// The `seed` parameter controls the PRNG, ensuring deterministic but
/// distinct test vectors across calls (e.g. seed `[0u8; 32]` for R1CS
/// shape, `[1u8; 32]` for the actual proof).
pub fn sample_batch_commitment_tree_proof(
	seed: [u8; 32],
) -> Result<(
	CircuitDataNative,
	ProofNative,
	BatchCommitmentProof<Hash>,
	Vec<Hash>,
)> {
	const DEPTH: usize = 32;
	const BATCH_SIZE: usize = 128;

	print!("Alloc tree 2^{DEPTH}: ");
	let now = Instant::now();
	let mut tree: CommitmentTree<Hash> = CommitmentTree::new(TREE_DEPTH);
	println!("{:?}", now.elapsed());

	let mut rng: StdRng = StdRng::from_seed(seed);

	print!("Insert batch: ");
	let now: Instant = Instant::now();
	let mut batch: Vec<Hash> = Vec::with_capacity(BATCH_SIZE);
	for _ in 0..BATCH_SIZE {
		batch.push(Hash::new_random(&mut rng));
	}
	let batch_proof = tree.insert_batch(batch.clone())?;
	assert!(batch_proof.verify());
	println!("{:?}", now.elapsed());

	let config: CircuitConfig = CircuitConfig::standard_recursion_config();
	let mut builder: CircuitBuilder<F, D> = CircuitBuilder::<F, D>::new(config);

	print!("sha256 commit builder init: ");
	let now: Instant = Instant::now();
	let sha256_com: Sha256Commitment = Sha256Commitment::new(&mut builder, 8);
	println!("{:?}", now.elapsed());

	print!("Alloc Targets: ");
	let now: Instant = Instant::now();
	let targets: BatchCommitmentProofTargets = BatchCommitmentProofTargets::new::<F, D>(
		&mut builder,
		DEPTH,
		BATCH_SIZE,
		Some(&sha256_com),
	);
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

	let com = batch_proof.compute_commitment::<F, D>(&sha256_com);

	print!("Prove: ");
	let now = Instant::now();
	let proof = circuit_data.prove(pw)?;
	println!("{:?}", now.elapsed());

	assert_eq!(proof.public_inputs, com);

	println!("proof.pi: {}", proof.public_inputs.len());

	let bytes = proof.to_bytes();
	println!("size: {}KB", bytes.len() >> 10);

	circuit_data.verify(proof.clone())?;
	println!("{:?}", now.elapsed());

	Ok((circuit_data, proof, batch_proof, batch))
}

/// Generate a sample batch nullifier insertion proof for testing.
///
/// Creates 128 random deposits, hashes each via SHA-256 to derive Merkle
/// leaves, inserts them into a depth-32 nullifier tree, builds and proves
/// a plonky2 circuit (with SHA-256 nullifier), and returns the circuit
/// data, proof, batch proof (roots + leaves), and raw deposits.
///
/// The `seed` parameter controls the PRNG, ensuring deterministic but
/// distinct test vectors across calls (e.g. seed `[0u8; 32]` for R1CS
/// shape, `[1u8; 32]` for the actual proof).
pub fn sample_batch_nullifier_tree_proof(
	seed: [u8; 32],
) -> Result<(
	CircuitDataNative,
	ProofNative,
	NullifierChainedInsertProof<Hash>,
	Vec<Hash>,
)> {
	const DEPTH: usize = 32;
	const BATCH_SIZE: usize = 128;

	print!("Alloc tree 2^{DEPTH}: ");
	let now = Instant::now();
	let mut tree = NullifierTree::new(TREE_DEPTH);
	println!("{:?}", now.elapsed());

	let mut rng: StdRng = StdRng::from_seed(seed);

	print!("Insert batch: ");
	let now = Instant::now();
	let mut batch: Vec<Hash> = Vec::with_capacity(BATCH_SIZE);
	for _ in 0..BATCH_SIZE {
		batch.push(Hash::new_random(&mut rng));
	}
	let batch_proof = tree.insert_chained(batch.clone())?;
	assert!(batch_proof.verify());
	println!("{:?}", now.elapsed());

	let config: CircuitConfig = CircuitConfig::standard_recursion_config();
	let mut builder: CircuitBuilder<F, D> = CircuitBuilder::<F, D>::new(config);

	print!("sha256 commit builder init: ");
	let now: Instant = Instant::now();
	let sha256_com: Sha256Commitment = Sha256Commitment::new(&mut builder, 8);
	println!("{:?}", now.elapsed());

	print!("Alloc Targets: ");
	let now: Instant = Instant::now();
	let targets: ChainedInsertProofTargets =
		ChainedInsertProofTargets::new::<F, D>(&mut builder, DEPTH, BATCH_SIZE, Some(&sha256_com));
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

	let com = batch_proof.compute_commitment::<F, D>(&sha256_com);

	print!("Prove: ");
	let now = Instant::now();
	let proof = circuit_data.prove(pw)?;
	println!("{:?}", now.elapsed());

	assert_eq!(proof.public_inputs, com);

	println!("proof.pi: {}", proof.public_inputs.len());

	let bytes = proof.to_bytes();
	println!("size: {}KB", bytes.len() >> 10);

	circuit_data.verify(proof.clone())?;
	println!("{:?}", now.elapsed());

	Ok((circuit_data, proof, batch_proof, batch))
}
