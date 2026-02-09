use std::{fs, path::{PathBuf}, time::Instant};

use anyhow::Result;
use tessera_trees::{
	CircuitDataNative, ConfigNative, D, F, ProofBN128, ProofNative, groth::{BN128Wrapper, Groth16Wrapper}, tree::{
		BatchCommitmentProofTargets, CommitmentTree,
		hasher::{Hash, NewRandom, Sha256Commitment},
	}
};
use plonky2::{
	iop::witness::PartialWitness,
	plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
};
use rand::{SeedableRng, rngs::StdRng};

fn main() -> Result<()>{

    // Create temporary directory to store Groth16 proving & verifying keys, 
    // as well R1CS data, circuit common data & verifier data and solidity
    // verification contract.
    let tmp_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .join("examples")
    .join("tmp");

    fs::create_dir_all(&tmp_dir)?;

	let input_path: PathBuf = tmp_dir.join("plonky2-proof");
    let output_path: PathBuf = tmp_dir.join("groth-artifacts");

	println!("Instantiate BN128Wrapper");
    // Unfortunately the Go R1CS compiler needs a concrete proof for the shape of the circuit, so we 
    // need to produce one. Doesn't matter what are the private/public witnesses.
	let (circuit_data, proof_with_pis): (CircuitDataNative, ProofNative) = sample_batch_tree_proof([0u8; 32])?;
	let bn128_wrapper: BN128Wrapper = BN128Wrapper::new(circuit_data, proof_with_pis)?;

	// If plonky2 groth16-friendly proof infos do not exist yet, generate them
	if !input_path.is_dir() {
		println!("store BN128 proof circuit data for R1CS compiler");
		fs::create_dir_all(&input_path)?;
		bn128_wrapper.store_circuit_data_bn128(&input_path)?;
	}

	// if trusted setup does not exist yet, generate it
	if !output_path.is_dir() {
		println!("generating groth16's trusted setup");
		let result = Groth16Wrapper::trusted_setup(&input_path, &output_path);
		println!("trusted_setup result: {}", result);
	}

    // Initialize the [Groth16Wrapper]
	let result: String = Groth16Wrapper::init(&input_path, &output_path)?;
	println!("init result: {}", result);

    // Sanity check of the initialization
	let result: String = Groth16Wrapper::check_init();
	println!("check_init result: {}", result);

	// Creates a new proof ensuring independence from the original proof used to generate the R1CS
	// circuit
	let (_, proof_with_pis): (CircuitDataNative, ProofNative) = sample_batch_tree_proof([1u8; 32])?;

	// Wraps the proof into a BN128 proof ()
	println!("calling bn128 wrapper");
	let start = Instant::now();
	let proof_with_public_inputs_bn128: ProofBN128 = bn128_wrapper.wrap_proof_to_bn128(proof_with_pis)?;
	println!("[TIME] bn128 wrapper took: {:?}", start.elapsed());

	println!("calling groth16_prove");
	let start = Instant::now();
	let (g16_proof, g16_pub_inp) = Groth16Wrapper::prove(proof_with_public_inputs_bn128.clone())?;
	println!("[TIME] groth16_prove took: {:?}", start.elapsed());

	println!("{:?} {:?}", g16_proof, g16_pub_inp);
	
	Groth16Wrapper::verify(g16_proof.clone(), g16_pub_inp.clone())?;

	// Format proof + public inputs as a single JSON object ready for the
	// Solidity verifier contract, and persist it next to the other artifacts.
	let solidity_json = Groth16Wrapper::proof_to_solidity_json(&g16_proof, &g16_pub_inp)?;
	let json_path = output_path.join("proof_solidity.json");
	fs::write(&json_path, &solidity_json)?;
	println!("\n(rust) Solidity proof JSON written to {:?}\n{}", json_path, solidity_json);

	Ok(())
}

pub fn sample_batch_tree_proof(seed: [u8; 32]) -> Result<(CircuitDataNative, ProofNative)> {
	const DEPTH: usize = 32;
	const BATCH_SIZE: usize = 512;

	print!("Alloc tree 2^{DEPTH}: ");
	let now = Instant::now();
	let mut tree: CommitmentTree<Hash> = CommitmentTree::<Hash>::new(DEPTH);
	println!("{:?}", now.elapsed());

	let mut rng: StdRng = StdRng::from_seed(seed);

	print!("Insert batch: ");
	let now = Instant::now();
	let mut leaves: Vec<Hash> = Vec::with_capacity(BATCH_SIZE);
	for _ in 0..BATCH_SIZE {
		leaves.push(Hash::new_random(&mut rng));
	}
	let proof = tree.insert_batch(leaves)?;
	assert!(proof.verify());
	println!("{:?}", now.elapsed());

	// Build the circuit
	let config: CircuitConfig = CircuitConfig::standard_recursion_config();
	let mut builder: CircuitBuilder<F, D> = CircuitBuilder::<F, D>::new(config);

	print!("sha256 commit builder init: ");
	let now: Instant = Instant::now();
	let sha256_com: Sha256Commitment = Sha256Commitment::new(&mut builder);
	println!("{:?}", now.elapsed());

	print!("Alloc Targets: ");
	let now: Instant = Instant::now();
	let targets: BatchCommitmentProofTargets =
		BatchCommitmentProofTargets::new(&mut builder, DEPTH, BATCH_SIZE, Some(&sha256_com));
	println!("{:?}", now.elapsed());

	print!("Connect: ");
	let now: Instant = Instant::now();
	targets.connect::<Hash, F, D>(&mut builder);
	println!("{:?}", now.elapsed());

	print!("Set Witnesses: ");
	let now: Instant = Instant::now();
	let mut pw: PartialWitness<F> = PartialWitness::new();
	targets.set::<Hash, F, DEPTH>(&mut pw, &proof)?;
	println!("{:?}", now.elapsed());

	print!("Build: ");
	let now = Instant::now();
	let circuit_data: CircuitDataNative = builder.build::<ConfigNative>();
	println!("{:?}", now.elapsed());

	let com = proof.compute_commitment::<F, D>(&sha256_com);

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

	Ok((circuit_data, proof))
}
