//! End-to-end Groth16 proof generation for the Tessera deposit rollup.
//!
//! This example performs the full off-chain proving pipeline:
//!
//!   1. Generate 128 random deposits (noteCommitment, address, amount)
//!   2. Hash each deposit via Poseidon to derive its Merkle leaf
//!   3. Insert all leaves into a depth-32 CommitmentTree
//!   4. Build a plonky2 circuit proving the batch insertion with SHA-256 commitment
//!   5. Prove the circuit (native Goldilocks field)
//!   6. Wrap the proof into a BN128-friendly format (for EVM verification)
//!   7. Generate a Groth16 proof via gnark (Go FFI)
//!   8. Export proof and bridge calldata as JSON for Foundry integration tests
//!
//! Outputs (in examples/tmp/groth-artifacts/):
//!   - proof_solidity.json:  Groth16 proof for Verifier128.sol
//!   - bridge_calldata.json: State transition data for DepositsRollupBridge.sol
//!
//! Usage:
//!   cargo run --example groth16_wrapper --release

use std::{fs, path::PathBuf, time::Instant};

use anyhow::Result;
use plonky2::{
	iop::witness::PartialWitness,
	plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
};
use plonky2::field::types::Field;
use rand::{Rng, SeedableRng, rngs::StdRng};
use tessera_trees::{
	CircuitDataNative, ConfigNative, D, F, ProofBN128, ProofNative,
	groth::{BN128Wrapper, Groth16Wrapper},
	tree::{
		BatchCommitmentProof, BatchCommitmentProofTargets, CommitmentTree,
		hasher::{Hash, MerkleHash, NewRandom, Sha256Commitment},
	},
};

/// Raw deposit data mirroring tessera-server's PendingDeposit.
/// Each deposit is hashed via Poseidon to produce a Merkle leaf.
#[derive(Clone, Debug)]
pub struct DepositData {
	pub note_commitment: Hash,
	pub address: [F; 3],
	pub amount: F,
}

impl DepositData {
	/// Hash matching PendingDeposit::hash():
	///   hash_2_to_1(note_commitment, Hash([addr0, addr1, addr2, amount]), false)
	pub fn leaf_hash(&self) -> Hash {
		let tmp = Hash::new([self.address[0], self.address[1], self.address[2], self.amount]);
		Hash::hash_2_to_1(&self.note_commitment, &tmp, false)
	}
}

fn main() -> Result<()> {
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
	let (circuit_data, proof_with_pis, _, _): (CircuitDataNative, ProofNative, BatchCommitmentProof<Hash>, Vec<DepositData>) =
		sample_batch_tree_proof([0u8; 32])?;
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
	let (_, proof_with_pis, batch_proof, deposits): (CircuitDataNative, ProofNative, BatchCommitmentProof<Hash>, Vec<DepositData>) =
		sample_batch_tree_proof([1u8; 32])?;

	// Wraps the proof into a BN128 proof ()
	println!("calling bn128 wrapper");
	let start = Instant::now();
	let proof_with_public_inputs_bn128: ProofBN128 =
		bn128_wrapper.wrap_proof_to_bn128(proof_with_pis)?;
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
	println!(
		"\n(rust) Solidity proof JSON written to {:?}\n{}",
		json_path, solidity_json
	);

	// ── Export bridge calldata ──────────────────────────────────────────
	// Produces bridge_calldata.json consumed by the Foundry integration test
	// (DepositsRollupBridgeIntegration.t.sol).
	//
	// Encoding convention (must match DepositsRollupBridge.sol):
	//   - Roots and leaves: each Goldilocks field element as 8-byte big-endian
	//     uint64, packed into bytes32 / bytes blobs.
	//   - Deposits: each field as a hex-encoded uint64, noteCommitment as bytes32.
	//
	// The resulting JSON has the shape:
	//   { oldRoot: bytes32, newRoot: bytes32, leaves: bytes, deposits: [...] }
	let hash_to_hex = |h: &Hash| -> String {
		let mut bytes = [0u8; 32];
		for i in 0..4 {
			bytes[i * 8..(i + 1) * 8].copy_from_slice(&h.0[i].0.to_be_bytes());
		}
		format!("0x{}", hex::encode(bytes))
	};

	let old_root_hex = hash_to_hex(&batch_proof.root_old);
	let new_root_hex = hash_to_hex(&batch_proof.root_new);

	let mut leaves_bytes: Vec<u8> = Vec::with_capacity(batch_proof.leaves.len() * 32);
	for leaf in &batch_proof.leaves {
		for i in 0..4 {
			leaves_bytes.extend_from_slice(&leaf.0[i].0.to_be_bytes());
		}
	}
	let leaves_hex = format!("0x{}", hex::encode(&leaves_bytes));

	// Export deposit data as a JSON array.
	let mut deposits_json_entries: Vec<String> = Vec::with_capacity(deposits.len());
	for d in &deposits {
		let nc_hex = hash_to_hex(&d.note_commitment);
		deposits_json_entries.push(format!(
			"    {{\n      \"noteCommitment\": \"{}\",\n      \"addr0\": \"0x{:016x}\",\n      \"addr1\": \"0x{:016x}\",\n      \"addr2\": \"0x{:016x}\",\n      \"amount\": \"0x{:016x}\"\n    }}",
			nc_hex,
			d.address[0].0,
			d.address[1].0,
			d.address[2].0,
			d.amount.0,
		));
	}
	let deposits_json_array = format!("[\n{}\n  ]", deposits_json_entries.join(",\n"));

	let bridge_json = format!(
		"{{\n  \"oldRoot\": \"{}\",\n  \"newRoot\": \"{}\",\n  \"leaves\": \"{}\",\n  \"deposits\": {}\n}}",
		old_root_hex, new_root_hex, leaves_hex, deposits_json_array
	);
	let bridge_json_path = output_path.join("bridge_calldata.json");
	fs::write(&bridge_json_path, &bridge_json)?;
	println!(
		"\n(rust) Bridge calldata JSON written to {:?}",
		bridge_json_path
	);

	Ok(())
}

/// Generate a sample batch insertion proof for testing.
///
/// Creates `BATCH_SIZE` random deposits, hashes each via Poseidon to derive
/// Merkle leaves, inserts them into a depth-`DEPTH` commitment tree, builds
/// and proves a plonky2 circuit (with SHA-256 commitment), and returns the
/// circuit data, proof, batch proof (roots + leaves), and raw deposits.
///
/// The `seed` parameter controls the PRNG, ensuring deterministic but
/// distinct test vectors across calls (e.g. seed `[0u8; 32]` for R1CS
/// shape, `[1u8; 32]` for the actual proof).
pub fn sample_batch_tree_proof(seed: [u8; 32]) -> Result<(CircuitDataNative, ProofNative, BatchCommitmentProof<Hash>, Vec<DepositData>)> {
	const DEPTH: usize = 32;
	const BATCH_SIZE: usize = 128;

	print!("Alloc tree 2^{DEPTH}: ");
	let now = Instant::now();
	let mut tree: CommitmentTree<Hash> = CommitmentTree::<Hash>::new(DEPTH);
	println!("{:?}", now.elapsed());

	let mut rng: StdRng = StdRng::from_seed(seed);

	print!("Insert batch: ");
	let now = Instant::now();
	// Generate deposits (noteCommitment, address, amount) and hash each
	// via Poseidon to derive the Merkle leaf, mirroring PendingDeposit::hash().
	let mut deposits: Vec<DepositData> = Vec::with_capacity(BATCH_SIZE);
	let mut leaves: Vec<Hash> = Vec::with_capacity(BATCH_SIZE);
	for _ in 0..BATCH_SIZE {
		let deposit = DepositData {
			note_commitment: Hash::new_random(&mut rng),
			address: [
				F::from_canonical_u64(rng.next_u64()),
				F::from_canonical_u64(rng.next_u64()),
				F::from_canonical_u64(rng.next_u64()),
			],
			amount: F::from_canonical_u64(rng.next_u64()),
		};
		leaves.push(deposit.leaf_hash());
		deposits.push(deposit);
	}
	let batch_proof = tree.insert_batch(leaves)?;
	assert!(batch_proof.verify());
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

	Ok((circuit_data, proof, batch_proof, deposits))
}
