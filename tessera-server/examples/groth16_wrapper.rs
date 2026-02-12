//! End-to-end Groth16 proof generation for the Tessera deposit rollup.
//!
//! This example performs the full off-chain proving pipeline:
//!
//!   1. Generate 128 random deposits (noteCommitment, address, amount)
//!   2. Hash each deposit via SHA-256 to derive its Merkle leaf
//!   3. Insert all leaves into a depth-32 CommitmentTree
//!   4. Build a plonky2 circuit proving the batch insertion with SHA-256 commitment (leaves are
//!      derived off-circuit)
//!   5. Prove the circuit (native Goldilocks field)
//!   6. Wrap the proof into a BN128-friendly format (for EVM verification)
//!   7. Generate a Groth16 proof via gnark (Go FFI)
//!   8. Export proof and bridge calldata as JSON for Foundry integration tests
//!
//! Outputs (in examples/tmp/groth-artifacts/):
//!   - proof_solidity.json:  Groth16 proof for Verifier.sol
//!   - bridge_calldata.json: State transition data for DepositsRollupBridge.sol
//!
//! Usage:
//!   cargo run --example groth16_wrapper --release

use std::{fs, path::PathBuf, time::Instant};

use anyhow::Result;
use tessera_server::{sample_batch_commitment_tree_proof, Deposit};
use tessera_trees::{
	groth::{BN128Wrapper, Groth16Wrapper},
	tree::{hasher::Hash, BatchCommitmentProof},
	CircuitDataNative, ProofBN128, ProofNative,
};

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
	let (circuit_data, proof_with_pis, _, _): (
		CircuitDataNative,
		ProofNative,
		BatchCommitmentProof<Hash>,
		Vec<Deposit>,
	) = sample_batch_commitment_tree_proof([0u8; 32])?;
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
	let (_, proof_with_pis, batch_proof, deposits): (
		CircuitDataNative,
		ProofNative,
		BatchCommitmentProof<Hash>,
		Vec<Deposit>,
	) = sample_batch_commitment_tree_proof([1u8; 32])?;

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
	//   - Roots and leaves: each Goldilocks field element as 8-byte big-endian uint64, packed into
	//     bytes32 / bytes blobs.
	//   - Deposits: noteCommitment as bytes32, address as bytes20, amount as uint64.
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
		let nc_hex = format!("0x{}", hex::encode(d.note_commitment()));
		let addr_hex = format!("0x{}", hex::encode(d.address()));
		deposits_json_entries.push(format!(
			"    {{\n      \"noteCommitment\": \"{}\",\n      \"recipient\": \"{}\",\n      \"value\": {}\n    }}",
			nc_hex,
			addr_hex,
			d.amount(),
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
