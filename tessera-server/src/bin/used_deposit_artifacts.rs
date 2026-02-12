//! Generate Groth16 artifacts for the UsedDeposit tree.
//!
//! Outputs (in artifacts/used-deposit/):
//!   - plonky2-proof/    (plonky2 circuit data for R1CS)
//!   - groth-artifacts/  (Groth16 proving/verifying keys)
//!   - proof_solidity.json
//!   - bridge_calldata.json
//!
//! Usage:
//!   cargo run --bin used_deposit_artifacts --release

use std::{fs, path::PathBuf, time::Instant};

use anyhow::{ensure, Result};
use tessera_server::{Deposit, sample_batch_nullifier_tree_proof};
use tessera_trees::{
	CircuitDataNative, ProofBN128, ProofNative, groth::{BN128Wrapper, Groth16Wrapper}, tree::{NullifierChainedInsertProof, hasher::Hash}
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

fn main() -> Result<()> {
	let tmp_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.join("artifacts")
		.join("used-deposit");

	fs::create_dir_all(&tmp_dir)?;

	let input_path: PathBuf = tmp_dir.join("plonky2-proof");
	let output_path: PathBuf = tmp_dir.join("groth-artifacts");

	println!("used-deposit artifacts: {}", tmp_dir.display());
	println!("plonky2 data: {}", input_path.display());
	println!("groth16 artifacts: {}", output_path.display());

	debug_log("Instantiate BN128Wrapper");
	let (circuit_data, proof_with_pis, _, _): (
		CircuitDataNative,
		ProofNative,
		NullifierChainedInsertProof<Hash>,
		Vec<Deposit>,
	) = sample_batch_nullifier_tree_proof([0u8; 32])?;
	let bn128_wrapper: BN128Wrapper = BN128Wrapper::new(circuit_data, proof_with_pis)?;

	if !BN128Wrapper::has_full_artifacts(&input_path) {
		println!("writing plonky2 circuit data");
		fs::create_dir_all(&input_path)?;
		bn128_wrapper.store_full_circuit_data(&input_path)?;
	}

	if !output_path.is_dir() {
		println!("generating groth16 trusted setup");
		let result = Groth16Wrapper::trusted_setup(&input_path, &output_path);
		debug_log(&format!("trusted_setup result: {result}"));
	}

	let result: String = Groth16Wrapper::init(&input_path, &output_path)?;
	debug_log(&format!("init result: {result}"));

	let result: String = Groth16Wrapper::check_init();
	debug_log(&format!("check_init result: {result}"));

	let (_, proof_with_pis, batch_proof, deposits): (
		CircuitDataNative,
		ProofNative,
		NullifierChainedInsertProof<Hash>,
		Vec<Deposit>,
	) = sample_batch_nullifier_tree_proof([1u8; 32])?;
	ensure!(
		!batch_proof.is_empty(),
		"cannot generate used-deposit artifacts for an empty insertion batch"
	);

	println!("wrapping proof to bn128");
	let start = Instant::now();
	let proof_with_public_inputs_bn128: ProofBN128 =
		bn128_wrapper.wrap_proof_to_bn128(proof_with_pis)?;
	debug_log(&format!("[TIME] bn128 wrapper took: {:?}", start.elapsed()));

	println!("generating groth16 proof");
	let start = Instant::now();
	let (g16_proof, g16_pub_inp) = Groth16Wrapper::prove(proof_with_public_inputs_bn128.clone())?;
	debug_log(&format!("[TIME] groth16_prove took: {:?}", start.elapsed()));
	debug_log(&format!("{:?} {:?}", g16_proof, g16_pub_inp));

	Groth16Wrapper::verify(g16_proof.clone(), g16_pub_inp.clone())?;

	let solidity_json = Groth16Wrapper::proof_to_solidity_json(&g16_proof, &g16_pub_inp)?;
	let json_path = output_path.join("proof_solidity.json");
	fs::write(&json_path, &solidity_json)?;
	println!("wrote proof: {}", json_path.display());
	debug_log(&format!(
		"\n(rust) Solidity proof JSON written to {:?}\n{}",
		json_path, solidity_json
	));

	let hash_to_hex = |h: &Hash| -> String {
		let mut bytes = [0u8; 32];
		for i in 0..4 {
			bytes[i * 8..(i + 1) * 8].copy_from_slice(&h.0[i].0.to_be_bytes());
		}
		format!("0x{}", hex::encode(bytes))
	};

	let old_root_hex = hash_to_hex(&batch_proof.initial_root().unwrap());
	let new_root_hex = hash_to_hex(&batch_proof.final_root().unwrap());

	let mut leaves_bytes: Vec<u8> = Vec::with_capacity(batch_proof.len() * 32);
	for leaf in &batch_proof.inserted_values() {
		for i in 0..4 {
			leaves_bytes.extend_from_slice(&leaf.0[i].0.to_be_bytes());
		}
	}
	let leaves_hex = format!("0x{}", hex::encode(&leaves_bytes));

	let mut deposits_json_entries: Vec<String> = Vec::with_capacity(deposits.len());
	for d in &deposits {
		let nc_hex = format!("0x{}", hex::encode(d.note_commitment()));
		let addr_hex = format!("0x{}", hex::encode(d.address()));
		deposits_json_entries.push(format!(
			"    {{\n      \"noteCommitment\": \"{}\",\n      \"address\": \"{}\",\n      \"amount\": \"0x{:016x}\"\n    }}",
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
	println!("wrote bridge calldata: {}", bridge_json_path.display());
	debug_log(&format!(
		"\n(rust) Bridge calldata JSON written to {:?}",
		bridge_json_path
	));

	Ok(())
}
