//! Generate V2 artifacts: V2 TX aggregator, SubtreeRootCircuit, SuperAggregatorV2.
//!
//! This binary is self-contained: it builds the V2 TX aggregator (sized for
//! `TESSERA_ACCOUNT_BATCH_SIZE` slots), the SubtreeRootCircuit, and the
//! SuperAggregatorV2, then verifies an end-to-end dummy round-trip through
//! Plonky2 → BN128 → Groth16.
//!
//! V2 batch dimensions (defaults):
//!   account_batch_size = 16   (TESSERA_ACCOUNT_BATCH_SIZE)
//!   notes_per_slot     = 8    (tessera_client::NOTE_BATCH, fixed)
//!   sr_batch_size      = 128  (= account_batch_size × notes_per_slot)
//!   agg_depth          = 4    (2^4 = 16 = account_batch_size, ARITY=2)
//!
//! Artifact layout:
//!   artifacts/v2-tx-aggregator/          — TX GenericAggregator for V2 batch size
//!   artifacts/v2-tx-aggregator/dummy_inner_tx_proof.bin  — single dummy PrivTx proof
//!   artifacts/subtree-root/              — SubtreeRootCircuit
//!   artifacts/super-aggregator-v2/       — SuperAggregatorV2 Plonky2 data
//!   artifacts/super-aggregator-v2/dummy_root_proof.bin   — dummy SA root proof
//!   artifacts/super-aggregator-v2/plonky2-proof/         — BN128 wrapper
//!   artifacts/super-aggregator-v2/groth-artifacts/       — Groth16 keys
//!
//! Usage:
//!   TESSERA_ACCOUNT_BATCH_SIZE=16 cargo run --bin super_aggregator_v2_artifacts --release

use std::{fs, path::PathBuf, time::Instant};

use anyhow::{ensure, Result};
use plonky2::field::types::Field;
use tessera_client::TesseraGateSerializer;
use tessera_trees::{
	groth::{BN128Wrapper, Groth16Wrapper},
	proof_aggregation::{
		GenericAggregator, GenericAggregatorConfig, SubtreeRootCircuit, SuperAggregatorV2,
		SuperAggregatorV2CircuitData, TX_DATA_OFFSET, TX_LEAF_PI_SIZE,
	},
	tree::hasher::HashOutput,
	ProofBN128, ProofNative, F,
};

const ARITY: usize = 2;
const NOTES_PER_SLOT: usize = tessera_client::NOTE_BATCH;

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

fn extract_hash(pis: &[F], offset: usize) -> [F; 4] {
	[
		pis[offset],
		pis[offset + 1],
		pis[offset + 2],
		pis[offset + 3],
	]
}

fn main() -> Result<()> {
	let account_batch_size: usize = std::env::var("TESSERA_ACCOUNT_BATCH_SIZE")
		.unwrap_or_else(|_| "16".to_string())
		.parse()
		.expect("TESSERA_ACCOUNT_BATCH_SIZE must be a valid usize");

	ensure!(
		account_batch_size.is_power_of_two() && account_batch_size >= 2,
		"TESSERA_ACCOUNT_BATCH_SIZE ({account_batch_size}) must be a power of two >= 2"
	);

	let sr_batch_size = account_batch_size * NOTES_PER_SLOT;
	let agg_depth = account_batch_size.trailing_zeros() as usize; // log2 of power-of-two
	ensure!(
		ARITY.pow(agg_depth as u32) == account_batch_size,
		"ARITY^depth ({}) != account_batch_size ({})",
		ARITY.pow(agg_depth as u32),
		account_batch_size
	);

	let artifacts_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifacts");
	let tx_agg_dir = artifacts_root.join("v2-tx-aggregator");
	let sr_dir = artifacts_root.join("subtree-root");
	let sav2_dir = artifacts_root.join("super-aggregator-v2");
	let plonky2_path = sav2_dir.join("plonky2-proof");
	let groth_path = sav2_dir.join("groth-artifacts");

	println!("=== SuperAggregatorV2 Artifact Builder ===");
	println!("account_batch_size : {account_batch_size}");
	println!("notes_per_slot     : {NOTES_PER_SLOT}");
	println!("sr_batch_size      : {sr_batch_size}");
	println!("agg_depth          : {agg_depth}  (ARITY={ARITY}, {ARITY}^{agg_depth}={account_batch_size})");
	println!("tx-aggregator dir  : {}", tx_agg_dir.display());
	println!("subtree-root dir   : {}", sr_dir.display());
	println!("super-agg-v2 dir   : {}", sav2_dir.display());

	// =======================================================================
	// 1. Build inner PrivTx circuit + generate one dummy inner proof
	// =======================================================================
	println!("\n[1] Building inner PrivTx circuit...");
	let now = Instant::now();
	let (priv_tx_cd, priv_tx_targets) = tessera_client::build_priv_tx_circuit();
	println!(
		"  PrivTx circuit: {} PIs, degree_bits={} [{:?}]",
		priv_tx_cd.common.num_public_inputs,
		priv_tx_cd.common.degree_bits(),
		now.elapsed()
	);

	// Single dummy inner proof used for all padding slots in the runtime.
	println!("  Generating dummy inner TX proof (seed=0)...");
	let now = Instant::now();
	let zero_an = [F::ZERO; 4];
	let zero_nn = [[F::ZERO; 4]; tessera_client::NOTE_BATCH];
	let zero_ac = [F::ZERO; 4];
	let zero_nc = [[F::ZERO; 4]; tessera_client::NOTE_BATCH];
	let dummy_inner_proof = tessera_client::prove_dummy_priv_tx(
		&priv_tx_cd,
		&priv_tx_targets,
		zero_an,
		zero_nn,
		zero_ac,
		zero_nc,
	);
	println!("  dummy inner proof [{:?}]", now.elapsed());

	// =======================================================================
	// 2. Build V2 TX aggregator
	// =======================================================================
	println!("\n[2] Building V2 TX aggregator (ARITY={ARITY}, depth={agg_depth})...");
	let now = Instant::now();
	let agg_config = GenericAggregatorConfig {
		arity: ARITY,
		depth: agg_depth,
	};
	let tx_agg = GenericAggregator::new(
		agg_config,
		priv_tx_cd.common.clone(),
		priv_tx_cd.verifier_only.clone(),
	)?;
	println!("  built [{:?}]", now.elapsed());

	fs::create_dir_all(&tx_agg_dir)?;
	tx_agg.store_artifacts(&tx_agg_dir, &TesseraGateSerializer)?;
	println!("  stored TX aggregator → {}", tx_agg_dir.display());

	// Store dummy inner proof here for the runtime (loaded when prover starts).
	let dummy_inner_bytes = dummy_inner_proof.to_bytes();
	fs::write(
		tx_agg_dir.join("dummy_inner_tx_proof.bin"),
		&dummy_inner_bytes,
	)?;
	println!(
		"  stored dummy_inner_tx_proof.bin ({} bytes)",
		dummy_inner_bytes.len()
	);

	// =======================================================================
	// 3. Generate account_batch_size dummy TX proofs, aggregate them
	// =======================================================================
	println!("\n[3] Generating {account_batch_size} dummy TX proofs + aggregating...");
	let now = Instant::now();
	// Reuse the same dummy proof for all slots — is_real=0 so cross-check is gated off.
	let dummy_tx_proofs: Vec<ProofNative> = (0..account_batch_size)
		.map(|_s| {
			tessera_client::prove_dummy_priv_tx(
				&priv_tx_cd,
				&priv_tx_targets,
				zero_an,
				zero_nn,
				zero_ac,
				zero_nc,
			)
		})
		.collect();
	println!(
		"  {account_batch_size} dummy TX proofs [{:?}]",
		now.elapsed()
	);

	println!("  Aggregating...");
	let now = Instant::now();
	let agg_result = tx_agg.aggregate(dummy_tx_proofs)?;
	tx_agg.verify_root(&agg_result.proof)?;
	println!("  TX aggregation done [{:?}]", now.elapsed());

	let tx_pis = &agg_result.proof.public_inputs;
	let n_tx_slots = tx_pis.len() / TX_LEAF_PI_SIZE;
	println!(
		"  TX root PIs: {} ({n_tx_slots} slots × {TX_LEAF_PI_SIZE})",
		tx_pis.len()
	);

	// =======================================================================
	// 4. Extract NC leaves from TX aggregated proof PIs
	// =======================================================================
	let nc_off = TX_DATA_OFFSET + 40; // AN(4) + AC(4) + NN(8×4) = 40
	let nc_leaves: Vec<HashOutput> = (0..n_tx_slots)
		.flat_map(|s| {
			(0..NOTES_PER_SLOT).map(move |j| {
				HashOutput::new(extract_hash(tx_pis, s * TX_LEAF_PI_SIZE + nc_off + j * 4))
			})
		})
		.collect();
	ensure!(
		nc_leaves.len() == sr_batch_size,
		"NC leaves count ({}) != sr_batch_size ({})",
		nc_leaves.len(),
		sr_batch_size
	);
	println!("  Extracted {sr_batch_size} NC leaves");

	// =======================================================================
	// 5. Build SubtreeRootCircuit + prove SR on NC leaves
	// =======================================================================
	println!("\n[5] Building SubtreeRootCircuit (batch_size={sr_batch_size})...");
	let now = Instant::now();
	let sr_circuit = SubtreeRootCircuit::build(sr_batch_size)?;
	println!("  SR circuit built [{:?}]", now.elapsed());

	fs::create_dir_all(&sr_dir)?;
	sr_circuit.store_artifacts(&sr_dir)?;
	println!("  stored SubtreeRootCircuit → {}", sr_dir.display());

	println!("  Proving SR on NC leaves...");
	let now = Instant::now();
	let sr_proof = sr_circuit.prove(&nc_leaves)?;
	sr_circuit.circuit_data.verify(sr_proof.clone())?;
	println!("  SR proof verified [{:?}]", now.elapsed());

	// =======================================================================
	// 6. Build SuperAggregatorV2
	// =======================================================================
	println!("\n[6] Building SuperAggregatorV2 circuit...");
	let now = Instant::now();
	let tx_root = tx_agg.level_circuit(agg_depth - 1)?;
	let inner = SuperAggregatorV2CircuitData {
		tx_common: tx_root.circuit_data.common.clone(),
		tx_verifier: tx_root.circuit_data.verifier_only.clone(),
		sr_common: sr_circuit.circuit_data.common.clone(),
		sr_verifier: sr_circuit.circuit_data.verifier_only.clone(),
	};
	let sav2 = SuperAggregatorV2::build(inner)?;
	println!("  SAV2 circuit built [{:?}]", now.elapsed());

	// =======================================================================
	// 7. Prove SuperAggregatorV2 with all-dummy input + zero private witnesses
	// =======================================================================
	println!("\n[7] Proving SuperAggregatorV2 (dummy)...");
	let now = Instant::now();
	let zero_hash = HashOutput::new([F::ZERO; 4]);
	let dummy_sa_proof = sav2.prove(agg_result.proof, sr_proof, zero_hash, zero_hash, [0u8; 32])?;
	sav2.circuit_data.verify(dummy_sa_proof.clone())?;
	println!("  SAV2 dummy proof verified [{:?}]", now.elapsed());
	assert_eq!(
		dummy_sa_proof.public_inputs.len(),
		8,
		"SAV2 root must have exactly 8 public inputs"
	);
	println!(
		"  piCommitment words: {:?}",
		&dummy_sa_proof.public_inputs[..8]
	);

	// =======================================================================
	// 8. Store SuperAggregatorV2 artifacts
	// =======================================================================
	fs::create_dir_all(&sav2_dir)?;
	sav2.store_artifacts(&sav2_dir)?;

	let dummy_sa_bytes = dummy_sa_proof.to_bytes();
	fs::write(sav2_dir.join("dummy_root_proof.bin"), &dummy_sa_bytes)?;
	println!(
		"\nStored SAV2 artifacts → {} (dummy proof {} bytes)",
		sav2_dir.display(),
		dummy_sa_bytes.len()
	);

	// Also store dummy inner TX proof in SAV2 dir for convenient loading by the runtime.
	fs::write(
		sav2_dir.join("dummy_inner_tx_proof.bin"),
		&dummy_inner_bytes,
	)?;
	println!(
		"Stored dummy_inner_tx_proof.bin in SAV2 dir ({} bytes)",
		dummy_inner_bytes.len()
	);

	// =======================================================================
	// 9. BN128 wrap
	// =======================================================================
	debug_log("Instantiating BN128Wrapper...");
	let bn128_wrapper = BN128Wrapper::new(sav2.circuit_data.clone(), dummy_sa_proof.clone())?;

	if !BN128Wrapper::has_full_artifacts(&plonky2_path) {
		println!("\n[9] Writing BN128 wrapper artifacts...");
		fs::create_dir_all(&plonky2_path)?;
		bn128_wrapper.store_full_circuit_data(&plonky2_path)?;
		println!("  stored → {}", plonky2_path.display());
	} else {
		println!("\n[9] BN128 artifacts already exist, skipping.");
	}

	// =======================================================================
	// 10. Groth16 trusted setup
	// =======================================================================
	if !groth_path.is_dir() {
		println!("[10] Generating Groth16 trusted setup...");
		let result = Groth16Wrapper::trusted_setup(&plonky2_path, &groth_path);
		debug_log(&format!("  trusted_setup result: {result}"));
		println!("  stored → {}", groth_path.display());
	} else {
		println!("[10] Groth16 artifacts already exist, skipping.");
	}

	let result: String = Groth16Wrapper::init(&plonky2_path, &groth_path)?;
	debug_log(&format!("init result: {result}"));
	let result: String = Groth16Wrapper::check_init();
	debug_log(&format!("check_init result: {result}"));

	// =======================================================================
	// 11. Groth16 round-trip test
	// =======================================================================
	println!("\n[11] Groth16 round-trip test...");
	let now = Instant::now();
	let proof_bn128: ProofBN128 = bn128_wrapper.wrap_proof_to_bn128(dummy_sa_proof)?;
	debug_log(&format!("  BN128 wrap: {:?}", now.elapsed()));

	let now = Instant::now();
	let (g16_proof, g16_pub_inp) = Groth16Wrapper::prove(proof_bn128)?;
	debug_log(&format!("  Groth16 prove: {:?}", now.elapsed()));

	Groth16Wrapper::verify(g16_proof.clone(), g16_pub_inp.clone())?;
	println!("  Groth16 verify ok");

	let solidity_json = Groth16Wrapper::proof_to_solidity_json(&g16_proof, &g16_pub_inp)?;
	let json_path = groth_path.join("proof_solidity.json");
	fs::write(&json_path, &solidity_json)?;
	println!("  wrote proof: {}", json_path.display());
	debug_log(&format!(
		"\n(rust) Solidity proof JSON written to {json_path:?}\n{solidity_json}"
	));

	// =======================================================================
	// 12. Copy Verifier.sol → tessera-solidity/src/VerifierSuperAggregatorV2.sol Copy
	//     proof_solidity.json → tessera-solidity/test/fixtures/groth16_proof.json
	// =======================================================================
	println!("\n[12] Syncing Solidity artifacts...");
	let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	let workspace_root = manifest_dir
		.parent()
		.expect("CARGO_MANIFEST_DIR has parent");
	let sol_src_dir = workspace_root.join("tessera-solidity/src");
	let sol_fixtures_dir = workspace_root.join("tessera-solidity/test/fixtures");

	let verifier_src = groth_path.join("Verifier.sol");
	if verifier_src.exists() && sol_src_dir.is_dir() {
		// Rename contract to VerifierSuperAggregatorV2 so both TX and deposit
		// verifier deployments can share the same file without name collisions.
		let content = fs::read_to_string(&verifier_src)?;
		let renamed = content.replace("contract Verifier ", "contract VerifierSuperAggregatorV2 ");
		let dst = sol_src_dir.join("VerifierSuperAggregatorV2.sol");
		fs::write(&dst, renamed)?;
		println!("  VerifierSuperAggregatorV2.sol → {}", dst.display());
	} else {
		println!("  Verifier.sol not found or Foundry src dir absent — skipping Solidity copy.");
	}

	if sol_fixtures_dir.is_dir() || fs::create_dir_all(&sol_fixtures_dir).is_ok() {
		let fixture_dst = sol_fixtures_dir.join("groth16_proof.json");
		fs::copy(&json_path, &fixture_dst)?;
		println!("  groth16_proof.json → {}", fixture_dst.display());
	} else {
		println!("  Could not create fixtures dir — skipping proof fixture copy.");
	}

	println!("\n=== SuperAggregatorV2 artifacts generated successfully ===");
	Ok(())
}
