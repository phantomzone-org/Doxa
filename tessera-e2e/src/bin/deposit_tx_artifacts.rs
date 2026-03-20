//! Generate deposit-pipeline artifacts: deposit-TX aggregator, SubtreeRootCircuit,
//! DepositSuperAggregatorV2, BN128 wrapper, and Groth16 trusted setup.
//!
//! This binary generates every artifact needed to initialise the deposit-proving
//! pipeline in `ProverRuntimeV2`. It is the deposit-pipeline counterpart to
//! `super_aggregator_v2_artifacts`.
//!
//! # Pipeline
//!
//! 1. **Deposit-TX circuit** — inner leaf circuit (`DEPOSIT_LEAF_PI_SIZE = 31` PIs).
//! 2. **Deposit-TX aggregator** — binary tree of depth `agg_depth` over `deposit_batch_size`
//!    deposit-TX proofs.  During artifact generation the tree is seeded with a single dummy proof
//!    and doubled up level-by-level (`merge(p, p) → p_next`) — only `agg_depth` prove calls instead
//!    of `2^(agg_depth+1) - 1`.
//! 3. **SubtreeRootCircuit** — proves `batchPoseidonRoot = Poseidon(deposit NCs)`.
//! 4. **DepositSuperAggregatorV2** — merges the deposit-TX aggregation proof and the SR proof,
//!    producing 8 Goldilocks field elements (Keccak-256 piCommitment) as public inputs.
//! 5. **BN128 wrapper + Groth16 trusted setup** — wraps the DSAV2 Plonky2 proof into a Groth16
//!    proof verifiable on-chain.  Uses Groth16 label `"deposit"` so the TX and deposit proving keys
//!    are independent.
//!
//! # Batch dimensions
//!
//!   deposit_batch_size = `DEPOSIT_BATCH_SIZE` constant below (default 64)
//!   agg_depth          = log2(deposit_batch_size)
//!   sr_batch_size      = deposit_batch_size  (one NC per slot)
//!
//! # Artifact layout (under `$TESSERA_ARTIFACTS_DIR` or `<workspace>/artifacts`)
//!
//!   deposit-tx-aggregator/              — deposit GenericAggregator
//!   deposit-tx-aggregator/dummy_inner_deposit_proof.bin
//!   deposit-subtree-root/               — SubtreeRootCircuit (deposit)
//!   deposit-super-aggregator-v2/        — DepositSuperAggregatorV2 Plonky2 data
//!   deposit-super-aggregator-v2/dummy_root_proof.bin
//!   deposit-super-aggregator-v2/plonky2-proof/   — BN128 wrapper
//!   deposit-super-aggregator-v2/groth-artifacts/ — Groth16 keys (label="deposit")
//!
//! # Usage
//!
//!   cargo run -p tessera-e2e --bin deposit_tx_artifacts --release
//!
//! Output directory (in order of precedence):
//!   1. `$TESSERA_ARTIFACTS_DIR`
//!   2. `<workspace-root>/artifacts/`

use std::{fs, path::PathBuf, time::Instant};

use anyhow::{ensure, Result};
use plonky2::{
	field::types::Field,
	iop::witness::{PartialWitness, WitnessWrite},
};
use tessera_client::TesseraGateSerializer;
use tessera_server::{
	proof_aggregation::{
		AggregatedProof, DepositSuperAggregatorV2, DepositSuperAggregatorV2CircuitData,
		GenericAggregator, GenericAggregatorConfig, SubtreeRootCircuit,
	},
	ProofBN128,
};
use tessera_utils::{
	groth::{BN128Wrapper, Groth16Wrapper},
	hasher::HashOutput,
	ProofNative, F,
};

const ARITY: usize = 2;

/// Number of deposit-TX slots per batch.  Must be a power of two.
const DEPOSIT_BATCH_SIZE: usize = 64;

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

/// Resolve artifact output directory.
fn artifacts_root() -> PathBuf {
	std::env::var("TESSERA_ARTIFACTS_DIR")
		.map(PathBuf::from)
		.unwrap_or_else(|_| {
			PathBuf::from(env!("CARGO_MANIFEST_DIR"))
				.parent()
				.expect("tessera-e2e has a workspace parent")
				.join("artifacts")
		})
}

fn main() -> Result<()> {
	let deposit_batch_size: usize = DEPOSIT_BATCH_SIZE;
	let agg_depth = deposit_batch_size.trailing_zeros() as usize;
	ensure!(
		ARITY.pow(agg_depth as u32) == deposit_batch_size,
		"ARITY^depth ({}) != deposit_batch_size ({})",
		ARITY.pow(agg_depth as u32),
		deposit_batch_size
	);
	// One NC per deposit slot → SR batch size == deposit batch size.
	let sr_batch_size = deposit_batch_size;

	let artifacts_root = artifacts_root();
	let dep_agg_dir = artifacts_root.join("deposit-tx-aggregator");
	let sr_dir = artifacts_root.join("deposit-subtree-root");
	let dsav2_dir = artifacts_root.join("deposit-super-aggregator-v2");
	let plonky2_path = dsav2_dir.join("plonky2-proof");
	let groth_path = dsav2_dir.join("groth-artifacts");

	println!("=== DepositSuperAggregatorV2 Artifact Builder ===");
	println!("deposit_batch_size : {deposit_batch_size}");
	println!("sr_batch_size      : {sr_batch_size}");
	println!(
		"agg_depth          : {agg_depth}  (ARITY={ARITY}, {ARITY}^{agg_depth}={deposit_batch_size})"
	);
	println!("artifacts root     : {}", artifacts_root.display());
	println!("deposit-agg dir    : {}", dep_agg_dir.display());
	println!("subtree-root dir   : {}", sr_dir.display());
	println!("dsav2 dir          : {}", dsav2_dir.display());

	// =======================================================================
	// 1. Build deposit-TX circuit + generate one dummy inner proof
	// =======================================================================
	println!("\n[1] Building deposit-TX circuit...");
	let now = Instant::now();
	let deposit_circuit = tessera_client::build_deposit_tx_circuit();
	println!(
		"  deposit-TX circuit: {} PIs, degree_bits={} [{:?}]",
		deposit_circuit.circuit_data.common.num_public_inputs,
		deposit_circuit.circuit_data.common.degree_bits(),
		now.elapsed()
	);

	println!("  Generating dummy deposit-TX proof...");
	let now = Instant::now();
	let dummy_inner_proof = deposit_circuit.prove_dummy();
	println!("  dummy inner proof [{:?}]", now.elapsed());

	// =======================================================================
	// 2. Build deposit-TX aggregator
	// =======================================================================
	println!("\n[2] Building deposit-TX aggregator (ARITY={ARITY}, depth={agg_depth})...");
	let now = Instant::now();
	let agg_config = GenericAggregatorConfig {
		arity: ARITY,
		depth: agg_depth,
	};
	let dep_agg = GenericAggregator::new(
		agg_config.clone(),
		deposit_circuit.circuit_data.common.clone(),
		deposit_circuit.circuit_data.verifier_only.clone(),
	)?;
	println!("  built [{:?}]", now.elapsed());

	fs::create_dir_all(&dep_agg_dir)?;
	dep_agg.store_artifacts(&dep_agg_dir, &TesseraGateSerializer)?;
	println!("  stored deposit-TX aggregator → {}", dep_agg_dir.display());

	let dummy_inner_bytes = dummy_inner_proof.to_bytes();
	fs::write(
		dep_agg_dir.join("dummy_inner_deposit_proof.bin"),
		&dummy_inner_bytes,
	)?;
	println!(
		"  stored dummy_inner_deposit_proof.bin ({} bytes)",
		dummy_inner_bytes.len()
	);

	// =======================================================================
	// 3. Aggregate deposit-TX tree using O(log N) doubling: merge(p, p) → p_next
	// =======================================================================
	println!(
		"\n[3] Aggregating deposit-TX tree via O(log N) doubling \
		 ({agg_depth} merges, arity={ARITY})..."
	);
	let mut current: ProofNative = dummy_inner_proof;
	for level_idx in 0..agg_depth {
		let level = dep_agg.level_circuit(level_idx)?;
		let inner_verifier = dep_agg.inner_verifier_for_level(level_idx);
		let mut pw = PartialWitness::new();
		pw.set_verifier_data_target(&level.verifier_target, inner_verifier)?;
		for i in 0..ARITY {
			pw.set_proof_with_pis_target(&level.proof_targets[i], &current)?;
		}
		let now = Instant::now();
		current = level.circuit_data.prove(pw)?;
		println!("  level {level_idx} merged [{:?}]", now.elapsed());
	}
	let agg_result = AggregatedProof {
		proof: current,
		config: agg_config.clone(),
	};
	dep_agg.verify_root(&agg_result.proof)?;
	println!("  deposit-TX aggregation done ({agg_depth} steps)");

	// =======================================================================
	// 4. Extract deposit NC leaves from aggregated proof PIs
	//
	// Deposit-TX leaf PI layout (DEPOSIT_LEAF_PI_SIZE = 33):
	//   PI[0]       accin.subpool_id  (auto via add_virtual_account_target)
	//   PI[1]       accout.subpool_id (auto via add_virtual_account_target)
	//   PI[2]       not_fake_tx
	//   PI[3..7]    act_root[4]
	//   PI[7..11]   accin_null[4]
	//   PI[11..15]  accout_comm[4]
	//   PI[15..19]  deposit_note_comm[4]  ← used as SR leaf
	//   PI[19..24]  eth_address[5]
	//   PI[24..32]  amount[8]
	//   PI[32]      asset_id
	// =======================================================================
	use tessera_server::proof_aggregation::{DEPOSIT_LEAF_PI_SIZE, DEPOSIT_NOTE_COMM_OFFSET};

	let dep_pis = &agg_result.proof.public_inputs;
	let n_dep_slots = dep_pis.len() / DEPOSIT_LEAF_PI_SIZE;
	ensure!(
		n_dep_slots == deposit_batch_size,
		"aggregated deposit PI slots ({n_dep_slots}) != deposit_batch_size ({deposit_batch_size})"
	);

	let nc_leaves: Vec<HashOutput> = (0..n_dep_slots)
		.map(|s| {
			let base = s * DEPOSIT_LEAF_PI_SIZE + DEPOSIT_NOTE_COMM_OFFSET;
			HashOutput::new([
				dep_pis[base],
				dep_pis[base + 1],
				dep_pis[base + 2],
				dep_pis[base + 3],
			])
		})
		.collect();
	println!("  Extracted {sr_batch_size} deposit NC leaves");

	// =======================================================================
	// 5. Build SubtreeRootCircuit + prove SR on deposit NC leaves
	// =======================================================================
	println!("\n[5] Building SubtreeRootCircuit (batch_size={sr_batch_size})...");
	let now = Instant::now();
	let sr_circuit = SubtreeRootCircuit::build(sr_batch_size)?;
	println!("  SR circuit built [{:?}]", now.elapsed());

	fs::create_dir_all(&sr_dir)?;
	sr_circuit.store_artifacts(&sr_dir)?;
	println!("  stored SubtreeRootCircuit → {}", sr_dir.display());

	println!("  Proving SR on deposit NC leaves...");
	let now = Instant::now();
	let sr_proof = sr_circuit.prove(&nc_leaves)?;
	sr_circuit.circuit_data.verify(sr_proof.clone())?;
	println!("  SR proof verified [{:?}]", now.elapsed());

	// =======================================================================
	// 6. Build DepositSuperAggregatorV2
	// =======================================================================
	println!("\n[6] Building DepositSuperAggregatorV2 circuit...");
	let now = Instant::now();
	let dep_root_level = dep_agg.level_circuit(agg_depth - 1)?;
	let inner = DepositSuperAggregatorV2CircuitData {
		deposit_common: dep_root_level.circuit_data.common.clone(),
		deposit_verifier: dep_root_level.circuit_data.verifier_only.clone(),
		sr_common: sr_circuit.circuit_data.common.clone(),
		sr_verifier: sr_circuit.circuit_data.verifier_only.clone(),
	};
	let dsav2 = DepositSuperAggregatorV2::build(inner)?;
	println!("  DSAV2 circuit built [{:?}]", now.elapsed());

	// =======================================================================
	// 7. Prove DepositSuperAggregatorV2 with dummy inputs
	// =======================================================================
	println!("\n[7] Proving DepositSuperAggregatorV2 (dummy)...");
	let now = Instant::now();
	let zero_hash = HashOutput::new([F::ZERO; 4]);
	let dummy_dsav2_proof = dsav2.prove(agg_result.proof, sr_proof, zero_hash, [0u8; 32])?;
	dsav2.circuit_data.verify(dummy_dsav2_proof.clone())?;
	println!("  DSAV2 dummy proof verified [{:?}]", now.elapsed());
	assert_eq!(
		dummy_dsav2_proof.public_inputs.len(),
		8,
		"DSAV2 root must have exactly 8 public inputs"
	);
	println!(
		"  piCommitment words: {:?}",
		&dummy_dsav2_proof.public_inputs[..8]
	);

	// =======================================================================
	// 8. Store DepositSuperAggregatorV2 artifacts
	// =======================================================================
	fs::create_dir_all(&dsav2_dir)?;
	dsav2.store_artifacts(&dsav2_dir)?;

	let dummy_dsav2_bytes = dummy_dsav2_proof.to_bytes();
	fs::write(dsav2_dir.join("dummy_root_proof.bin"), &dummy_dsav2_bytes)?;
	println!(
		"\nStored DSAV2 artifacts → {} (dummy proof {} bytes)",
		dsav2_dir.display(),
		dummy_dsav2_bytes.len()
	);

	fs::write(
		dsav2_dir.join("dummy_inner_deposit_proof.bin"),
		&dummy_inner_bytes,
	)?;
	println!(
		"Stored dummy_inner_deposit_proof.bin in DSAV2 dir ({} bytes)",
		dummy_inner_bytes.len()
	);

	// =======================================================================
	// 9. BN128 wrap
	// =======================================================================
	debug_log("Instantiating BN128Wrapper...");
	let bn128_wrapper = BN128Wrapper::new(dsav2.circuit_data.clone(), dummy_dsav2_proof.clone())?;

	if !BN128Wrapper::has_full_artifacts(&plonky2_path) {
		println!("\n[9] Writing BN128 wrapper artifacts...");
		fs::create_dir_all(&plonky2_path)?;
		bn128_wrapper.store_full_circuit_data(&plonky2_path)?;
		println!("  stored → {}", plonky2_path.display());
	} else {
		println!("\n[9] BN128 artifacts already exist, skipping.");
	}

	// =======================================================================
	// 10. Groth16 trusted setup  (label = "deposit")
	// =======================================================================
	if !groth_path.is_dir() {
		println!("[10] Generating Groth16 trusted setup (label=deposit)...");
		let result =
			Groth16Wrapper::trusted_setup_with_label("deposit", &plonky2_path, &groth_path);
		debug_log(&format!("  trusted_setup_with_label result: {result}"));
		println!("  stored → {}", groth_path.display());
	} else {
		println!("[10] Groth16 artifacts already exist, skipping.");
	}

	let result = Groth16Wrapper::init_with_label("deposit", &plonky2_path, &groth_path)?;
	debug_log(&format!("init_with_label result: {result}"));
	let result = Groth16Wrapper::check_init_with_label("deposit");
	debug_log(&format!("check_init_with_label result: {result}"));

	// =======================================================================
	// 11. Groth16 round-trip test  (label = "deposit")
	// =======================================================================
	println!("\n[11] Groth16 round-trip test (label=deposit)...");
	let now = Instant::now();
	let proof_bn128: ProofBN128 = bn128_wrapper.wrap_proof_to_bn128(dummy_dsav2_proof)?;
	debug_log(&format!("  BN128 wrap: {:?}", now.elapsed()));

	let now = Instant::now();
	let (g16_proof, g16_pub_inp) = Groth16Wrapper::prove_with_label("deposit", proof_bn128)?;
	debug_log(&format!("  Groth16 prove: {:?}", now.elapsed()));

	Groth16Wrapper::verify_with_label("deposit", g16_proof.clone(), g16_pub_inp.clone())?;
	println!("  Groth16 verify ok");

	let solidity_json = Groth16Wrapper::proof_to_solidity_json(&g16_proof, &g16_pub_inp)?;
	let json_path = groth_path.join("proof_solidity.json");
	fs::write(&json_path, &solidity_json)?;
	println!("  wrote proof: {}", json_path.display());

	// =======================================================================
	// 12. Copy Verifier.sol → tessera-solidity/src/VerifierDepositSuperAggregatorV2.sol Copy
	//     proof_solidity.json → tessera-solidity/test/fixtures/groth16_deposit_proof.json
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
		let content = fs::read_to_string(&verifier_src)?;
		let renamed = content.replace(
			"contract Verifier ",
			"contract VerifierDepositSuperAggregatorV2 ",
		);
		let dst = sol_src_dir.join("VerifierDepositSuperAggregatorV2.sol");
		fs::write(&dst, renamed)?;
		println!("  VerifierDepositSuperAggregatorV2.sol → {}", dst.display());
	} else {
		println!("  Verifier.sol not found or Foundry src dir absent — skipping Solidity copy.");
	}

	if sol_fixtures_dir.is_dir() || fs::create_dir_all(&sol_fixtures_dir).is_ok() {
		let fixture_dst = sol_fixtures_dir.join("groth16_deposit_proof.json");
		fs::copy(&json_path, &fixture_dst)?;
		println!("  groth16_deposit_proof.json → {}", fixture_dst.display());
	} else {
		println!("  Could not create fixtures dir — skipping proof fixture copy.");
	}

	println!("\n=== DepositSuperAggregatorV2 artifacts generated successfully ===");
	Ok(())
}
