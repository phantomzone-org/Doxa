use std::{fs, path::PathBuf, time::Instant};

use anyhow::{ensure, Result};
use plonky2::{
	field::types::{Field, PrimeField64},
	hash::{hash_types::HashOut, poseidon::PoseidonHash},
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::config::Hasher,
};
use tessera_client::{TesseraGateSerializer, NOTE_BATCH};
use tessera_server::{
	proof_aggregation::{
		AggregatedProof, GenericAggregator, GenericAggregatorConfig, SubtreeRootCircuit,
		SuperAggregator, SuperAggregatorV2CircuitData, TX_DATA_OFFSET, TX_LEAF_PI_SIZE,
	},
	ProofBN128, TREE_DEPTH,
};
use tessera_utils::{
	groth::{BN128Wrapper, Groth16Wrapper},
	hasher::HashOutput,
	ConfigNative, ProofNative, D, F,
};

/// Compute the on-chain genesis root: `zeros[depth]` where
/// `zeros[0] = 0` and `zeros[i] = Poseidon.compress(zeros[i-1], zeros[i-1])`.
///
/// This matches the Goldilocks Poseidon used in `TesseraContract.sol`.
fn compute_genesis_root(depth: usize) -> HashOutput {
	let mut h = HashOutput::new([F::ZERO; 4]);
	for _ in 0..depth {
		let data = [
			h.0[0], h.0[1], h.0[2], h.0[3], h.0[0], h.0[1], h.0[2], h.0[3],
		];
		let out: HashOut<F> = PoseidonHash::hash_no_pad(&data);
		h = HashOutput::new(out.elements);
	}
	h
}

/// Pack a `HashOutput` to a `0x`-prefixed hex bytes32 string using the same
/// big-endian LE-packed uint256 layout as `compute_pi_commitment_native`.
fn hash_to_bytes32_hex(h: &HashOutput) -> String {
	let mut bytes = [0u8; 32];
	let mut pos = 0usize;
	// Reversed field-element order, each element as [hi32, lo32] big-endian bytes.
	for &field in &[h.0[3], h.0[2], h.0[1], h.0[0]] {
		let v = field.to_canonical_u64();
		bytes[pos..pos + 4].copy_from_slice(&((v >> 32) as u32).to_be_bytes());
		bytes[pos + 4..pos + 8].copy_from_slice(&(v as u32).to_be_bytes());
		pos += 8;
	}
	format!("0x{}", hex::encode(bytes))
}

const ARITY: usize = 2;

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

/// Resolve artifact output directory.
///
/// Priority:
///   1. `$TESSERA_ARTIFACTS_DIR` environment variable
///   2. `<workspace-root>/artifacts/`  (sibling of this crate's manifest dir)
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
	let priv_tx_batch_size: usize = tessera_client::PRIV_TX_BATCH_SIZE;

	// SR has NOTE_BATCH NC + 1 AC per TX slot = NOTE_BATCH+1 = 8 leaves per slot.
	let leaves_per_slot = NOTE_BATCH + 1;
	let sr_batch_size = priv_tx_batch_size * leaves_per_slot;
	let agg_depth = priv_tx_batch_size.trailing_zeros() as usize; // log2 of power-of-two
	ensure!(
		ARITY.pow(agg_depth as u32) == priv_tx_batch_size,
		"ARITY^depth ({}) != priv_tx_batch_size ({})",
		ARITY.pow(agg_depth as u32),
		priv_tx_batch_size
	);

	let artifacts_root = artifacts_root();
	let tx_artifacts_dir = artifacts_root.join("transactions");
	let tx_agg_dir = tx_artifacts_dir.join("tx-aggregator");
	let sr_dir = tx_artifacts_dir.join("subtree-root");
	let sav2_dir = tx_artifacts_dir.join("super-aggregator");
	let plonky2_path = sav2_dir.join("plonky2-proof");
	let groth_path = sav2_dir.join("groth-artifacts");

	println!("=== TX Artifact Builder ===");
	println!("priv_tx_batch_size : {priv_tx_batch_size}");
	println!("notes_per_slot     : {NOTE_BATCH} NC + 1 AC = {leaves_per_slot} SR leaves/slot");
	println!("sr_batch_size      : {sr_batch_size}");
	println!(
		"agg_depth          : {agg_depth}  (ARITY={ARITY}, {ARITY}^{agg_depth}={priv_tx_batch_size})"
	);
	println!("artifacts root     : {}", artifacts_root.display());
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
		agg_config.clone(),
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
	// 3. Aggregate TX tree using O(log N) doubling: merge(p, p) → p_next
	//
	// Instead of proving all priv_tx_batch_size=64 leaf proofs and doing the
	// full tree aggregation (127 prove calls), we prove one leaf and double
	// it up through each level: agg_depth=6 prove calls total.
	// =======================================================================
	println!(
		"\n[3] Aggregating TX tree via O(log N) doubling ({agg_depth} merges, \
		 arity={ARITY}, depth={agg_depth})..."
	);
	// Reuse the single dummy inner proof from step 1 as the leaf proof p0.
	let mut current: ProofNative = dummy_inner_proof.clone();
	for level_idx in 0..agg_depth {
		let level = tx_agg.level_circuit(level_idx)?;
		let inner_verifier = tx_agg.inner_verifier_for_level(level_idx);
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
	tx_agg.verify_root(&agg_result.proof)?;
	println!("  TX aggregation done ({agg_depth} steps instead of {priv_tx_batch_size})");

	let tx_pis = &agg_result.proof.public_inputs;
	let n_tx_slots = tx_pis.len() / TX_LEAF_PI_SIZE;
	println!(
		"  TX root PIs: {} ({n_tx_slots} slots × {TX_LEAF_PI_SIZE})",
		tx_pis.len()
	);

	// =======================================================================
	// 4. Extract SR leaves from TX aggregated proof PIs
	//
	// SR leaf layout per slot: [NC[0], NC[1], ..., NC[NOTE_BATCH-1], AC]
	// NC starts at TX_DATA_OFFSET + AN(4) + AC(4) + NN(NOTE_BATCH×4).
	// AC is at TX_DATA_OFFSET + AN(4).
	// =======================================================================
	let nc_off = TX_DATA_OFFSET + 8 + NOTE_BATCH * 4; // AN(4) + AC(4) + NN(NOTE_BATCH×4)
	let ac_off = TX_DATA_OFFSET + 4; // AN(4)
	let nc_leaves: Vec<HashOutput> = (0..n_tx_slots)
		.flat_map(|s| {
			let base = s * TX_LEAF_PI_SIZE;
			let ncs = (0..NOTE_BATCH)
				.map(move |j| HashOutput::new(extract_hash(tx_pis, base + nc_off + j * 4)));
			let ac = HashOutput::new(extract_hash(tx_pis, base + ac_off));
			ncs.chain(std::iter::once(ac))
		})
		.collect();
	ensure!(
		nc_leaves.len() == sr_batch_size,
		"SR leaves count ({}) != sr_batch_size ({})",
		nc_leaves.len(),
		sr_batch_size
	);
	println!("  Extracted {sr_batch_size} SR leaves ({NOTE_BATCH} NC + 1 AC per slot)");

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
	// 6. Build SuperAggregator
	// =======================================================================
	println!("\n[6] Building SuperAggregator circuit...");
	let now = Instant::now();
	let tx_root = tx_agg.level_circuit(agg_depth - 1)?;
	let inner = SuperAggregatorV2CircuitData {
		tx_common: tx_root.circuit_data.common.clone(),
		tx_verifier: tx_root.circuit_data.verifier_only.clone(),
		sr_common: sr_circuit.circuit_data.common.clone(),
		sr_verifier: sr_circuit.circuit_data.verifier_only.clone(),
	};
	let sav2 = SuperAggregator::build(inner)?;
	println!("  Final Plonky2 Proof circuit built [{:?}]", now.elapsed());

	// =======================================================================
	// 7. Prove SuperAggregator with all-dummy input + zero private witnesses
	//
	// Use the genesis root as the single IMT root so the
	// dummy proof is accepted by the Solidity rollup in integration tests.
	// =======================================================================
	println!("\n[7] Proving SuperAggregator (dummy)...");
	let now = Instant::now();
	let genesis_root = compute_genesis_root(TREE_DEPTH);
	let tx_agg_proof = agg_result.proof;
	let dummy_sa_proof = sav2.prove(
		tx_agg_proof.clone(),
		sr_proof.clone(),
		genesis_root,
		[0u8; 32],
	)?;
	sav2.circuit_data.verify(dummy_sa_proof.clone())?;
	println!(
		"  Final Plonky2 Proof dummy proof verified [{:?}]",
		now.elapsed()
	);
	assert_eq!(
		dummy_sa_proof.public_inputs.len(),
		8,
		"Final Plonky2 Proof must have exactly 8 public inputs"
	);
	println!(
		"  piCommitment words: {:?}",
		&dummy_sa_proof.public_inputs[..8]
	);

	// =======================================================================
	// 8. Store SuperAggregator artifacts
	// =======================================================================
	fs::create_dir_all(&sav2_dir)?;
	sav2.store_artifacts(&sav2_dir)?;

	let dummy_sa_bytes = dummy_sa_proof.to_bytes();
	fs::write(sav2_dir.join("dummy_root_proof.bin"), &dummy_sa_bytes)?;
	println!(
		"\nStored Final Plonky2 Proof artifacts → {} (dummy proof {} bytes)",
		sav2_dir.display(),
		dummy_sa_bytes.len()
	);

	// Also store dummy inner TX proof in Final Plonky2 Proof dir for convenient loading by the
	// runtime.
	fs::write(
		sav2_dir.join("dummy_inner_tx_proof.bin"),
		&dummy_inner_bytes,
	)?;
	println!(
		"Stored dummy_inner_tx_proof.bin in Final Plonky2 Proof dir ({} bytes)",
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

	// Augment with batch parameters needed by the Solidity integration test so it
	// can reconstruct the exact TransactionBatch that matches this proof's piCommitment.
	let sr_root_hash = HashOutput::new([
		sr_proof.public_inputs[0],
		sr_proof.public_inputs[1],
		sr_proof.public_inputs[2],
		sr_proof.public_inputs[3],
	]);
	let nc_per_slot = NOTE_BATCH; // = NOTE_BATCH = 7 (NC and NN count per TX slot)
	let mut fixture: serde_json::Value = serde_json::from_str(&solidity_json)?;
	fixture["root"] = serde_json::Value::String(hash_to_bytes32_hex(&genesis_root));
	fixture["batchPoseidonRoot"] = serde_json::Value::String(hash_to_bytes32_hex(&sr_root_hash));

	// Extract the exact AC/AN/NC/NN arrays that the circuit's keccak preimage uses,
	// so the Solidity integration test can reconstruct the exact TransactionBatch.
	let acs = SuperAggregator::acs_from_tx_proof(&tx_agg_proof, n_tx_slots);
	let ans = SuperAggregator::ans_from_tx_proof(&tx_agg_proof, n_tx_slots);
	let ncs =
		SuperAggregator::ncs_from_sr_proof(&sr_proof, n_tx_slots, leaves_per_slot, nc_per_slot);
	let nns = SuperAggregator::nn_from_tx_proof(&tx_agg_proof, n_tx_slots, nc_per_slot);

	let to_hex_array = |hashes: &[HashOutput]| -> serde_json::Value {
		serde_json::json!(hashes
			.iter()
			.map(|h| hash_to_bytes32_hex(h))
			.collect::<Vec<_>>())
	};
	fixture["accountCommitments"] = to_hex_array(&acs);
	fixture["accountNullifiers"] = to_hex_array(&ans);
	fixture["noteCommitments"] = to_hex_array(&ncs);
	fixture["noteNullifiers"] = to_hex_array(&nns);
	let augmented_json = serde_json::to_string_pretty(&fixture)?;

	let json_path = groth_path.join("proof_solidity.json");
	fs::write(&json_path, &augmented_json)?;
	println!("  wrote proof: {}", json_path.display());
	debug_log(&format!(
		"\n(rust) Solidity proof JSON written to {json_path:?}\n{augmented_json}"
	));

	// =======================================================================
	// 12. Copy Verifier.sol → tessera-solidity/src/TesseraBatchTransactionVerifier.sol Copy
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
	anyhow::ensure!(
		verifier_src.exists(),
		"Verifier.sol not found at {} — Groth16 trusted setup must have failed",
		verifier_src.display()
	);
	anyhow::ensure!(
		sol_src_dir.is_dir(),
		"tessera-solidity/src not found at {} — is the workspace layout correct?",
		sol_src_dir.display()
	);
	// Rename contract to TesseraBatchTransactionVerifier so both TX and deposit
	// verifier deployments can share the same file without name collisions.
	let content = fs::read_to_string(&verifier_src)?;
	let renamed = content.replace(
		"contract Verifier ",
		"contract TesseraBatchTransactionVerifier ",
	);
	let dst = sol_src_dir.join("TesseraBatchTransactionVerifier.sol");
	fs::write(&dst, renamed)?;
	println!("  TesseraBatchTransactionVerifier.sol → {}", dst.display());

	let sol_root = workspace_root.join("tessera-solidity");
	println!("  running forge build in {} ...", sol_root.display());
	let status = std::process::Command::new("forge")
		.arg("build")
		.current_dir(&sol_root)
		.status()
		.map_err(|e| anyhow::anyhow!("failed to run forge build: {e}"))?;
	anyhow::ensure!(status.success(), "forge build failed");
	println!("  forge build ok");

	fs::create_dir_all(&sol_fixtures_dir)?;
	let fixture_dst = sol_fixtures_dir.join("groth16_proof.json");
	fs::copy(&json_path, &fixture_dst)?;
	println!("  groth16_proof.json → {}", fixture_dst.display());

	// =======================================================================
	// 13. Build and serialize 2-slot unit-test Final Plonky2 Proof circuit
	//
	// The unit tests in `proof_aggregation::super_aggregator_v2::tests` build
	// a small SuperAggregator (2 TX slots × 8 SR leaves = 16 leaves) on
	// every `cargo test` run, which takes ~30s.  We serialize it here so
	// the tests can load from disk instead of rebuilding.
	//
	// Layout under artifacts/sav2-unit-test/:
	//   circuit_data.bin, tx_common.bin, tx_verifier.bin,
	//   sr_common.bin, sr_verifier.bin  — SuperAggregator (2 slots)
	//   subtree-root/circuit_data.bin   — SubtreeRootCircuit (16 leaves)
	// =======================================================================
	let unit_test_dir = tx_artifacts_dir.join("unit-test");
	if SuperAggregator::has_artifacts(&unit_test_dir) {
		println!("\n[13] Unit-test Final Plonky2 Proof artifacts already exist, skipping.");
	} else {
		println!("\n[13] Building 2-slot unit-test Final Plonky2 Proof circuit...");
		let now = Instant::now();

		// Synthetic TX-agg circuit: 2 slots × TX_LEAF_PI_SIZE PIs.
		let n_unit_slots: usize = 2;
		let unit_sr_leaves: usize = n_unit_slots * leaves_per_slot; // = 16
		let unit_tx_cd = {
			use plonky2::plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig};
			let n_pi = n_unit_slots * TX_LEAF_PI_SIZE;
			let mut b = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
			let targets: Vec<_> = (0..n_pi).map(|_| b.add_virtual_target()).collect();
			for &t in &targets {
				b.register_public_input(t);
			}
			b.build::<ConfigNative>()
		};
		println!("  synthetic TX-agg circuit built [{:?}]", now.elapsed());

		let now = Instant::now();
		let unit_sr = SubtreeRootCircuit::build(unit_sr_leaves)?;
		println!(
			"  SubtreeRootCircuit({unit_sr_leaves}) built [{:?}]",
			now.elapsed()
		);

		let unit_inner = SuperAggregatorV2CircuitData {
			tx_common: unit_tx_cd.common.clone(),
			tx_verifier: unit_tx_cd.verifier_only.clone(),
			sr_common: unit_sr.circuit_data.common.clone(),
			sr_verifier: unit_sr.circuit_data.verifier_only.clone(),
		};
		let now = Instant::now();
		let unit_sav2 = SuperAggregator::build(unit_inner)?;
		println!("  SuperAggregator built [{:?}]", now.elapsed());

		unit_sav2.store_artifacts(&unit_test_dir)?;
		unit_sr.store_artifacts(&unit_test_dir.join("subtree-root"))?;
		println!("  stored unit-test artifacts → {}", unit_test_dir.display());
	}

	println!("\n=== TX artifacts generated successfully ===");
	Ok(())
}
