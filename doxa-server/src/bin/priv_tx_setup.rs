//! Generate and store **all** artifacts needed for PrivTx batch proving.
//!
//! Runs the full pipeline once and writes everything to a single root directory:
//!
//! ```text
//! <DOXA_PRIV_TX_ARTIFACTS_PATH>/
//! ├── generic-agg/      ← GenericAggregator (arity=8, depth=2, 64 slots)
//! ├── subtree-root/     ← SubtreeRootCircuit
//! ├── super-circuit/    ← PrivTxSuperCircuit
//! ├── plonky2-proof/    ← BN128Wrapper circuit data (JSON + .bin)
//! └── groth-artifacts/  ← Groth16 proving key, verifying key, r1cs
//! ```
//!
//! ## Usage
//!
//! ```bash
//! DOXA_PRIV_TX_ARTIFACTS_PATH=artifacts/priv-tx \
//!     cargo run --bin priv_tx_setup --release
//! ```
//!
//! Re-running is idempotent: each stage is skipped when its artifacts are
//! already present.

use std::{fs, path::PathBuf, time::Instant};

use anyhow::Result;
use doxa_client::{DoxaGateSerializer, build_priv_tx_circuit};
use doxa_server::aggregator_service::PrivTxAggregator;
use doxa_utils::groth::{BN128Wrapper, Groth16Wrapper};
use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
	tracing_subscriber::fmt()
		.with_env_filter(
			EnvFilter::try_from_default_env()
				.unwrap_or_else(|_| EnvFilter::new("info")),
		)
		.init();

	let root: PathBuf = std::env::var("DOXA_PRIV_TX_ARTIFACTS_PATH")
		.map(PathBuf::from)
		.unwrap_or_else(|_| PathBuf::from("artifacts/priv-tx"));

	let plonky2_path = root.join("plonky2-proof");
	let groth_path = root.join("groth-artifacts");

	info!("PrivTx artifact root: {}", root.display());

	// =========================================================================
	// 1. Build or reload the PrivTxAggregator
	// =========================================================================
	let agg = if PrivTxAggregator::has_full_artifacts(&root)? {
		info!("[1] Aggregator artifacts found — loading from disk");
		PrivTxAggregator::from_artifacts(&root, &DoxaGateSerializer)?
	} else {
		info!("[1] Building PrivTxAggregator (arity=8, depth=2, 64 slots) …");
		let now = Instant::now();
		let leaf = build_priv_tx_circuit();
		let agg = PrivTxAggregator::build(
			leaf.circuit_data.common.clone(),
			leaf.circuit_data.verifier_only.clone(),
		)?;
		info!("    built in {:.1?}", now.elapsed());

		info!("[1] Storing aggregator artifacts → {}", root.display());
		fs::create_dir_all(&root)?;
		agg.store_artifacts(&root, &DoxaGateSerializer)?;
		agg
	};

	// =========================================================================
	// 2. BN128 wrap
	// =========================================================================
	if !BN128Wrapper::has_full_artifacts(&plonky2_path) {
		info!("[2] Generating dummy super proof for BN128Wrapper …");
		let now = Instant::now();
		let dummy_proof = agg.prove_dummy()?;
		info!("    dummy super proof generated in {:.1?}", now.elapsed());

		let circuit_data = agg.super_circuit_data().clone();
		info!("[2] Building BN128Wrapper …");
		let bn128 = BN128Wrapper::new(circuit_data, dummy_proof)?;

		info!("[2] Storing BN128 artifacts → {}", plonky2_path.display());
		fs::create_dir_all(&plonky2_path)?;
		bn128.store_full_circuit_data(&plonky2_path)?;
	} else {
		info!("[2] BN128 artifacts already present, skipping.");
	}

	// =========================================================================
	// 3. Groth16 trusted setup
	// =========================================================================
	if !groth_path.is_dir() {
		info!("[3] Running Groth16 trusted setup …");
		let now = Instant::now();
		let result = Groth16Wrapper::trusted_setup(&plonky2_path, &groth_path);
		info!("    trusted_setup: {result} (elapsed {:.1?})", now.elapsed());
	} else {
		info!("[3] Groth16 artifacts already present, skipping.");
	}

	// Smoke-test: verify we can load the Groth16 singleton.
	let result = Groth16Wrapper::init(&plonky2_path, &groth_path)?;
	info!("Groth16 init: {result}");
	Groth16Wrapper::check_init();

	// =========================================================================
	// 4. Copy Verifier.sol → doxa-solidity/src/DoxaBatchTransactionVerifier.sol
	//    and run forge build so the deployed verifier matches the proving key.
	// =========================================================================
	{
		let verifier_src = fs::read_to_string(groth_path.join("Verifier.sol"))
			.map_err(|e| anyhow::anyhow!("read Verifier.sol: {e}"))?;
		let renamed = verifier_src.replace(
			"contract Verifier {",
			"contract DoxaBatchTransactionVerifier {",
		);
		let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
			.parent()
			.expect("doxa-server has a parent workspace");
		let dest = workspace.join("doxa-solidity/src/DoxaBatchTransactionVerifier.sol");
		fs::write(&dest, renamed)
			.map_err(|e| anyhow::anyhow!("write DoxaBatchTransactionVerifier.sol: {e}"))?;
		info!("[4] Wrote DoxaBatchTransactionVerifier.sol → {dest:?}");

		let solidity_dir = workspace.join("doxa-solidity");
		let status = std::process::Command::new("forge")
			.args(["build"])
			.current_dir(&solidity_dir)
			.status()
			.map_err(|e| anyhow::anyhow!("forge build: {e}"))?;
		if !status.success() {
			return Err(anyhow::anyhow!("forge build failed in {solidity_dir:?}"));
		}
		info!("[4] forge build complete");
	}

	info!("All PrivTx batch artifacts ready → {}", root.display());
	Ok(())
}
