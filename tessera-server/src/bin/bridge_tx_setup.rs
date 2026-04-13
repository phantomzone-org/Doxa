//! Generate and store **all** artifacts needed for BridgeTx batch proving.
//!
//! Runs the full pipeline once and writes everything to a single root directory:
//!
//! ```text
//! <TESSERA_BRIDGE_TX_ARTIFACTS_PATH>/
//! ├── pair-agg/         ← Pair GenericAggregator (arity=4, depth=4, 256 (W,D) pair slots)
//! │   └── pair-leaf/    ← PairLeaf circuit data + inner W/D circuit data
//! ├── subtree-root/     ← SubtreeRootCircuit (512 leaves)
//! ├── super-circuit/    ← BridgeTxSuperCircuit
//! ├── plonky2-proof/    ← BN128Wrapper circuit data (JSON + .bin)
//! └── groth-artifacts/  ← Groth16 proving key, verifying key, r1cs
//! ```
//!
//! ## Usage
//!
//! ```bash
//! TESSERA_BRIDGE_TX_ARTIFACTS_PATH=artifacts/bridge-tx \
//!     cargo run --bin bridge_tx_setup --release
//! ```
//!
//! Re-running is idempotent: each stage is skipped when its artifacts are
//! already present.

use std::{fs, path::PathBuf, time::Instant};

use anyhow::Result;
use tessera_client::{TesseraGateSerializer, build_deposit_tx_circuit, build_withdraw_tx_circuit};
use tessera_server::aggregator_service::BridgeTxAggregator;
use tessera_utils::groth::{BN128Wrapper, Groth16Wrapper};
use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
	tracing_subscriber::fmt()
		.with_env_filter(
			EnvFilter::try_from_default_env()
				.unwrap_or_else(|_| EnvFilter::new("info")),
		)
		.init();

	let root: PathBuf = std::env::var("TESSERA_BRIDGE_TX_ARTIFACTS_PATH")
		.map(PathBuf::from)
		.unwrap_or_else(|_| PathBuf::from("artifacts/bridge-tx"));

	let plonky2_path = root.join("plonky2-proof");
	let groth_path = root.join("groth-artifacts");

	info!("BridgeTx artifact root: {}", root.display());

	// =========================================================================
	// 1. Build or reload the BridgeTxAggregator
	// =========================================================================
	let agg = if BridgeTxAggregator::has_full_artifacts(&root)? {
		info!("[1] Aggregator artifacts found — loading from disk");
		BridgeTxAggregator::from_artifacts(
			&root,
			&TesseraGateSerializer,
			&TesseraGateSerializer,
		)?
	} else {
		info!("[1] Building BridgeTxAggregator (pair-based, arity=4, depth=4, 256 W+D pairs) …");
		let now = Instant::now();
		let w = build_withdraw_tx_circuit();
		let d = build_deposit_tx_circuit();
		let agg = BridgeTxAggregator::build(
			w.circuit_data.common.clone(),
			w.circuit_data.verifier_only.clone(),
			d.circuit_data.common.clone(),
			d.circuit_data.verifier_only.clone(),
		)?;
		info!("    built in {:.1?}", now.elapsed());

		info!("[1] Storing aggregator artifacts → {}", root.display());
		fs::create_dir_all(&root)?;
		agg.store_artifacts(&root, &TesseraGateSerializer, &TesseraGateSerializer)?;
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

	info!("All BridgeTx batch artifacts ready → {}", root.display());
	Ok(())
}
