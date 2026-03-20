//! E2E test: FreshAcc TX proved with a real Plonky2 PrivTx proof, sequenced
//! through the full aggregation pipeline, validated on-chain via `AcceptAllVerifier`.

#[macro_use]
mod common;

use std::time::Duration;

use alloy::primitives::U256;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use tessera_e2e::client_state::{hash_output_to_bytes32, TesseraClientState};
use tessera_server::contract::ITesseraRollupV2;

#[tokio::test]
async fn test_e2e_freshacc_real_proof() -> Result<(), String> {
	let _ = tracing_subscriber::fmt().with_test_writer().try_init();

	let prover = match common::try_load_prover() {
		Some(p) => p,
		None => skip!("TESSERA_ARTIFACTS_DIR not set or artifacts absent"),
	};

	let mut rng = ChaCha8Rng::seed_from_u64(42);
	let mut client = TesseraClientState::new(&mut rng, 0);
	let pool_config_root = hash_output_to_bytes32(&client.pool_config.root().0);

	let (env, provider) = common::setup_env(pool_config_root).await;
	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(env.rollup, &provider);

	let proven = client.prove_freshacc(&mut rng).expect("FreshAcc prove failed");

	let (handle, _jh) = common::start_sequencer(&env, prover);
	tokio::time::sleep(Duration::from_secs(2)).await;

	handle
		.submit_private_tx(
			Some("freshacc-1".into()),
			proven.an,
			proven.ac,
			proven.nn.to_vec(),
			proven.nc.to_vec(),
			proven.proof_bytes,
		)
		.await
		.expect("submit_private_tx");

	let mut confirmed = false;
	for _ in 0..120 {
		tokio::time::sleep(Duration::from_secs(2)).await;
		let root = rollup.currentRoot().call().await.expect("currentRoot");
		if root != U256::ZERO {
			confirmed = true;
			break;
		}
	}
	assert!(confirmed, "batch was not confirmed within timeout");

	let root = rollup.currentRoot().call().await.expect("currentRoot");
	let is_confirmed =
		rollup.confirmedRoots(root).call().await.expect("confirmedRoots");
	assert!(is_confirmed, "currentRoot not in confirmedRoots after proof");
	Ok(())
}
