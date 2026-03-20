//! E2E test: FreshAcc TX proved end-to-end through the full Groth16 pipeline
//! and verified on-chain by the real `VerifierSuperAggregatorV2` contract.

#[macro_use]
mod common;

use std::time::Duration;

use alloy::primitives::U256;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use tessera_e2e::client_state::{hash_output_to_bytes32, TesseraClientState};
use tessera_server::contract::ITesseraRollupV2;

#[tokio::test]
async fn test_e2e_freshacc_groth16() -> Result<(), String> {
	let _ = tracing_subscriber::fmt().with_test_writer().try_init();

	let prover = match common::try_load_prover() {
		Some(p) => p,
		None => skip!("TESSERA_ARTIFACTS_DIR not set or artifacts absent"),
	};

	let verifier_bytecode = match common::try_load_verifier_bytecode() {
		Some(b) => b,
		None => skip!(
			"VerifierSuperAggregatorV2 bytecode not found in Foundry out/ \
			 (run `forge build` in tessera-solidity/ after the artifact binary)"
		),
	};

	let mut rng = ChaCha8Rng::seed_from_u64(45);
	let mut client = TesseraClientState::new(&mut rng, 0);
	let pool_config_root = hash_output_to_bytes32(&client.pool_config.root().0);

	let (env, provider) =
		common::setup_env_real_verifier(pool_config_root, &verifier_bytecode).await;
	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(env.rollup, &provider);

	let proven = client.prove_freshacc(&mut rng).expect("FreshAcc prove failed");

	let (handle, _jh) = common::start_sequencer(&env, prover);
	tokio::time::sleep(Duration::from_secs(2)).await;

	handle
		.submit_private_tx(
			Some("freshacc-groth16".into()),
			proven.an,
			proven.ac,
			proven.nn.to_vec(),
			proven.nc.to_vec(),
			proven.proof_bytes,
		)
		.await
		.expect("submit_private_tx");

	let mut confirmed = false;
	for _ in 0..240 {
		tokio::time::sleep(Duration::from_secs(2)).await;
		let root = rollup.currentRoot().call().await.expect("currentRoot");
		if root != U256::ZERO {
			confirmed = true;
			break;
		}
	}
	assert!(confirmed, "batch was not confirmed by the real Groth16 verifier within timeout");

	let root = rollup.currentRoot().call().await.expect("currentRoot");
	let is_confirmed =
		rollup.confirmedRoots(root).call().await.expect("confirmedRoots");
	assert!(is_confirmed, "currentRoot not in confirmedRoots after real Groth16 proof");
	Ok(())
}
