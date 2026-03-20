//! E2E test: FreshAcc followed by a dummy Spend TX, both proved with real
//! Plonky2 PrivTx proofs and sequenced through the full aggregation pipeline.

#[macro_use]
mod common;

use std::time::Duration;

use alloy::primitives::U256;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use tessera_e2e::client_state::{hash_output_to_bytes32, TesseraClientState};
use tessera_server::contract::ITesseraRollupV2;

#[tokio::test]
async fn test_e2e_spend_real_proof() -> Result<(), String> {
	let _ = tracing_subscriber::fmt().with_test_writer().try_init();

	let prover = match common::try_load_prover() {
		Some(p) => p,
		None => skip!("TESSERA_ARTIFACTS_DIR not set or artifacts absent"),
	};

	let mut rng = ChaCha8Rng::seed_from_u64(43);
	let mut client = TesseraClientState::new(&mut rng, 0);
	let pool_config_root = hash_output_to_bytes32(&client.pool_config.root().0);

	let (env, provider) = common::setup_env(pool_config_root).await;
	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(env.rollup, &provider);

	let freshacc = client.prove_freshacc(&mut rng).expect("freshacc prove");

	client.insert_account_commitment().expect("insert_account_commitment");

	let spend = client.prove_spend_dummy(&mut rng).expect("spend prove");

	let (handle, _jh) = common::start_sequencer(&env, prover);
	tokio::time::sleep(Duration::from_secs(2)).await;

	handle
		.submit_private_tx(
			Some("freshacc-2".into()),
			freshacc.an,
			freshacc.ac,
			freshacc.nn.to_vec(),
			freshacc.nc.to_vec(),
			freshacc.proof_bytes,
		)
		.await
		.expect("submit freshacc");

	handle
		.submit_private_tx(
			Some("spend-2".into()),
			spend.an,
			spend.ac,
			spend.nn.to_vec(),
			spend.nc.to_vec(),
			spend.proof_bytes,
		)
		.await
		.expect("submit spend");

	let mut confirmed = false;
	for _ in 0..120 {
		tokio::time::sleep(Duration::from_secs(2)).await;
		let root = rollup.currentRoot().call().await.expect("currentRoot");
		if root != U256::ZERO {
			confirmed = true;
			break;
		}
	}
	assert!(confirmed, "batch not confirmed within timeout");
	Ok(())
}
