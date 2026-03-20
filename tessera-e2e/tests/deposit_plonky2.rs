//! E2E test: Deposit lifecycle — on-chain register → SAV2 Plonky2 proof →
//! `AcceptAllVerifier` on-chain validation.

#[macro_use]
mod common;

use std::time::Duration;

use alloy::primitives::{B256, U256};
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;
use tessera_e2e::client_state::{hash_output_to_bytes32, TesseraClientState};
use tessera_server::contract::ITesseraRollupV2;

use common::IToyUSDT;

#[tokio::test]
async fn test_e2e_deposit_real_proof() -> Result<(), String> {
	let _ = tracing_subscriber::fmt().with_test_writer().try_init();

	let prover = match common::try_load_prover() {
		Some(p) => p,
		None => skip!("TESSERA_ARTIFACTS_DIR not set or artifacts absent"),
	};

	let mut rng = ChaCha8Rng::seed_from_u64(44);
	let client = TesseraClientState::new(&mut rng, 0);
	let pool_config_root = hash_output_to_bytes32(&client.pool_config.root().0);

	let (env, provider) = common::setup_env(pool_config_root).await;
	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(env.rollup, &provider);
	let token = IToyUSDT::IToyUSDTInstance::new(env.token, &provider);

	let amount = U256::from(1_000u64);
	token.mint(env.operator, amount).send().await.expect("mint send").get_receipt().await.expect("mint receipt");
	token.approve(env.rollup, amount).send().await.expect("approve send").get_receipt().await.expect("approve receipt");

	let note_commitment = {
		let bytes: [u64; 4] =
			[rng.random(), rng.random(), rng.random(), rng.random()];
		let mut out = [0u8; 32];
		for (i, &v) in bytes.iter().enumerate() {
			out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_be_bytes());
		}
		out
	};

	rollup
		.depositAndRegister(B256::from(note_commitment), amount)
		.send()
		.await
		.expect("depositAndRegister send")
		.get_receipt()
		.await
		.expect("depositAndRegister receipt");

	let (handle, _jh) = common::start_sequencer(&env, prover);
	tokio::time::sleep(Duration::from_secs(2)).await;

	handle.submit_deposit(note_commitment, None).await.expect("submit_deposit");

	let mut confirmed = false;
	for _ in 0..120 {
		tokio::time::sleep(Duration::from_secs(2)).await;
		let deposit =
			rollup.getDeposit(B256::from(note_commitment)).call().await.expect("getDeposit");
		if matches!(deposit.status, ITesseraRollupV2::DepositStatus::Validated) {
			confirmed = true;
			break;
		}
	}
	assert!(confirmed, "deposit not validated within timeout");
	Ok(())
}
