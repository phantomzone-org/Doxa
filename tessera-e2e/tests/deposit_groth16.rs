//! E2E test: Deposit lifecycle proved end-to-end through the full Groth16
//! pipeline and verified on-chain by the real `VerifierDepositSuperAggregatorV2`
//! contract.
//!
//! # Workflow
//!
//! ```text
//! Setup
//!   1. Spawn Anvil (local EVM)
//!   2. Deploy AcceptAllVerifier              (txVerifier — not exercised here)
//!   3. Deploy VerifierDepositSuperAggregatorV2 (real Groth16 deposit verifier)
//!   4. Deploy TesseraRollupV2(txVerifier=Accept, depositVerifier=real)
//!   5. Deploy ToyUSDT token
//!
//! On-chain deposit
//!   6.  token.mint(operator, 1000)
//!   7.  token.approve(rollup, 1000)
//!   8.  rollup.depositAndRegister(nc, 1000)  → status: Pending
//!
//! Sequencer + InProcessProver (full deposit pipeline)
//!   9.  Start sequencer (InProcessProver loads all deposit artifacts)
//!   10. handle.submit_deposit(nc)
//!       → GenericAggregator (deposit-tx-aggregator/)
//!       → SubtreeRootCircuit (deposit-subtree-root/)
//!       → DepositSuperAggregatorV2 Plonky2 proof
//!       → BN128 wrap → Groth16 prove
//!       → rollup.proveDepositBatch(proof, ...)
//!       → VerifierDepositSuperAggregatorV2 verifies on-chain
//!
//! Assert
//!   11. Poll for rollup.getDeposit(nc).status == Validated
//! ```

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
async fn test_e2e_deposit_groth16() -> Result<(), String> {
	let _ = tracing_subscriber::fmt().with_test_writer().try_init();

	let prover = match common::try_load_prover() {
		Some(p) => p,
		None => skip!("TESSERA_ARTIFACTS_DIR not set or artifacts absent"),
	};

	let deposit_verifier_bytecode = match common::try_load_deposit_verifier_bytecode() {
		Some(b) => b,
		None => skip!(
			"VerifierDepositSuperAggregatorV2 bytecode not found in Foundry out/ \
			 (run `forge build` in tessera-solidity/ after the deposit artifact binary)"
		),
	};

	let mut rng = ChaCha8Rng::seed_from_u64(46);
	let client = TesseraClientState::new(&mut rng, 0);
	let pool_config_root = hash_output_to_bytes32(&client.pool_config.root().0);

	let (env, provider) =
		common::setup_env_real_deposit_verifier(pool_config_root, &deposit_verifier_bytecode)
			.await;
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
	for _ in 0..240 {
		tokio::time::sleep(Duration::from_secs(2)).await;
		let deposit =
			rollup.getDeposit(B256::from(note_commitment)).call().await.expect("getDeposit");
		if matches!(deposit.status, ITesseraRollupV2::DepositStatus::Validated) {
			confirmed = true;
			break;
		}
	}
	assert!(confirmed, "deposit not validated by the real Groth16 verifier within timeout");
	Ok(())
}
