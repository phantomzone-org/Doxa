//! E2E tests with real Plonky2 proofs.
//!
//! Tests:
//! 1. `test_e2e_freshacc_real_proof`   — FreshAcc TX with real Plonky2 proof.
//! 2. `test_e2e_spend_real_proof`      — Spend TX with real Plonky2 proof.
//! 3. `test_e2e_deposit_real_proof`    — Deposit lifecycle with real SAV2 proof.
//! 4. `test_e2e_freshacc_groth16`      — FreshAcc TX validated by real on-chain Groth16 verifier.
//!
//! Every test skips automatically when TESSERA_ARTIFACTS_DIR is not set or the
//! directories are absent.  Test 4 additionally requires the Foundry `out/` directory
//! to contain a compiled `VerifierSuperAggregatorV2` (run `forge build` after the
//! artifact binary generates `VerifierSuperAggregatorV2.sol`).

use std::{sync::Arc, time::Duration};

use alloy::{
	network::{EthereumWallet, TransactionBuilder},
	node_bindings::{Anvil, AnvilInstance},
	primitives::{Address, Bytes, B256, U256},
	providers::{Provider, ProviderBuilder},
	rpc::types::TransactionRequest,
	signers::local::PrivateKeySigner,
	sol,
	sol_types::SolValue,
};
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha8Rng;
use tessera_e2e::{
	client_state::{hash_output_to_bytes32, TesseraClientState},
	contract_bytecodes::{ACCEPT_BYTECODE, POSEIDON_BYTECODE, ROLLUP_BYTECODE, TOKEN_BYTECODE},
	prover_adapter::InProcessProver,
};
use tessera_server::{config::SequencerConfig, contract::ITesseraRollupV2, sequencer::Sequencer};

/// Account batch size for tests (2 slots × 8 notes = 16 NC leaves).
/// On-chain IMT depth (must match deployment): 32 - ceil(log2(2*8)) = 32 - 4 = 28.
const TREE_DEPTH_VAL: u64 = 23;
/// Anvil's default first account private key.
const OPERATOR_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

// ---------------------------------------------------------------------------
// sol! bindings (minimal ToyUSDT)
// ---------------------------------------------------------------------------

sol! {
	#[sol(rpc)]
	interface IToyUSDT {
		function mint(address to, uint256 amount) external;
		function approve(address spender, uint256 amount) external returns (bool);
		function balanceOf(address account) external view returns (uint256);
	}
}

// ---------------------------------------------------------------------------
// Deployment helpers
// ---------------------------------------------------------------------------

async fn deploy_no_args<P: Provider + Clone>(provider: &P, bytecode_hex: &str) -> Address {
	let bytecode = Bytes::from(hex::decode(bytecode_hex).expect("hex decode"));
	let tx = TransactionRequest::default().with_deploy_code(bytecode);
	provider
		.send_transaction(tx)
		.await
		.expect("deploy_no_args send")
		.get_receipt()
		.await
		.expect("deploy_no_args receipt")
		.contract_address
		.expect("no contract_address in receipt")
}

async fn deploy_with_args<P: Provider + Clone>(
	provider: &P,
	bytecode_hex: &str,
	constructor_args: Vec<u8>,
) -> Address {
	let mut bytecode = hex::decode(bytecode_hex).expect("hex decode");
	bytecode.extend_from_slice(&constructor_args);
	let tx = TransactionRequest::default().with_deploy_code(Bytes::from(bytecode));
	provider
		.send_transaction(tx)
		.await
		.expect("deploy_with_args send")
		.get_receipt()
		.await
		.expect("deploy_with_args receipt")
		.contract_address
		.expect("no contract_address in receipt")
}

// ---------------------------------------------------------------------------
// Test environment
// ---------------------------------------------------------------------------

struct TestEnv {
	rollup: Address,
	token: Address,
	operator: Address,
	url: String,
	_anvil: AnvilInstance,
}

/// Spawn Anvil, deploy all contracts, return environment + provider.
async fn setup_env(pool_config_root: [u8; 32]) -> (TestEnv, impl Provider + Clone) {
	let anvil = Anvil::new().try_spawn().expect("anvil spawn");
	let url = anvil.endpoint_url().to_string();
	let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
	let operator = signer.address();
	let wallet = EthereumWallet::from(signer);
	let provider = ProviderBuilder::new()
		.wallet(wallet)
		.connect_http(anvil.endpoint_url());

	let accept_addr = deploy_no_args(&provider, ACCEPT_BYTECODE).await;
	let poseidon_addr = deploy_no_args(&provider, POSEIDON_BYTECODE).await;
	let token_addr = deploy_no_args(&provider, TOKEN_BYTECODE).await;

	// TesseraRollupV2 constructor:
	//   (address txVerifier, address depositVerifier, address poseidon,
	//    address operator, address monitoredToken, bytes32 poolConfigRoot, uint256 treeDepth)
	let constructor_args = (
		accept_addr, // txVerifier (AcceptAll)
		accept_addr, // depositVerifier (AcceptAll)
		poseidon_addr,
		operator,
		token_addr,
		B256::from(pool_config_root),
		U256::from(TREE_DEPTH_VAL),
	)
		.abi_encode();

	let rollup_addr = deploy_with_args(&provider, ROLLUP_BYTECODE, constructor_args).await;

	(
		TestEnv {
			rollup: rollup_addr,
			token: token_addr,
			operator,
			url,
			_anvil: anvil,
		},
		provider,
	)
}

/// Spin up the sequencer with an in-process prover and return handle + join handle.
fn start_sequencer(
	env: &TestEnv,
	prover: Arc<InProcessProver>,
) -> (
	tessera_server::sequencer::SequencerHandle,
	tokio::task::JoinHandle<()>,
) {
	let config = SequencerConfig {
		rpc_url: env.url.clone(),
		operator_private_key: OPERATOR_KEY.into(),
		bridge_address: env.rollup,
		chain_id: 31337,
		poll_interval_secs: 1,
		batch_timeout_secs: 2,
		tree_store_path: std::env::temp_dir().join("tessera-e2e-trees"),
		snapshot_every_batches: 1,
		prover_api_url: "http://unused".into(),
		prover_api_timeout_secs: 3600,
		testing: false,
	};

	let (mut sequencer, handle) = Sequencer::new_with_prover(config, prover);
	let jh = tokio::spawn(async move {
		if let Err(e) = sequencer.run().await {
			eprintln!("sequencer error: {e}");
		}
	});
	(handle, jh)
}

/// Load the in-process prover from TESSERA_ARTIFACTS_DIR, or return None to skip.
fn try_load_prover() -> Option<Arc<InProcessProver>> {
	let dir = std::env::var("TESSERA_ARTIFACTS_DIR").ok()?;
	let path = std::path::PathBuf::from(&dir);
	InProcessProver::from_artifacts(&path).map(Arc::new)
}

// ---------------------------------------------------------------------------
// Test 1: FreshAcc with real Plonky2 proof, full sequencer pipeline
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_freshacc_real_proof() {
	let _ = tracing_subscriber::fmt().with_test_writer().try_init();

	let prover = match try_load_prover() {
		Some(p) => p,
		None => {
			eprintln!("TESSERA_ARTIFACTS_DIR not set or artifacts absent – skipping");
			return;
		},
	};

	let mut rng = ChaCha8Rng::seed_from_u64(42);
	let mut client = TesseraClientState::new(&mut rng, 0);
	let pool_config_root = hash_output_to_bytes32(&client.pool_config.root().0);

	let (env, provider) = setup_env(pool_config_root).await;
	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(env.rollup, &provider);

	// Prove FreshAcc.
	let proven = client
		.prove_freshacc(&mut rng)
		.expect("FreshAcc prove failed");

	// Start sequencer.
	let (handle, _jh) = start_sequencer(&env, prover);
	tokio::time::sleep(Duration::from_secs(2)).await;

	// Submit the proven FreshAcc TX.
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

	// Wait for the batch to be confirmed (root advances from zero).
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
	let is_confirmed = rollup
		.confirmedRoots(root)
		.call()
		.await
		.expect("confirmedRoots");
	assert!(
		is_confirmed,
		"currentRoot not in confirmedRoots after proof"
	);
}

// ---------------------------------------------------------------------------
// Test 2: FreshAcc + Spend dummy TX pipeline
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_spend_real_proof() {
	let _ = tracing_subscriber::fmt().with_test_writer().try_init();

	let prover = match try_load_prover() {
		Some(p) => p,
		None => {
			eprintln!("TESSERA_ARTIFACTS_DIR not set or artifacts absent – skipping");
			return;
		},
	};

	let mut rng = ChaCha8Rng::seed_from_u64(43);
	let mut client = TesseraClientState::new(&mut rng, 0);
	let pool_config_root = hash_output_to_bytes32(&client.pool_config.root().0);

	let (env, provider) = setup_env(pool_config_root).await;
	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(env.rollup, &provider);

	// Prove FreshAcc.
	let freshacc = client.prove_freshacc(&mut rng).expect("freshacc prove");

	// Insert account commitment before proving spend.
	client
		.insert_account_commitment()
		.expect("insert_account_commitment");

	// Prove Spend (dummy – no active notes).
	let spend = client.prove_spend_dummy(&mut rng).expect("spend prove");

	let (handle, _jh) = start_sequencer(&env, prover);
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
}

// ---------------------------------------------------------------------------
// Test 3: Deposit lifecycle with real SAV2 proof
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_deposit_real_proof() {
	let _ = tracing_subscriber::fmt().with_test_writer().try_init();

	let prover = match try_load_prover() {
		Some(p) => p,
		None => {
			eprintln!("TESSERA_ARTIFACTS_DIR not set or artifacts absent – skipping");
			return;
		},
	};

	let mut rng = ChaCha8Rng::seed_from_u64(44);
	let client = TesseraClientState::new(&mut rng, 0);
	let pool_config_root = hash_output_to_bytes32(&client.pool_config.root().0);

	let (env, provider) = setup_env(pool_config_root).await;
	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(env.rollup, &provider);
	let token = IToyUSDT::IToyUSDTInstance::new(env.token, &provider);

	// Mint tokens and approve the rollup.
	let amount = U256::from(1_000u64);
	token
		.mint(env.operator, amount)
		.send()
		.await
		.expect("mint send")
		.get_receipt()
		.await
		.expect("mint receipt");
	token
		.approve(env.rollup, amount)
		.send()
		.await
		.expect("approve send")
		.get_receipt()
		.await
		.expect("approve receipt");

	// Use a fixed arbitrary note commitment (the sequencer only checks on-chain status).
	let note_commitment = {
		let bytes: [u64; 4] = [
			rng.random::<u64>(),
			rng.random::<u64>(),
			rng.random::<u64>(),
			rng.random::<u64>(),
		];
		let mut out = [0u8; 32];
		for (i, &v) in bytes.iter().enumerate() {
			out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_be_bytes());
		}
		out
	};

	// Deposit on-chain.
	rollup
		.depositAndRegister(B256::from(note_commitment), amount)
		.send()
		.await
		.expect("depositAndRegister send")
		.get_receipt()
		.await
		.expect("depositAndRegister receipt");

	// Start sequencer and submit deposit.
	let (handle, _jh) = start_sequencer(&env, prover);
	tokio::time::sleep(Duration::from_secs(2)).await;

	handle
		.submit_deposit(note_commitment, None)
		.await
		.expect("submit_deposit");

	// Wait for deposit to be validated.
	let mut confirmed = false;
	for _ in 0..120 {
		tokio::time::sleep(Duration::from_secs(2)).await;
		let deposit = rollup
			.getDeposit(B256::from(note_commitment))
			.call()
			.await
			.expect("getDeposit");
		if matches!(deposit.status, ITesseraRollupV2::DepositStatus::Validated) {
			confirmed = true;
			break;
		}
	}
	assert!(confirmed, "deposit not validated within timeout");
}

// ---------------------------------------------------------------------------
// Test 4: FreshAcc with real on-chain Groth16 verifier
// ---------------------------------------------------------------------------

/// Load the `VerifierSuperAggregatorV2` deployment bytecode from the Foundry
/// `out/` directory.
///
/// Looks first at `$TESSERA_FOUNDRY_OUT`, then falls back to
/// `<workspace-root>/tessera-solidity/out`.  Returns `None` if the compiled
/// JSON is absent or its `bytecode.object` field is empty (placeholder).
fn try_load_verifier_bytecode() -> Option<String> {
	let out_dir = if let Ok(dir) = std::env::var("TESSERA_FOUNDRY_OUT") {
		std::path::PathBuf::from(dir)
	} else {
		// CARGO_MANIFEST_DIR is tessera-e2e/; parent is workspace root.
		let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
		manifest.parent()?.join("tessera-solidity/out")
	};

	let json_path = out_dir
		.join("VerifierSuperAggregatorV2.sol")
		.join("VerifierSuperAggregatorV2.json");

	let content = std::fs::read_to_string(&json_path).ok()?;
	let json: serde_json::Value = serde_json::from_str(&content).ok()?;
	let hex = json["bytecode"]["object"].as_str()?;
	let hex = hex.strip_prefix("0x").unwrap_or(hex);
	if hex.is_empty() {
		return None;
	}
	Some(hex.to_string())
}

/// Like [`setup_env`] but deploys the real `VerifierSuperAggregatorV2` instead
/// of `AcceptAllVerifier`.
async fn setup_env_real_verifier(
	pool_config_root: [u8; 32],
	verifier_bytecode_hex: &str,
) -> (TestEnv, impl Provider + Clone) {
	let anvil = Anvil::new().try_spawn().expect("anvil spawn");
	let url = anvil.endpoint_url().to_string();
	let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
	let operator = signer.address();
	let wallet = EthereumWallet::from(signer);
	let provider = ProviderBuilder::new()
		.wallet(wallet)
		.connect_http(anvil.endpoint_url());

	let verifier_addr = deploy_no_args(&provider, verifier_bytecode_hex).await;
	let poseidon_addr = deploy_no_args(&provider, POSEIDON_BYTECODE).await;
	let token_addr = deploy_no_args(&provider, TOKEN_BYTECODE).await;

	let constructor_args = (
		verifier_addr, // txVerifier — real Groth16
		verifier_addr, // depositVerifier — same circuit
		poseidon_addr,
		operator,
		token_addr,
		B256::from(pool_config_root),
		U256::from(TREE_DEPTH_VAL),
	)
		.abi_encode();

	let rollup_addr = deploy_with_args(&provider, ROLLUP_BYTECODE, constructor_args).await;

	(
		TestEnv {
			rollup: rollup_addr,
			token: token_addr,
			operator,
			url,
			_anvil: anvil,
		},
		provider,
	)
}

/// Full Groth16 E2E: prove FreshAcc → sequence → verify on-chain with the real
/// `VerifierSuperAggregatorV2` contract (no AcceptAllVerifier shortcut).
///
/// Skips when:
/// - `TESSERA_ARTIFACTS_DIR` is absent or incomplete (prover not available), or
/// - the Foundry `out/` directory has no compiled `VerifierSuperAggregatorV2`
///   (run `forge build` in `tessera-solidity/` after the artifact binary).
#[tokio::test]
async fn test_e2e_freshacc_groth16() {
	let _ = tracing_subscriber::fmt().with_test_writer().try_init();

	let prover = match try_load_prover() {
		Some(p) => p,
		None => {
			eprintln!("TESSERA_ARTIFACTS_DIR not set or artifacts absent – skipping");
			return;
		},
	};

	let verifier_bytecode = match try_load_verifier_bytecode() {
		Some(b) => b,
		None => {
			eprintln!(
				"VerifierSuperAggregatorV2 bytecode not found in Foundry out/ – skipping \
				 (run `forge build` in tessera-solidity/ after the artifact binary)"
			);
			return;
		},
	};

	let mut rng = ChaCha8Rng::seed_from_u64(45);
	let mut client = TesseraClientState::new(&mut rng, 0);
	let pool_config_root = hash_output_to_bytes32(&client.pool_config.root().0);

	let (env, provider) = setup_env_real_verifier(pool_config_root, &verifier_bytecode).await;
	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(env.rollup, &provider);

	// Prove FreshAcc with a real Plonky2 PrivTx proof.
	let proven = client
		.prove_freshacc(&mut rng)
		.expect("FreshAcc prove failed");

	// Start sequencer (uses InProcessProver → full Groth16 pipeline).
	let (handle, _jh) = start_sequencer(&env, prover);
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

	// Poll until the on-chain root advances (Groth16 proof accepted by real verifier).
	let mut confirmed = false;
	for _ in 0..240 {
		tokio::time::sleep(Duration::from_secs(2)).await;
		let root = rollup.currentRoot().call().await.expect("currentRoot");
		if root != U256::ZERO {
			confirmed = true;
			break;
		}
	}
	assert!(
		confirmed,
		"batch was not confirmed by the real Groth16 verifier within timeout"
	);

	let root = rollup.currentRoot().call().await.expect("currentRoot");
	let is_confirmed = rollup
		.confirmedRoots(root)
		.call()
		.await
		.expect("confirmedRoots");
	assert!(
		is_confirmed,
		"currentRoot not in confirmedRoots after real Groth16 proof"
	);
}
