//! Shared test infrastructure for E2E real-proof tests.

#![allow(dead_code)]

use std::sync::Arc;

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
use tessera_e2e::{
	contract_bytecodes::{ACCEPT_BYTECODE, POSEIDON_BYTECODE, ROLLUP_BYTECODE, TOKEN_BYTECODE},
	prover_adapter::InProcessProver,
};
use tessera_server::{config::SequencerConfig, sequencer::Sequencer};

/// On-chain IMT depth for tests (2 slots × 8 leaves = 16; 32 - ceil(log2(16)) = 28;
/// kept at 23 to match the existing artifact batch size).
pub const TREE_DEPTH_VAL: u64 = 23;

/// Anvil's default first account private key.
pub const OPERATOR_KEY: &str =
	"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

sol! {
	#[sol(rpc)]
	interface IToyUSDT {
		function mint(address to, uint256 amount) external;
		function approve(address spender, uint256 amount) external returns (bool);
		function balanceOf(address account) external view returns (uint256);
	}
}

pub struct TestEnv {
	pub rollup: Address,
	pub token: Address,
	pub operator: Address,
	pub url: String,
	pub _anvil: AnvilInstance,
}

// ---------------------------------------------------------------------------
// Deployment helpers
// ---------------------------------------------------------------------------

pub async fn deploy_no_args<P: Provider + Clone>(provider: &P, bytecode_hex: &str) -> Address {
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

pub async fn deploy_with_args<P: Provider + Clone>(
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
// Environment setup variants
// ---------------------------------------------------------------------------

/// Spawn Anvil and deploy all contracts with `AcceptAllVerifier` for both
/// TX and deposit verifiers.
pub async fn setup_env(pool_config_root: [u8; 32]) -> (TestEnv, impl Provider + Clone) {
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
		TestEnv { rollup: rollup_addr, token: token_addr, operator, url, _anvil: anvil },
		provider,
	)
}

/// Like [`setup_env`] but deploys the real `VerifierSuperAggregatorV2` for
/// both TX and deposit verifiers.
pub async fn setup_env_real_verifier(
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
		TestEnv { rollup: rollup_addr, token: token_addr, operator, url, _anvil: anvil },
		provider,
	)
}

/// Like [`setup_env`] but deploys `AcceptAllVerifier` for TX and the real
/// `VerifierDepositSuperAggregatorV2` for deposits.
pub async fn setup_env_real_deposit_verifier(
	pool_config_root: [u8; 32],
	deposit_verifier_bytecode_hex: &str,
) -> (TestEnv, impl Provider + Clone) {
	let anvil = Anvil::new().try_spawn().expect("anvil spawn");
	let url = anvil.endpoint_url().to_string();
	let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
	let operator = signer.address();
	let wallet = EthereumWallet::from(signer);
	let provider = ProviderBuilder::new()
		.wallet(wallet)
		.connect_http(anvil.endpoint_url());

	let accept_addr = deploy_no_args(&provider, ACCEPT_BYTECODE).await;
	let deposit_verifier_addr = deploy_no_args(&provider, deposit_verifier_bytecode_hex).await;
	let poseidon_addr = deploy_no_args(&provider, POSEIDON_BYTECODE).await;
	let token_addr = deploy_no_args(&provider, TOKEN_BYTECODE).await;

	let constructor_args = (
		accept_addr,           // txVerifier — AcceptAll
		deposit_verifier_addr, // depositVerifier — real Groth16
		poseidon_addr,
		operator,
		token_addr,
		B256::from(pool_config_root),
		U256::from(TREE_DEPTH_VAL),
	)
		.abi_encode();

	let rollup_addr = deploy_with_args(&provider, ROLLUP_BYTECODE, constructor_args).await;

	(
		TestEnv { rollup: rollup_addr, token: token_addr, operator, url, _anvil: anvil },
		provider,
	)
}

// ---------------------------------------------------------------------------
// Sequencer
// ---------------------------------------------------------------------------

/// Spin up the sequencer with an in-process prover and return handle + join handle.
pub fn start_sequencer(
	env: &TestEnv,
	prover: Arc<InProcessProver>,
) -> (tessera_server::sequencer::SequencerHandle, tokio::task::JoinHandle<()>) {
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

// ---------------------------------------------------------------------------
// Artifact loaders
// ---------------------------------------------------------------------------

/// Load the in-process prover from `TESSERA_ARTIFACTS_DIR`, or return `None` to skip.
pub fn try_load_prover() -> Option<Arc<InProcessProver>> {
	let dir = std::env::var("TESSERA_ARTIFACTS_DIR").ok()?;
	let path = std::path::PathBuf::from(&dir);
	InProcessProver::from_artifacts(&path).map(Arc::new)
}

/// Load the `VerifierSuperAggregatorV2` deployment bytecode from the Foundry
/// `out/` directory (`$TESSERA_FOUNDRY_OUT` or `<workspace>/tessera-solidity/out`).
/// Returns `None` if the compiled JSON is absent or its `bytecode.object` is empty.
pub fn try_load_verifier_bytecode() -> Option<String> {
	let out_dir = if let Ok(dir) = std::env::var("TESSERA_FOUNDRY_OUT") {
		std::path::PathBuf::from(dir)
	} else {
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
	if hex.is_empty() { None } else { Some(hex.to_string()) }
}

/// Load the `VerifierDepositSuperAggregatorV2` deployment bytecode from the Foundry
/// `out/` directory. Returns `None` if the compiled JSON is absent or empty.
pub fn try_load_deposit_verifier_bytecode() -> Option<String> {
	let out_dir = if let Ok(dir) = std::env::var("TESSERA_FOUNDRY_OUT") {
		std::path::PathBuf::from(dir)
	} else {
		let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
		manifest.parent()?.join("tessera-solidity/out")
	};
	let json_path = out_dir
		.join("VerifierDepositSuperAggregatorV2.sol")
		.join("VerifierDepositSuperAggregatorV2.json");
	let content = std::fs::read_to_string(&json_path).ok()?;
	let json: serde_json::Value = serde_json::from_str(&content).ok()?;
	let hex = json["bytecode"]["object"].as_str()?;
	let hex = hex.strip_prefix("0x").unwrap_or(hex);
	if hex.is_empty() { None } else { Some(hex.to_string()) }
}

// ---------------------------------------------------------------------------
// Macros
// ---------------------------------------------------------------------------

/// Return an error (shown as `FAILED`) when a prerequisite is not met.
/// Using `Err` (rather than silently passing) ensures skipped tests are visible.
macro_rules! skip {
	($reason:expr) => {
		return Err(format!("prerequisite not met: {}", $reason))
	};
}
