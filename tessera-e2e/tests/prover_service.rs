//! Integration tests for [`ProverService`].
//!
//! Each test deploys `TesseraContract` on a local Anvil node backed by the
//! `AcceptAllVerifier` stub, starts a [`StateService`] (so that the genesis
//! root is in the confirmed-root set), and drives the full batch-proving
//! pipeline via [`ProverServiceHandle`].
//!
//! # What is tested
//!
//! - A single TX submitted via the handle results in a `ProveOutcome::Success` being emitted (after
//!   the batch-timeout flush).
//! - A full batch (64 slots) flushes immediately without waiting for the timeout.
//! - The timeout flush triggers when the batch is non-empty but not yet full.
//! - A TX carrying an unconfirmed root is silently rejected (no outcome).
//! - A TX whose account nullifier is already spent (on-chain) is rejected.
//! - A single deposit results in a `ProveOutcome::Success`.
//! - A few deposits trigger a flush after the batch timeout.
//! - A deposit with an unconfirmed root is silently rejected.

#[macro_use]
mod common;

use std::time::Duration;

use alloy::{
	network::EthereumWallet,
	node_bindings::{Anvil, AnvilInstance},
	primitives::{Address, B256, U256},
	providers::{Provider, ProviderBuilder},
	signers::local::PrivateKeySigner,
	sol_types::SolValue,
};
use plonky2::field::types::Field;
use tessera_client::NOTE_BATCH;
use tessera_e2e::contract_bytecodes::{
	ACCEPT_ALL_BYTECODE, POSEIDON_BYTECODE, ROLLUP_BYTECODE, TOKEN_BYTECODE,
};
use tessera_server::{
	contract::{self, ITesseraRollupV2},
	prover_service::{
		Deposit, MockBridgeTxAggregator, MockTxAggregator, ProverService, ProverServiceConfig,
		ProverServiceHandle, SubmitTxRequest,
	},
	state_service::{StateService, StateServiceConfig, StateServiceHandle},
	types::ProveOutcome,
};
use tessera_utils::hasher::HashOutput;

// ---------------------------------------------------------------------------
// Minimal ERC-20 interface for minting and approving
// ---------------------------------------------------------------------------

alloy::sol! {
	#[sol(rpc)]
	interface IToyUSDT {
		function mint(address to, uint256 amount) external;
		function approve(address spender, uint256 amount) external returns (bool);
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

mod helpers {
	use super::*;

	// -----------------------------------------------------------------------
	// Test context
	// -----------------------------------------------------------------------

	/// Shared test context holding Anvil process and deployed addresses.
	pub struct TestCtx {
		/// Keeps the Anvil process alive for the lifetime of the test.
		pub _anvil: AnvilInstance,
		/// JSON-RPC endpoint URL.
		pub url: String,
		/// Hex-encoded operator private key.
		pub operator_key: String,
		/// Deployed rollup contract address.
		pub rollup_addr: Address,
		/// Deployed ERC-20 token address.
		pub token_addr: Address,
	}

	// -----------------------------------------------------------------------
	// Setup
	// -----------------------------------------------------------------------

	/// Spawn Anvil and deploy the full contract stack backed by
	/// `AcceptAllVerifier`.  Returns the test context and a concrete provider.
	pub async fn setup_impl() -> (TestCtx, impl Provider + Clone) {
		let anvil = Anvil::new().try_spawn().expect("anvil spawn");
		let url = anvil.endpoint_url().to_string();

		let operator_key_bytes = anvil.keys()[0].to_bytes();
		let operator_key = format!("0x{}", hex::encode(operator_key_bytes));

		let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
		let wallet = EthereumWallet::from(signer);
		let provider = ProviderBuilder::new()
			.wallet(wallet)
			.connect_http(anvil.endpoint_url());

		let verifier_addr = common::deploy_no_args(&provider, ACCEPT_ALL_BYTECODE).await;
		let poseidon_addr = common::deploy_no_args(&provider, POSEIDON_BYTECODE).await;
		let token_addr = common::deploy_no_args(&provider, TOKEN_BYTECODE).await;

		let operator = provider.get_accounts().await.expect("eth_accounts")[0];

		let constructor_args = (
			verifier_addr,
			verifier_addr,
			poseidon_addr,
			operator,
			token_addr,
			B256::ZERO,
			U256::from(32_u64),
		)
			.abi_encode();

		let rollup_addr =
			common::deploy_with_args(&provider, ROLLUP_BYTECODE, constructor_args).await;

		let ctx = TestCtx {
			_anvil: anvil,
			url: url.clone(),
			operator_key,
			rollup_addr,
			token_addr,
		};
		(ctx, provider)
	}

	// -----------------------------------------------------------------------
	// Service lifecycle
	// -----------------------------------------------------------------------

	/// Spawn a [`StateService`] in a background task and return its handle.
	pub fn start_state_service(
		url: String,
		rollup_addr: Address,
	) -> (tokio::task::JoinHandle<()>, StateServiceHandle) {
		let config = StateServiceConfig {
			rpc_url: url,
			bridge_address: rollup_addr,
			chain_id: 31337,
			poll_interval_secs: 1,
			log_chunk_blocks: 1_000,
		};
		let (mut svc, handle) = StateService::new(config);
		let jh = tokio::spawn(async move {
			if let Err(e) = svc.run().await {
				eprintln!("StateService error: {e}");
			}
		});
		(jh, handle)
	}

	/// Spawn a [`ProverService`] with the given batch timeout and return its handle.
	pub fn start_prover_service(
		url: String,
		rollup_addr: Address,
		operator_key: String,
		state_handle: StateServiceHandle,
		batch_timeout_secs: u64,
	) -> (tokio::task::JoinHandle<()>, ProverServiceHandle) {
		let config = ProverServiceConfig {
			rpc_url: url,
			bridge_address: rollup_addr,
			operator_private_key: operator_key,
			chain_id: 31337,
			batch_timeout_secs,
		};
		let (mut svc, handle) = ProverService::new(
			config,
			state_handle,
			MockTxAggregator,
			MockBridgeTxAggregator,
		);
		let jh = tokio::spawn(async move {
			if let Err(e) = svc.run().await {
				eprintln!("ProverService error: {e}");
			}
		});
		(jh, handle)
	}

	// -----------------------------------------------------------------------
	// TX construction helpers
	// -----------------------------------------------------------------------

	/// Build a valid [`SubmitTxRequest`] with deterministic leaves derived from
	/// `seed`.
	pub fn make_tx_request(seed: u8, root: HashOutput) -> SubmitTxRequest {
		let mut ac = [0u8; 32];
		ac[0] = 0x10;
		ac[1] = seed;

		let mut an = [0u8; 32];
		an[0] = 0x20;
		an[1] = seed;

		let nc: [[u8; 32]; NOTE_BATCH] = std::array::from_fn(|i| {
			let mut b = [0u8; 32];
			b[0] = 0x30;
			b[1] = seed;
			b[2] = i as u8;
			b
		});

		let nn: [[u8; 32]; NOTE_BATCH] = std::array::from_fn(|i| {
			let mut b = [0u8; 32];
			b[0] = 0x40;
			b[1] = seed;
			b[2] = i as u8;
			b
		});

		SubmitTxRequest {
			ac,
			an,
			nc,
			nn,
			tx_proof: vec![0u8; 1],
			root,
		}
	}

	// -----------------------------------------------------------------------
	// Deposit construction helpers
	// -----------------------------------------------------------------------

	/// Register a deposit on-chain (mint token → approve → depositAndRegister)
	/// and return the NC as `[u8; 32]`.
	pub async fn register_deposit<P: Provider + Clone>(
		provider: &P,
		rollup_addr: Address,
		token_addr: Address,
		nc: [u8; 32],
	) {
		let operator = provider.get_accounts().await.expect("eth_accounts")[0];
		let token = IToyUSDT::new(token_addr, provider);
		let amount = U256::from(1_000_000_u64);
		token
			.mint(operator, amount)
			.send()
			.await
			.expect("mint send")
			.get_receipt()
			.await
			.expect("mint receipt");
		token
			.approve(rollup_addr, amount)
			.send()
			.await
			.expect("approve send")
			.get_receipt()
			.await
			.expect("approve receipt");

		let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(rollup_addr, provider);
		rollup
			.depositAndRegister(nc.into(), amount)
			.send()
			.await
			.expect("depositAndRegister send")
			.get_receipt()
			.await
			.expect("depositAndRegister receipt");
	}

	/// Build a [`SubmitDepositRequest`] with a deterministic NC derived from `seed`.
	pub fn make_deposit_request(seed: u8, root: HashOutput) -> Deposit {
		let mut nc = [0u8; 32];
		nc[0] = 0xD0;
		nc[1] = seed;

		let mut eth_address = [0u8; 20];
		eth_address[0] = 0xAB;
		eth_address[1] = seed;

		Deposit {
			note_commitment: nc,
			eth_address,
			proof: vec![0u8; 1],
			root,
		}
	}

	// -----------------------------------------------------------------------
	// Synchronisation helpers
	// -----------------------------------------------------------------------

	/// Block until `state_handle.is_confirmed_root(root)` returns `true`, or
	/// panic on timeout.
	pub async fn wait_for_confirmed_root(
		state_handle: &StateServiceHandle,
		root: HashOutput,
		timeout: Duration,
	) {
		let deadline = tokio::time::Instant::now() + timeout;
		loop {
			match state_handle.is_confirmed_root(root).await {
				Ok(true) => return,
				Ok(false) => {},
				Err(e) => panic!("wait_for_confirmed_root: service error: {e}"),
			}
			if tokio::time::Instant::now() >= deadline {
				panic!("wait_for_confirmed_root: timed out after {timeout:?}");
			}
			tokio::time::sleep(Duration::from_millis(200)).await;
		}
	}

	/// Block until `state_handle.contains_nullifier(nullifier)` returns `true`,
	/// or panic on timeout.
	pub async fn wait_for_nullifier(
		state_handle: &StateServiceHandle,
		nullifier: [u8; 32],
		timeout: Duration,
	) {
		let deadline = tokio::time::Instant::now() + timeout;
		loop {
			match state_handle.contains_nullifier(nullifier).await {
				Ok(true) => return,
				Ok(false) => {},
				Err(e) => panic!("wait_for_nullifier: service error: {e}"),
			}
			if tokio::time::Instant::now() >= deadline {
				panic!("wait_for_nullifier: timed out after {timeout:?}");
			}
			tokio::time::sleep(Duration::from_millis(200)).await;
		}
	}

	/// Fetch the genesis root from the contract (= `currentRoot()` on a freshly
	/// deployed contract with no proven batches).
	pub async fn fetch_genesis_root<P: Provider + Clone>(
		provider: &P,
		rollup_addr: Address,
	) -> HashOutput {
		let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(rollup_addr, provider);
		let root_u256 = rollup.currentRoot().call().await.expect("currentRoot");
		contract::u256_le_to_hash(root_u256).expect("genesis root is valid Goldilocks hash")
	}

	/// Timeout for waiting for a [`ProveOutcome`] to arrive.
	pub const OUTCOME_TIMEOUT: Duration = Duration::from_secs(30);
	/// Timeout for waiting for StateService to sync a new confirmed root.
	pub const SYNC_TIMEOUT: Duration = Duration::from_secs(15);
}

// ---------------------------------------------------------------------------
// TX Tests
// ---------------------------------------------------------------------------

/// A single TX submitted via the handle produces a `ProveOutcome::Success`
/// after the batch-timeout flush.
#[tokio::test]
async fn single_tx_proven() {
	let (ctx, provider) = helpers::setup_impl().await;
	let genesis_root = helpers::fetch_genesis_root(&provider, ctx.rollup_addr).await;

	let (_ss_jh, state_handle) = helpers::start_state_service(ctx.url.clone(), ctx.rollup_addr);

	helpers::wait_for_confirmed_root(&state_handle, genesis_root, helpers::SYNC_TIMEOUT).await;

	let (_ps_jh, mut prover_handle) = helpers::start_prover_service(
		ctx.url.clone(),
		ctx.rollup_addr,
		ctx.operator_key.clone(),
		state_handle.clone(),
		2,
	);

	let req = helpers::make_tx_request(0, genesis_root);
	prover_handle.submit_tx(req).await.expect("submit_tx");

	let outcome = tokio::time::timeout(helpers::OUTCOME_TIMEOUT, prover_handle.next_tx_outcome())
		.await
		.expect("outcome did not arrive within timeout")
		.expect("next_tx_outcome error");

	assert!(
		matches!(
			outcome,
			ProveOutcome::Success {
				batch_id: 0,
				..
			}
		),
		"expected ProveOutcome::Success with batch_id=0, got: {outcome:?}"
	);
}

/// Submitting a full batch (64 TXs) causes an immediate flush without waiting
/// for the batch timeout.
#[tokio::test]
async fn full_batch_flushes_immediately() {
	use tessera_client::PRIV_TX_BATCH_SIZE;

	let (ctx, provider) = helpers::setup_impl().await;
	let genesis_root = helpers::fetch_genesis_root(&provider, ctx.rollup_addr).await;

	let (_ss_jh, state_handle) = helpers::start_state_service(ctx.url.clone(), ctx.rollup_addr);

	helpers::wait_for_confirmed_root(&state_handle, genesis_root, helpers::SYNC_TIMEOUT).await;

	let (_ps_jh, mut prover_handle) = helpers::start_prover_service(
		ctx.url.clone(),
		ctx.rollup_addr,
		ctx.operator_key.clone(),
		state_handle.clone(),
		60,
	);

	for seed in 0..PRIV_TX_BATCH_SIZE as u8 {
		prover_handle
			.submit_tx(helpers::make_tx_request(seed, genesis_root))
			.await
			.expect("submit_tx");
	}

	let outcome = tokio::time::timeout(helpers::OUTCOME_TIMEOUT, prover_handle.next_tx_outcome())
		.await
		.expect("full batch did not flush within timeout")
		.expect("next_tx_outcome error");

	assert!(
		matches!(
			outcome,
			ProveOutcome::Success {
				batch_id: 0,
				..
			}
		),
		"expected Success outcome, got: {outcome:?}"
	);
}

/// Submitting a few TXs and waiting for the batch timeout causes a flush.
#[tokio::test]
async fn batch_timeout_flushes() {
	let (ctx, provider) = helpers::setup_impl().await;
	let genesis_root = helpers::fetch_genesis_root(&provider, ctx.rollup_addr).await;

	let (_ss_jh, state_handle) = helpers::start_state_service(ctx.url.clone(), ctx.rollup_addr);

	helpers::wait_for_confirmed_root(&state_handle, genesis_root, helpers::SYNC_TIMEOUT).await;

	let (_ps_jh, mut prover_handle) = helpers::start_prover_service(
		ctx.url.clone(),
		ctx.rollup_addr,
		ctx.operator_key.clone(),
		state_handle.clone(),
		2,
	);

	for seed in 0..3u8 {
		prover_handle
			.submit_tx(helpers::make_tx_request(seed, genesis_root))
			.await
			.expect("submit_tx");
	}

	let outcome = tokio::time::timeout(helpers::OUTCOME_TIMEOUT, prover_handle.next_tx_outcome())
		.await
		.expect("batch did not flush after timeout")
		.expect("next_tx_outcome error");

	assert!(
		matches!(outcome, ProveOutcome::Success { .. }),
		"expected Success outcome, got: {outcome:?}"
	);
}

/// A TX that carries a root not present in the confirmed-root set is silently
/// discarded; no `ProveOutcome` is emitted within the batch timeout.
#[tokio::test]
async fn invalid_root_rejected() {
	use plonky2::field::types::Field;

	let (ctx, provider) = helpers::setup_impl().await;
	let genesis_root = helpers::fetch_genesis_root(&provider, ctx.rollup_addr).await;

	let (_ss_jh, state_handle) = helpers::start_state_service(ctx.url.clone(), ctx.rollup_addr);

	helpers::wait_for_confirmed_root(&state_handle, genesis_root, helpers::SYNC_TIMEOUT).await;

	let (_ps_jh, mut prover_handle) = helpers::start_prover_service(
		ctx.url.clone(),
		ctx.rollup_addr,
		ctx.operator_key.clone(),
		state_handle.clone(),
		2,
	);

	let bad_root = HashOutput::new([
		tessera_utils::F::from_canonical_u64(0xDEAD_BEEF),
		tessera_utils::F::ZERO,
		tessera_utils::F::ZERO,
		tessera_utils::F::ZERO,
	]);
	let req = helpers::make_tx_request(0, bad_root);
	prover_handle.submit_tx(req).await.expect("submit_tx");

	let result =
		tokio::time::timeout(Duration::from_secs(6), prover_handle.next_tx_outcome()).await;

	assert!(
		result.is_err(),
		"expected timeout (no outcome), but got an outcome: {result:?}"
	);
}

/// A TX whose account nullifier (AN) is already recorded as spent by the
/// StateService is rejected and no second batch is produced.
#[tokio::test]
async fn spent_nullifier_rejected() {
	let (ctx, provider) = helpers::setup_impl().await;
	let genesis_root = helpers::fetch_genesis_root(&provider, ctx.rollup_addr).await;

	let (_ss_jh, state_handle) = helpers::start_state_service(ctx.url.clone(), ctx.rollup_addr);

	helpers::wait_for_confirmed_root(&state_handle, genesis_root, helpers::SYNC_TIMEOUT).await;

	let (_ps_jh, mut prover_handle) = helpers::start_prover_service(
		ctx.url.clone(),
		ctx.rollup_addr,
		ctx.operator_key.clone(),
		state_handle.clone(),
		2,
	);

	let req = helpers::make_tx_request(0, genesis_root);
	let spent_an = req.an;

	prover_handle.submit_tx(req).await.expect("submit_tx");
	let outcome = tokio::time::timeout(helpers::OUTCOME_TIMEOUT, prover_handle.next_tx_outcome())
		.await
		.expect("first outcome timed out")
		.expect("next_tx_outcome error");
	assert!(
		matches!(
			outcome,
			ProveOutcome::Success {
				batch_id: 0,
				..
			}
		),
		"expected first batch proven"
	);

	helpers::wait_for_nullifier(&state_handle, spent_an, helpers::SYNC_TIMEOUT).await;

	let req2 = helpers::make_tx_request(0, genesis_root);
	prover_handle.submit_tx(req2).await.expect("submit_tx");

	let result =
		tokio::time::timeout(Duration::from_secs(6), prover_handle.next_tx_outcome()).await;

	assert!(
		result.is_err(),
		"expected no second outcome (nullifier spent), got: {result:?}"
	);
}

// ---------------------------------------------------------------------------
// Deposit Tests
// ---------------------------------------------------------------------------

/// A single deposit registered on-chain and submitted via the handle produces
/// a `ProveOutcome::Success`.
#[tokio::test]
async fn single_deposit_proven() {
	let (ctx, provider) = helpers::setup_impl().await;
	let genesis_root = helpers::fetch_genesis_root(&provider, ctx.rollup_addr).await;

	let (_ss_jh, state_handle) = helpers::start_state_service(ctx.url.clone(), ctx.rollup_addr);

	helpers::wait_for_confirmed_root(&state_handle, genesis_root, helpers::SYNC_TIMEOUT).await;

	let (_ps_jh, mut prover_handle) = helpers::start_prover_service(
		ctx.url.clone(),
		ctx.rollup_addr,
		ctx.operator_key.clone(),
		state_handle.clone(),
		2,
	);

	let req = helpers::make_deposit_request(0, genesis_root);

	// Register the deposit on-chain so submitDepositBatch won't revert.
	helpers::register_deposit(
		&provider,
		ctx.rollup_addr,
		ctx.token_addr,
		req.note_commitment,
	)
	.await;

	prover_handle
		.submit_deposit(req)
		.await
		.expect("submit_deposit");

	let outcome = tokio::time::timeout(
		helpers::OUTCOME_TIMEOUT,
		prover_handle.next_deposit_outcome(),
	)
	.await
	.expect("deposit outcome did not arrive within timeout")
	.expect("next_deposit_outcome error");

	assert!(
		matches!(
			outcome,
			ProveOutcome::Success {
				batch_id: 0,
				..
			}
		),
		"expected ProveOutcome::Success with batch_id=0, got: {outcome:?}"
	);
}

/// Submitting a few deposits and waiting for the batch timeout causes a flush.
#[tokio::test]
async fn deposit_batch_timeout_flushes() {
	let (ctx, provider) = helpers::setup_impl().await;
	let genesis_root = helpers::fetch_genesis_root(&provider, ctx.rollup_addr).await;

	let (_ss_jh, state_handle) = helpers::start_state_service(ctx.url.clone(), ctx.rollup_addr);

	helpers::wait_for_confirmed_root(&state_handle, genesis_root, helpers::SYNC_TIMEOUT).await;

	let (_ps_jh, mut prover_handle) = helpers::start_prover_service(
		ctx.url.clone(),
		ctx.rollup_addr,
		ctx.operator_key.clone(),
		state_handle.clone(),
		2,
	);

	for seed in 0..3u8 {
		let req = helpers::make_deposit_request(seed, genesis_root);
		helpers::register_deposit(
			&provider,
			ctx.rollup_addr,
			ctx.token_addr,
			req.note_commitment,
		)
		.await;
		prover_handle
			.submit_deposit(req)
			.await
			.expect("submit_deposit");
	}

	let outcome = tokio::time::timeout(
		helpers::OUTCOME_TIMEOUT,
		prover_handle.next_deposit_outcome(),
	)
	.await
	.expect("deposit batch did not flush after timeout")
	.expect("next_deposit_outcome error");

	assert!(
		matches!(outcome, ProveOutcome::Success { .. }),
		"expected Success outcome, got: {outcome:?}"
	);
}

/// A deposit carrying an unconfirmed root is silently discarded; no outcome is
/// emitted within the batch timeout.
#[tokio::test]
async fn deposit_invalid_root_rejected() {
	let (ctx, provider) = helpers::setup_impl().await;
	let genesis_root = helpers::fetch_genesis_root(&provider, ctx.rollup_addr).await;

	let (_ss_jh, state_handle) = helpers::start_state_service(ctx.url.clone(), ctx.rollup_addr);

	helpers::wait_for_confirmed_root(&state_handle, genesis_root, helpers::SYNC_TIMEOUT).await;

	let (_ps_jh, mut prover_handle) = helpers::start_prover_service(
		ctx.url.clone(),
		ctx.rollup_addr,
		ctx.operator_key.clone(),
		state_handle.clone(),
		2,
	);

	let bad_root = HashOutput::new([
		tessera_utils::F::from_canonical_u64(0xBAD_DEAD),
		tessera_utils::F::ZERO,
		tessera_utils::F::ZERO,
		tessera_utils::F::ZERO,
	]);
	let req = helpers::make_deposit_request(0, bad_root);
	prover_handle
		.submit_deposit(req)
		.await
		.expect("submit_deposit");

	let result =
		tokio::time::timeout(Duration::from_secs(6), prover_handle.next_deposit_outcome()).await;

	assert!(
		result.is_err(),
		"expected timeout (no outcome), but got an outcome: {result:?}"
	);
}
