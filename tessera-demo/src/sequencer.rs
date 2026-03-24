use std::{
	collections::BTreeSet,
	sync::Arc,
	time::{Duration, Instant},
};

use alloy::{
	network::EthereumWallet,
	primitives::{Address, B256, U256},
	providers::ProviderBuilder,
	signers::{local::PrivateKeySigner, Signer},
	sol,
};
use axum::{
	extract::State,
	http::StatusCode,
	routing::{get, post},
	Json, Router,
};
use plonky2::field::types::Field;
use serde::{Deserialize, Serialize};
use tessera_client::{COM_TREE_DEPTH, NOTE_BATCH};
use tessera_server::{
	contract::{self, hash_to_u256_le, ITesseraRollupV2},
	proof_aggregation::SubtreeRootCircuit,
	sequencer::BatchBuilder,
};
use tessera_trees::MerkleTree;
use tessera_utils::hasher::HashOutput;
use tokio::sync::Mutex;
use tracing::{error, info};

// ---------------------------------------------------------------------------
// Minimal ToyUSDT sol! binding (only needed for demo mint/approve flow)
// ---------------------------------------------------------------------------

sol! {
	#[sol(rpc)]
	interface IToyUSDT {
		function mint(address to, uint256 value) external;
		function approve(address spender, uint256 value) external returns (bool);
		function balanceOf(address account) external view returns (uint256);
	}
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the demo sequencer.
pub struct DemoSequencerConfig {
	/// Ethereum JSON-RPC endpoint.
	pub rpc_url: String,
	/// Operator private key (hex-encoded).
	pub operator_key: String,
	/// EVM chain ID.
	pub chain_id: u64,
	/// TesseraContract address.
	pub bridge_address: Address,
	/// ERC-20 token address (ToyUSDT or USDC).
	pub token_address: Address,
	/// HTTP listen address (e.g. `127.0.0.1:3000`).
	pub bind_addr: String,
	/// Max time before flushing a partial batch.
	pub batch_timeout: Duration,
	/// Delay before sending zero proof after batch submission.
	pub prove_delay: Duration,
	/// Background loop poll interval.
	pub poll_interval: Duration,
}

impl DemoSequencerConfig {
	/// Load configuration from environment variables.
	///
	/// Required: `DEMO_RPC_URL`, `DEMO_OPERATOR_KEY`, `DEMO_BRIDGE_ADDRESS`,
	/// `DEMO_TOKEN_ADDRESS`.
	///
	/// Optional: `DEMO_BIND_ADDR` (default `127.0.0.1:3000`),
	/// `DEMO_BATCH_TIMEOUT_SECS` (default `12`), `DEMO_PROVE_DELAY_SECS`
	/// (default `10`), `DEMO_CHAIN_ID` (default `31337`).
	pub fn from_env() -> Self {
		Self {
			rpc_url: std::env::var("DEMO_RPC_URL").expect("DEMO_RPC_URL required"),
			operator_key: std::env::var("DEMO_OPERATOR_KEY").expect("DEMO_OPERATOR_KEY required"),
			chain_id: std::env::var("DEMO_CHAIN_ID")
				.unwrap_or_else(|_| "31337".to_string())
				.parse()
				.expect("invalid DEMO_CHAIN_ID"),
			bridge_address: std::env::var("DEMO_BRIDGE_ADDRESS")
				.expect("DEMO_BRIDGE_ADDRESS required")
				.parse()
				.expect("invalid DEMO_BRIDGE_ADDRESS"),
			token_address: std::env::var("DEMO_TOKEN_ADDRESS")
				.expect("DEMO_TOKEN_ADDRESS required")
				.parse()
				.expect("invalid DEMO_TOKEN_ADDRESS"),
			bind_addr: std::env::var("DEMO_BIND_ADDR")
				.unwrap_or_else(|_| "127.0.0.1:3000".to_string()),
			batch_timeout: Duration::from_secs(
				std::env::var("DEMO_BATCH_TIMEOUT_SECS")
					.unwrap_or_else(|_| "10".to_string())
					.parse()
					.expect("invalid DEMO_BATCH_TIMEOUT_SECS"),
			),
			prove_delay: Duration::from_secs(
				std::env::var("DEMO_PROVE_DELAY_SECS")
					.unwrap_or_else(|_| "10".to_string())
					.parse()
					.expect("invalid DEMO_PROVE_DELAY_SECS"),
			),
			poll_interval: Duration::from_secs(2),
		}
	}
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

struct SequencerState {
	rollup_addr: Address,
	token_addr: Address,
	operator: Address,
	confirmed_root: U256,
	confirmed_root_history: BTreeSet<U256>,
	tx_batch_builder: Option<BatchBuilder>,
	tx_batch_pending_since: Option<Instant>,
	deposit_queue: Vec<B256>,
	deposit_batch_pending_since: Option<Instant>,
	prove_delay: Duration,
	/// Local Poseidon Merkle tree mirroring the on-chain commitment tree.
	/// Leaves are inserted in batch after each proven batch.
	local_tree: MerkleTree<HashOutput>,
}

type SharedState = Arc<Mutex<SequencerState>>;

// Concrete provider type from ProviderBuilder::new().wallet(w).connect_http(url).
type DemoProvider = alloy::providers::fillers::FillProvider<
	alloy::providers::fillers::JoinFill<
		alloy::providers::fillers::JoinFill<
			alloy::providers::Identity,
			alloy::providers::fillers::JoinFill<
				alloy::providers::fillers::GasFiller,
				alloy::providers::fillers::JoinFill<
					alloy::providers::fillers::BlobGasFiller,
					alloy::providers::fillers::JoinFill<
						alloy::providers::fillers::NonceFiller,
						alloy::providers::fillers::ChainIdFiller,
					>,
				>,
			>,
		>,
		alloy::providers::fillers::WalletFiller<EthereumWallet>,
	>,
	alloy::providers::RootProvider,
>;
type AppState = (SharedState, Arc<DemoProvider>);

// ---------------------------------------------------------------------------
// HTTP request/response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DepositRequest {
	note_commitment: String,
	amount: u64,
}

#[derive(Serialize)]
struct DepositResponse {
	status: String,
	note_commitment: String,
	tx_hash: String,
}

#[derive(Deserialize)]
struct TransactionRequest {
	tx_id: Option<String>,
	input_account_leaf: String,
	output_account_leaf: String,
	input_notes: Vec<String>,
	output_notes: Vec<String>,
	tx_proof: String,
}

#[derive(Serialize)]
struct TransactionResponse {
	status: String,
	tx_id: String,
	batch_slots_used: usize,
}

#[derive(Serialize)]
struct StatusResponse {
	confirmed_root: String,
	tx_batch_slots: usize,
	pending_deposits: usize,
	confirmed_roots_count: usize,
}

#[derive(Serialize)]
struct ConfigResponse {
	contract_address: String,
	token_address: String,
	operator_address: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_hex_bytes32(s: &str) -> Result<[u8; 32], String> {
	let s = s.strip_prefix("0x").unwrap_or(s);
	let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
	if bytes.len() != 32 {
		return Err(format!("expected 32 bytes, got {}", bytes.len()));
	}
	let mut out = [0u8; 32];
	out.copy_from_slice(&bytes);
	Ok(out)
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
	let s = s.strip_prefix("0x").unwrap_or(s);
	hex::decode(s).map_err(|e| format!("invalid hex: {e}"))
}

fn zero_proof() -> ITesseraRollupV2::Proof {
	ITesseraRollupV2::Proof {
		proof: [U256::ZERO; 8],
		commitments: [U256::ZERO; 2],
		commitmentPok: [U256::ZERO; 2],
	}
}

// ---------------------------------------------------------------------------
// Batch submission & delayed proving
// ---------------------------------------------------------------------------

async fn flush_tx_batch(state: &SharedState, provider: &Arc<DemoProvider>) -> anyhow::Result<()> {
	let (rollup_addr, bb, prove_delay, confirmed_root) = {
		let mut st = state.lock().await;
		let bb = match st.tx_batch_builder.take() {
			Some(bb) => bb,
			None => return Ok(()),
		};
		st.tx_batch_pending_since = None;
		(st.rollup_addr, bb, st.prove_delay, st.confirmed_root)
	};

	let finalized = bb.finalize();

	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(rollup_addr, provider.as_ref());
	let pool_cfg_root: [u8; 32] = rollup.poolConfigRoot().call().await?.into();

	let n_slots = finalized.ac_leaves.len();
	let stride = NOTE_BATCH + 1; // 8 entries per slot in nc/nn_leaves

	let mut note_commitments = Vec::with_capacity(n_slots * NOTE_BATCH);
	for s in 0..n_slots {
		let nc_base = s * stride;
		for j in 0..NOTE_BATCH {
			note_commitments.push(contract::bytes32_be_to_u256_le(
				&finalized.nc_leaves[nc_base + j],
			));
		}
	}

	let mut note_nullifiers = Vec::with_capacity(n_slots * NOTE_BATCH);
	for s in 0..n_slots {
		let nn_base = s * stride;
		for j in 0..NOTE_BATCH {
			note_nullifiers.push(contract::bytes32_be_to_u256_le(
				&finalized.nn_leaves[nn_base + j],
			));
		}
	}

	let account_commitments: Vec<U256> = finalized
		.ac_leaves
		.iter()
		.map(contract::bytes32_be_to_u256_le)
		.collect();
	let account_nullifiers: Vec<U256> = finalized
		.an_leaves
		.iter()
		.map(contract::bytes32_be_to_u256_le)
		.collect();

	let batch_poseidon_root = hash_to_u256_le(&finalized.batch_poseidon_root);

	let batch = ITesseraRollupV2::TransactionBatch {
		root: confirmed_root,
		mainPoolConfigRoot: pool_cfg_root.into(),
		noteCommitments: note_commitments,
		noteNullifiers: note_nullifiers,
		accountCommitments: account_commitments,
		accountNullifiers: account_nullifiers,
		batchPoseidonRoot: batch_poseidon_root,
		confirmed: false,
	};

	info!(
		real_slots = finalized.tx_proofs_by_slot.len(),
		note_commitments = batch.noteCommitments.len(),
		account_commitments = batch.accountCommitments.len(),
		"submitting TX batch on-chain"
	);

	let call = rollup.submitTransactionBatch(batch);
	let gas_estimate = call.estimate_gas().await;
	info!(gas_estimate = ?gas_estimate, "TX batch gas estimate");

	let receipt = call
		.send()
		.await
		.map_err(|e| anyhow::anyhow!("submitTransactionBatch failed: {e}"))?
		.get_receipt()
		.await
		.map_err(|e| anyhow::anyhow!("submitTransactionBatch receipt: {e}"))?;

	anyhow::ensure!(receipt.status(), "submitTransactionBatch reverted");

	let pi_commitment: B256 = receipt
		.inner
		.logs()
		.iter()
		.find_map(|l| {
			l.log_decode::<ITesseraRollupV2::TransactionBatchSubmitted>()
				.ok()
				.map(|d| d.inner.piCommitment)
		})
		.ok_or_else(|| anyhow::anyhow!("TransactionBatchSubmitted event not found"))?;

	// Collect the 512 leaves (as HashOutput) for local tree insertion after prove.
	let batch_leaves: Vec<HashOutput> = finalized
		.nc_leaves
		.iter()
		.map(|c| HashOutput::from_32bytes_digest(*c))
		.collect();

	info!(
		pi_commitment = %pi_commitment,
		"TX batch submitted; scheduling proof in {}s",
		prove_delay.as_secs()
	);

	let state_clone = state.clone();
	let provider_clone = provider.clone();
	tokio::spawn(async move {
		tokio::time::sleep(prove_delay).await;
		if let Err(e) =
			prove_tx_batch(&state_clone, &provider_clone, pi_commitment, batch_leaves).await
		{
			error!("failed to prove TX batch: {e}");
		}
	});

	Ok(())
}

async fn prove_tx_batch(
	state: &SharedState,
	provider: &Arc<DemoProvider>,
	pi_commitment: B256,
	batch_leaves: Vec<HashOutput>,
) -> anyhow::Result<()> {
	let rollup_addr = state.lock().await.rollup_addr;
	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(rollup_addr, provider.as_ref());

	info!(%pi_commitment, "proving TX batch (zero proof)");

	let receipt = rollup
		.proveTransactionBatch(pi_commitment, zero_proof())
		.send()
		.await
		.map_err(|e| anyhow::anyhow!("proveTransactionBatch failed: {e}"))?
		.get_receipt()
		.await
		.map_err(|e| anyhow::anyhow!("proveTransactionBatch receipt: {e}"))?;

	anyhow::ensure!(receipt.status(), "proveTransactionBatch reverted");

	let new_root = receipt
		.inner
		.logs()
		.iter()
		.find_map(|l| {
			l.log_decode::<ITesseraRollupV2::TransactionBatchProven>()
				.ok()
				.map(|d| d.inner.newTreeRoot)
		})
		.ok_or_else(|| anyhow::anyhow!("TransactionBatchProven event not found"))?;

	let mut st = state.lock().await;
	st.confirmed_root = new_root;
	st.confirmed_root_history.insert(new_root);

	// Insert all 512 batch leaves into the local tree.
	st.local_tree
		.insert_batch(batch_leaves)
		.map_err(|e| anyhow::anyhow!("local tree insert_batch: {e}"))?;
	let confirmed_roots = st.confirmed_root_history.len();
	info!(
		new_root = %new_root,
		confirmed_roots,
		local_tree_leaves = st.local_tree.num_leaves(),
		"=== TX batch CONFIRMED ==="
	);

	Ok(())
}

async fn flush_deposit_batch(
	state: &SharedState,
	provider: &Arc<DemoProvider>,
) -> anyhow::Result<()> {
	let (rollup_addr, deposits, prove_delay, confirmed_root) = {
		let mut st = state.lock().await;
		if st.deposit_queue.is_empty() {
			return Ok(());
		}
		let deposits = std::mem::take(&mut st.deposit_queue);
		st.deposit_batch_pending_since = None;
		(st.rollup_addr, deposits, st.prove_delay, st.confirmed_root)
	};

	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(rollup_addr, provider.as_ref());
	let pool_cfg_root: [u8; 32] = rollup.poolConfigRoot().call().await?.into();

	let deposit_nc_hashes: Vec<HashOutput> = deposits
		.iter()
		.map(|nc| HashOutput::from_32bytes_digest(nc.0))
		.collect();

	const DEPOSIT_BATCH_SIZE: usize = 512;
	let mut padded = deposit_nc_hashes;
	padded.resize(DEPOSIT_BATCH_SIZE, HashOutput::new([tessera_utils::F::ZERO; 4]));
	let batch_poseidon_root = SubtreeRootCircuit::compute_root_native(&padded);
	let batch_poseidon_root_u256 = hash_to_u256_le(&batch_poseidon_root);

	let deposit_batch = ITesseraRollupV2::DepositBatch {
		root: confirmed_root,
		mainPoolConfigRoot: pool_cfg_root.into(),
		depositNoteCommitments: deposits.clone(),
		batchPoseidonRoot: batch_poseidon_root_u256,
		confirmed: false,
	};

	info!(
		deposits = deposits.len(),
		"submitting deposit batch on-chain"
	);

	let receipt = rollup
		.submitDepositBatch(deposit_batch)
		.send()
		.await
		.map_err(|e| anyhow::anyhow!("submitDepositBatch failed: {e}"))?
		.get_receipt()
		.await
		.map_err(|e| anyhow::anyhow!("submitDepositBatch receipt: {e}"))?;

	anyhow::ensure!(receipt.status(), "submitDepositBatch reverted");

	let pi_commitment: B256 = receipt
		.inner
		.logs()
		.iter()
		.find_map(|l| {
			l.log_decode::<ITesseraRollupV2::DepositBatchSubmitted>()
				.ok()
				.map(|d| d.inner.piCommitment)
		})
		.ok_or_else(|| anyhow::anyhow!("DepositBatchSubmitted event not found"))?;

	// Collect deposit leaves (as HashOutput) for local tree insertion after prove.
	let deposit_leaves: Vec<HashOutput> = padded;

	info!(
		%pi_commitment,
		"deposit batch submitted; scheduling proof in {}s",
		prove_delay.as_secs()
	);

	let state_clone = state.clone();
	let provider_clone = provider.clone();
	tokio::spawn(async move {
		tokio::time::sleep(prove_delay).await;
		if let Err(e) =
			prove_deposit_batch(&state_clone, &provider_clone, pi_commitment, deposit_leaves).await
		{
			error!("failed to prove deposit batch: {e}");
		}
	});

	Ok(())
}

async fn prove_deposit_batch(
	state: &SharedState,
	provider: &Arc<DemoProvider>,
	pi_commitment: B256,
	deposit_leaves: Vec<HashOutput>,
) -> anyhow::Result<()> {
	let rollup_addr = state.lock().await.rollup_addr;
	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(rollup_addr, provider.as_ref());

	info!(%pi_commitment, "proving deposit batch (zero proof)");

	let receipt = rollup
		.proveDepositBatch(pi_commitment, zero_proof())
		.send()
		.await
		.map_err(|e| anyhow::anyhow!("proveDepositBatch failed: {e}"))?
		.get_receipt()
		.await
		.map_err(|e| anyhow::anyhow!("proveDepositBatch receipt: {e}"))?;

	anyhow::ensure!(receipt.status(), "proveDepositBatch reverted");

	let new_root = receipt
		.inner
		.logs()
		.iter()
		.find_map(|l| {
			l.log_decode::<ITesseraRollupV2::DepositBatchProven>()
				.ok()
				.map(|d| d.inner.newTreeRoot)
		})
		.ok_or_else(|| anyhow::anyhow!("DepositBatchProven event not found"))?;

	let mut st = state.lock().await;
	st.confirmed_root = new_root;
	st.confirmed_root_history.insert(new_root);

	// Insert deposit leaves into the local tree.
	st.local_tree
		.insert_batch(deposit_leaves)
		.map_err(|e| anyhow::anyhow!("local tree insert_batch (deposit): {e}"))?;
	let confirmed_roots = st.confirmed_root_history.len();
	info!(
		new_root = %new_root,
		confirmed_roots,
		local_tree_leaves = st.local_tree.num_leaves(),
		"=== Deposit batch CONFIRMED ==="
	);

	Ok(())
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

async fn handle_deposit(
	State((state, provider)): State<AppState>,
	Json(req): Json<DepositRequest>,
) -> Result<Json<DepositResponse>, (StatusCode, String)> {
	let nc_bytes =
		parse_hex_bytes32(&req.note_commitment).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
	let nc = B256::from(nc_bytes);
	let amount = U256::from(req.amount);

	let (rollup_addr, token_addr, operator) = {
		let st = state.lock().await;
		(st.rollup_addr, st.token_addr, st.operator)
	};

	let token = IToyUSDT::IToyUSDTInstance::new(token_addr, provider.as_ref());
	let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(rollup_addr, provider.as_ref());

	// Mint tokens to operator (demo with ToyUSDT only — remove for real USDC).
	token
		.mint(operator, amount)
		.send()
		.await
		.map_err(|e| {
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				format!("mint failed: {e}"),
			)
		})?
		.get_receipt()
		.await
		.map_err(|e| {
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				format!("mint receipt: {e}"),
			)
		})?;

	token
		.approve(rollup_addr, amount)
		.send()
		.await
		.map_err(|e| {
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				format!("approve failed: {e}"),
			)
		})?
		.get_receipt()
		.await
		.map_err(|e| {
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				format!("approve receipt: {e}"),
			)
		})?;

	let receipt = rollup
		.depositAndRegister(nc, amount)
		.send()
		.await
		.map_err(|e| {
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				format!("depositAndRegister failed: {e}"),
			)
		})?
		.get_receipt()
		.await
		.map_err(|e| {
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				format!("depositAndRegister receipt: {e}"),
			)
		})?;

	if !receipt.status() {
		return Err((
			StatusCode::INTERNAL_SERVER_ERROR,
			"depositAndRegister reverted".to_string(),
		));
	}

	let tx_hash = format!("{:?}", receipt.transaction_hash);

	{
		let mut st = state.lock().await;
		st.deposit_queue.push(nc);
		if st.deposit_batch_pending_since.is_none() {
			st.deposit_batch_pending_since = Some(Instant::now());
		}
	}

	info!(note_commitment = %nc, amount = req.amount, "deposit registered");

	Ok(Json(DepositResponse {
		status: "pending".to_string(),
		note_commitment: format!("{nc}"),
		tx_hash,
	}))
}

async fn handle_transaction(
	State((state, _provider)): State<AppState>,
	Json(req): Json<TransactionRequest>,
) -> Result<Json<TransactionResponse>, (StatusCode, String)> {
	let input_account_leaf =
		parse_hex_bytes32(&req.input_account_leaf).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
	let output_account_leaf =
		parse_hex_bytes32(&req.output_account_leaf).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

	let input_notes: Vec<[u8; 32]> = req
		.input_notes
		.iter()
		.map(|s| parse_hex_bytes32(s))
		.collect::<Result<_, _>>()
		.map_err(|e| (StatusCode::BAD_REQUEST, e))?;

	let output_notes: Vec<[u8; 32]> = req
		.output_notes
		.iter()
		.map(|s| parse_hex_bytes32(s))
		.collect::<Result<_, _>>()
		.map_err(|e| (StatusCode::BAD_REQUEST, e))?;

	let tx_proof = parse_hex_bytes(&req.tx_proof).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
	let tx_id = req.tx_id.unwrap_or_else(|| "anonymous".to_string());

	let nc: [[u8; 32]; NOTE_BATCH] = {
		let mut arr = [[0u8; 32]; NOTE_BATCH];
		for (i, note) in output_notes.iter().enumerate().take(NOTE_BATCH) {
			arr[i] = *note;
		}
		arr
	};
	let nn: [[u8; 32]; NOTE_BATCH] = {
		let mut arr = [[0u8; 32]; NOTE_BATCH];
		for (i, note) in input_notes.iter().enumerate().take(NOTE_BATCH) {
			arr[i] = *note;
		}
		arr
	};

	let slots_used = {
		let mut st = state.lock().await;

		if st
			.tx_batch_builder
			.as_ref()
			.is_some_and(|b| b.contains_an(&input_account_leaf))
		{
			return Err((
				StatusCode::CONFLICT,
				"AN leaf already in current batch".to_string(),
			));
		}
		for note in &input_notes {
			if st
				.tx_batch_builder
				.as_ref()
				.is_some_and(|b| b.contains_nn(note))
			{
				return Err((
					StatusCode::CONFLICT,
					"NN leaf already in current batch".to_string(),
				));
			}
		}

		if st.tx_batch_builder.is_none() {
			st.tx_batch_builder = Some(BatchBuilder::new());
			st.tx_batch_pending_since = Some(Instant::now());
		}

		st.tx_batch_builder
			.as_mut()
			.unwrap()
			.add_private_tx(tx_proof, output_account_leaf, input_account_leaf, nc, nn)
			.map_err(|e| {
				(
					StatusCode::INTERNAL_SERVER_ERROR,
					format!("batch error: {e}"),
				)
			})?;

		st.tx_batch_builder.as_ref().unwrap().len()
	};

	info!(tx_id = %tx_id, slots_used, "transaction queued");

	Ok(Json(TransactionResponse {
		status: "queued".to_string(),
		tx_id,
		batch_slots_used: slots_used,
	}))
}

async fn handle_status(State((state, _)): State<AppState>) -> Json<StatusResponse> {
	let st = state.lock().await;
	Json(StatusResponse {
		confirmed_root: format!("{}", st.confirmed_root),
		tx_batch_slots: st.tx_batch_builder.as_ref().map_or(0, |b| b.len()),
		pending_deposits: st.deposit_queue.len(),
		confirmed_roots_count: st.confirmed_root_history.len(),
	})
}

async fn handle_config(State((state, _)): State<AppState>) -> Json<ConfigResponse> {
	let st = state.lock().await;
	Json(ConfigResponse {
		contract_address: format!("{}", st.rollup_addr),
		token_address: format!("{}", st.token_addr),
		operator_address: format!("{}", st.operator),
	})
}

// ---------------------------------------------------------------------------
// DemoSequencer — the public entry point
// ---------------------------------------------------------------------------

/// A demo sequencer that can be started with [`DemoSequencer::run`].
pub struct DemoSequencer {
	config: DemoSequencerConfig,
}

/// Handle returned by [`DemoSequencer::start`] that keeps the sequencer alive.
pub struct RunningSequencer {
	/// The address the HTTP server is actually bound to (useful when binding to port 0).
	pub addr: std::net::SocketAddr,
	_handle: tokio::task::JoinHandle<()>,
}

impl DemoSequencer {
	pub fn new(config: DemoSequencerConfig) -> Self {
		Self {
			config,
		}
	}

	/// Start the sequencer in the background and return a handle with the
	/// bound address. The sequencer runs until the handle is dropped.
	pub async fn start(self) -> anyhow::Result<RunningSequencer> {
		let (app, bind_addr) = self.build_app().await?;
		let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
		let addr = listener.local_addr()?;

		info!(bind_addr = %addr, "sequencer HTTP API listening");
		info!("  POST /deposit        - register a deposit");
		info!("  POST /transaction    - submit a private transaction");
		info!("  GET  /status         - sequencer status");
		info!("  GET  /config         - contract addresses");

		let handle = tokio::spawn(async move {
			axum::serve(listener, app).await.ok();
		});

		Ok(RunningSequencer {
			addr,
			_handle: handle,
		})
	}

	/// Run the sequencer: connect to the chain, start the background batch
	/// flushing loop, and serve the HTTP API. Blocks until the server shuts
	/// down.
	pub async fn run(self) -> anyhow::Result<()> {
		let _handle = self.start().await?;
		// Block forever (the spawned task serves requests).
		std::future::pending::<()>().await;
		Ok(())
	}

	async fn build_app(self) -> anyhow::Result<(Router, String)> {
		let config = self.config;

		let signer: PrivateKeySigner = config.operator_key.parse()?;
		let signer = signer.with_chain_id(Some(config.chain_id));
		let operator = signer.address();
		let wallet = EthereumWallet::from(signer);
		let provider = Arc::new(
			ProviderBuilder::new()
				.wallet(wallet)
				.connect_http(config.rpc_url.parse()?),
		);

		// Fetch current on-chain root.
		let rollup = ITesseraRollupV2::ITesseraRollupV2Instance::new(
			config.bridge_address,
			provider.as_ref(),
		);
		let current_root: U256 = rollup.currentRoot().call().await?;

		let mut root_history = BTreeSet::new();
		root_history.insert(current_root);

		info!(
			%operator,
			bridge = %config.bridge_address,
			token = %config.token_address,
			current_root = %current_root,
			"connected to on-chain contracts"
		);

		let state: SharedState = Arc::new(Mutex::new(SequencerState {
			rollup_addr: config.bridge_address,
			token_addr: config.token_address,
			operator,
			confirmed_root: current_root,
			confirmed_root_history: root_history,
			tx_batch_builder: None,
			tx_batch_pending_since: None,
			deposit_queue: Vec::new(),
			deposit_batch_pending_since: None,
			prove_delay: config.prove_delay,
			local_tree: MerkleTree::new(COM_TREE_DEPTH),
		}));

		let app_state: AppState = (state.clone(), provider.clone());
		let app = Router::new()
			.route("/deposit", post(handle_deposit))
			.route("/transaction", post(handle_transaction))
			.route("/status", get(handle_status))
			.route("/config", get(handle_config))
			.with_state(app_state);

		// Background batch flushing loop.
		let state_bg = state.clone();
		let provider_bg = provider.clone();
		let batch_timeout = config.batch_timeout;
		let poll_interval = config.poll_interval;
		tokio::spawn(async move {
			let mut interval = tokio::time::interval(poll_interval);
			loop {
				interval.tick().await;

				let should_flush_tx = {
					let st = state_bg.lock().await;
					st.tx_batch_builder.as_ref().is_some_and(|b| {
						b.is_full()
							|| st
								.tx_batch_pending_since
								.is_some_and(|since| since.elapsed() >= batch_timeout)
					})
				};
				if should_flush_tx {
					if let Err(e) = flush_tx_batch(&state_bg, &provider_bg).await {
						error!("failed to flush TX batch: {e}");
					}
				}

				let should_flush_dep = {
					let st = state_bg.lock().await;
					!st.deposit_queue.is_empty()
						&& st
							.deposit_batch_pending_since
							.is_some_and(|since| since.elapsed() >= batch_timeout)
				};
				if should_flush_dep {
					if let Err(e) = flush_deposit_batch(&state_bg, &provider_bg).await {
						error!("failed to flush deposit batch: {e}");
					}
				}
			}
		});

		Ok((app, config.bind_addr))
	}
}
