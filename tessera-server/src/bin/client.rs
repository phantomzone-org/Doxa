//! E2E test CLI for Tessera.
//!
//! Subcommands:
//!   deposit          — mint ERC20, approve bridge, call depositAndRegister N times
//!   consume          — load 4-PI circuit, prove, POST /consume-request N times
//!   private-tx       — generate random TX data, prove 73-PI, POST /private-tx

use std::{fs, path::Path};

use alloy::{
	network::EthereumWallet,
	primitives::{Address, B256, U256},
	providers::ProviderBuilder,
	signers::local::PrivateKeySigner,
	sol,
};
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use plonky2::{
	field::types::Field,
	iop::{
		target::Target,
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::circuit_data::CircuitData,
	util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use tessera_trees::{ConfigNative, D, F};

// ---------------------------------------------------------------------------
// Contract bindings
// ---------------------------------------------------------------------------

sol! {
	#[sol(rpc)]
	interface IDepositBridge {
		function depositAndRegister(bytes32 noteCommitment, uint256 maxAmount) external returns (bytes32);
	}
}

sol! {
	#[sol(rpc)]
	interface IToyToken {
		function mint(address to, uint256 amount) external;
		function approve(address spender, uint256 amount) external returns (bool);
	}
}

// ---------------------------------------------------------------------------
// CLI types
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "client", about = "Tessera E2E test client")]
struct Cli {
	#[command(subcommand)]
	command: Command,
}

#[derive(Subcommand)]
enum Command {
	/// Mint ERC20 tokens and register N deposits on-chain.
	Deposit {
		/// Number of deposits to register.
		#[arg(long)]
		count: usize,
		/// Starting note index (note commitment = 0x{i:064x}).
		#[arg(long, default_value_t = 1)]
		start_index: usize,
		/// Token amount per deposit.
		#[arg(long, default_value_t = 1)]
		amount: u64,
	},
	/// Prove N consume-requests and submit them to the sequencer.
	Consume {
		/// Number of consume-requests to submit.
		#[arg(long)]
		count: usize,
		/// Starting note index.
		#[arg(long, default_value_t = 1)]
		start_index: usize,
	},
	/// Prove N private transactions with random data and submit them to the sequencer.
	PrivateTx {
		/// Number of private transactions to submit.
		#[arg(long, default_value_t = 1)]
		count: usize,
	},
}

// ---------------------------------------------------------------------------
// HTTP response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ApiResponse {
	accepted: bool,
	invalid_proof_tx: Option<RejectionReason>,
}

#[derive(Debug, Deserialize)]
struct RejectionReason {
	reason: String,
}

#[derive(Serialize)]
struct ConsumeBody {
	note_commitment: String,
	input_proof: String,
}

#[derive(Serialize)]
struct PrivateTxBody {
	input_notes: Vec<String>,
	output_notes: Vec<String>,
	input_account_commitment: String,
	output_account_commitment: String,
	tx_proof: String,
	tx_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
	dotenvy::from_path(concat!(env!("CARGO_MANIFEST_DIR"), "/.env")).ok();
	let cli = Cli::parse();
	match cli.command {
		Command::Deposit {
			count,
			start_index,
			amount,
		} => cmd_deposit(count, start_index, amount).await,
		Command::Consume {
			count,
			start_index,
		} => cmd_consume(count, start_index).await,
		Command::PrivateTx {
			count,
		} => cmd_private_tx(count).await,
	}
}

// ---------------------------------------------------------------------------
// deposit
// ---------------------------------------------------------------------------

async fn cmd_deposit(count: usize, start_index: usize, amount: u64) -> Result<()> {
	let rpc_url = env_required("TESSERA_RPC_URL")?;
	let bridge_addr: Address = env_required("TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS")?
		.parse()
		.context("invalid TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS")?;
	let token_addr: Address = env_required("TESSERA_MONITORED_TOKEN")?
		.parse()
		.context("invalid TESSERA_MONITORED_TOKEN")?;
	let private_key = env_required("TESSERA_CLIENT_KEY")?;

	let signer: PrivateKeySigner = private_key.parse().context("invalid TESSERA_CLIENT_KEY")?;
	let operator_addr = signer.address();
	let wallet = EthereumWallet::from(signer);
	let provider = ProviderBuilder::new()
		.wallet(wallet)
		.connect_http(rpc_url.parse().context("invalid TESSERA_RPC_URL")?);

	let token = IToyToken::IToyTokenInstance::new(token_addr, &provider);
	let bridge = IDepositBridge::IDepositBridgeInstance::new(bridge_addr, &provider);

	let total = U256::from(count as u64 * amount);
	println!("minting {total} tokens to {operator_addr}");
	token
		.mint(operator_addr, total)
		.send()
		.await?
		.get_receipt()
		.await?;

	println!("approving bridge {bridge_addr} for {total} tokens");
	token
		.approve(bridge_addr, total)
		.send()
		.await?
		.get_receipt()
		.await?;

	for i in start_index..(start_index + count) {
		let note = index_to_b256(i);
		let amt = U256::from(amount);
		bridge
			.depositAndRegister(note, amt)
			.send()
			.await?
			.get_receipt()
			.await?;
		println!("deposit {i}: {note}");
	}
	println!("done: registered {count} deposits");
	Ok(())
}

// ---------------------------------------------------------------------------
// consume
// ---------------------------------------------------------------------------

async fn cmd_consume(count: usize, start_index: usize) -> Result<()> {
	let artifacts_dir = env_required("TESSERA_CONSUME_ARTIFACTS_PATH")?;
	let sequencer_url =
		std::env::var("TESSERA_SEQUENCER_API_URL").unwrap_or("http://127.0.0.1:8081".to_string());

	let circuit = load_circuit(Path::new(&artifacts_dir))?;
	let targets = circuit.prover_only.public_inputs.clone();
	let http = reqwest::Client::new();

	for i in start_index..(start_index + count) {
		let note_bytes = index_to_bytes32(i);
		let pi_vals = bytes32_to_pi_fields(&note_bytes);

		let proof_bytes = tokio::task::spawn_blocking({
			let circuit = circuit.clone();
			let targets = targets.clone();
			move || prove(&circuit, &targets, &pi_vals.map(|v| v))
		})
		.await??;

		let note_hex = format!("0x{}", hex::encode(note_bytes));
		let proof_hex = format!("0x{}", hex::encode(&proof_bytes));

		let body = ConsumeBody {
			note_commitment: note_hex.clone(),
			input_proof: proof_hex,
		};
		let url = format!("{sequencer_url}/consume-request");
		let raw_resp = http.post(&url).json(&body).send().await?;
		let status = raw_resp.status();
		if !status.is_success() {
			let text = raw_resp.text().await.unwrap_or_default();
			anyhow::bail!("/consume-request returned {status}: {text}");
		}
		let resp: ApiResponse = raw_resp
			.json()
			.await
			.context("failed to parse /consume-request response")?;

		if resp.accepted {
			println!("consume {i} ({note_hex}): accepted");
		} else {
			let reason = resp.invalid_proof_tx.map(|r| r.reason).unwrap_or_default();
			println!("consume {i} ({note_hex}): REJECTED — {reason}");
		}
	}
	Ok(())
}

// ---------------------------------------------------------------------------
// private-tx (random data + dummy proof)
// ---------------------------------------------------------------------------

async fn cmd_private_tx(count: usize) -> Result<()> {
	let artifacts_dir = env_required("TESSERA_AGGREGATOR_ARTIFACTS_PATH")?;
	let sequencer_url =
		std::env::var("TESSERA_SEQUENCER_API_URL").unwrap_or("http://127.0.0.1:8081".to_string());

	let circuit = load_circuit(Path::new(&artifacts_dir))?;
	let n_pi = circuit.common.num_public_inputs;
	anyhow::ensure!(
		n_pi == 73,
		"expected 73-PI circuit (is_real + 72 data), got {n_pi}"
	);
	let targets = circuit.prover_only.public_inputs.clone();
	let http = reqwest::Client::new();

	for tx_idx in 0..count {
		// Generate 8 random note nullifiers, 8 random note commitments,
		// 1 random account nullifier, 1 random account commitment.
		let input_nullifiers: Vec<B256> = (0..8).map(|_| random_b256()).collect();
		let output_commitments: Vec<B256> = (0..8).map(|_| random_b256()).collect();
		let input_account_nullifier = random_b256();
		let output_account_commitment = random_b256();

		// Build the 73-field PI array.
		//   [0]      : is_real = 1
		//   [1..33]  : 8 input note nullifiers  (4 fields each)
		//   [33..65] : 8 output note commitments (4 fields each)
		//   [65..69] : input account nullifier   (4 fields)
		//   [69..73] : output account commitment (4 fields)
		let mut pi = [0u64; 73];
		pi[0] = 1; // is_real = true
		for (slot, nf) in input_nullifiers.iter().enumerate() {
			let fields = bytes32_to_pi_fields(&nf.0);
			pi[1 + slot * 4..1 + slot * 4 + 4].copy_from_slice(&fields);
		}
		for (slot, oc) in output_commitments.iter().enumerate() {
			let fields = bytes32_to_pi_fields(&oc.0);
			pi[33 + slot * 4..33 + slot * 4 + 4].copy_from_slice(&fields);
		}
		{
			let fields = bytes32_to_pi_fields(&input_account_nullifier.0);
			pi[65..69].copy_from_slice(&fields);
		}
		{
			let fields = bytes32_to_pi_fields(&output_account_commitment.0);
			pi[69..73].copy_from_slice(&fields);
		}

		let proof_bytes = tokio::task::spawn_blocking({
			let circuit = circuit.clone();
			let targets = targets.clone();
			move || prove(&circuit, &targets, &pi)
		})
		.await??;

		let proof_hex = format!("0x{}", hex::encode(&proof_bytes));
		let norm_b256 = |b: &B256| -> String { format!("0x{}", hex::encode(b.as_slice())) };
		let body = PrivateTxBody {
			input_notes: input_nullifiers.iter().map(norm_b256).collect(),
			output_notes: output_commitments.iter().map(norm_b256).collect(),
			input_account_commitment: norm_b256(&input_account_nullifier),
			output_account_commitment: norm_b256(&output_account_commitment),
			tx_proof: proof_hex,
			tx_id: None,
		};

		let url = format!("{sequencer_url}/private-tx");
		let raw_resp = http.post(&url).json(&body).send().await?;
		let status = raw_resp.status();
		if !status.is_success() {
			let text = raw_resp.text().await.unwrap_or_default();
			anyhow::bail!("/private-tx returned {status}: {text}");
		}
		let resp: ApiResponse = raw_resp
			.json()
			.await
			.context("failed to parse /private-tx response")?;

		if resp.accepted {
			println!("private-tx {tx_idx}: accepted");
		} else {
			let reason = resp.invalid_proof_tx.map(|r| r.reason).unwrap_or_default();
			println!("private-tx {tx_idx}: REJECTED — {reason}");
		}
	}

	println!("done: submitted {count} private transactions");
	Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn env_required(key: &str) -> Result<String> {
	std::env::var(key).with_context(|| format!("{key} not set"))
}

fn load_circuit(dir: &Path) -> Result<CircuitData<F, ConfigNative, D>> {
	let bytes = fs::read(dir.join("leaf_prover.bin"))
		.with_context(|| format!("failed to read leaf_prover.bin from {}", dir.display()))?;
	CircuitData::from_bytes(
		&bytes,
		&DefaultGateSerializer,
		&DefaultGeneratorSerializer::<ConfigNative, D>::default(),
	)
	.map_err(|e| anyhow!("failed to deserialize leaf_prover.bin: {e:?}"))
}

fn prove(
	circuit: &CircuitData<F, ConfigNative, D>,
	targets: &[Target],
	values: &[u64],
) -> Result<Vec<u8>> {
	let mut pw = PartialWitness::new();
	for (&t, &v) in targets.iter().zip(values.iter()) {
		pw.set_target(t, F::from_canonical_u64(v))?;
	}
	let proof = circuit.prove(pw)?;
	Ok(proof.to_bytes())
}

/// Encode a `bytes32` as 4 big-endian u64 Goldilocks field elements.
fn bytes32_to_pi_fields(b: &[u8; 32]) -> [u64; 4] {
	std::array::from_fn(|i| u64::from_be_bytes(b[i * 8..(i + 1) * 8].try_into().unwrap()))
}

fn index_to_bytes32(i: usize) -> [u8; 32] {
	let mut b = [0u8; 32];
	let le = (i as u64).to_be_bytes();
	b[24..32].copy_from_slice(&le);
	b
}

fn index_to_b256(i: usize) -> B256 {
	B256::from(index_to_bytes32(i))
}

const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

/// Generate a random B256 with each 8-byte limb clamped to < GOLDILOCKS_PRIME.
fn random_b256() -> B256 {
	let mut bytes = [0u8; 32];
	rand::rng().fill(&mut bytes[..]);
	for i in 0..4 {
		let limb = u64::from_be_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
		let clamped = limb % GOLDILOCKS_PRIME;
		bytes[i * 8..(i + 1) * 8].copy_from_slice(&clamped.to_be_bytes());
	}
	B256::from(bytes)
}
