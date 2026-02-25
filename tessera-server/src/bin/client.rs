//! E2E test CLI for Tessera.
//!
//! Subcommands:
//!   deposit          — mint ERC20, approve bridge, call depositAndRegister N times
//!   consume          — load 4-PI circuit, prove, POST /consume-request N times
//!   register-account — derive account commitment, prove 8-PI circuit, POST /accounts/commitment
//!   private-tx       — derive nullifiers/commitments/dummies, prove 73-PI, POST /private-tx

use std::{fs, path::Path, str::FromStr};

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
	field::types::{Field, PrimeField64},
	hash::{hash_types::HashOut, poseidon::PoseidonHash},
	iop::{
		target::Target,
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::{circuit_data::CircuitData, config::Hasher},
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
	/// Register an account commitment on the sequencer (8-PI proof).
	RegisterAccount {
		/// Private key (bytes32 hex, required).
		#[arg(long)]
		private_key: String,
		/// Account balance (default 0).
		#[arg(long, default_value_t = 0)]
		balance: u64,
		/// Account nonce (default 0).
		#[arg(long, default_value_t = 0)]
		nonce: u64,
	},
	/// Prove a single private transaction and submit it to the sequencer.
	PrivateTx {
		/// Comma-separated input note commitments (1–8 bytes32 hex values).
		#[arg(long, value_delimiter = ',')]
		input_notes: Vec<String>,
		/// Account commitment to nullify (bytes32 hex).
		#[arg(long)]
		account_commitment: String,
		/// Private key for nullifier derivation (bytes32 hex).
		/// If omitted, a random key is generated.
		#[arg(long)]
		private_key: Option<String>,
		/// Optional transaction ID for tracing.
		#[arg(long)]
		tx_id: Option<String>,
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
struct AccountRegisterBody {
	leaf: String,
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
		Command::RegisterAccount {
			private_key,
			balance,
			nonce,
		} => cmd_register_account(private_key, balance, nonce).await,
		Command::PrivateTx {
			input_notes,
			account_commitment,
			private_key,
			tx_id,
		} => cmd_private_tx(input_notes, account_commitment, private_key, tx_id).await,
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
	let private_key = env_required("TESSERA_OPERATOR_KEY")?;

	let signer: PrivateKeySigner = private_key
		.parse()
		.context("invalid TESSERA_OPERATOR_KEY")?;
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
// register-account
// ---------------------------------------------------------------------------

async fn cmd_register_account(private_key: String, balance: u64, nonce: u64) -> Result<()> {
	let artifacts_dir = env_required("TESSERA_ACCOUNT_ARTIFACTS_PATH")?;
	let sequencer_url =
		std::env::var("TESSERA_SEQUENCER_API_URL").unwrap_or("http://127.0.0.1:8081".to_string());

	let pk = resolve_private_key(Some(private_key))?;
	println!("private key: 0x{}", hex::encode(pk.as_slice()));

	let commitment = derive_account_commitment(&pk, balance, nonce);
	let nullifier_key = derive_nullifier_key(&pk);
	println!(
		"account commitment: 0x{}",
		hex::encode(commitment.as_slice())
	);
	println!("nullifier key: 0x{}", hex::encode(nullifier_key.as_slice()));

	// Load 8-PI account circuit and prove.
	let circuit = load_circuit(Path::new(&artifacts_dir))?;
	let n_pi = circuit.common.num_public_inputs;
	anyhow::ensure!(n_pi == 8, "expected 8-PI account circuit, got {n_pi}");
	let targets = circuit.prover_only.public_inputs.clone();

	// PI[0..4] = commitment, PI[4..8] = nullifier key
	let mut pi = [0u64; 8];
	let commitment_fields = bytes32_to_pi_fields(&commitment.0);
	let nk_fields = bytes32_to_pi_fields(&nullifier_key.0);
	pi[0..4].copy_from_slice(&commitment_fields);
	pi[4..8].copy_from_slice(&nk_fields);

	let proof_bytes = tokio::task::spawn_blocking({
		let circuit = circuit.clone();
		let targets = targets.clone();
		move || prove(&circuit, &targets, &pi)
	})
	.await??;

	let leaf_hex = format!("0x{}", hex::encode(commitment.as_slice()));
	let proof_hex = format!("0x{}", hex::encode(&proof_bytes));

	let body = AccountRegisterBody {
		leaf: leaf_hex.clone(),
		input_proof: proof_hex,
	};
	let http = reqwest::Client::new();
	let url = format!("{sequencer_url}/accounts/commitment");
	let raw_resp = http.post(&url).json(&body).send().await?;
	let status = raw_resp.status();
	if !status.is_success() {
		let text = raw_resp.text().await.unwrap_or_default();
		anyhow::bail!("/accounts/commitment returned {status}: {text}");
	}
	let resp: ApiResponse = raw_resp
		.json()
		.await
		.context("failed to parse /accounts/commitment response")?;

	if resp.accepted {
		println!("register-account: accepted");
		println!("  commitment: {leaf_hex}");
		println!(
			"  nullifier key: 0x{}",
			hex::encode(nullifier_key.as_slice())
		);
	} else {
		let reason = resp.invalid_proof_tx.map(|r| r.reason).unwrap_or_default();
		println!("register-account: REJECTED — {reason}");
	}
	Ok(())
}

// ---------------------------------------------------------------------------
// private-tx (with derivation & dummy padding)
// ---------------------------------------------------------------------------

async fn cmd_private_tx(
	input_notes: Vec<String>,
	account_commitment: String,
	private_key: Option<String>,
	tx_id: Option<String>,
) -> Result<()> {
	let artifacts_dir = env_required("TESSERA_AGGREGATOR_ARTIFACTS_PATH")?;
	let sequencer_url =
		std::env::var("TESSERA_SEQUENCER_API_URL").unwrap_or("http://127.0.0.1:8081".to_string());

	anyhow::ensure!(
		!input_notes.is_empty(),
		"at least one input note is required"
	);
	anyhow::ensure!(input_notes.len() <= 8, "too many input notes (max 8)");

	let pk = resolve_private_key(private_key)?;
	println!("private key: 0x{}", hex::encode(pk.as_slice()));

	// Parse real input notes.
	let real_notes: Vec<B256> = input_notes
		.iter()
		.map(|h| parse_b256(h))
		.collect::<Result<Vec<_>>>()?;

	// Output key = nullifier key = Poseidon(pk)
	let output_key = derive_nullifier_key(&pk);
	println!("output key: 0x{}", hex::encode(output_key.as_slice()));

	// Pad to exactly 8 notes (real + dummies).
	let all_notes = pad_dummy_notes(&real_notes);

	// Derive nullifiers and output commitments for all 8 notes.
	let input_nullifiers: Vec<B256> = all_notes
		.iter()
		.map(|note| derive_nullifier(&pk, note))
		.collect();
	let output_commitments: Vec<B256> = all_notes
		.iter()
		.map(|note| derive_output_commitment(&output_key, note))
		.collect();

	for (i, nf) in input_nullifiers.iter().enumerate() {
		let tag = if i < real_notes.len() {
			"real"
		} else {
			"dummy"
		};
		println!(
			"note {i} ({tag}) nullifier: 0x{}",
			hex::encode(nf.as_slice())
		);
	}

	// Account derivation.
	let acct = parse_b256(&account_commitment)?;
	let input_account_nullifier = derive_nullifier(&pk, &acct);
	let output_account_commitment = derive_output_commitment(&output_key, &acct);
	println!(
		"input account nullifier: 0x{}",
		hex::encode(input_account_nullifier.as_slice())
	);
	println!(
		"output account commitment: 0x{}",
		hex::encode(output_account_commitment.as_slice())
	);

	// --- Circuit proving ---
	let circuit = load_circuit(Path::new(&artifacts_dir))?;
	let n_pi = circuit.common.num_public_inputs;
	anyhow::ensure!(
		n_pi == 73,
		"expected 73-PI circuit (is_real + 72 data), got {n_pi}"
	);
	let targets = circuit.prover_only.public_inputs.clone();

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
		tx_id: tx_id.clone(),
	};

	let http = reqwest::Client::new();
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
		println!(
			"private-tx {}: accepted",
			tx_id.as_deref().unwrap_or("(no id)")
		);
	} else {
		let reason = resp.invalid_proof_tx.map(|r| r.reason).unwrap_or_default();
		println!(
			"private-tx {}: REJECTED — {reason}",
			tx_id.as_deref().unwrap_or("(no id)")
		);
	}
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

fn parse_b256(s: &str) -> Result<B256> {
	let hex = s.strip_prefix("0x").unwrap_or(s);
	anyhow::ensure!(
		hex.len() <= 64 && hex.chars().all(|c| c.is_ascii_hexdigit()),
		"invalid bytes32 hex: {s}"
	);
	let padded = format!("0x{:0>64}", hex);
	B256::from_str(&padded).with_context(|| format!("invalid bytes32 hex: {s}"))
}

const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

/// Derive a Poseidon nullifier: `nullifier = Poseidon(pk || note)`.
///
/// Both values are interpreted as 4 big-endian u64 Goldilocks field elements.
fn derive_nullifier(pk: &B256, note: &B256) -> B256 {
	let pk_fields = bytes32_to_pi_fields(&pk.0);
	let note_fields = bytes32_to_pi_fields(&note.0);
	let preimage: Vec<F> = pk_fields
		.iter()
		.chain(note_fields.iter())
		.map(|&v| F::from_canonical_u64(v))
		.collect();
	let hash: HashOut<F> = PoseidonHash::hash_no_pad(&preimage);
	pi_fields_to_b256(&hash.elements)
}

/// Encode 4 Goldilocks field elements back to a bytes32 (big-endian u64 per limb).
fn pi_fields_to_b256(fields: &[F; 4]) -> B256 {
	let mut bytes = [0u8; 32];
	for (i, &elem) in fields.iter().enumerate() {
		bytes[i * 8..(i + 1) * 8].copy_from_slice(&elem.to_canonical_u64().to_be_bytes());
	}
	B256::from(bytes)
}

/// Parse or generate a private key for nullifier derivation.
fn resolve_private_key(pk_arg: Option<String>) -> Result<B256> {
	match pk_arg {
		Some(hex) => parse_b256(&hex).context("invalid --private-key"),
		None => {
			let mut bytes = [0u8; 32];
			rand::rng().fill(&mut bytes[..]);
			// Clamp each 8-byte limb to < GOLDILOCKS_PRIME.
			for i in 0..4 {
				let limb = u64::from_be_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
				let clamped = limb % GOLDILOCKS_PRIME;
				bytes[i * 8..(i + 1) * 8].copy_from_slice(&clamped.to_be_bytes());
			}
			Ok(B256::from(bytes))
		},
	}
}

/// Derive account commitment: `Poseidon(pk_fields[0..4] || balance || nonce)` -> B256.
fn derive_account_commitment(pk: &B256, balance: u64, nonce: u64) -> B256 {
	let pk_fields = bytes32_to_pi_fields(&pk.0);
	let preimage: Vec<F> = pk_fields
		.iter()
		.copied()
		.chain([balance, nonce])
		.map(F::from_canonical_u64)
		.collect();
	let hash: HashOut<F> = PoseidonHash::hash_no_pad(&preimage);
	pi_fields_to_b256(&hash.elements)
}

/// Derive nullifier key: `Poseidon(pk_fields[0..4])` -> B256.
fn derive_nullifier_key(pk: &B256) -> B256 {
	let pk_fields = bytes32_to_pi_fields(&pk.0);
	let preimage: Vec<F> = pk_fields
		.iter()
		.map(|&v| F::from_canonical_u64(v))
		.collect();
	let hash: HashOut<F> = PoseidonHash::hash_no_pad(&preimage);
	pi_fields_to_b256(&hash.elements)
}

/// Derive output commitment: `Poseidon(output_key_fields || note_fields)` -> B256.
fn derive_output_commitment(output_key: &B256, note: &B256) -> B256 {
	let ok_fields = bytes32_to_pi_fields(&output_key.0);
	let note_fields = bytes32_to_pi_fields(&note.0);
	let preimage: Vec<F> = ok_fields
		.iter()
		.chain(note_fields.iter())
		.map(|&v| F::from_canonical_u64(v))
		.collect();
	let hash: HashOut<F> = PoseidonHash::hash_no_pad(&preimage);
	pi_fields_to_b256(&hash.elements)
}

/// Domain separator for dummy note derivation ("DUMMY" in ASCII).
const DS_DUMMY_NOTE: u64 = 0x44554d4d59;

/// Pad real input notes to 8 with deterministic Poseidon-derived dummies.
/// Returns exactly 8 B256 values (real notes first, then dummies).
fn pad_dummy_notes(real_notes: &[B256]) -> Vec<B256> {
	let n = real_notes.len();
	assert!(n <= 8, "cannot pad: more than 8 real notes");
	if n == 8 {
		return real_notes.to_vec();
	}

	// Build the real-concat field vector for the dummy derivation preimage.
	let real_concat: Vec<F> = real_notes
		.iter()
		.flat_map(|note| {
			bytes32_to_pi_fields(&note.0)
				.into_iter()
				.map(F::from_canonical_u64)
		})
		.collect();

	let mut result = real_notes.to_vec();
	for i in n..8 {
		// dummy_note[i] = Poseidon(DS_DUMMY_NOTE || i || real_concat)
		let mut preimage: Vec<F> = Vec::with_capacity(2 + real_concat.len());
		preimage.push(F::from_canonical_u64(DS_DUMMY_NOTE));
		preimage.push(F::from_canonical_u64(i as u64));
		preimage.extend_from_slice(&real_concat);
		let hash: HashOut<F> = PoseidonHash::hash_no_pad(&preimage);
		result.push(pi_fields_to_b256(&hash.elements));
	}
	result
}
