//! End-to-end test: 3 clients across 3 subpools.
//!
//! This binary:
//! 1. Registers 3 accounts, one on each subpool (DB API ports 8081/8082/8083)
//! 2. Waits for operator approval on each
//! 3. Each client deposits different amounts (1000, 2000, 3000)
//! 4. Waits for deposit approval (AST updated)
//! 5. Each client sends a partial amount to the next (1→2: 300, 2→3: 500, 3→1: 700), keeping the
//!    change as a second output note
//! 6. Waits for spend tx approval, then prints final balances
//!
//! Expected final balances (asset 1):
//!   client 1: 1000 - 300 + 700 = 1400
//!   client 2: 2000 - 500 + 300 = 1800
//!   client 3: 3000 - 700 + 500 = 2800
//!
//! Env vars:
//!   ROLLUP_ADDRESS   - deployed DoxaRollupV2 address (required)
//!   TOKEN_ADDRESS    - deployed ToyUSDT/USDX address (required)
//!   RPC_URL          - Anvil RPC (default http://localhost:8545)
//!   ASSET_ID         - asset ID as u64 (default 1)
//!   DB_API_BASE      - base URL without port (default http://localhost)

use alloy::{
	eips::Encodable2718,
	network::{EthereumWallet, TransactionBuilder},
	primitives::{Address, Bytes, U256},
	providers::{Provider, ProviderBuilder, SendableTx},
	rpc::types::TransactionRequest,
	signers::local::PrivateKeySigner,
	sol,
	sol_types::SolCall,
};
use anyhow::{Context, Result};
use plonky2_field::types::{Field, Field64, PrimeField64};
use rand::{distr::Uniform, RngExt};
use doxa_client::{
	sample_dummy_notes,
	schnorr::{CompressedPublicKey, PrivateKey, Scalar},
	AccountAddress, AssetId, DepositNote, NoteIdentifier, PrivateIdentifier, StandardAccount,
	SubpoolId, NOTE_BATCH,
};
use doxa_subpool_database::convert::{
	f_to_bytes, hash_to_hex, private_id_to_bytes, u256_to_bytes,
};
use doxa_utils::F;

/// Anvil accounts 1–3 (depositors for each subpool client).
const DEPOSITOR_KEYS: [&str; 3] = [
	"0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
	"0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
	"0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
];

sol! {
	interface IERC20 {
		function mint(address to, uint256 value) external;
		function approve(address spender, uint256 amount) external returns (bool);
	}

	interface IRollup {
		function depositAndRegister(bytes32 noteCommitment, uint256 amount) external returns (bytes32);
	}
}

fn env_or(name: &str, default: &str) -> String {
	std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_required(name: &str) -> Result<String> {
	std::env::var(name).with_context(|| format!("{name} not set"))
}

/// Per-client state built during the test.
struct Client {
	index: usize,
	subpool_id: u64,
	api_url: String,
	private_identifier: PrivateIdentifier,
	acc_address: String, // 80-char hex
	depositor_signer: PrivateKeySigner,
	depositor_addr: Address,
	deposit_note_id_hex: String, // 32-char hex (the input note identifier after deposit)
	asset_id_hex: String,        // 16-char hex
	deposit_amount: u64,         // per-client deposit amount
	send_amount: u64,            // amount to send to the next client
}

#[tokio::main]
async fn main() -> Result<()> {
	dotenvy::dotenv().ok();

	let rollup_addr: Address = env_required("ROLLUP_ADDRESS")?
		.parse()
		.context("invalid ROLLUP_ADDRESS")?;
	let token_addr: Address = env_required("TOKEN_ADDRESS")?
		.parse()
		.context("invalid TOKEN_ADDRESS")?;
	let rpc_url = env_or("RPC_URL", "http://localhost:8545");
	let db_api_base = env_or("DB_API_BASE", "http://localhost");
	let asset_id_u64: u64 = env_or("ASSET_ID", "1")
		.parse()
		.context("invalid ASSET_ID")?;
	let asset_id = AssetId::from_u64(asset_id_u64)?;

	// Per-client deposit and send amounts
	let deposit_amounts: [u64; 3] = [1000, 2000, 3000];
	let send_amounts: [u64; 3] = [300, 500, 700]; // 1→2: 300, 2→3: 500, 3→1: 700

	let http = reqwest::Client::new();
	let mut rng = rand::rng();

	let api_ports = [8081, 8082, 8083];
	let subpool_ids: [u64; 3] = [1, 2, 3];

	// ════════════════════════════════════════════════════════════════════════════
	//  PHASE 1: Register 3 accounts
	// ════════════════════════════════════════════════════════════════════════════
	println!("═══ PHASE 1: Register accounts ═══\n");

	let mut clients: Vec<Client> = Vec::new();

	for i in 0..3 {
		let api_url = format!("{}:{}", db_api_base, api_ports[i]);
		let subpool_id = subpool_ids[i];
		let depositor_signer: PrivateKeySigner = DEPOSITOR_KEYS[i].parse()?;
		let depositor_addr = depositor_signer.address();

		// Random private identifier
		let private_identifier = PrivateIdentifier([
			F::from_canonical_u64(rng.sample(Uniform::new(0, F::ORDER).unwrap())),
			F::from_canonical_u64(rng.sample(Uniform::new(0, F::ORDER).unwrap())),
		]);
		let pi_hex = hex::encode(private_id_to_bytes(&private_identifier));

		// Random spend_auth keypair
		let spend_sk = PrivateKey::new(Scalar::sample(&mut rng));
		let spend_pk = spend_sk.public_key::<F>();
		let compressed_pk: CompressedPublicKey<F> = spend_pk.into();
		let spend_pk_hex = hex::encode(compressed_pk.encode());

		let register_body = serde_json::json!({
			"private_identifier": pi_hex,
			"spend_auth_pk": spend_pk_hex,
			"eth_address": format!("{depositor_addr}"),
			"name": format!("client-{}", i + 1),
			"physical_address": "test",
			"dob": "2000-01-01",
		});

		println!(
			"[client {}] registering on subpool {} ({})...",
			i + 1,
			subpool_id,
			api_url
		);

		let resp = http
			.post(format!("{api_url}/register"))
			.json(&register_body)
			.send()
			.await
			.with_context(|| format!("failed to reach {api_url}/register"))?;

		let status = resp.status();
		let resp_body: serde_json::Value =
			resp.json().await.context("invalid JSON from /register")?;
		if !status.is_success() {
			anyhow::bail!(
				"[client {}] registration failed (HTTP {status}): {resp_body}",
				i + 1
			);
		}

		let acc_address = resp_body["private_acc_address"]
			.as_str()
			.context("missing private_acc_address")?
			.to_string();

		println!("[client {}] registered: {}", i + 1, acc_address);

		clients.push(Client {
			index: i,
			subpool_id,
			api_url,
			private_identifier,
			acc_address,
			depositor_signer,
			depositor_addr,
			deposit_note_id_hex: String::new(),
			asset_id_hex: hex::encode(f_to_bytes(F::from_canonical_u64(asset_id_u64))),
			deposit_amount: deposit_amounts[i],
			send_amount: send_amounts[i],
		});
	}

	// ════════════════════════════════════════════════════════════════════════════
	//  PHASE 2: Wait for operator approval
	// ════════════════════════════════════════════════════════════════════════════
	println!("\n═══ PHASE 2: Wait for operator approval ═══\n");

	for c in &clients {
		print!("[client {}] waiting for approval", c.index + 1);
		loop {
			let resp = http
				.get(format!("{}/account/{}", c.api_url, c.acc_address))
				.send()
				.await?;

			if resp.status().is_success() {
				println!(" confirmed!");
				break;
			}
			tokio::time::sleep(std::time::Duration::from_secs(2)).await;
			print!(".");
		}
	}

	// ════════════════════════════════════════════════════════════════════════════
	//  PHASE 3: Deposit funds
	// ════════════════════════════════════════════════════════════════════════════
	println!("\n═══ PHASE 3: Deposit funds ═══\n");

	for c in &mut clients {
		let amount = c.deposit_amount;
		let amount_u256 = U256::from(amount);

		let wallet = EthereumWallet::from(c.depositor_signer.clone());
		let provider = ProviderBuilder::new()
			.wallet(wallet)
			.connect_http(rpc_url.parse()?);

		// Mint tokens
		println!("[client {}] minting {} tokens...", c.index + 1, amount);
		let mint_calldata = IERC20::mintCall {
			to: c.depositor_addr,
			value: amount_u256,
		}
		.abi_encode();

		let mint_tx = TransactionRequest::default()
			.to(token_addr)
			.input(mint_calldata.into());
		provider
			.send_transaction(mint_tx)
			.await?
			.get_receipt()
			.await?;

		// Approve rollup
		let approve_calldata = IERC20::approveCall {
			spender: rollup_addr,
			amount: amount_u256,
		}
		.abi_encode();

		let approve_tx = TransactionRequest::default()
			.to(token_addr)
			.input(approve_calldata.into());
		provider
			.send_transaction(approve_tx)
			.await?
			.get_receipt()
			.await?;

		// Build deposit note
		let note_identifier = NoteIdentifier([
			F::from_canonical_u64(rng.sample(Uniform::new(0, F::ORDER).unwrap())),
			F::from_canonical_u64(rng.sample(Uniform::new(0, F::ORDER).unwrap())),
		]);

		let sid = SubpoolId(F::from_canonical_u64(c.subpool_id));
		let acc = StandardAccount::new_with(c.private_identifier, sid);
		let recipient = AccountAddress::from_acc(&acc);

		let deposit_note = DepositNote {
			identifier: note_identifier,
			recipient,
			amount: primitive_types::U256::from(amount),
			asset_id,
		};
		let note_comm = deposit_note.commitment();

		let comm_bytes: [u8; 32] = {
			let mut out = [0u8; 32];
			for (i, f) in note_comm.0 .0.iter().enumerate() {
				out[i * 8..(i + 1) * 8].copy_from_slice(&f.to_canonical_u64().to_be_bytes());
			}
			out
		};

		// Build signed depositAndRegister tx
		let deposit_calldata = IRollup::depositAndRegisterCall {
			noteCommitment: comm_bytes.into(),
			amount: amount_u256,
		}
		.abi_encode();

		let nonce = provider.get_transaction_count(c.depositor_addr).await?;
		let gas_price = provider.get_gas_price().await?;
		let chain_id = provider.get_chain_id().await?;

		let mut deposit_tx = TransactionRequest::default()
			.to(rollup_addr)
			.input(Bytes::from(deposit_calldata).into())
			.nonce(nonce)
			.gas_price(gas_price.saturating_add(gas_price / 10))
			.gas_limit(500_000);
		deposit_tx.set_chain_id(chain_id);

		let sendable = provider
			.fill(deposit_tx)
			.await
			.context("failed to fill deposit tx")?;
		let raw_tx = match &sendable {
			SendableTx::Envelope(env) => env.encoded_2718(),
			_ => anyhow::bail!("fill did not produce a signed envelope"),
		};
		let raw_tx_hex = hex::encode(&raw_tx);

		// Encode and POST deposit
		let note_id_bytes = {
			let mut out = [0u8; 16];
			out[..8].copy_from_slice(&f_to_bytes(note_identifier.0[0]));
			out[8..].copy_from_slice(&f_to_bytes(note_identifier.0[1]));
			out
		};
		let note_id_hex = hex::encode(note_id_bytes);
		let amount_bytes = u256_to_bytes(primitive_types::U256::from(amount));
		let asset_id_bytes = f_to_bytes(F::from_canonical_u64(asset_id_u64));

		let body = serde_json::json!({
			"recipient_address": c.acc_address,
			"eth_address": format!("{}", c.depositor_addr),
			"deposit_note_identifier": &note_id_hex,
			"deposit_amount": hex::encode(amount_bytes),
			"asset_id": hex::encode(asset_id_bytes),
			"signed_public_tx": raw_tx_hex,
		});

		let resp = http
			.post(format!("{}/deposit", c.api_url))
			.json(&body)
			.send()
			.await
			.with_context(|| format!("failed to POST deposit for client {}", c.index + 1))?;

		let status = resp.status();
		let resp_text = resp.text().await.unwrap_or_default();
		if !status.is_success() {
			anyhow::bail!(
				"[client {}] deposit failed (HTTP {status}): {resp_text}",
				c.index + 1
			);
		}

		// Store note identifier for the spend tx input note
		c.deposit_note_id_hex = note_id_hex;

		println!(
			"[client {}] deposit of {} submitted (note_id={})",
			c.index + 1,
			amount,
			&c.deposit_note_id_hex
		);
	}

	// ════════════════════════════════════════════════════════════════════════════
	//  PHASE 4: Wait for deposit approval
	// ════════════════════════════════════════════════════════════════════════════
	println!("\n═══ PHASE 4: Wait for deposit approval ═══\n");

	for c in &clients {
		print!(
			"[client {}] waiting for deposit to be processed",
			c.index + 1
		);
		loop {
			let resp = http
				.get(format!("{}/account/{}", c.api_url, c.acc_address))
				.send()
				.await?;

			if resp.status().is_success() {
				let body: serde_json::Value = resp.json().await?;
				// Check if AST has a non-empty entry (deposit was applied to the account state
				// tree)
				if let Some(ast) = body.get("ast").and_then(|v| v.as_object()) {
					if !ast.is_empty() {
						println!(" AST updated!");
						break;
					}
				}
			}
			tokio::time::sleep(std::time::Duration::from_secs(2)).await;
			print!(".");
		}
	}

	// ════════════════════════════════════════════════════════════════════════════
	//  PHASE 5: Submit spend txs (client N → client N+1 mod 3)
	// ════════════════════════════════════════════════════════════════════════════
	println!("\n═══ PHASE 5: Spend transactions ═══\n");

	// Collect data needed across clients before the loop
	let recipient_addresses: Vec<String> = clients.iter().map(|c| c.acc_address.clone()).collect();
	let deposit_amount_hexes: Vec<String> = clients
		.iter()
		.map(|c| hex::encode(u256_to_bytes(primitive_types::U256::from(c.deposit_amount))))
		.collect();

	for i in 0..3 {
		let next = (i + 1) % 3;
		let sender = &clients[i];
		let recipient_addr = &recipient_addresses[next];
		let send_amount = sender.send_amount;
		let change_amount = sender.deposit_amount - send_amount;

		// The spend tx consumes the deposit input note and creates:
		//   - 1 output note to the recipient (send_amount)
		//   - 1 output note back to self as change (change_amount)
		// Conservation: deposit_amount == send_amount + change_amount

		let send_amount_hex = hex::encode(u256_to_bytes(primitive_types::U256::from(send_amount)));
		let change_amount_hex =
			hex::encode(u256_to_bytes(primitive_types::U256::from(change_amount)));

		// Generate random identifiers for output notes
		let gen_note_id_hex = |rng: &mut rand::rngs::ThreadRng| -> String {
			let id: [F; 2] = [
				F::from_canonical_u64(rng.sample(Uniform::new(0, F::ORDER).unwrap())),
				F::from_canonical_u64(rng.sample(Uniform::new(0, F::ORDER).unwrap())),
			];
			let mut out = [0u8; 16];
			out[..8].copy_from_slice(&f_to_bytes(id[0]));
			out[8..].copy_from_slice(&f_to_bytes(id[1]));
			hex::encode(out)
		};

		let send_note_id = gen_note_id_hex(&mut rng);
		let change_note_id = gen_note_id_hex(&mut rng);
		let (dummy_in_notes, dummy_out_notes) = sample_dummy_notes(&mut rand::rng());
		let dinotes: Vec<String> = dummy_in_notes
			.into_iter()
			.take(NOTE_BATCH - 1)
			.map(|note| hash_to_hex(&note))
			.collect();
		let donotes: Vec<String> = dummy_out_notes
			.into_iter()
			.take(NOTE_BATCH - 2)
			.map(|note| hash_to_hex(&note))
			.collect();

		let spend_body = serde_json::json!({
			"priv_acc_address": sender.acc_address,
			"input_notes": [{
				"identifier": sender.deposit_note_id_hex,
				"asset_id": sender.asset_id_hex,
				"amount": deposit_amount_hexes[i],
				"recipient_address": sender.acc_address,
				"sender_address": sender.acc_address,
				"memo": "",
			}],
			"output_notes": [
				{
					"identifier": send_note_id,
					"asset_id": sender.asset_id_hex,
					"amount": send_amount_hex,
					"recipient_address": recipient_addr,
					"sender_address": sender.acc_address,
					"memo": "",
				},
				{
					"identifier": change_note_id,
					"asset_id": sender.asset_id_hex,
					"amount": change_amount_hex,
					"recipient_address": sender.acc_address,
					"sender_address": sender.acc_address,
					"memo": "",
				}
			],
			"dinotes": dinotes,
			"donotes": donotes,
			"spend_tx_signature": "",
		});

		println!(
			"[client {}] sending {} to client {}, keeping {} change (subpool {} -> subpool {})",
			i + 1,
			send_amount,
			next + 1,
			change_amount,
			sender.subpool_id,
			clients[next].subpool_id
		);

		// Retry until input notes are APPROVED (on-chain deposit confirmation may take a few
		// seconds)
		let mut attempts = 0;
		loop {
			let resp = http
				.post(format!("{}/spend_tx", sender.api_url))
				.json(&spend_body)
				.send()
				.await
				.with_context(|| format!("failed to POST spend_tx for client {}", i + 1))?;

			let status = resp.status();
			let resp_text = resp.text().await.unwrap_or_default();

			if status.is_success() {
				println!("[client {}] spend tx submitted: {}", i + 1, resp_text);
				break;
			}

			attempts += 1;
			if attempts > 30 {
				println!(
					"[client {}] spend tx FAILED after 30 attempts: {resp_text}",
					i + 1
				);
				break;
			}

			// Input notes may still be PENDING (awaiting on-chain confirmation), retry
			if attempts == 1 {
				print!("[client {}] waiting for input notes to be approved", i + 1);
			}
			print!(".");
			tokio::time::sleep(std::time::Duration::from_secs(2)).await;
		}
	}

	// ════════════════════════════════════════════════════════════════════════════
	//  PHASE 6: Wait for spend tx approval
	// ════════════════════════════════════════════════════════════════════════════
	println!("\n═══ PHASE 6: Wait for spend tx approval ═══\n");

	// After spend tx approval, sender's nonce should be incremented to 2
	// (nonce 0→1 from deposit, 1→2 from spend tx).
	for c in &clients {
		print!(
			"[client {}] waiting for spend tx to be processed",
			c.index + 1
		);
		let mut attempts = 0;
		loop {
			let resp = http
				.get(format!("{}/account/{}", c.api_url, c.acc_address))
				.send()
				.await?;

			if resp.status().is_success() {
				let body: serde_json::Value = resp.json().await?;
				// Nonce is hex-encoded u64 LE (8 bytes = 16 hex chars).
				// After deposit (nonce=1) + spend (nonce=2), we expect nonce >= 2.
				if let Some(nonce_hex) = body.get("nonce").and_then(|v| v.as_str()) {
					let nonce_bytes = hex::decode(nonce_hex).unwrap_or_default();
					if nonce_bytes.len() == 8 {
						let nonce_val = u64::from_le_bytes(nonce_bytes.try_into().unwrap());
						if nonce_val >= 2 {
							println!(" nonce={nonce_val} (spend tx processed)!");
							break;
						}
					}
				}
			}

			attempts += 1;
			if attempts > 30 {
				println!(" TIMEOUT (nonce not updated after 60s)");
				break;
			}
			tokio::time::sleep(std::time::Duration::from_secs(2)).await;
			print!(".");
		}
	}

	// ════════════════════════════════════════════════════════════════════════════
	//  PHASE 7: Print final balances
	// ════════════════════════════════════════════════════════════════════════════
	println!("\n═══ PHASE 7: Final balances ═══\n");

	let asset_key = asset_id_u64.to_string();
	// After spend txs:
	//   AST (confirmed) = deposit - sent_to_others
	//   total (once confirmed) = AST + pending = deposit - sent + received
	let expected_ast = [
		deposit_amounts[0] - send_amounts[0], // 700
		deposit_amounts[1] - send_amounts[1], // 1500
		deposit_amounts[2] - send_amounts[2], // 2300
	];
	let expected_pending = [
		send_amounts[2], // 700  (received from client 3)
		send_amounts[0], // 300  (received from client 1)
		send_amounts[1], // 500  (received from client 2)
	];
	let expected_total = [
		expected_ast[0] + expected_pending[0], // 1400
		expected_ast[1] + expected_pending[1], // 1800
		expected_ast[2] + expected_pending[2], // 2800
	];

	// Parse AST balance for a given asset key from the AST JSON object
	let parse_ast_balance = |ast: &serde_json::Value, key: &str| -> u64 {
		ast.get(key)
			.and_then(|e| e.get("amount"))
			.and_then(|v| v.as_str())
			.and_then(|hex_str| {
				let bytes = hex::decode(hex_str).ok()?;
				let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
				Some(doxa_subpool_database::convert::bytes_to_u256(&arr))
			})
			.map(|u| u.as_u64())
			.unwrap_or(0)
	};

	let parse_notes_balance = |body: &serde_json::Value| -> u64 {
		body.get("balances")
			.and_then(|b| b.get(&asset_key))
			.and_then(|e| e.get("amount"))
			.and_then(|v| v.as_str())
			.and_then(|hex_str| {
				let trimmed = hex_str.trim_start_matches('0');
				if trimmed.is_empty() {
					Some(0)
				} else {
					u64::from_str_radix(trimmed, 16).ok()
				}
			})
			.unwrap_or(0)
	};

	println!("Waiting for cross-subpool notes to settle...");
	let mut printed = vec![false; clients.len()];
	for c in &clients {
		println!("[client {}] waiting for final confirmation", c.index + 1);
	}
	for attempt in 0..=30 {
		let mut remaining = 0usize;
		for c in &clients {
			if printed[c.index] {
				continue;
			}

			let resp = http
				.get(format!("{}/account/{}", c.api_url, c.acc_address))
				.send()
				.await?;
			let ast_bal = if resp.status().is_success() {
				let body: serde_json::Value = resp.json().await?;
				body.get("ast")
					.map(|a| parse_ast_balance(a, &asset_key))
					.unwrap_or(0)
			} else {
				0
			};

			let nb_resp = http
				.get(format!("{}/notes_balance/{}", c.api_url, c.acc_address))
				.send()
				.await?;
			let notes_bal = if nb_resp.status().is_success() {
				let nb_body: serde_json::Value = nb_resp.json().await?;
				parse_notes_balance(&nb_body)
			} else {
				0
			};

			let total = notes_bal;
			if ast_bal == expected_ast[c.index] && total == expected_total[c.index] {
				printed[c.index] = true;
				println!(
					"[client {}] subpool {} | asset {} | confirmed: {} (exp {}) [OK] | total: {} (exp {}) [OK]",
					c.index + 1,
					c.subpool_id,
					asset_id_u64,
					ast_bal,
					expected_ast[c.index],
					total,
					expected_total[c.index],
				);
			} else {
				println!(
					"[client {}] still waiting: confirmed={} / {} | total={} / {}",
					c.index + 1,
					ast_bal,
					expected_ast[c.index],
					total,
					expected_total[c.index],
				);
				remaining += 1;
				if attempt == 30 {
					let ast_check = if ast_bal == expected_ast[c.index] {
						"OK"
					} else {
						"MISMATCH"
					};
					let total_check = if total == expected_total[c.index] {
						"OK"
					} else {
						"MISMATCH"
					};
					println!(
						"[client {}] TIMEOUT -> subpool {} | asset {} | confirmed: {} (exp {}) [{}] | total: {} (exp {}) [{}]",
						c.index + 1,
						c.subpool_id,
						asset_id_u64,
						ast_bal,
						expected_ast[c.index],
						ast_check,
						total,
						expected_total[c.index],
						total_check,
					);
					printed[c.index] = true;
				}
			}
		}
		if remaining == 0 {
			break;
		}
		if attempt < 30 {
			tokio::time::sleep(std::time::Duration::from_secs(2)).await;
		}
	}

	println!("\n═══ E2E TEST COMPLETE ═══");
	println!(
		"  deposits:  client 1={}, client 2={}, client 3={}",
		deposit_amounts[0], deposit_amounts[1], deposit_amounts[2]
	);
	println!(
		"  transfers: 1->2: {}, 2->3: {}, 3->1: {}",
		send_amounts[0], send_amounts[1], send_amounts[2]
	);
	println!(
		"  expected totals: client 1={}, client 2={}, client 3={}",
		expected_total[0], expected_total[1], expected_total[2]
	);

	Ok(())
}
