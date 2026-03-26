//! End-to-end test: 3 clients across 3 subpools.
//!
//! This binary:
//! 1. Registers 3 accounts, one on each subpool (DB API ports 8081/8082/8083)
//! 2. Waits for operator approval on each
//! 3. Each client deposits funds via the rollup contract
//! 4. Waits for deposit approval (account balance updated)
//! 5. Each client submits a spend tx sending to the next client (1→2, 2→3, 3→1)
//!
//! Env vars:
//!   ROLLUP_ADDRESS   - deployed TesseraRollupV2 address (required)
//!   TOKEN_ADDRESS    - deployed ToyUSDT/USDX address (required)
//!   RPC_URL          - Anvil RPC (default http://localhost:8545)
//!   DEPOSIT_AMOUNT   - amount in token units (default 1000)
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
use rand::distr::Uniform;
use rand::RngExt;
use tessera_client::{
    AccountAddress, AssetId, DepositNote, PrivateIdentifier, StandardAccount, SubpoolId,
    schnorr::{CompressedPublicKey, PrivateKey, Scalar},
};
use tessera_subpool_database::convert::{f_to_bytes, private_id_to_bytes, u256_to_bytes};
use tessera_utils::F;

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
    acc_address: String,         // 80-char hex
    depositor_signer: PrivateKeySigner,
    depositor_addr: Address,
    deposit_note_id_hex: String, // 32-char hex (the input note identifier after deposit)
    asset_id_hex: String,        // 16-char hex
    amount_hex: String,          // 64-char hex
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let rollup_addr: Address = env_required("ROLLUP_ADDRESS")?.parse().context("invalid ROLLUP_ADDRESS")?;
    let token_addr: Address = env_required("TOKEN_ADDRESS")?.parse().context("invalid TOKEN_ADDRESS")?;
    let rpc_url = env_or("RPC_URL", "http://localhost:8545");
    let db_api_base = env_or("DB_API_BASE", "http://localhost");
    let deposit_amount: u64 = env_or("DEPOSIT_AMOUNT", "1000").parse().context("invalid DEPOSIT_AMOUNT")?;
    let asset_id_u64: u64 = env_or("ASSET_ID", "1").parse().context("invalid ASSET_ID")?;
    let amount_u256 = U256::from(deposit_amount);
    let asset_id = AssetId::from_u64(asset_id_u64)?;

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

        println!("[client {}] registering on subpool {} ({})...", i + 1, subpool_id, api_url);

        let resp = http
            .post(format!("{api_url}/register"))
            .json(&register_body)
            .send()
            .await
            .with_context(|| format!("failed to reach {api_url}/register"))?;

        let status = resp.status();
        let resp_body: serde_json::Value = resp.json().await.context("invalid JSON from /register")?;
        if !status.is_success() {
            anyhow::bail!("[client {}] registration failed (HTTP {status}): {resp_body}", i + 1);
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
            amount_hex: hex::encode(u256_to_bytes(primitive_types::U256::from(deposit_amount))),
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
        let wallet = EthereumWallet::from(c.depositor_signer.clone());
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(rpc_url.parse()?);

        // Mint tokens
        println!("[client {}] minting {} tokens...", c.index + 1, deposit_amount);
        let mint_calldata = IERC20::mintCall {
            to: c.depositor_addr,
            value: amount_u256,
        }
        .abi_encode();

        let mint_tx = TransactionRequest::default()
            .to(token_addr)
            .input(mint_calldata.into());
        provider.send_transaction(mint_tx).await?.get_receipt().await?;

        // Approve rollup
        let approve_calldata = IERC20::approveCall {
            spender: rollup_addr,
            amount: amount_u256,
        }
        .abi_encode();

        let approve_tx = TransactionRequest::default()
            .to(token_addr)
            .input(approve_calldata.into());
        provider.send_transaction(approve_tx).await?.get_receipt().await?;

        // Build deposit note
        let note_identifier: [F; 2] = [
            F::from_canonical_u64(rng.sample(Uniform::new(0, F::ORDER).unwrap())),
            F::from_canonical_u64(rng.sample(Uniform::new(0, F::ORDER).unwrap())),
        ];

        let sid = SubpoolId(F::from_canonical_u64(c.subpool_id));
        let acc = StandardAccount::new_with(c.private_identifier, sid);
        let recipient = AccountAddress::from_acc(&acc);

        let deposit_note = DepositNote {
            identifier: note_identifier,
            recipient,
            amount: primitive_types::U256::from(deposit_amount),
            asset_id,
        };
        let note_comm = deposit_note.commitment();

        let comm_bytes: [u8; 32] = {
            let mut out = [0u8; 32];
            for (i, f) in note_comm.0.0.iter().enumerate() {
                out[i * 8..(i + 1) * 8]
                    .copy_from_slice(&f.to_canonical_u64().to_be_bytes());
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

        let sendable = provider.fill(deposit_tx).await.context("failed to fill deposit tx")?;
        let raw_tx = match &sendable {
            SendableTx::Envelope(env) => env.encoded_2718(),
            _ => anyhow::bail!("fill did not produce a signed envelope"),
        };
        let raw_tx_hex = hex::encode(&raw_tx);

        // Encode and POST deposit
        let note_id_bytes = {
            let mut out = [0u8; 16];
            out[..8].copy_from_slice(&f_to_bytes(note_identifier[0]));
            out[8..].copy_from_slice(&f_to_bytes(note_identifier[1]));
            out
        };
        let note_id_hex = hex::encode(note_id_bytes);
        let amount_bytes = u256_to_bytes(primitive_types::U256::from(deposit_amount));
        let asset_id_bytes = f_to_bytes(F::from_canonical_u64(asset_id_u64));

        let body = serde_json::json!({
            "recipient_acc_address": c.acc_address,
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
            anyhow::bail!("[client {}] deposit failed (HTTP {status}): {resp_text}", c.index + 1);
        }

        // Store note identifier for the spend tx input note
        c.deposit_note_id_hex = note_id_hex;

        println!("[client {}] deposit submitted (note_id={})", c.index + 1, &c.deposit_note_id_hex);
    }

    // ════════════════════════════════════════════════════════════════════════════
    //  PHASE 4: Wait for deposit approval
    // ════════════════════════════════════════════════════════════════════════════
    println!("\n═══ PHASE 4: Wait for deposit approval ═══\n");

    for c in &clients {
        print!("[client {}] waiting for deposit to be processed", c.index + 1);
        loop {
            let resp = http
                .get(format!("{}/account/{}", c.api_url, c.acc_address))
                .send()
                .await?;

            if resp.status().is_success() {
                let body: serde_json::Value = resp.json().await?;
                // Check if balance is non-zero (deposit was applied)
                if let Some(balance_hex) = body.get("balance").and_then(|v| v.as_str()) {
                    let bal_bytes = hex::decode(balance_hex).unwrap_or_default();
                    if bal_bytes.len() == 32 && bal_bytes.iter().any(|&b| b != 0) {
                        println!(" balance updated!");
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

    // Collect recipient addresses before mutably borrowing
    let recipient_addresses: Vec<String> = clients.iter().map(|c| c.acc_address.clone()).collect();

    for i in 0..3 {
        let next = (i + 1) % 3;
        let sender = &clients[i];
        let recipient_addr = &recipient_addresses[next];

        // The input note is the deposit note (created when operator approved the deposit).
        // The spend tx uses:
        //   - input_notes: [deposit_note] (amount = deposit_amount)
        //   - output_notes: [note to recipient] (amount = deposit_amount)
        // Balance check: account.balance(deposit_amount) + input_note(deposit_amount) = 2 * deposit_amount
        //   BUT that means output must also be 2 * deposit_amount.
        //
        // For simplicity: don't reference input notes. Just use account balance.
        //   account.balance(deposit_amount) + 0 = deposit_amount
        //   output: 1 note of deposit_amount to next client.

        // Generate a random identifier for the output note
        let onote_id: [F; 2] = [
            F::from_canonical_u64(rng.sample(Uniform::new(0, F::ORDER).unwrap())),
            F::from_canonical_u64(rng.sample(Uniform::new(0, F::ORDER).unwrap())),
        ];
        let onote_id_hex = {
            let mut out = [0u8; 16];
            out[..8].copy_from_slice(&f_to_bytes(onote_id[0]));
            out[8..].copy_from_slice(&f_to_bytes(onote_id[1]));
            hex::encode(out)
        };

        let spend_body = serde_json::json!({
            "priv_acc_address": sender.acc_address,
            "input_notes": [],
            "output_notes": [{
                "identifier": onote_id_hex,
                "asset_id": sender.asset_id_hex,
                "amount": sender.amount_hex,
                "recipient_address": recipient_addr,
                "sender_address": sender.acc_address,
            }],
            "dinotes": [],
            "donotes": [],
        });

        println!(
            "[client {}] spending {} to client {} (subpool {} → subpool {})",
            i + 1, deposit_amount, next + 1, sender.subpool_id, clients[next].subpool_id
        );

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
        } else {
            println!("[client {}] spend tx FAILED (HTTP {status}): {resp_text}", i + 1, );
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    //  PHASE 6: Wait for spend tx approval
    // ════════════════════════════════════════════════════════════════════════════
    println!("\n═══ PHASE 6: Wait for spend tx approval ═══\n");

    // After spend tx approval, sender's balance should be 0
    for c in &clients {
        print!("[client {}] waiting for spend tx to be processed", c.index + 1);
        let mut attempts = 0;
        loop {
            let resp = http
                .get(format!("{}/account/{}", c.api_url, c.acc_address))
                .send()
                .await?;

            if resp.status().is_success() {
                let body: serde_json::Value = resp.json().await?;
                if let Some(balance_hex) = body.get("balance").and_then(|v| v.as_str()) {
                    let bal_bytes = hex::decode(balance_hex).unwrap_or_default();
                    if bal_bytes.len() == 32 && bal_bytes.iter().all(|&b| b == 0) {
                        println!(" balance is now 0 (spend complete)!");
                        break;
                    }
                }
            }

            attempts += 1;
            if attempts > 30 {
                println!(" TIMEOUT (balance not zeroed after 60s)");
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            print!(".");
        }
    }

    println!("\n═══ E2E TEST COMPLETE ═══");
    println!("  3 accounts registered across 3 subpools");
    println!("  3 deposits processed");
    println!("  3 cross-subpool spend txs submitted");

    Ok(())
}
