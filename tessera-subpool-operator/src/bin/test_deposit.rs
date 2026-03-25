//! Test helper: register a Tessera account, then submit a deposit request.
//!
//! This binary:
//! 1. Generates a random private_identifier and spend_auth keypair
//! 2. Registers a fresh account via the DB API `/register`
//! 3. Mints test USDC to the depositor (Anvil account 1)
//! 4. Approves the rollup contract to spend it
//! 5. Creates and signs a `depositAndRegister(noteCommitment, amount)` tx
//!    WITHOUT broadcasting (the operator will broadcast it later)
//! 6. Computes the deposit note commitment (Poseidon hash)
//! 7. POSTs the deposit request to the DB API `/deposit`
//!
//! Env vars:
//!   ROLLUP_ADDRESS   - deployed TesseraRollupV2 address (required)
//!   TOKEN_ADDRESS    - deployed ToyUSDT/USDX address (required)
//!   RPC_URL          - Anvil RPC (default http://localhost:8545)
//!   DB_API_URL       - subpool database API (default http://localhost:8080)
//!   DEPOSIT_AMOUNT   - amount in token units (default 1000)
//!   ASSET_ID         - asset ID as u64 (default 1)

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
use tessera_subpool_database::convert::{f_to_bytes, hash_to_hex, private_id_to_bytes, u256_to_bytes};
use tessera_subpool_database::SUBPOOL_ID;
use tessera_utils::F;

/// Anvil account 1 (depositor).
const DEPOSITOR_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

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

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let rollup_addr: Address = env_required("ROLLUP_ADDRESS")?.parse().context("invalid ROLLUP_ADDRESS")?;
    let token_addr: Address = env_required("TOKEN_ADDRESS")?.parse().context("invalid TOKEN_ADDRESS")?;
    let rpc_url = env_or("RPC_URL", "http://localhost:8545");
    let db_api_url = env_or("DB_API_URL", "http://localhost:8080");
    let deposit_amount: u64 = env_or("DEPOSIT_AMOUNT", "1000").parse().context("invalid DEPOSIT_AMOUNT")?;
    let asset_id_u64: u64 = env_or("ASSET_ID", "1").parse().context("invalid ASSET_ID")?;

    let client = reqwest::Client::new();
    let api_base = db_api_url.trim_end_matches('/');

    // ── 1. Build depositor provider (Anvil account 1) ────────────────────────
    let depositor_signer: PrivateKeySigner = DEPOSITOR_KEY.parse()?;
    let depositor_addr = depositor_signer.address();
    let wallet = EthereumWallet::from(depositor_signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse()?);

    // ── 2. Register a fresh Tessera account ─────────────────────────────────
    println!("registering a fresh Tessera account...");
    let mut rng = rand::rng();

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
        "name": "test-depositor",
        "physical_address": "test",
        "dob": "2000-01-01",
    });

    let resp = client
        .post(format!("{api_base}/register"))
        .json(&register_body)
        .send()
        .await
        .context("failed to reach DB API /register")?;

    let status = resp.status();
    let resp_body: serde_json::Value = resp.json().await.context("invalid JSON from /register")?;
    if !status.is_success() {
        anyhow::bail!("registration failed (HTTP {status}): {resp_body}");
    }

    let user_acc = resp_body["private_acc_address"]
        .as_str()
        .context("missing private_acc_address in register response")?
        .to_string();

    // Derive the AccountAddress for the deposit note
    let subpool_id = SubpoolId(F::from_canonical_u64(SUBPOOL_ID));
    let acc = StandardAccount::new_with(private_identifier, subpool_id);
    let recipient = AccountAddress::from_acc(&acc);

    println!("  registered: {user_acc}");

    // ── 3. Wait for operator to process the freshacc request ────────────────
    println!("\nwaiting for operator to approve registration...");
    loop {
        let resp = client
            .get(format!("{api_base}/account/{user_acc}"))
            .send()
            .await
            .context("failed to reach DB API")?;

        if resp.status().is_success() {
            println!("  account confirmed in DB");
            break;
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        print!(".");
    }

    // ── 3. Print summary ────────────────────────────────────────────────────
    println!("\ndepositor:  {depositor_addr}");
    println!("rollup:     {rollup_addr}");
    println!("token:      {token_addr}");
    println!("recipient:  {user_acc}");
    println!("amount:     {deposit_amount}");
    println!("asset_id:   {asset_id_u64}");

    let amount_u256 = U256::from(deposit_amount);

    // ── 4. Mint tokens to depositor ─────────────────────────────────────────
    println!("\nminting {deposit_amount} tokens to depositor...");
    let mint_calldata = IERC20::mintCall {
        to: depositor_addr,
        value: amount_u256,
    }
    .abi_encode();

    let mint_tx = TransactionRequest::default()
        .to(token_addr)
        .input(mint_calldata.into());
    provider.send_transaction(mint_tx).await?.get_receipt().await?;
    println!("  minted");

    // ── 5. Approve rollup to spend tokens ───────────────────────────────────
    println!("approving rollup to spend tokens...");
    let approve_calldata = IERC20::approveCall {
        spender: rollup_addr,
        amount: amount_u256,
    }
    .abi_encode();

    let approve_tx = TransactionRequest::default()
        .to(token_addr)
        .input(approve_calldata.into());
    provider.send_transaction(approve_tx).await?.get_receipt().await?;
    println!("  approved");

    // ── 6. Generate deposit note identifier and compute commitment ──────────
    let note_identifier: [F; 2] = [
        F::from_canonical_u64(rng.sample(Uniform::new(0, F::ORDER).unwrap())),
        F::from_canonical_u64(rng.sample(Uniform::new(0, F::ORDER).unwrap())),
    ];

    let asset_id = AssetId::from_u64(asset_id_u64)?;
    let deposit_note = DepositNote {
        identifier: note_identifier,
        recipient,
        amount: primitive_types::U256::from(deposit_amount),
        asset_id,
    };
    let note_comm = deposit_note.commitment();
    let note_comm_hex = hash_to_hex(&note_comm.0.0);
    println!("\nnote_commitment = {note_comm_hex}");

    // Convert to bytes32 for the on-chain call.
    let comm_bytes: [u8; 32] = {
        let mut out = [0u8; 32];
        for (i, f) in note_comm.0.0.iter().enumerate() {
            out[i * 8..(i + 1) * 8]
                .copy_from_slice(&f.to_canonical_u64().to_be_bytes());
        }
        out
    };

    // ── 7. Build signed depositAndRegister tx (without broadcasting) ─
    println!("creating signed depositAndRegister tx...");
    let deposit_calldata = IRollup::depositAndRegisterCall {
        noteCommitment: comm_bytes.into(),
        amount: amount_u256,
    }
    .abi_encode();

    // Get nonce and gas for the depositor.
    let nonce = provider.get_transaction_count(depositor_addr).await?;
    let gas_price = provider.get_gas_price().await?;
    let chain_id = provider.get_chain_id().await?;

    let mut deposit_tx = TransactionRequest::default()
        .to(rollup_addr)
        .input(Bytes::from(deposit_calldata).into())
        .nonce(nonce)
        .gas_price(gas_price.saturating_add(gas_price / 10))
        .gas_limit(500_000);
    deposit_tx.set_chain_id(chain_id);

    // Fill and sign the tx locally (wallet signer), without broadcasting.
    let sendable = provider.fill(deposit_tx).await.context("failed to fill deposit tx")?;
    let raw_tx = match &sendable {
        SendableTx::Envelope(env) => env.encoded_2718(),
        _ => anyhow::bail!("fill did not produce a signed envelope"),
    };
    let raw_tx_hex = hex::encode(&raw_tx);
    println!("  signed tx: {} bytes", raw_tx.len());

    // ── 8. Encode deposit fields for DB API ─────────────────────────────────
    let note_id_bytes = {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&f_to_bytes(note_identifier[0]));
        out[8..].copy_from_slice(&f_to_bytes(note_identifier[1]));
        out
    };
    let amount_bytes = {
        let v = primitive_types::U256::from(deposit_amount);
        u256_to_bytes(v)
    };
    let asset_id_bytes = f_to_bytes(F::from_canonical_u64(asset_id_u64));

    let body = serde_json::json!({
        "recipient_acc_address": user_acc,
        "eth_address": format!("{depositor_addr}"),
        "deposit_note_identifier": hex::encode(note_id_bytes),
        "deposit_amount": hex::encode(amount_bytes),
        "asset_id": hex::encode(asset_id_bytes),
        "signed_public_tx": raw_tx_hex,
    });

    // ── 9. POST deposit to DB API ───────────────────────────────────────────
    println!("\nsubmitting deposit request to {api_base}/deposit ...");
    let resp = client
        .post(format!("{api_base}/deposit"))
        .json(&body)
        .send()
        .await
        .context("failed to reach DB API /deposit")?;

    let status = resp.status();
    let resp_body = resp.text().await.unwrap_or_default();
    println!("  HTTP {status}");
    println!("  {resp_body}");

    if !status.is_success() {
        anyhow::bail!("DB API rejected deposit request");
    }

    println!("\nDeposit request submitted. The operator will:");
    println!("  1. Broadcast the signed tx on-chain");
    println!("  2. Compute note commitment and post to sequencer");
    println!("  3. Update the DB");

    Ok(())
}
