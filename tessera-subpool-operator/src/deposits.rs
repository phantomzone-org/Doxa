use alloy::{
	primitives::{Address, Bytes, B256},
	providers::Provider,
	rpc::types::TransactionRequest,
	sol,
	sol_types::SolCall,
};
use anyhow::{Context, Result};
use plonky2_field::types::{Field, PrimeField64};
use primitive_types::U256;
use serde::Serialize;
use sqlx::PgPool;
use tessera_client::{
	derive_deposit_tx_hash,
	schnorr::{schnorr_sign, PrivateKey, Scalar},
	AccountAddress, AssetId, DepositNote, StandardAccount,
};
use tessera_subpool_database::{
	convert::{
		account_from_row, build_ast_json, bytes_to_f, bytes_to_u256, f_to_bytes, hash_to_hex,
		parse_eth_address, u256_to_bytes,
	},
	db::{insert_pending_input_note, update_account_after_deposit},
	types::{account::AccountRow, deposit::DepositTxRow},
};
use tessera_utils::F;
use tracing::{error, info};

// ── On-chain contract interface (subset) ────────────────────────────────────

sol! {
	function getDeposit(bytes32 noteCommitment) external view returns (uint256 value, address recipient, uint8 status);
}

// ── Sequencer deposit request ───────────────────────────────────────────────

#[derive(Serialize)]
struct DepositValidationRequest {
	note_commitment: String,
}

// ── On-chain broadcast ──────────────────────────────────────────────────────

/// Broadcast the depositor's pre-signed ETH tx and wait for confirmation.
async fn broadcast_deposit_tx<P: Provider + Clone>(
	rpc_provider: &P,
	raw_tx: &[u8],
	id: i64,
) -> Result<()> {
	let pending = rpc_provider
		.send_raw_transaction(raw_tx)
		.await
		.context("failed to broadcast deposit tx")?;

	let tx_hash = *pending.tx_hash();
	info!(id, %tx_hash, "deposit tx broadcast, waiting for receipt");

	let receipt = pending
		.get_receipt()
		.await
		.context("failed to get deposit tx receipt")?;

	anyhow::ensure!(
		receipt.status(),
		"deposit tx reverted on-chain (tx={tx_hash})"
	);
	info!(id, %tx_hash, "deposit tx confirmed on-chain");
	Ok(())
}

// ── Deposit note construction ───────────────────────────────────────────────

struct ParsedDeposit {
	note_identifier: [F; 2],
	deposit_amount: U256,
	asset_id: AssetId,
	asset_id_u64: u64,
	eth_address: primitive_types::H160,
}

/// Parse the raw DB fields into typed deposit values.
fn parse_deposit_fields(row: &DepositTxRow) -> Result<ParsedDeposit> {
	let note_id_arr: [u8; 16] = row
		.deposit_note_identifier
		.as_slice()
		.try_into()
		.context("deposit_note_identifier must be 16 bytes")?;
	let note_identifier = [
		bytes_to_f(&note_id_arr[..8].try_into().unwrap()),
		bytes_to_f(&note_id_arr[8..].try_into().unwrap()),
	];

	let amount_arr: [u8; 32] = row
		.deposit_amount
		.as_slice()
		.try_into()
		.context("deposit_amount must be 32 bytes")?;
	let deposit_amount = bytes_to_u256(&amount_arr);

	let asset_id_arr: [u8; 8] = row
		.asset_id
		.as_slice()
		.try_into()
		.context("asset_id must be 8 bytes")?;
	let asset_id_f = bytes_to_f(&asset_id_arr);
	let asset_id_u64 = asset_id_f.to_canonical_u64();
	let asset_id = AssetId::from_u64(asset_id_u64)?;

	let eth_address = parse_eth_address(&row.eth_address)?;

	Ok(ParsedDeposit {
		note_identifier,
		deposit_amount,
		asset_id,
		asset_id_u64,
		eth_address,
	})
}

/// Build the deposit note and compute its Poseidon commitment hash.
fn build_deposit_note(accin: &StandardAccount, deposit: &ParsedDeposit) -> [F; 4] {
	let recipient = AccountAddress::from_acc(accin);
	let note = DepositNote {
		identifier: deposit.note_identifier,
		recipient,
		amount: deposit.deposit_amount,
		asset_id: deposit.asset_id,
	};
	note.commitment().0 .0
}

/// Build accout from accin with the deposit applied (nonce+1, AST updated).
fn apply_deposit(accin: &StandardAccount, deposit: &ParsedDeposit) -> StandardAccount {
	let mut accout = accin.clone_with_incremented_nonce();
	let old_balance = accout
		.ast
		.amount_for(deposit.asset_id)
		.map(|(_, b)| b)
		.unwrap_or(U256::zero());
	let new_balance = old_balance + deposit.deposit_amount;
	accout
		.ast
		.insert_or_update_asset(deposit.asset_id, new_balance);
	accout
}

// ── Sequencer interaction ───────────────────────────────────────────────────

/// POST the deposit note commitment to the sequencer's /deposit endpoint.
async fn post_deposit_to_sequencer(
	http: &reqwest::Client,
	sequencer_url: &str,
	nc_hex: &str,
) -> Result<()> {
	let req = DepositValidationRequest {
		note_commitment: nc_hex.to_string(),
	};
	let url = format!("{}/deposit", sequencer_url.trim_end_matches('/'));
	let resp = http
		.post(&url)
		.json(&req)
		.send()
		.await
		.context("failed to reach sequencer /deposit")?;

	if !resp.status().is_success() {
		let status = resp.status();
		let body = resp.text().await.unwrap_or_default();
		anyhow::bail!("sequencer rejected deposit (HTTP {status}): {body}");
	}
	Ok(())
}

// ── Core loop ───────────────────────────────────────────────────────────────

pub async fn process_pending_deposits<P: Provider + Clone>(
	pool: &PgPool,
	approval_sk: &PrivateKey,
	sequencer_url: &str,
	http: &reqwest::Client,
	rpc_provider: &P,
	subpool_id: u64,
) -> Result<()> {
	let rows: Vec<DepositTxRow> = sqlx::query_as(
		"SELECT * FROM deposit_tx_requests \
         WHERE status = 'PENDING' \
         ORDER BY created_at ASC",
	)
	.fetch_all(pool)
	.await?;

	info!(pending = rows.len(), "polled deposit_tx_requests");

	if rows.is_empty() {
		return Ok(());
	}

	for row in rows {
		if let Err(e) = process_one_deposit(
			pool,
			approval_sk,
			sequencer_url,
			http,
			rpc_provider,
			&row,
			subpool_id,
		)
		.await
		{
			error!(
				id = row.id,
				addr = row.recipient_acc_address,
				"failed to process deposit request: {e:#}"
			);
		}
	}

	Ok(())
}

async fn process_one_deposit<P: Provider + Clone>(
	pool: &PgPool,
	approval_sk: &PrivateKey,
	sequencer_url: &str,
	http: &reqwest::Client,
	rpc_provider: &P,
	row: &DepositTxRow,
	subpool_id: u64,
) -> Result<()> {
	// ── 1. Broadcast deposit tx on-chain ─────────────────────────────────────
	info!(id = row.id, addr = %row.recipient_acc_address, "broadcasting deposit tx on-chain");
	// TODO: get the tx_hash of the broadcasted tx and put in deposit_tx_request row
	broadcast_deposit_tx(rpc_provider, &row.signed_public_tx, row.id).await?;

	// ── 2. Reconstruct accin from DB ─────────────────────────────────────────
	let acc_row: AccountRow =
		sqlx::query_as("SELECT * FROM accounts WHERE private_acc_address = $1")
			.bind(&row.recipient_acc_address)
			.fetch_one(pool)
			.await
			.context("account row not found for deposit recipient")?;

	let accin = account_from_row(&acc_row)?;

	// ── 3. Parse deposit fields and build note commitment ────────────────────
	let deposit = parse_deposit_fields(row)?;
	// TODO: use proper names (also use single purpose functions)
	let nc_hash = build_deposit_note(&accin, &deposit);

	// ── 4. Build accout with deposit applied ─────────────────────────────────
	let accout = apply_deposit(&accin, &deposit);

	// ── 5. Sign deposit tx_hash ──────────────────────────────────────────────
	// TODO: don't redo wrappin gin DepositNOteCommitment. Have builde_deposit_note return
	// DepositNoteCommitment
	let deposit_note_comm =
		tessera_client::DepositNoteCommitment(tessera_client::HashOutput(nc_hash));
	let tx_hash = derive_deposit_tx_hash(
		accin.nullifier(),
		accout.commitment(),
		deposit_note_comm,
		deposit.eth_address,
	);

	let mut rng = rand::rng();
	let k = Scalar::sample(&mut rng);
	let approval_sig = schnorr_sign(approval_sk, &tx_hash.0, k);
	let sig_bytes = approval_sig.encode();

	// ── 6. POST to sequencer ─────────────────────────────────────────────────
	let nc_hex = hash_to_hex(&nc_hash);
	post_deposit_to_sequencer(http, sequencer_url, &nc_hex).await?;
	info!(id = row.id, addr = %row.recipient_acc_address, "deposit note submitted to sequencer");

	// ── 7. Update deposit_tx_requests: APPROVED ──────────────────────────────
	sqlx::query(
		"UPDATE deposit_tx_requests \
         SET status = 'APPROVED', approval_signature = $1, updated_at = NOW() \
         WHERE id = $2",
	)
	.bind(sig_bytes.as_ref())
	.bind(row.id)
	.execute(pool)
	.await
	.context("failed to update deposit_tx_requests")?;

	// ── 8. Update account in DB ──────────────────────────────────────────────

	// TODO: accout is aready updated with the latest balance. Convert accout (an instance of
	// StandardAccount) to AccountInsert using `account_to_insert` method in convert.rs and then
	// update the account using private_acc_address
	let new_asset_balance = accout
		.ast
		.amount_for(deposit.asset_id)
		.map(|(_, b)| b)
		.unwrap_or(U256::zero());
	let ast_json = build_ast_json(&acc_row.ast, deposit.asset_id_u64, new_asset_balance);

	update_account_after_deposit(pool, &row.recipient_acc_address, accout.nonce.0, ast_json)
		.await?;

	// ── 9. Create PENDING input note for the deposit recipient ────────────────
	// The note stays PENDING until the deposit is confirmed on-chain (status = Validated).
	let note_id_hex = hex::encode(&row.deposit_note_identifier);
	let asset_id_bytes = f_to_bytes(F::from_canonical_u64(deposit.asset_id_u64));
	let amount_bytes = u256_to_bytes(deposit.deposit_amount);

	// Encode note commitment as 32 bytes (4 × u64 BE) for on-chain lookup.
	let nc_bytes: Vec<u8> = nc_hash
		.iter()
		.flat_map(|f| f.to_canonical_u64().to_be_bytes())
		.collect();

	insert_pending_input_note(
		pool,
		&note_id_hex,
		&asset_id_bytes,
		&amount_bytes,
		&row.recipient_acc_address,
		&format!("{:?}", deposit.eth_address),
		&nc_bytes,
	)
	.await?;

	info!(
		id = row.id,
		addr = %row.recipient_acc_address,
		asset_id = deposit.asset_id_u64,
		new_balance = %new_asset_balance,
		"deposit approved, PENDING input note created (awaiting on-chain confirmation)"
	);

	Ok(())
}

// ── On-chain deposit confirmation ──────────────────────────────────────────

/// Row type for PENDING input notes that have a note_commitment.
#[derive(sqlx::FromRow)]
struct PendingNoteRow {
	id: i64,
	identifier: String,
	note_commitment: Option<Vec<u8>>,
}

/// Poll for PENDING input notes with a note_commitment, check on-chain
/// deposit status, and mark APPROVED once Validated (status == 2).
pub async fn confirm_pending_notes<P: Provider + Clone>(
	pool: &PgPool,
	rpc_provider: &P,
	rollup_address: Address,
) -> Result<()> {
	let rows: Vec<PendingNoteRow> = sqlx::query_as(
		"SELECT id, identifier, note_commitment FROM input_notes \
         WHERE status = 'PENDING' AND note_commitment IS NOT NULL",
	)
	.fetch_all(pool)
	.await?;

	if rows.is_empty() {
		return Ok(());
	}

	for row in &rows {
		let nc_bytes = row.note_commitment.as_ref().unwrap();
		if nc_bytes.len() != 32 {
			error!(id = row.id, "note_commitment is not 32 bytes, skipping");
			continue;
		}
		let nc: [u8; 32] = nc_bytes.as_slice().try_into().unwrap();
		let nc_b256 = B256::from(nc);

		let calldata = getDepositCall {
			noteCommitment: nc_b256,
		}
		.abi_encode();
		let tx = TransactionRequest::default()
			.to(rollup_address)
			.input(Bytes::from(calldata).into());
		let result = rpc_provider.call(tx).await;

		match result {
			Ok(output) => {
				let decoded = getDepositCall::abi_decode_returns(&output);
				let Ok(deposit_info) = decoded else {
					error!(id = row.id, "failed to decode getDeposit return data");
					continue;
				};
				let status: u8 = deposit_info.status;
				if status == 2 {
					// Validated on-chain — mark APPROVED
					sqlx::query(
						"UPDATE input_notes SET status = 'APPROVED', updated_at = NOW() WHERE id = $1",
					)
					.bind(row.id)
					.execute(pool)
					.await
					.with_context(|| format!("failed to approve input note {}", row.id))?;

					info!(
						id = row.id,
						note_id = %row.identifier,
						"input note confirmed on-chain (deposit Validated)"
					);
				}
				// 0=None, 1=Pending, 3=Withdrawn → keep polling
				if status > 3 {
					error!(
						id = row.id,
						status, "unexpected deposit status from on-chain getDeposit"
					);
				}
			},
			Err(e) => {
				error!(
					id = row.id,
					note_id = %row.identifier,
					"failed to query on-chain deposit status: {e}"
				);
			},
		}
	}

	Ok(())
}
