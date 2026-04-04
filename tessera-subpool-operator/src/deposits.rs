use alloy::{
	network::EthereumWallet,
	primitives::{Address, Bytes, B256, U256 as AlloyU256},
	providers::{Provider, ProviderBuilder},
	rpc::types::TransactionRequest,
	signers::local::PrivateKeySigner,
	sol,
	sol_types::SolCall,
};
use anyhow::{Context, Result};
use plonky2_field::types::PrimeField64;
use primitive_types::U256;
use serde::Serialize;
use sqlx::PgPool;
use tessera_client::{
	derive_deposit_tx_hash,
	schnorr::{schnorr_sign, PrivateKey, Scalar},
	AccountAddress, AssetId, DepositNote, NoteIdentifier, StandardAccount,
};
use tessera_subpool_database::{
	convert::{
		account_from_row, bytes_to_f, bytes_to_u256, f_to_bytes, hash_to_hex, u256_to_bytes,
	},
	db::{insert_pending_input_note, update_account, update_deposit_tx_request_to_settled},
	types::{account::AccountRow, deposit::DepositTxRow},
};
use tracing::{error, info};

// ── On-chain contract interface (subset) ────────────────────────────────────

sol! {
	function getDeposit(bytes32 noteCommitment) external view returns (uint256 value, address recipient, uint8 status);
	function signedDepositAndRegister(bytes signature, bytes32 depositNoteCommitment, uint256 amount) external;
}

// ── Sequencer deposit request ───────────────────────────────────────────────

#[derive(Serialize)]
struct DepositValidationRequest {
	note_commitment: String,
}

// ── On-chain call ────────────────────────────────────────────────────────────

/// Call `signedDepositAndRegister` on the Tessera contract using the operator's wallet.
/// Returns the confirmed tx hash.
async fn call_signed_deposit_and_register(
	operator_eth_key: &str,
	rpc_url: &str,
	rollup_address: Address,
	signature: Vec<u8>,
	note_commitment: B256,
	amount_le: [u8; 32],
	id: i64,
) -> Result<B256> {
	let key = operator_eth_key.trim_start_matches("0x");
	let signer: PrivateKeySigner = key
		.parse()
		.context("invalid OPERATOR_KEY for signedDepositAndRegister")?;
	let wallet = EthereumWallet::from(signer);
	let provider = ProviderBuilder::new()
		.wallet(wallet)
		.connect_http(rpc_url.parse().context("invalid RPC_URL")?);

	let amount_alloy = AlloyU256::from_le_bytes(amount_le);
	let calldata = signedDepositAndRegisterCall {
		signature: Bytes::from(signature),
		depositNoteCommitment: note_commitment,
		amount: amount_alloy,
	}
	.abi_encode();

	let eth_tx = TransactionRequest::default()
		.to(rollup_address)
		.input(Bytes::from(calldata).into());

	let pending = provider
		.send_transaction(eth_tx)
		.await
		.context("failed to send signedDepositAndRegister tx")?;

	let tx_hash = *pending.tx_hash();
	info!(id, %tx_hash, "signedDepositAndRegister tx broadcast, waiting for receipt");

	let receipt = pending
		.get_receipt()
		.await
		.context("failed to get signedDepositAndRegister receipt")?;

	anyhow::ensure!(
		receipt.status(),
		"signedDepositAndRegister reverted on-chain (tx={tx_hash})"
	);
	info!(id, %tx_hash, "signedDepositAndRegister confirmed on-chain");
	Ok(tx_hash)
}

/// Build accout from accin with the deposit applied (nonce+1, AST updated).
fn apply_deposit(accin: &StandardAccount, deposit: &DepositNote) -> StandardAccount {
	let mut accout = accin.clone_with_incremented_nonce();
	let old_balance = accout
		.ast
		.amount_for(deposit.asset_id)
		.map(|(_, b)| b)
		.unwrap_or(U256::zero());
	let new_balance = old_balance + deposit.amount;
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

// ── Deposit triage & processing ─────────────────────────────────────────────

/// Deposits with amount > TRIGGER_THRESHOLD_DEPOSIT_AMOUNT are placed in UNDERREVIEW
/// regardless of AML outcome (require manual operator approval).
/// 1 000 USDX at 6 decimals = 1_000_000_000 units.
const TRIGGER_THRESHOLD_DEPOSIT_AMOUNT: u64 = 1_000_000_000;

/// Triage PENDING deposits where the deposit_check has been APPROVED.
/// Small deposits (≤ threshold) move to APPROVED; large ones go to UNDERREVIEW.
pub async fn triage_deposit_reqs_with_approved_deposit_check(pool: &PgPool) -> Result<()> {
	let rows: Vec<DepositTxRow> = sqlx::query_as(
		"SELECT dtr.* FROM deposit_tx_requests dtr \
         INNER JOIN deposit_checks dc ON dc.deposit_tx_request_id = dtr.id \
         WHERE dtr.status = 'PENDING' AND dc.status = 'APPROVED' \
         ORDER BY dtr.created_at ASC",
	)
	.fetch_all(pool)
	.await?;

	let threshold = U256::from(TRIGGER_THRESHOLD_DEPOSIT_AMOUNT);
	for row in rows {
		let amount = row.amount()?;
		let new_status = if amount > threshold {
			"UNDERREVIEW"
		} else {
			"APPROVED"
		};
		sqlx::query("UPDATE deposit_tx_requests SET status = $1, updated_at = NOW() WHERE id = $2")
			.bind(new_status)
			.bind(row.id)
			.execute(pool)
			.await?;
		info!(
			id = row.id,
			status = new_status,
			"triaged deposit (check=APPROVED)"
		);
	}
	Ok(())
}

/// Triage PENDING deposits where the deposit_check has been REJECTED.
/// All such deposits move to UNDERREVIEW for manual review.
pub async fn triage_deposit_reqs_with_rejected_deposit_check(pool: &PgPool) -> Result<()> {
	let rows: Vec<DepositTxRow> = sqlx::query_as(
		"SELECT dtr.* FROM deposit_tx_requests dtr \
         INNER JOIN deposit_checks dc ON dc.deposit_tx_request_id = dtr.id \
         WHERE dtr.status = 'PENDING' AND dc.status = 'REJECTED' \
         ORDER BY dtr.created_at ASC",
	)
	.fetch_all(pool)
	.await?;

	for row in rows {
		sqlx::query(
			"UPDATE deposit_tx_requests SET status = 'UNDERREVIEW', updated_at = NOW() WHERE id = $1",
		)
		.bind(row.id)
		.execute(pool)
		.await?;
		info!(id = row.id, "deposit moved to UNDERREVIEW (check=REJECTED)");
	}
	Ok(())
}

/// Process all APPROVED deposits: call on-chain, update account, submit to sequencer, mark SETTLED.
pub async fn process_approved_deposits(
	pool: &PgPool,
	approval_sk: &PrivateKey,
	sequencer_url: &str,
	http: &reqwest::Client,
	operator_eth_key: &str,
	rpc_url: &str,
	rollup_address: Address,
) -> Result<()> {
	let rows: Vec<DepositTxRow> = sqlx::query_as(
		"SELECT * FROM deposit_tx_requests WHERE status = 'APPROVED' ORDER BY created_at ASC",
	)
	.fetch_all(pool)
	.await?;

	info!(approved = rows.len(), "polled approved deposit_tx_requests");

	for row in rows {
		if let Err(e) = settle_one_deposit(
			pool,
			approval_sk,
			sequencer_url,
			http,
			operator_eth_key,
			rpc_url,
			rollup_address,
			&row,
		)
		.await
		{
			error!(
				id = row.id,
				addr = row.recipient_address,
				"failed to settle deposit: {e:#}"
			);
		}
	}

	Ok(())
}

async fn settle_one_deposit(
	pool: &PgPool,
	approval_sk: &PrivateKey,
	sequencer_url: &str,
	http: &reqwest::Client,
	operator_eth_key: &str,
	rpc_url: &str,
	rollup_address: Address,
	row: &DepositTxRow,
) -> Result<()> {
	// ── 1. Call signedDepositAndRegister on-chain (idempotent via deposit_tx_hash) ─
	let _on_chain_tx_hash = if let Some(tx_hash) = &row.deposit_tx_hash {
		let parsed = tx_hash
			.parse::<B256>()
			.with_context(|| format!("invalid persisted deposit_tx_hash '{tx_hash}'"))?;
		info!(
			id = row.id,
			addr = %row.recipient_address,
			tx_hash = %parsed,
			"reusing previously submitted signedDepositAndRegister tx"
		);
		parsed
	} else {
		info!(
			id = row.id,
			addr = %row.recipient_address,
			"calling signedDepositAndRegister on-chain"
		);

		let deposit = row.to_deposite_note()?;
		let deposit_note_comm = deposit.commitment();
		let nc_b256 = B256::from_slice(
			&deposit_note_comm
				.0
				 .0
				.iter()
				.flat_map(|f| f.to_canonical_u64().to_le_bytes())
				.collect::<Vec<_>>(),
		);
		let amount_le: [u8; 32] = row
			.deposit_amount
			.as_slice()
			.try_into()
			.context("deposit_amount must be 32 bytes")?;

		let tx_hash = call_signed_deposit_and_register(
			operator_eth_key,
			rpc_url,
			rollup_address,
			row.deposit_type_signature.clone(),
			nc_b256,
			amount_le,
			row.id,
		)
		.await?;
		sqlx::query(
			"UPDATE deposit_tx_requests \
	         SET deposit_tx_hash = $1, updated_at = NOW() \
	         WHERE id = $2",
		)
		.bind(tx_hash.to_string())
		.bind(row.id)
		.execute(pool)
		.await
		.context("failed to persist deposit tx hash")?;
		tx_hash
	};

	// ── 2. Reconstruct accin from DB ─────────────────────────────────────────
	// TODO: add a helper function on row
	let acc_row: AccountRow =
		sqlx::query_as("SELECT * FROM accounts WHERE private_acc_address = $1")
			.bind(&row.recipient_address)
			.fetch_one(pool)
			.await
			.context("account row not found for deposit recipient")?;

	let accin = account_from_row(&acc_row)?;

	// ── 4. Parse deposit fields and build note commitment ────────────────────
	let deposit = row.to_deposite_note()?;
	let deposit_note_comm = deposit.commitment();

	// ── 4. Build accout with deposit applied ─────────────────────────────────
	let accout = apply_deposit(&accin, &deposit);

	let deposit_eth_address = row.eth_address()?;

	// ── 5. Sign deposit tx_hash ──────────────────────────────────────────────
	let tx_hash = derive_deposit_tx_hash(
		accin.nullifier(),
		accout.commitment(),
		deposit_note_comm,
		deposit_eth_address,
	);

	let mut rng = rand::rng();
	let k = Scalar::sample(&mut rng);
	let approval_sig = schnorr_sign(approval_sk, &tx_hash.0, k);
	let sig_bytes = approval_sig.encode();

	// ── 6. POST to sequencer ─────────────────────────────────────────────────
	// TODO: the sequencer receives deposit_note_comm, accin.nullifier(), accout.commitment(). The
	// smart contract already has the ethaddress
	let nc_hex = hash_to_hex(&deposit_note_comm.0 .0);
	info!(nc = nc_hex, "deposit note cm hex");
	post_deposit_to_sequencer(http, sequencer_url, &nc_hex).await?;
	info!(id = row.id, addr = %row.recipient_address, "deposit note submitted to sequencer");

	// ── 7–9. Approve deposit, update account, and insert input note atomically

	let mut tx = pool
		.begin()
		.await
		.context("failed to begin deposit transaction")?;

	update_deposit_tx_request_to_settled(&mut *tx, sig_bytes.as_ref(), row.id).await?;

	update_account(
		&mut *tx,
		&accout,
		acc_row.eth_address,
		row.recipient_address.clone(),
	)
	.await?;

	tx.commit()
		.await
		.context("failed to commit deposit transaction")?;

	let new_asset_balance = accout
		.ast
		.amount_for(deposit.asset_id)
		.map(|(_, balance)| balance)
		.unwrap_or(U256::zero());

	info!(
		id = row.id,
		addr = %row.recipient_address,
		asset_id = deposit.asset_id.0.to_canonical_u64(),
		new_balance = %new_asset_balance,
		"deposit settled, account balance updated"
	);

	Ok(())
}

// ── On-chain deposit confirmation ──────────────────────────────────────────

/// Row type for PENDING input notes that have a note_commitment.
#[derive(sqlx::FromRow)]
struct PendingNoteRow {
	id: i64,
	identifier: String,
	asset_id: Vec<u8>,
	amount: Vec<u8>,
	recipient_address: String,
}

impl PendingNoteRow {
	pub fn amount(&self) -> Result<U256> {
		let amount_arr: [u8; 32] = self
			.amount
			.as_slice()
			.try_into()
			.context("pending note amount must be 32 bytes")?;
		let amount = bytes_to_u256(&amount_arr);
		Ok(amount)
	}

	pub fn asset_id(&self) -> Result<AssetId> {
		let asset_id_arr: [u8; 8] = self
			.asset_id
			.as_slice()
			.try_into()
			.context("pending note asset_id must be 8 bytes")?;
		let asset_id = AssetId::from_u64(bytes_to_f(&asset_id_arr).to_canonical_u64())?;

		Ok(asset_id)
	}

	pub fn identifier(&self) -> Result<NoteIdentifier> {
		let id_bytes =
			hex::decode(&self.identifier).context("invalid pending note identifier hex")?;
		let id_arr: [u8; 16] = id_bytes
			.as_slice()
			.try_into()
			.context("pending note identifier must be 16 bytes")?;
		let identifier = [
			bytes_to_f(&id_arr[..8].try_into().unwrap()),
			bytes_to_f(&id_arr[8..].try_into().unwrap()),
		];

		Ok(NoteIdentifier(identifier))
	}

	pub fn recipient(&self) -> Result<AccountAddress> {
		let recipient = AccountAddress::from_hex(&self.recipient_address)
			.context("invalid pending note recipient address")?;

		Ok(recipient)
	}

	pub fn note(&self) -> Result<DepositNote> {
		let identifier = self.identifier()?;
		let recipient = self.recipient()?;
		let amount = self.amount()?;
		let asset_id = self.asset_id()?;

		Ok(DepositNote {
			identifier,
			recipient,
			amount,
			asset_id,
		})
	}
}

/// Poll for PENDING input notes with a note_commitment, check on-chain
/// deposit status, and mark APPROVED once Validated (status == 2).
pub async fn confirm_pending_notes<P: Provider + Clone>(
	pool: &PgPool,
	rpc_provider: &P,
	rollup_address: Address,
) -> Result<()> {
	let rows: Vec<PendingNoteRow> = sqlx::query_as(
		"SELECT id, identifier, asset_id, amount, recipient_address FROM input_notes \
         WHERE status = 'PENDING'",
	)
	.fetch_all(pool)
	.await?;

	if rows.is_empty() {
		return Ok(());
	}

	for row in &rows {
		let deposit_note = row.note()?;
		let deposit_note_comm = deposit_note.commitment();

		let nc_b256 = B256::from_slice(
			&deposit_note_comm
				.0
				 .0
				.iter()
				.flat_map(|f| f.to_canonical_u64().to_le_bytes())
				.collect::<Vec<_>>(),
		);

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
