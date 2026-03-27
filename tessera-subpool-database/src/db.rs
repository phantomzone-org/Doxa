use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tessera_client::StandardAccount;

use crate::convert::{account_to_insert, AccountInsert};

pub async fn create_pool(database_url: &str, max_connections: u32) -> Result<sqlx::PgPool> {
	Ok(PgPoolOptions::new()
		.max_connections(max_connections)
		.connect(database_url)
		.await?)
}

/// Insert an `accounts` row and a `users` row in a single transaction.
pub async fn insert_account_and_user(
	pool: &PgPool,
	insert: &AccountInsert,
	name: &str,
	physical_address: &str,
	dob: chrono::NaiveDate,
) -> Result<()> {
	let mut tx = pool.begin().await?;

	sqlx::query(
		r#"
        INSERT INTO accounts
            (private_acc_address, eth_address,
             private_identifier, subpool_id, nonce,
             spend_auth, consume_auth, ast)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
	)
	.bind(&insert.private_acc_address)
	.bind(&insert.eth_address)
	.bind(&insert.private_identifier)
	.bind(&insert.subpool_id)
	.bind(&insert.nonce)
	.bind(&insert.spend_auth)
	.bind(&insert.consume_auth)
	.bind(&insert.ast)
	.execute(&mut *tx)
	.await
	.context("failed to insert account row")?;

	sqlx::query(
		r#"
        INSERT INTO users (private_acc_address, name, physical_address, dob)
        VALUES ($1, $2, $3, $4)
        "#,
	)
	.bind(&insert.private_acc_address)
	.bind(name)
	.bind(physical_address)
	.bind(dob)
	.execute(&mut *tx)
	.await
	.context("failed to insert user row")?;

	tx.commit().await?;
	Ok(())
}

/// Insert a row into the `input_notes` table with status APPROVED (default).
/// If `note_commitment` is provided, it is stored for later NCT position lookup.
pub async fn insert_input_note(
	pool: &PgPool,
	identifier: &str,
	asset_id: &[u8],
	amount: &[u8],
	recipient_address: &str,
	sender_address: &str,
) -> Result<()> {
	insert_approved_input_note(
		pool,
		identifier,
		asset_id,
		amount,
		recipient_address,
		sender_address,
		None,
	)
	.await
}

/// Insert a row into the `input_notes` table with status APPROVED and a note commitment.
pub async fn insert_input_note_with_commitment(
	pool: &PgPool,
	identifier: &str,
	asset_id: &[u8],
	amount: &[u8],
	recipient_address: &str,
	sender_address: &str,
	note_commitment: &[u8],
) -> Result<()> {
	insert_approved_input_note(
		pool,
		identifier,
		asset_id,
		amount,
		recipient_address,
		sender_address,
		Some(note_commitment),
	)
	.await
}

async fn insert_approved_input_note(
	pool: &PgPool,
	identifier: &str,
	asset_id: &[u8],
	amount: &[u8],
	recipient_address: &str,
	sender_address: &str,
	note_commitment: Option<&[u8]>,
) -> Result<()> {
	sqlx::query(
		r#"INSERT INTO input_notes
               (identifier, asset_id, amount, recipient_address, sender_address, note_commitment)
           VALUES ($1, $2, $3, $4, $5, 'APPROVED', $6)"#,
	)
	.bind(identifier)
	.bind(asset_id)
	.bind(amount)
	.bind(recipient_address)
	.bind(sender_address)
	.bind(note_commitment)
	.execute(pool)
	.await
	.context("failed to insert input_note")?;
	Ok(())
}

/// Insert a row into the `input_notes` table with status PENDING and a
/// note commitment hash, so the operator can confirm it on-chain before use.
pub async fn insert_pending_input_note(
	pool: &PgPool,
	identifier: &str,
	asset_id: &[u8],
	amount: &[u8],
	recipient_address: &str,
	sender_address: &str,
	note_commitment: &[u8],
) -> Result<()> {
	sqlx::query(
		r#"INSERT INTO input_notes
               (identifier, asset_id, amount, recipient_address, sender_address,
                status, note_commitment)
           VALUES ($1, $2, $3, $4, $5, 'PENDING', $6)"#,
	)
	.bind(identifier)
	.bind(asset_id)
	.bind(amount)
	.bind(recipient_address)
	.bind(sender_address)
	.bind(note_commitment)
	.execute(pool)
	.await
	.context("failed to insert pending input_note")?;
	Ok(())
}

pub async fn update_account(
	pool: &PgPool,
	account: &StandardAccount,
	eth_address: String,
	priv_acc_address: String,
) -> Result<()> {
	let updated_account = account_to_insert(account, eth_address);
	sqlx::query(
		"UPDATE accounts \
         SET private_identifier = $1, subpool_id = $2, nonce = $3, spend_auth = $4, \
             consume_auth = $5, ast = $6, updated_at = NOW() \
         WHERE private_acc_address = $7",
	)
	.bind(&updated_account.private_identifier)
	.bind(&updated_account.subpool_id)
	.bind(&updated_account.nonce)
	.bind(&updated_account.spend_auth)
	.bind(&updated_account.consume_auth)
	.bind(&updated_account.ast)
	.bind(&priv_acc_address)
	.execute(pool)
	.await
	.context("failed to update sender account after spend tx")?;

	Ok(())
}

pub async fn update_spend_tx_request_to_approved(
	pool: &PgPool,
	sig_bytes: &[u8],
	id: i64,
) -> Result<()> {
	sqlx::query(
		"UPDATE spend_tx_requests \
         SET status = 'APPROVED', approval_signature = $1, updated_at = NOW() \
         WHERE id = $2",
	)
	.bind(sig_bytes)
	.bind(id)
	.execute(pool)
	.await
	.context("failed to update spend_tx_requests")?;
	Ok(())
}
