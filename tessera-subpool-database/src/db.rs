use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::convert::{f_to_bytes, AccountInsert};

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
	insert_input_note_opt(
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
	insert_input_note_opt(
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

async fn insert_input_note_opt(
	pool: &PgPool,
	identifier: &str,
	asset_id: &[u8],
	amount: &[u8],
	recipient_address: &str,
	sender_address: &str,
	note_commitment: Option<&[u8]>,
) -> Result<()> {
	// TODO JP: what is the status of the input note at insertion?
	sqlx::query(
		r#"INSERT INTO input_notes
               (identifier, asset_id, amount, recipient_address, sender_address, note_commitment)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
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

/// Update only the AST column for an account (e.g. when receiving a note).
pub async fn update_account_ast(
	pool: &PgPool,
	private_acc_address: &str,
	ast_json: serde_json::Value,
) -> Result<()> {
	sqlx::query(
		"UPDATE accounts \
         SET ast = $1, updated_at = NOW() \
         WHERE private_acc_address = $2",
	)
	.bind(&ast_json)
	.bind(private_acc_address)
	.execute(pool)
	.await
	.context("failed to update account AST")?;
	Ok(())
}

/// Update an account's nonce and AST after a deposit is processed.
pub async fn update_account_after_deposit(
	pool: &PgPool,
	private_acc_address: &str,
	new_nonce: tessera_utils::F,
	ast_json: serde_json::Value,
) -> Result<()> {
	sqlx::query(
		"UPDATE accounts \
         SET nonce = $1, ast = $2, updated_at = NOW() \
         WHERE private_acc_address = $3",
	)
	.bind(f_to_bytes(new_nonce).as_ref())
	.bind(&ast_json)
	.bind(private_acc_address)
	.execute(pool)
	.await
	.context("failed to update account after deposit")?;
	Ok(())
}
