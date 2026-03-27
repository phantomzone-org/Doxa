use std::sync::Arc;

use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, Executor, PgPool, Postgres};
use tessera_client::StandardAccount;

use crate::convert::{account_to_insert, AccountInsert};

pub async fn create_pool(
	database_url: &str,
	max_connections: u32,
	schema_name: &str,
) -> Result<sqlx::PgPool> {
	let schema_name = Arc::<str>::from(schema_name.to_owned());

	let bootstrap_pool = PgPoolOptions::new()
		.max_connections(1)
		.connect(database_url)
		.await?;

	let create_schema_sql = format!("CREATE SCHEMA IF NOT EXISTS {}", schema_name);
	sqlx::query(&create_schema_sql)
		.execute(&bootstrap_pool)
		.await?;
	bootstrap_pool.close().await;

	Ok(PgPoolOptions::new()
		.max_connections(max_connections)
		.after_connect({
			let schema_name = Arc::clone(&schema_name);
			move |conn, _meta| {
				let schema_name = Arc::clone(&schema_name);
				Box::pin(async move {
					let set_search_path_sql = format!("SET search_path TO {}", schema_name);
					sqlx::query(&set_search_path_sql).execute(conn).await?;
					Ok(())
				})
			}
		})
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

pub async fn insert_approved_input_note<'e>(
	executor: impl Executor<'e, Database = Postgres>,
	identifier: &str,
	asset_id: &[u8],
	amount: &[u8],
	recipient_address: &str,
	sender_address: &str,
) -> Result<()> {
	sqlx::query(
		r#"INSERT INTO input_notes
               (identifier, asset_id, amount, recipient_address, sender_address, status)
           VALUES ($1, $2, $3, $4, $5, 'APPROVED')
           ON CONFLICT (identifier) DO NOTHING"#,
	)
	.bind(identifier)
	.bind(asset_id)
	.bind(amount)
	.bind(recipient_address)
	.bind(sender_address)
	.execute(executor)
	.await
	.context("failed to insert input_note")?;
	Ok(())
}

/// Insert a row into the `input_notes` table with status PENDING.
pub async fn insert_pending_input_note<'e>(
	executor: impl Executor<'e, Database = Postgres>,
	identifier: &str,
	asset_id: &[u8],
	amount: &[u8],
	recipient_address: &str,
	sender_address: &str,
) -> Result<()> {
	sqlx::query(
		r#"INSERT INTO input_notes
               (identifier, asset_id, amount, recipient_address, sender_address, status)
           VALUES ($1, $2, $3, $4, $5, 'PENDING')
           ON CONFLICT (identifier) DO NOTHING"#,
	)
	.bind(identifier)
	.bind(asset_id)
	.bind(amount)
	.bind(recipient_address)
	.bind(sender_address)
	.execute(executor)
	.await
	.context("failed to insert pending input_note")?;
	Ok(())
}

pub async fn update_account<'e>(
	executor: impl Executor<'e, Database = Postgres>,
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
	.execute(executor)
	.await
	.context("failed to update sender account after spend tx")?;

	Ok(())
}

pub async fn update_spend_tx_request_to_approved<'e>(
	executor: impl Executor<'e, Database = Postgres>,
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
	.execute(executor)
	.await
	.context("failed to update spend_tx_requests")?;
	Ok(())
}

pub async fn update_deposit_tx_request_to_approved<'e>(
	executor: impl Executor<'e, Database = Postgres>,
	sig_bytes: &[u8],
	id: i64,
) -> Result<()> {
	sqlx::query(
		"UPDATE deposit_tx_requests \
         SET status = 'APPROVED', approval_signature = $1, updated_at = NOW() \
         WHERE id = $2",
	)
	.bind(sig_bytes)
	.bind(id)
	.execute(executor)
	.await
	.context("failed to update deposit_tx_requests")?;
	Ok(())
}
