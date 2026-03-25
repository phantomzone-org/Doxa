use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::convert::AccountInsert;

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
             private_identifier, subpool_id, balance, nonce,
             spend_auth, consume_auth, ast)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(&insert.private_acc_address)
    .bind(&insert.eth_address)
    .bind(&insert.private_identifier)
    .bind(&insert.subpool_id)
    .bind(&insert.balance)
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
