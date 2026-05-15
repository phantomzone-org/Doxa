use axum::{extract::State, http::StatusCode, Json};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;

use crate::{error::AppError, state::AppState, types::freshacc::FreshAccStatus};

// ── Accounts + KYC ───────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
struct AccountKycRow {
	pub private_acc_address: String,
	pub eth_address: String,
	pub nonce: Vec<u8>,
	pub spend_auth: Vec<u8>,
	pub created_at: DateTime<Utc>,
	pub updated_at: DateTime<Utc>,
	pub name: Option<String>,
	pub physical_address: Option<String>,
	pub dob: Option<NaiveDate>,
}

#[derive(Debug, Serialize)]
pub struct AccountWithKyc {
	pub private_acc_address: String,
	pub eth_address: String,
	/// 16 hex chars — Nonce(F), 8 bytes LE
	pub nonce: String,
	/// 80 hex chars — spend-auth CompressedPublicKey
	pub spend_auth: String,
	pub created_at: DateTime<Utc>,
	pub updated_at: DateTime<Utc>,
	pub name: Option<String>,
	pub physical_address: Option<String>,
	pub dob: Option<NaiveDate>,
}

pub async fn list_accounts_handler(
	State(state): State<AppState>,
) -> Result<(StatusCode, Json<Vec<AccountWithKyc>>), AppError> {
	let rows: Vec<AccountKycRow> = sqlx::query_as(
		r#"
        SELECT
            a.private_acc_address,
            a.eth_address,
            a.nonce,
            a.spend_auth,
            a.created_at,
            a.updated_at,
            u.name,
            u.physical_address,
            u.dob
        FROM accounts a
        LEFT JOIN users u ON u.private_acc_address = a.private_acc_address
        ORDER BY a.created_at DESC
        "#,
	)
	.fetch_all(&state.pool)
	.await?;

	let out = rows
		.into_iter()
		.map(|r| AccountWithKyc {
			nonce: hex::encode(&r.nonce),
			spend_auth: hex::encode(&r.spend_auth),
			private_acc_address: r.private_acc_address,
			eth_address: r.eth_address,
			created_at: r.created_at,
			updated_at: r.updated_at,
			name: r.name,
			physical_address: r.physical_address,
			dob: r.dob,
		})
		.collect();

	Ok((StatusCode::OK, Json(out)))
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct FreshAccWithKyc {
	pub id: i64,
	pub private_acc_address: String,
	pub private_identifier: String,
	pub status: FreshAccStatus,
	pub rejection_msg: Option<String>,
	pub created_at: DateTime<Utc>,
	pub updated_at: DateTime<Utc>,
	/// KYC fields from `users` table (NULL when no matching user row).
	pub name: Option<String>,
	pub physical_address: Option<String>,
	pub dob: Option<NaiveDate>,
}

pub async fn list_freshacc_handler(
	State(state): State<AppState>,
) -> Result<(StatusCode, Json<Vec<FreshAccWithKyc>>), AppError> {
	let rows: Vec<FreshAccWithKyc> = sqlx::query_as(
		r#"
        SELECT
            fr.id,
            fr.private_acc_address,
            fr.private_identifier,
            fr.status,
            fr.rejection_msg,
            fr.created_at,
            fr.updated_at,
            u.name,
            u.physical_address,
            u.dob
        FROM freshacc_requests fr
        LEFT JOIN users u ON u.private_acc_address = fr.private_acc_address
        ORDER BY fr.created_at DESC
        "#,
	)
	.fetch_all(&state.pool)
	.await?;

	Ok((StatusCode::OK, Json(rows)))
}
