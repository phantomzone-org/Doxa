use axum::{extract::State, http::StatusCode, Json};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;

use crate::{error::AppError, state::AppState, types::freshacc::FreshAccStatus};

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
