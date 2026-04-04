use axum::{
	extract::{Path, State},
	http::StatusCode,
	Json,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

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

// ── Deposits under review ─────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
struct DepositJoinRow {
	// deposit_tx_requests
	id: i64,
	recipient_address: String,
	eth_address: String,
	deposit_amount: Vec<u8>,
	asset_id: Vec<u8>,
	deposit_tx_hash: Option<String>,
	status: String,
	rejection_reason: Option<String>,
	created_at: DateTime<Utc>,
	// deposit_checks (LEFT JOIN — nullable)
	check_id: Option<i64>,
	check_status: Option<String>,
	check_response: Option<String>,
	check_updated_at: Option<DateTime<Utc>>,
	// users (LEFT JOIN — nullable)
	name: Option<String>,
	physical_address: Option<String>,
	dob: Option<NaiveDate>,
}

#[derive(Debug, Serialize)]
pub struct DepositCheckInfo {
	pub id: Option<i64>,
	pub status: Option<String>,
	pub check_response: Option<String>,
	pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct AccountInfo {
	pub name: Option<String>,
	pub physical_address: Option<String>,
	pub dob: Option<NaiveDate>,
}

#[derive(Debug, Serialize)]
pub struct DepositAdminRow {
	pub id: i64,
	pub recipient_address: String,
	pub eth_address: String,
	/// 64 hex chars — U256 amount, 32 bytes LE
	pub deposit_amount: String,
	/// 16 hex chars — F asset_id, 8 bytes LE
	pub asset_id: String,
	pub status: String,
	pub deposit_tx_hash: Option<String>,
	pub rejection_reason: Option<String>,
	pub created_at: DateTime<Utc>,
	pub deposit_check: DepositCheckInfo,
	pub account: AccountInfo,
}

const DEPOSIT_JOIN_QUERY: &str = r#"
    SELECT
        dtr.id,
        dtr.recipient_address,
        dtr.eth_address,
        dtr.deposit_amount,
        dtr.asset_id,
        dtr.deposit_tx_hash,
        dtr.status::text AS status,
        dtr.rejection_reason,
        dtr.created_at,
        dc.id           AS check_id,
        dc.status::text AS check_status,
        dc.check_response,
        dc.updated_at   AS check_updated_at,
        u.name,
        u.physical_address,
        u.dob
    FROM deposit_tx_requests dtr
    LEFT JOIN deposit_checks dc ON dc.deposit_tx_request_id = dtr.id
    LEFT JOIN users u ON u.private_acc_address = dtr.recipient_address
"#;

fn map_deposit_join_row(r: DepositJoinRow) -> DepositAdminRow {
	DepositAdminRow {
		deposit_amount: hex::encode(&r.deposit_amount),
		asset_id: hex::encode(&r.asset_id),
		status: r.status,
		deposit_check: DepositCheckInfo {
			id: r.check_id,
			status: r.check_status,
			check_response: r.check_response,
			updated_at: r.check_updated_at,
		},
		account: AccountInfo {
			name: r.name,
			physical_address: r.physical_address,
			dob: r.dob,
		},
		id: r.id,
		recipient_address: r.recipient_address,
		eth_address: r.eth_address,
		deposit_tx_hash: r.deposit_tx_hash,
		rejection_reason: r.rejection_reason,
		created_at: r.created_at,
	}
}

pub async fn list_underreview_deposits_handler(
	State(state): State<AppState>,
) -> Result<(StatusCode, Json<Vec<DepositAdminRow>>), AppError> {
	let query = format!("{DEPOSIT_JOIN_QUERY} WHERE dtr.status = 'UNDERREVIEW' ORDER BY dtr.created_at ASC");
	let rows: Vec<DepositJoinRow> = sqlx::query_as(&query).fetch_all(&state.pool).await?;
	Ok((StatusCode::OK, Json(rows.into_iter().map(map_deposit_join_row).collect())))
}

pub async fn list_all_deposits_handler(
	State(state): State<AppState>,
) -> Result<(StatusCode, Json<Vec<DepositAdminRow>>), AppError> {
	let query = format!("{DEPOSIT_JOIN_QUERY} ORDER BY dtr.created_at DESC");
	let rows: Vec<DepositJoinRow> = sqlx::query_as(&query).fetch_all(&state.pool).await?;
	Ok((StatusCode::OK, Json(rows.into_iter().map(map_deposit_join_row).collect())))
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReviewAction {
	Approve,
	Reject,
}

#[derive(Deserialize)]
pub struct ReviewDepositRequest {
	pub action: ReviewAction,
}

#[derive(Serialize)]
pub struct ReviewDepositResponse {
	pub id: i64,
	pub status: String,
}

pub async fn review_deposit_handler(
	State(state): State<AppState>,
	Path(id): Path<i64>,
	Json(req): Json<ReviewDepositRequest>,
) -> Result<(StatusCode, Json<ReviewDepositResponse>), AppError> {
	let exists: Option<(i64,)> = sqlx::query_as(
		"SELECT id FROM deposit_tx_requests WHERE id = $1 AND status = 'UNDERREVIEW'",
	)
	.bind(id)
	.fetch_optional(&state.pool)
	.await?;

	if exists.is_none() {
		return Err(AppError::NotFound(format!(
			"deposit_tx_request {id} not found or not UNDERREVIEW"
		)));
	}

	let (new_status_str, new_status_pg) = match req.action {
		ReviewAction::Approve => ("Approved", "APPROVED"),
		ReviewAction::Reject => ("Rejected", "REJECTED"),
	};

	sqlx::query(
		"UPDATE deposit_tx_requests \
         SET status = $1::deposit_tx_status, updated_at = NOW() \
         WHERE id = $2",
	)
	.bind(new_status_pg)
	.bind(id)
	.execute(&state.pool)
	.await?;

	Ok((
		StatusCode::OK,
		Json(ReviewDepositResponse { id, status: new_status_str.to_string() }),
	))
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
