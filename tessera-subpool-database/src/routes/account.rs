use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;

use crate::{error::AppError, state::AppState, types::account::AccountRow};

/// JSON response body for `GET /account/:private_acc_address`.
///
/// All `BYTEA` columns are returned as lowercase hex strings so the
/// caller does not need to handle raw binary.
#[derive(Serialize)]
pub struct AccountResponse {
    pub private_acc_address: String,
    pub eth_address: String,
    /// 32 hex chars — 16 bytes (2 × u64 LE), `PrivateIdentifier([F; 2])`
    pub private_identifier: String,
    /// 16 hex chars — 8 bytes (1 × u64 LE), `SubpoolId(F)`
    pub subpool_id: String,
    /// 64 hex chars — 32 bytes (4 × u64 LE), `U256` balance
    pub balance: String,
    /// 16 hex chars — 8 bytes (1 × u64 LE), `Nonce(F)`
    pub nonce: String,
    /// 80 hex chars — 40 bytes (5 × u64 LE), `CompressedPublicKey` spend-auth; all-zeros if absent
    pub spend_auth: String,
    /// 80 hex chars — 40 bytes (5 × u64 LE), `CompressedPublicKey` consume-auth; all-zeros if absent
    pub consume_auth: String,
    pub ast: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<AccountRow> for AccountResponse {
    fn from(row: AccountRow) -> Self {
        AccountResponse {
            private_acc_address: row.private_acc_address,
            eth_address: row.eth_address,
            private_identifier: hex::encode(&row.private_identifier),
            subpool_id: hex::encode(&row.subpool_id),
            balance: hex::encode(&row.balance),
            nonce: hex::encode(&row.nonce),
            spend_auth: hex::encode(&row.spend_auth),
            consume_auth: hex::encode(&row.consume_auth),
            ast: row.ast,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

pub async fn get_account_handler(
    State(state): State<AppState>,
    Path(private_acc_address): Path<String>,
) -> Result<(StatusCode, Json<AccountResponse>), AppError> {
    let row: Option<AccountRow> = sqlx::query_as(
        "SELECT * FROM accounts WHERE private_acc_address = $1",
    )
    .bind(&private_acc_address)
    .fetch_optional(&state.pool)
    .await?;

    match row {
        Some(r) => Ok((StatusCode::OK, Json(AccountResponse::from(r)))),
        None => Err(AppError::NotFound("account not found".into())),
    }
}
