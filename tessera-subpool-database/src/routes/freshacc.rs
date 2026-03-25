use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;

use crate::{
    error::AppError,
    state::AppState,
    types::freshacc::FreshAccStatus,
};

/// JSON response body for `GET /freshacc/:private_acc_address/status`.
#[derive(Serialize)]
pub struct FreshAccStatusResponse {
    pub status: FreshAccStatus,
}

pub async fn get_freshacc_status_handler(
    State(state): State<AppState>,
    Path(private_acc_address): Path<String>,
) -> Result<(StatusCode, Json<FreshAccStatusResponse>), AppError> {
    let status: Option<FreshAccStatus> = sqlx::query_scalar(
        "SELECT status FROM freshacc_requests WHERE private_acc_address = $1",
    )
    .bind(&private_acc_address)
    .fetch_optional(&state.pool)
    .await?;

    match status {
        Some(s) => Ok((StatusCode::OK, Json(FreshAccStatusResponse { status: s }))),
        None => Err(AppError::NotFound("freshacc request not found".into())),
    }
}
