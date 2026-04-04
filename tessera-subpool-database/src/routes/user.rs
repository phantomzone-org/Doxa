use axum::{
	extract::{Path, State},
	http::StatusCode,
	Json,
};
use serde::Serialize;

use crate::{error::AppError, state::AppState, types::user::UserRow};

#[derive(Serialize)]
pub struct UserResponse {
	pub id: i64,
	pub private_acc_address: String,
	pub name: String,
	pub physical_address: String,
	pub dob: chrono::NaiveDate,
	pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<UserRow> for UserResponse {
	fn from(row: UserRow) -> Self {
		UserResponse {
			id: row.id,
			private_acc_address: row.private_acc_address,
			name: row.name,
			physical_address: row.physical_address,
			dob: row.dob,
			created_at: row.created_at,
		}
	}
}

pub async fn list_users_handler(
	State(state): State<AppState>,
) -> Result<(StatusCode, Json<Vec<UserResponse>>), AppError> {
	let rows: Vec<UserRow> =
		sqlx::query_as("SELECT * FROM users ORDER BY name ASC")
			.fetch_all(&state.pool)
			.await?;
	let out = rows.into_iter().map(UserResponse::from).collect();
	Ok((StatusCode::OK, Json(out)))
}

pub async fn get_user_handler(
	State(state): State<AppState>,
	Path(private_acc_address): Path<String>,
) -> Result<(StatusCode, Json<UserResponse>), AppError> {
	let row: Option<UserRow> =
		sqlx::query_as("SELECT * FROM users WHERE private_acc_address = $1")
			.bind(&private_acc_address)
			.fetch_optional(&state.pool)
			.await?;

	match row {
		Some(r) => Ok((StatusCode::OK, Json(UserResponse::from(r)))),
		None => Err(AppError::NotFound("user not found".into())),
	}
}
