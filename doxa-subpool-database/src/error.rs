use axum::{
	http::StatusCode,
	response::{IntoResponse, Response},
	Json,
};
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
	/// Resource already exists — 409 Conflict.
	AlreadyExists(String),
	/// Resource not found — 404 Not Found.
	NotFound(String),
	/// Input validation failed — 400 Bad Request.
	InvalidInput(String),
	/// Database or internal error — 500 Internal Server Error.
	Internal(anyhow::Error),
}

impl IntoResponse for AppError {
	fn into_response(self) -> Response {
		let (status, message) = match self {
			AppError::AlreadyExists(msg) => (StatusCode::CONFLICT, msg),
			AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
			AppError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg),
			AppError::Internal(err) => {
				tracing::error!("internal error: {err:#}");
				(
					StatusCode::INTERNAL_SERVER_ERROR,
					"internal server error".to_string(),
				)
			},
		};
		(status, Json(json!({ "error": message }))).into_response()
	}
}

impl From<anyhow::Error> for AppError {
	fn from(e: anyhow::Error) -> Self {
		AppError::Internal(e)
	}
}

impl From<sqlx::Error> for AppError {
	fn from(e: sqlx::Error) -> Self {
		AppError::Internal(e.into())
	}
}
