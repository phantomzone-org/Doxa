use axum::{routing::post, Router};

use crate::state::AppState;

pub mod register;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/register", post(register::register_handler))
        .with_state(state)
}
