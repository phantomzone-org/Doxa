use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;

pub mod account;
pub mod register;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/register", post(register::register_handler))
        .route(
            "/account/:private_acc_address",
            get(account::get_account_handler),
        )
        .with_state(state)
}
