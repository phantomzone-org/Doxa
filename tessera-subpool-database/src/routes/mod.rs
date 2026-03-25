use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;

pub mod account;
pub mod deposit;
pub mod freshacc;
pub mod register;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/register", post(register::register_handler))
        .route("/deposit", post(deposit::submit_deposit_handler))
        .route(
            "/account/{private_acc_address}",
            get(account::get_account_handler),
        )
        .route(
            "/freshacc/{private_acc_address}/status",
            get(freshacc::get_freshacc_status_handler),
        )
        .with_state(state)
}
