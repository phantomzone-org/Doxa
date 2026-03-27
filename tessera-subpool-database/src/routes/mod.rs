use axum::{
	routing::{get, post},
	Router,
};

use crate::state::AppState;

pub mod account;
pub mod admin;
pub mod deposit;
pub mod faucet;
pub mod freshacc;
pub mod input_notes;
pub mod register;
pub mod spend_tx;

pub fn router(state: AppState) -> Router {
	Router::new()
		.route("/admin/freshacc", get(admin::list_freshacc_handler))
		.route("/admin/accounts", get(admin::list_accounts_handler))
		.route("/register", post(register::register_handler))
		.route("/deposit", post(deposit::submit_deposit_handler))
		.route("/deposit/{id}/status", get(deposit::get_deposit_status_handler))
		.route("/faucet", post(faucet::faucet_handler))
		.route("/spend_tx", post(spend_tx::submit_spend_tx_handler))
		.route(
			"/account/{private_acc_address}",
			get(account::get_account_handler),
		)
		.route(
			"/input_notes/{recipient_address}",
			get(input_notes::get_input_notes_handler),
		)
		.route(
			"/freshacc/{private_acc_address}/status",
			get(freshacc::get_freshacc_status_handler),
		)
		.with_state(state)
}
