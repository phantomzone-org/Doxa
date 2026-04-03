use serde::{Deserialize, Serialize};
use sqlx::Type;

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
#[sqlx(type_name = "withdrawal_tx_status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WithdrawalTxStatus {
    Pending,
    Approved,
    Rejected,
}
