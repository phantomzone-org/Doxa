use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Type;

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
#[sqlx(type_name = "deposit_tx_status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DepositTxStatus {
	Pending,
	Approved,
	Rejected,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct DepositTxRow {
	pub id: i64,
	pub recipient_acc_address: String,
	pub eth_address: String,
	pub deposit_note_identifier: Vec<u8>,
	pub deposit_amount: Vec<u8>,
	pub asset_id: Vec<u8>,
	pub signed_public_tx: Vec<u8>,
	pub deposit_tx_hash: Option<String>,
	pub status: DepositTxStatus,
	pub approval_signature: Option<Vec<u8>>,
	pub rejection_reason: Option<String>,
	pub created_at: DateTime<Utc>,
	pub updated_at: DateTime<Utc>,
}
