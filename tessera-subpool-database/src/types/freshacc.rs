/// Status of a FreshAcc transaction request.
#[derive(Debug, Clone, sqlx::Type, serde::Serialize, serde::Deserialize)]
#[sqlx(type_name = "freshacc_status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FreshAccStatus {
	Pending,
	Approved,
	Rejected,
}

/// Raw row returned from the `freshacc_requests` table.
#[derive(sqlx::FromRow)]
pub struct FreshAccRow {
	pub id: i64,
	pub private_acc_address: String,
	pub private_identifier: String,
	pub spend_auth: Vec<u8>,
	pub approval_signature: Option<Vec<u8>>,
	pub rejection_msg: Option<String>,
	pub status: FreshAccStatus,
	pub created_at: chrono::DateTime<chrono::Utc>,
	pub updated_at: chrono::DateTime<chrono::Utc>,
}
