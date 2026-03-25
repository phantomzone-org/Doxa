use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Type;

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
#[sqlx(type_name = "spend_tx_status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SpendTxStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
#[sqlx(type_name = "input_note_status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InputNoteStatus {
    Approved,
    Rejected,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SpendTxRow {
    pub id: i64,
    pub priv_acc_address: String,
    pub inote_identifiers: Vec<String>,
    pub onote_identifiers: Vec<String>,
    pub dinotes: Vec<String>,
    pub donotes: Vec<String>,
    pub status: SpendTxStatus,
    pub approval_signature: Option<Vec<u8>>,
    pub rejection_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct InputNoteRow {
    pub id: i64,
    pub identifier: String,
    pub asset_id: Vec<u8>,
    pub amount: Vec<u8>,
    pub recipient_address: String,
    pub sender_address: String,
    pub status: InputNoteStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct OutputNoteRow {
    pub id: i64,
    pub identifier: String,
    pub asset_id: Vec<u8>,
    pub amount: Vec<u8>,
    pub recipient_address: String,
    pub sender_address: String,
    pub created_at: DateTime<Utc>,
}
