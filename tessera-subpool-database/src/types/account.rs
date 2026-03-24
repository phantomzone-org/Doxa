/// Raw row returned from the `accounts` table.
#[derive(sqlx::FromRow)]
pub struct AccountRow {
    pub id: i64,
    pub private_acc_address: String,
    pub eth_address: String,
    pub private_identifier: Vec<u8>,
    pub subpool_id: Vec<u8>,
    pub balance: Vec<u8>,
    pub nonce: Vec<u8>,
    pub spend_auth: Vec<u8>,
    pub consume_auth: Vec<u8>,
    pub ast: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
