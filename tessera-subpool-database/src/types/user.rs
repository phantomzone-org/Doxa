/// Raw row returned from the `users` table.
#[derive(sqlx::FromRow)]
pub struct UserRow {
    pub id: i64,
    pub private_acc_address: String,
    pub name: String,
    pub physical_address: String,
    pub dob: chrono::NaiveDate,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
