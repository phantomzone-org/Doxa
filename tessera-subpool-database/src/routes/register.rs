use axum::{extract::State, http::StatusCode, Json};
use plonky2_field::types::Field;
use serde::{Deserialize, Serialize};
use tessera_client::{schnorr::CompressedPublicKey, AccountAddress, StandardAccount, SubpoolId};
use tessera_utils::F;

use crate::{
	convert::{account_to_insert, bytes_to_private_id},
	error::AppError,
	state::AppState,
	SUBPOOL_ID,
};

/// JSON request body for `POST /register`.
#[derive(Deserialize)]
pub struct RegisterRequest {
	/// Hex string: 16 bytes (2 × u64 LE) encoding `PrivateIdentifier([F; 2])`.
	/// Exactly 32 hex characters.
	pub private_identifier: String,

	/// Hex string: 40 bytes (5 × u64 LE) encoding `CompressedPublicKey<F>`.
	/// Exactly 80 hex characters.
	pub spend_auth_pk: String,

	/// Ethereum address, e.g. `"0x..."` (42 characters).
	pub eth_address: String,

	pub name: String,
	pub physical_address: String,
	/// Date of birth as `"YYYY-MM-DD"`.
	pub dob: String,
}

/// JSON response body for a successful 201 Created.
#[derive(Serialize)]
pub struct RegisterResponse {
	pub private_acc_address: String,
}

pub async fn register_handler(
	State(state): State<AppState>,
	Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), AppError> {
	// ── 1. Decode and validate private_identifier (must be exactly 16 bytes) ──
	let pi_bytes = hex::decode(&body.private_identifier).map_err(|_| {
		AppError::InvalidInput("private_identifier must be a valid hex string".into())
	})?;
	if pi_bytes.len() != 16 {
		return Err(AppError::InvalidInput(
			"private_identifier must be 16 bytes (32 hex chars)".into(),
		));
	}
	let pi_arr: &[u8; 16] = pi_bytes.as_slice().try_into().unwrap();
	let private_identifier = bytes_to_private_id(pi_arr);

	// ── 2. Build account and derive address ───────────────────────────────────
	let subpool_id = SubpoolId(F::from_canonical_u64(SUBPOOL_ID));
	let mut acc = StandardAccount::new_with(private_identifier, subpool_id);
	let private_acc_address = AccountAddress::from_acc(&acc).to_hex();

	// ── 3. Existence checks ───────────────────────────────────────────────────
	let pool = &state.pool;

	let user_exists: bool =
		sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE private_acc_address = $1)")
			.bind(&private_acc_address)
			.fetch_one(pool)
			.await?;

	if user_exists {
		return Err(AppError::AlreadyExists(
			"account address already registered".into(),
		));
	}

	let freshacc_exists: bool = sqlx::query_scalar(
		"SELECT EXISTS(SELECT 1 FROM freshacc_requests WHERE private_acc_address = $1)",
	)
	.bind(&private_acc_address)
	.fetch_one(pool)
	.await?;

	if freshacc_exists {
		return Err(AppError::AlreadyExists(
			"a pending freshacc request already exists for this account".into(),
		));
	}

	// ── 4. Decode and validate spend_auth_pk (must be exactly 40 bytes) ───────
	let pk_bytes = hex::decode(&body.spend_auth_pk)
		.map_err(|_| AppError::InvalidInput("spend_auth_pk must be a valid hex string".into()))?;
	if pk_bytes.len() != 40 {
		return Err(AppError::InvalidInput(
			"spend_auth_pk must be 40 bytes (80 hex chars)".into(),
		));
	}
	let pk_arr: &[u8; 40] = pk_bytes.as_slice().try_into().unwrap();
	let spend_pk = CompressedPublicKey::<F>::decode(pk_arr);
	acc.spend_auth.spend_pk = Some(spend_pk);

	// ── 5. Validate eth_address ───────────────────────────────────────────────
	if !body.eth_address.starts_with("0x") || body.eth_address.len() != 42 {
		return Err(AppError::InvalidInput(
			"eth_address must be a 42-character 0x-prefixed hex string".into(),
		));
	}

	// ── 6. Parse date of birth ────────────────────────────────────────────────
	let dob = chrono::NaiveDate::parse_from_str(&body.dob, "%Y-%m-%d")
		.map_err(|_| AppError::InvalidInput("dob must be in YYYY-MM-DD format".into()))?;

	// ── 7. Transactional insert ───────────────────────────────────────────────
	let spend_auth_bytes = spend_pk.encode();

	let mut tx = pool.begin().await?;

	sqlx::query(
		r#"
        INSERT INTO users (private_acc_address, name, physical_address, dob)
        VALUES ($1, $2, $3, $4)
        "#,
	)
	.bind(&private_acc_address)
	.bind(&body.name)
	.bind(&body.physical_address)
	.bind(dob)
	.execute(&mut *tx)
	.await?;

	sqlx::query(
		r#"
        INSERT INTO freshacc_requests (private_acc_address, spend_auth, status)
        VALUES ($1, $2, 'PENDING')
        "#,
	)
	.bind(&private_acc_address)
	.bind(spend_auth_bytes.as_ref())
	.execute(&mut *tx)
	.await?;

	tx.commit().await?;

	Ok((
		StatusCode::CREATED,
		Json(RegisterResponse {
			private_acc_address,
		}),
	))
}
