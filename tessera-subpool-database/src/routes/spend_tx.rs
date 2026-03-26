use axum::{extract::State, http::StatusCode, Json};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use plonky2_field::types::PrimeField64;
use tessera_client::AssetId;

use crate::{
    convert::{account_from_row, bytes_to_f, bytes_to_u256},
    error::AppError,
    state::AppState,
    types::{account::AccountRow, spend_tx::InputNoteStatus},
};

#[derive(Deserialize)]
pub struct NotePayload {
    /// hex string, 32 chars ([F;2] = 16 bytes)
    pub identifier: String,
    /// hex-encoded F (8 bytes = 16 hex chars)
    pub asset_id: String,
    /// hex-encoded U256 (32 bytes = 64 hex chars)
    pub amount: String,
    pub recipient_address: String,
    pub sender_address: String,
}

#[derive(Deserialize)]
pub struct SpendTxRequest {
    pub priv_acc_address: String,
    pub input_notes: Vec<NotePayload>,
    pub output_notes: Vec<NotePayload>,
    pub dinotes: Vec<String>,
    pub donotes: Vec<String>,
}

#[derive(Serialize)]
pub struct SpendTxResponse {
    pub id: i64,
}

fn u256_add(a: U256, b: U256) -> U256 {
    a.overflowing_add(b).0
}

pub async fn submit_spend_tx_handler(
    State(state): State<AppState>,
    Json(req): Json<SpendTxRequest>,
) -> Result<(StatusCode, Json<SpendTxResponse>), AppError> {
    // ── 1. Validate and fetch each input note ──────────────────────────────────
    let mut inote_amounts: Vec<U256> = Vec::with_capacity(req.input_notes.len());

    for note in &req.input_notes {
        if note.identifier.len() != 32 {
            return Err(AppError::InvalidInput(format!(
                "input note identifier '{}' must be 32 hex chars",
                note.identifier
            )));
        }

        let row: Option<(String, Vec<u8>, InputNoteStatus)> = sqlx::query_as(
            "SELECT recipient_address, amount, status FROM input_notes WHERE identifier = $1",
        )
        .bind(&note.identifier)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

        let (recipient_address, amount_bytes, status) = row.ok_or_else(|| {
            AppError::InvalidInput(format!("input note '{}' not found", note.identifier))
        })?;

        if recipient_address != req.priv_acc_address {
            return Err(AppError::InvalidInput(format!(
                "input note '{}' recipient does not match priv_acc_address",
                note.identifier
            )));
        }

        if !matches!(status, InputNoteStatus::Approved) {
            return Err(AppError::InvalidInput(format!(
                "input note '{}' is not approved",
                note.identifier
            )));
        }

        let arr: [u8; 32] = amount_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AppError::InvalidInput("input note amount must be 32 bytes".into()))?;
        inote_amounts.push(bytes_to_u256(&arr));
    }

    // ── 1b. Validate shared asset_id ──────────────────────────────────────────
    let all_asset_ids: Vec<&str> = req.input_notes.iter()
        .chain(req.output_notes.iter())
        .map(|n| n.asset_id.as_str())
        .collect();

    let asset_id_hex = all_asset_ids
        .first()
        .ok_or_else(|| AppError::InvalidInput("spend tx must have at least one note".into()))?;

    for id in &all_asset_ids {
        if id != asset_id_hex {
            return Err(AppError::InvalidInput(
                "all notes must share the same asset_id".into(),
            ));
        }
    }

    let asset_id_bytes = hex::decode(asset_id_hex)
        .map_err(|_| AppError::InvalidInput("invalid asset_id hex".into()))?;
    let asset_id_arr: [u8; 8] = asset_id_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AppError::InvalidInput("asset_id must be 8 bytes".into()))?;
    let asset_id = AssetId::from_u64(bytes_to_f(&asset_id_arr).to_canonical_u64())
        .map_err(|e| AppError::InvalidInput(e.to_string()))?;

    // ── 2. Validate and decode each output note ────────────────────────────────
    struct DecodedOutput {
        identifier: String,
        asset_id_bytes: Vec<u8>,
        amount_bytes: Vec<u8>,
        amount: U256,
        recipient_address: String,
        sender_address: String,
    }

    let mut decoded_outputs: Vec<DecodedOutput> = Vec::with_capacity(req.output_notes.len());

    for note in &req.output_notes {
        if note.sender_address != req.priv_acc_address {
            return Err(AppError::InvalidInput(format!(
                "output note '{}' sender does not match priv_acc_address",
                note.identifier
            )));
        }

        let asset_id_bytes = hex::decode(&note.asset_id)
            .map_err(|_| AppError::InvalidInput(format!("invalid asset_id hex in output note '{}'", note.identifier)))?;
        if asset_id_bytes.len() != 8 {
            return Err(AppError::InvalidInput(format!(
                "output note '{}' asset_id must be 8 bytes",
                note.identifier
            )));
        }

        let amount_bytes = hex::decode(&note.amount)
            .map_err(|_| AppError::InvalidInput(format!("invalid amount hex in output note '{}'", note.identifier)))?;
        if amount_bytes.len() != 32 {
            return Err(AppError::InvalidInput(format!(
                "output note '{}' amount must be 32 bytes",
                note.identifier
            )));
        }

        let arr: [u8; 32] = amount_bytes.as_slice().try_into().unwrap();
        let amount = bytes_to_u256(&arr);

        decoded_outputs.push(DecodedOutput {
            identifier: note.identifier.clone(),
            asset_id_bytes,
            amount_bytes,
            amount,
            recipient_address: note.recipient_address.clone(),
            sender_address: note.sender_address.clone(),
        });
    }

    // ── 3. Fetch and parse account ─────────────────────────────────────────────
    let row: Option<AccountRow> = sqlx::query_as(
        "SELECT * FROM accounts WHERE private_acc_address = $1",
    )
    .bind(&req.priv_acc_address)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

    let row = row.ok_or_else(|| {
        AppError::NotFound(format!("account '{}' not found", req.priv_acc_address))
    })?;

    let account = account_from_row(&row).map_err(AppError::Internal)?;

    let acc_balance = account.ast.amount_for(asset_id).map(|(_, amt)| amt).unwrap_or(U256::zero());

    // ── 4. Balance check: acc_balance + sum(inotes) == sum(onotes) ─────────────
    let total_in = inote_amounts
        .iter()
        .fold(acc_balance, |a, &v| u256_add(a, v));
    let total_out = decoded_outputs
        .iter()
        .fold(U256::zero(), |acc, d| u256_add(acc, d.amount));

    if total_in != total_out {
        return Err(AppError::InvalidInput(
            "balance mismatch: acc_balance + sum(inotes) != sum(onotes)".into(),
        ));
    }

    // ── 5. Transactional insert ────────────────────────────────────────────────
    let inote_identifiers: Vec<String> = req.input_notes.iter().map(|n| n.identifier.clone()).collect();
    let onote_identifiers: Vec<String> = req.output_notes.iter().map(|n| n.identifier.clone()).collect();

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

    let row = sqlx::query(
        r#"INSERT INTO spend_tx_requests
               (priv_acc_address, inote_identifiers, onote_identifiers, dinotes, donotes)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id"#,
    )
    .bind(&req.priv_acc_address)
    .bind(&inote_identifiers)
    .bind(&onote_identifiers)
    .bind(&req.dinotes)
    .bind(&req.donotes)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

    let id: i64 = row
        .try_get("id")
        .map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

    for out in &decoded_outputs {
        sqlx::query(
            r#"INSERT INTO output_notes
                   (identifier, asset_id, amount, recipient_address, sender_address)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(&out.identifier)
        .bind(&out.asset_id_bytes)
        .bind(&out.amount_bytes)
        .bind(&out.recipient_address)
        .bind(&out.sender_address)
        .execute(&mut *tx)
        .await
        .map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;
    }

    tx.commit()
        .await
        .map_err(|e: sqlx::Error| AppError::Internal(e.into()))?;

    Ok((StatusCode::CREATED, Json(SpendTxResponse { id })))
}
