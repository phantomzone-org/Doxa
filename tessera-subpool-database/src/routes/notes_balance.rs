use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use std::collections::HashMap;

use crate::{convert::bytes_to_u256, error::AppError, state::AppState};

/// Row type for summing input notes.
#[derive(sqlx::FromRow)]
struct NoteRow {
    asset_id: Vec<u8>,
    amount: Vec<u8>,
}

/// Per-asset balance entry.
#[derive(Serialize)]
pub struct AssetBalance {
    pub amount: String, // hex-encoded U256
}

/// Response: `{ "balances": { "<asset_id_u64>": { "amount": "hex" }, ... } }`
#[derive(Serialize)]
pub struct NotesBalanceResponse {
    pub balances: HashMap<String, AssetBalance>,
}

/// Sum all APPROVED input notes for a given recipient, grouped by asset.
pub async fn get_notes_balance_handler(
    State(state): State<AppState>,
    Path(private_acc_address): Path<String>,
) -> Result<(StatusCode, Json<NotesBalanceResponse>), AppError> {
    let rows: Vec<NoteRow> = sqlx::query_as(
        "SELECT asset_id, amount FROM input_notes \
         WHERE recipient_address = $1 AND status = 'APPROVED'",
    )
    .bind(&private_acc_address)
    .fetch_all(&state.pool)
    .await?;

    let mut balances: HashMap<String, primitive_types::U256> = HashMap::new();

    for row in &rows {
        let asset_id_arr: [u8; 8] = row
            .asset_id
            .as_slice()
            .try_into()
            .unwrap_or([0u8; 8]);
        let asset_id_u64 = u64::from_le_bytes(asset_id_arr);

        let amount_arr: [u8; 32] = row
            .amount
            .as_slice()
            .try_into()
            .unwrap_or([0u8; 32]);
        let amount = bytes_to_u256(&amount_arr);

        *balances
            .entry(asset_id_u64.to_string())
            .or_insert(primitive_types::U256::zero()) += amount;
    }

    let response = NotesBalanceResponse {
        balances: balances
            .into_iter()
            .map(|(k, v)| {
                let bytes = v.to_big_endian();
                (
                    k,
                    AssetBalance {
                        amount: hex::encode(bytes),
                    },
                )
            })
            .collect(),
    };

    Ok((StatusCode::OK, Json(response)))
}
