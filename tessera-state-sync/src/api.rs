use alloy::primitives::B256;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
};
use plonky2_field::types::Field;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::{BatchKind, BatchStatus, CommitmentStatus, DepositStatus, NullifierStatus, StateSyncService};

#[derive(Deserialize)]
pub struct CommitmentQuery {
    commitment: String,
}

#[derive(Deserialize)]
pub struct NullifierQuery {
    nullifier: String,
}

#[derive(Deserialize)]
pub struct SubpoolQuery {
    subpool_id: u64,
}

#[derive(Deserialize)]
pub struct BatchQuery {
    pi_commitment: String,
    kind: String, // "tx" or "bridge"
}

#[derive(Deserialize)]
pub struct DepositsQuery {
    from_block: Option<u64>,
}

#[derive(Serialize)]
struct MerklePathResponse {
    leaf_index: usize,
    siblings: Vec<String>,
    directions: Vec<u8>,
}

fn hash_output_to_hex_string(hash: &tessera_utils::hasher::HashOutput) -> String {
    let bytes = crate::contract::hash_to_bytes32(hash);
    format!("0x{}", hex::encode(bytes))
}

fn bytes32_to_hex_string(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn hex_string_to_bytes32(hex_str: &str) -> Result<[u8; 32], String> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if hex_str.len() != 64 {
        return Err("hex string must be 64 characters (32 bytes)".to_string());
    }

    let mut bytes = [0u8; 32];
    let decoded = hex::decode(hex_str)
        .map_err(|e| format!("invalid hex: {}", e))?;

    if decoded.len() != 32 {
        return Err("decoded hex must be 32 bytes".to_string());
    }

    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

pub async fn get_commitment_merkle_path(
    Query(params): Query<CommitmentQuery>,
    State(service): State<StateSyncService>,
) -> Result<Json<Value>, StatusCode> {
    let commitment_bytes = hex_string_to_bytes32(&params.commitment)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let commitment_hash = crate::contract::bytes32_to_hash(
        &B256::from(commitment_bytes)
    ).map_err(|_| StatusCode::BAD_REQUEST)?;

    let status = service.with_state(|state| state.get_commitment_status(&commitment_hash));

    match status {
        CommitmentStatus::Confirmed { batch_subtree_path, state_tree_path } => {
            let batch_subtree_response = MerklePathResponse {
                leaf_index: batch_subtree_path.pos,
                siblings: batch_subtree_path.siblings.iter().map(hash_output_to_hex_string).collect(),
                directions: batch_subtree_path.path.iter().map(|&b| if b { 1 } else { 0 }).collect(),
            };

            let state_tree_response = MerklePathResponse {
                leaf_index: state_tree_path.pos,
                siblings: state_tree_path.siblings.iter().map(hash_output_to_hex_string).collect(),
                directions: state_tree_path.path.iter().map(|&b| if b { 1 } else { 0 }).collect(),
            };

            Ok(Json(json!({
                "status": "confirmed",
                "batch_subtree_path": batch_subtree_response,
                "state_tree_path": state_tree_response
            })))
        },
        CommitmentStatus::Pending { pi_commitment } => {
            Ok(Json(json!({
                "status": "pending",
                "pi_commitment": bytes32_to_hex_string(&pi_commitment)
            })))
        },
        CommitmentStatus::NotFound => {
            Ok(Json(json!({
                "status": "not_found"
            })))
        },
    }
}

pub async fn get_nullifier_status(
    Query(params): Query<NullifierQuery>,
    State(service): State<StateSyncService>,
) -> Result<Json<Value>, StatusCode> {
    let nullifier_bytes = hex_string_to_bytes32(&params.nullifier)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let nullifier_hash = crate::contract::bytes32_to_hash(
        &B256::from(nullifier_bytes)
    ).map_err(|_| StatusCode::BAD_REQUEST)?;

    let status = service.with_state(|state| state.get_nullifier_status(&nullifier_hash));

    match status {
        NullifierStatus::Confirmed => {
            Ok(Json(json!({ "status": "confirmed" })))
        },
        NullifierStatus::Pending { pi_commitment } => {
            Ok(Json(json!({
                "status": "pending",
                "pi_commitment": bytes32_to_hex_string(&pi_commitment)
            })))
        },
        NullifierStatus::NotFound => {
            Ok(Json(json!({ "status": "not_found" })))
        },
    }
}

pub async fn get_subpool_full_proof(
    Query(params): Query<SubpoolQuery>,
    State(service): State<StateSyncService>,
) -> Result<Json<Value>, StatusCode> {
    if params.subpool_id == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    let result = service.with_state(|state| {
        if let Some(&subpool_root) = state.subpool_roots.get(&params.subpool_id) {
            // Create leaf and get its commitment
            use tessera_client::pool_config::MainPoolConfigLeaf;
            use tessera_client::SubpoolId;
            use tessera_utils::F;
            use tessera_utils::hasher::MerkleHash;

            let subpool_id_field = SubpoolId(F::from_canonical_u64(params.subpool_id));
            let leaf_value = if subpool_root == tessera_utils::hasher::HashOutput::ZERO {
                tessera_utils::hasher::HashOutput::ZERO
            } else {
                let leaf = MainPoolConfigLeaf::<tessera_utils::hasher::HashOutput>::new(subpool_root, subpool_id_field);
                leaf.commit()
            };

            // Get proof from config tree
            if let Ok(proof) = state.config_tree.subpool_proof(subpool_id_field, subpool_root) {
                Some((subpool_root, leaf_value, state.config_tree.root(), proof))
            } else {
                None
            }
        } else {
            None
        }
    });

    match result {
        Some((subpool_root, leaf_value, config_tree_root, proof)) => {
            Ok(Json(json!({
                "subpool_id": params.subpool_id,
                "subpool_root": hash_output_to_hex_string(&subpool_root),
                "leaf_value": hash_output_to_hex_string(&leaf_value),
                "config_tree_root": hash_output_to_hex_string(&config_tree_root),
                "siblings": proof.siblings.iter().map(hash_output_to_hex_string).collect::<Vec<_>>(),
                "directions": proof.path.iter().map(|&b| if b { 1 } else { 0 }).collect::<Vec<_>>()
            })))
        },
        None => Err(StatusCode::NOT_FOUND),
    }
}

pub async fn get_batch_status(
    Query(params): Query<BatchQuery>,
    State(service): State<StateSyncService>,
) -> Result<Json<Value>, StatusCode> {
    let pi_commitment = hex_string_to_bytes32(&params.pi_commitment)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let kind = match params.kind.as_str() {
        "tx" => BatchKind::Transaction,
        "bridge" => BatchKind::BridgeTx,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let status = service.with_state(|state| state.get_batch_status(&pi_commitment, kind));

    match status {
        BatchStatus::Confirmed => {
            Ok(Json(json!({ "status": "confirmed" })))
        },
        BatchStatus::Pending => {
            Ok(Json(json!({ "status": "pending" })))
        },
        BatchStatus::NotFound => {
            Ok(Json(json!({ "status": "not_found" })))
        },
    }
}

fn deposit_status_to_string(status: &DepositStatus) -> &'static str {
    match status {
        DepositStatus::Pending => "Pending",
        DepositStatus::Validated => "Validated",
        DepositStatus::Withdrawn => "Withdrawn",
    }
}

pub async fn get_deposits(
    Query(params): Query<DepositsQuery>,
    State(service): State<StateSyncService>,
) -> Result<Json<Value>, StatusCode> {
    let from_block = params.from_block.unwrap_or(0);

    let deposits = service.with_state(|state| {
        let deposit_records = state.get_deposits_from_block(from_block);
        deposit_records.into_iter().map(|deposit| {
            json!({
                "note_commitment": bytes32_to_hex_string(&deposit.note_commitment),
                "value": deposit.value.to_string(),
                "recipient": format!("0x{}", hex::encode(deposit.recipient)),
                "asset_id": deposit.asset_id.to_string(),
                "status": deposit_status_to_string(&deposit.status),
                "deposit_block": deposit.deposit_block
            })
        }).collect::<Vec<_>>()
    });

    Ok(Json(Value::Array(deposits)))
}