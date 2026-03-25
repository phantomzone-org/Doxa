use std::array;

use anyhow::{Context, Result};
use plonky2_field::types::Field;
use serde::Serialize;
use sqlx::PgPool;
use tessera_client::{
    NOTE_BATCH, NoteCommitment, NoteNullifier,
    SpendAuth, StandardAccount, SubpoolId,
    derive_priv_tx_hash, double_hash_native, sample_dummy_notes,
    schnorr::{CompressedPublicKey, PrivateKey, Scalar, schnorr_sign},
};
use tessera_utils::F;
use tracing::{error, info};

use tessera_subpool_database::{
    SUBPOOL_ID,
    convert::{account_to_insert, bytes_to_private_id, hash_to_hex},
    db::insert_account_and_user,
};

// ── DB row types ────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct PendingFreshAcc {
    id: i64,
    private_acc_address: String,
    spend_auth: Vec<u8>,
    private_identifier: Vec<u8>,
    eth_address: String,
    name: String,
    physical_address: String,
    dob: chrono::NaiveDate,
}

// ── Sequencer request ───────────────────────────────────────────────────────

#[derive(Serialize)]
struct TransactionRequest {
    tx_id: Option<String>,
    input_account_leaf: String,
    output_account_leaf: String,
    input_notes: Vec<String>,
    output_notes: Vec<String>,
    tx_proof: String,
}

// ── Core loop ───────────────────────────────────────────────────────────────

pub async fn process_pending(
    pool: &PgPool,
    approval_sk: &PrivateKey,
    sequencer_url: &str,
    http: &reqwest::Client,
) -> Result<()> {
    let rows: Vec<PendingFreshAcc> = sqlx::query_as(
        "SELECT id, private_acc_address, spend_auth, \
                private_identifier, eth_address, name, physical_address, dob \
         FROM freshacc_requests \
         WHERE status = 'PENDING' \
         ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await?;

    info!(pending = rows.len(), "polled freshacc_requests");

    if rows.is_empty() {
        return Ok(());
    }

    for row in rows {
        if let Err(e) = process_one(pool, approval_sk, sequencer_url, http, &row).await {
            error!(
                id = row.id,
                addr = %row.private_acc_address,
                "failed to process FreshAcc request: {e:#}"
            );
        }
    }

    Ok(())
}

async fn process_one(
    pool: &PgPool,
    approval_sk: &PrivateKey,
    sequencer_url: &str,
    http: &reqwest::Client,
    row: &PendingFreshAcc,
) -> Result<()> {
    // ── 1. Reconstruct accin from freshacc_requests data ──────────────────────
    let pi_arr: [u8; 16] = row
        .private_identifier
        .as_slice()
        .try_into()
        .context("private_identifier must be 16 bytes")?;
    let private_identifier = bytes_to_private_id(&pi_arr);

    let subpool_id = SubpoolId(F::from_canonical_u64(SUBPOOL_ID));
    let accin = StandardAccount::new_with(private_identifier, subpool_id);

    // ── 2. Build accout (nonce 0→1, set spend_auth) ──────────────────────────
    let spend_pk_bytes: [u8; 40] = row
        .spend_auth
        .as_slice()
        .try_into()
        .context("spend_auth must be 40 bytes")?;
    let spend_pk = CompressedPublicKey::<F>::decode(&spend_pk_bytes);

    let mut accout = accin.clone_with_incremented_nonce();
    accout.spend_auth = SpendAuth {
        spend_pk: Some(spend_pk),
    };

    // ── 3. Sample dummy notes and compute tx_hash ────────────────────────────
    let mut rng = rand::rng();
    let (dinotes, donotes) = sample_dummy_notes(&mut rng);

    let dinote_nulls: [NoteNullifier; NOTE_BATCH] =
        array::from_fn(|i| NoteNullifier(double_hash_native(dinotes[i]).into()));
    let donote_comms: [NoteCommitment; NOTE_BATCH] =
        array::from_fn(|i| NoteCommitment(double_hash_native(donotes[i]).into()));

    let tx_hash = derive_priv_tx_hash(
        accin.nullifier(),
        accout.commitment(),
        dinote_nulls.clone(),
        donote_comms.clone(),
    );

    // ── 4. Sign tx_hash with approval key ────────────────────────────────────
    let k = Scalar::sample(&mut rng);
    let approval_sig = schnorr_sign(approval_sk, &tx_hash.0, k);
    let sig_bytes = approval_sig.encode();

    // ── 5. POST to sequencer (must succeed before updating DB) ───────────────
    let an = hash_to_hex(&accin.nullifier().0 .0);
    let ac = hash_to_hex(&accout.commitment().0 .0);

    let input_notes: Vec<String> = dinote_nulls.iter().map(|n| hash_to_hex(&n.0 .0)).collect();
    let output_notes: Vec<String> = donote_comms.iter().map(|c| hash_to_hex(&c.0 .0)).collect();

    let tx_req = TransactionRequest {
        tx_id: Some(format!("freshacc-{}", row.private_acc_address)),
        input_account_leaf: an,
        output_account_leaf: ac,
        input_notes,
        output_notes,
        tx_proof: hex::encode([0u8; 1]),
    };

    let url = format!("{}/transaction", sequencer_url.trim_end_matches('/'));
    let resp = http
        .post(&url)
        .json(&tx_req)
        .send()
        .await
        .context("failed to reach sequencer")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "sequencer rejected transaction (HTTP {status}): {body}"
        );
    }

    info!(
        id = row.id,
        addr = %row.private_acc_address,
        "FreshAcc transaction submitted to sequencer"
    );

    // ── 6. Update freshacc_requests: APPROVED + signature ────────────────────
    sqlx::query(
        "UPDATE freshacc_requests \
         SET status = 'APPROVED', approval_signature = $1, updated_at = NOW() \
         WHERE id = $2",
    )
    .bind(sig_bytes.as_ref())
    .bind(row.id)
    .execute(pool)
    .await
    .context("failed to update freshacc_requests")?;

    info!(
        id = row.id,
        addr = %row.private_acc_address,
        "FreshAcc request approved in DB"
    );

    // ── 7. Create accounts + users rows (only after approval) ────────────────
    let insert = account_to_insert(&accout, row.eth_address.clone());
    insert_account_and_user(pool, &insert, &row.name, &row.physical_address, row.dob).await?;

    info!(
        id = row.id,
        addr = %row.private_acc_address,
        "account + user rows created in DB"
    );

    Ok(())
}
