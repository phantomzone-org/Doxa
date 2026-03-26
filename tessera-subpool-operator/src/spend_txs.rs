use std::array;

use anyhow::{Context, Result};
use primitive_types::U256;
use serde::Serialize;
use sqlx::PgPool;
use tessera_client::{
    NOTE_BATCH, NoteCommitment, NoteNullifier, SubpoolId,
    derive_priv_tx_hash, double_hash_native, sample_dummy_notes,
    schnorr::{PrivateKey, Scalar, schnorr_sign},
};
use tessera_utils::F;
use plonky2_field::types::Field;
use tracing::{error, info};

use tessera_subpool_database::{
    convert::{
        account_from_row, bytes_to_u256, hash_to_hex,
        f_to_bytes, u256_to_bytes,
    },
    db::insert_input_note,
    types::{
        account::AccountRow,
        spend_tx::{InputNoteRow, OutputNoteRow, SpendTxRow},
    },
};

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

pub async fn process_pending_spend_txs(
    pool: &PgPool,
    approval_sk: &PrivateKey,
    sequencer_url: &str,
    http: &reqwest::Client,
    subpool_id: u64,
) -> Result<()> {
    let rows: Vec<SpendTxRow> = sqlx::query_as(
        "SELECT * FROM spend_tx_requests \
         WHERE status = 'PENDING' \
         ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await?;

    info!(pending = rows.len(), "polled spend_tx_requests");

    if rows.is_empty() {
        return Ok(());
    }

    for row in rows {
        if let Err(e) = process_one_spend_tx(pool, approval_sk, sequencer_url, http, &row, subpool_id).await {
            error!(
                id = row.id,
                addr = %row.priv_acc_address,
                "failed to process spend tx: {e:#}"
            );
        }
    }

    Ok(())
}

async fn process_one_spend_tx(
    pool: &PgPool,
    approval_sk: &PrivateKey,
    sequencer_url: &str,
    http: &reqwest::Client,
    row: &SpendTxRow,
    subpool_id: u64,
) -> Result<()> {
    // ── 1. Sanity check: account exists ────────────────────────────────────────
    let acc_row: AccountRow = sqlx::query_as(
        "SELECT * FROM accounts WHERE private_acc_address = $1",
    )
    .bind(&row.priv_acc_address)
    .fetch_one(pool)
    .await
    .context("account not found for spend tx sender")?;

    let sid = SubpoolId(F::from_canonical_u64(subpool_id));
    let accin = account_from_row(&acc_row, sid)?;

    // ── 2. Sanity check: input notes exist and are unconsumed ──────────────────
    let mut total_input = U256::zero();

    for inote_id in &row.inote_identifiers {
        let inote: InputNoteRow = sqlx::query_as(
            "SELECT * FROM input_notes WHERE identifier = $1",
        )
        .bind(inote_id)
        .fetch_one(pool)
        .await
        .with_context(|| format!("input note '{inote_id}' not found"))?;

        if !matches!(inote.status, tessera_subpool_database::types::spend_tx::InputNoteStatus::Approved) {
            anyhow::bail!("input note '{inote_id}' is not in APPROVED status");
        }

        if inote.recipient_address != row.priv_acc_address {
            anyhow::bail!(
                "input note '{inote_id}' recipient '{}' does not match sender '{}'",
                inote.recipient_address,
                row.priv_acc_address
            );
        }

        let amount_arr: [u8; 32] = inote.amount.as_slice().try_into()
            .with_context(|| format!("input note '{inote_id}' amount must be 32 bytes"))?;
        total_input = total_input + bytes_to_u256(&amount_arr);
    }

    // ── 3. Sanity check: fetch output notes and verify balance ─────────────────
    let mut total_output = U256::zero();
    let mut output_notes: Vec<OutputNoteRow> = Vec::with_capacity(row.onote_identifiers.len());

    for onote_id in &row.onote_identifiers {
        let onote: OutputNoteRow = sqlx::query_as(
            "SELECT * FROM output_notes WHERE identifier = $1",
        )
        .bind(onote_id)
        .fetch_one(pool)
        .await
        .with_context(|| format!("output note '{onote_id}' not found"))?;

        let amount_arr: [u8; 32] = onote.amount.as_slice().try_into()
            .with_context(|| format!("output note '{onote_id}' amount must be 32 bytes"))?;
        total_output = total_output + bytes_to_u256(&amount_arr);

        output_notes.push(onote);
    }

    // Balance check: account.balance + sum(inotes) == sum(onotes)
    let balance_in = accin.balance + total_input;
    if balance_in != total_output {
        anyhow::bail!(
            "balance mismatch: account.balance({}) + inotes({}) != onotes({})",
            accin.balance, total_input, total_output
        );
    }

    // ── 4. Build accout with spend applied ─────────────────────────────────────
    let mut accout = accin.clone_with_incremented_nonce();
    accout.spend_auth = accin.spend_auth.clone();
    accout.ast = accin.ast.clone();

    // Update balance: new_balance = accin.balance + total_input - total_output
    // Since balance_in == total_output, the new account balance is 0 if all funds are spent,
    // or the remainder if partial. We need to track per-asset, but for now use aggregate.
    accout.balance = balance_in - total_output;

    // ── 5. Sample dummy notes and compute tx_hash ──────────────────────────────
    // For the demo (AcceptAllVerifier), we use dummy notes for the sequencer submission.
    // Real note nullifiers/commitments require NCT positions which the operator doesn't track.
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

    // ── 6. Sign tx_hash with approval key ──────────────────────────────────────
    let k = Scalar::sample(&mut rng);
    let approval_sig = schnorr_sign(approval_sk, &tx_hash.0, k);
    let sig_bytes = approval_sig.encode();

    // ── 7. POST to sequencer ───────────────────────────────────────────────────
    let an = hash_to_hex(&accin.nullifier().0 .0);
    let ac = hash_to_hex(&accout.commitment().0 .0);

    let input_note_hashes: Vec<String> = dinote_nulls.iter().map(|n| hash_to_hex(&n.0 .0)).collect();
    let output_note_hashes: Vec<String> = donote_comms.iter().map(|c| hash_to_hex(&c.0 .0)).collect();

    let tx_req = TransactionRequest {
        tx_id: Some(format!("spend-{}", row.id)),
        input_account_leaf: an,
        output_account_leaf: ac,
        input_notes: input_note_hashes,
        output_notes: output_note_hashes,
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
        anyhow::bail!("sequencer rejected spend tx (HTTP {status}): {body}");
    }

    info!(id = row.id, addr = %row.priv_acc_address, "spend tx submitted to sequencer");

    // ── 8. Mark input notes as consumed ────────────────────────────────────────
    for inote_id in &row.inote_identifiers {
        sqlx::query(
            "UPDATE input_notes SET status = 'REJECTED', updated_at = NOW() WHERE identifier = $1",
        )
        .bind(inote_id)
        .execute(pool)
        .await
        .with_context(|| format!("failed to mark input note '{inote_id}' as consumed"))?;
    }

    // ── 9. Update spend_tx_requests: APPROVED ──────────────────────────────────
    sqlx::query(
        "UPDATE spend_tx_requests \
         SET status = 'APPROVED', approval_signature = $1, updated_at = NOW() \
         WHERE id = $2",
    )
    .bind(sig_bytes.as_ref())
    .bind(row.id)
    .execute(pool)
    .await
    .context("failed to update spend_tx_requests")?;

    // ── 10. Update account in DB ───────────────────────────────────────────────
    // For now, keep existing AST (per-asset tracking will be refined later).
    let ast_json = acc_row.ast.clone();

    sqlx::query(
        "UPDATE accounts \
         SET nonce = $1, balance = $2, ast = $3, updated_at = NOW() \
         WHERE private_acc_address = $4",
    )
    .bind(f_to_bytes(accout.nonce.0).as_ref())
    .bind(u256_to_bytes(accout.balance).as_ref())
    .bind(&ast_json)
    .bind(&row.priv_acc_address)
    .execute(pool)
    .await
    .context("failed to update account after spend tx")?;

    // ── 11. Create input notes for local recipients ────────────────────────────
    for onote in &output_notes {
        // Check if the recipient account exists in this subpool
        let local: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE private_acc_address = $1)",
        )
        .bind(&onote.recipient_address)
        .fetch_one(pool)
        .await
        .unwrap_or(false);

        if local {
            insert_input_note(
                pool,
                &onote.identifier,
                &onote.asset_id,
                &onote.amount,
                &onote.recipient_address,
                &onote.sender_address,
            )
            .await?;

            info!(
                id = row.id,
                note_id = %onote.identifier,
                recipient = %onote.recipient_address,
                "created input note for local recipient"
            );
        } else {
            // Forward to sequencer for cross-subpool delivery.
            // Determine target subpool from the recipient address prefix (first 8 bytes = LE u64).
            let target_subpool = recipient_subpool_id(&onote.recipient_address);

            let forward_body = serde_json::json!({
                "target_subpool_id": target_subpool,
                "identifier": onote.identifier,
                "asset_id": hex::encode(&onote.asset_id),
                "amount": hex::encode(&onote.amount),
                "recipient_address": onote.recipient_address,
                "sender_address": onote.sender_address,
            });

            let fwd_url = format!("{}/forward_note", sequencer_url.trim_end_matches('/'));
            let resp = http.post(&fwd_url).json(&forward_body).send().await;
            match resp {
                Ok(r) if r.status().is_success() => {
                    info!(
                        id = row.id,
                        note_id = %onote.identifier,
                        target_subpool,
                        "forwarded output note to sequencer"
                    );
                }
                Ok(r) => {
                    let status = r.status();
                    let body = r.text().await.unwrap_or_default();
                    error!(
                        id = row.id,
                        note_id = %onote.identifier,
                        "sequencer rejected forward_note (HTTP {status}): {body}"
                    );
                }
                Err(e) => {
                    error!(
                        id = row.id,
                        note_id = %onote.identifier,
                        "failed to reach sequencer for forward_note: {e}"
                    );
                }
            }
        }
    }

    info!(
        id = row.id,
        addr = %row.priv_acc_address,
        "spend tx approved and settled"
    );

    Ok(())
}

/// Extract the subpool ID from an account address.
/// The first 8 bytes of the hex-encoded address are the LE-encoded subpool ID.
fn recipient_subpool_id(acc_address: &str) -> u64 {
    let bytes = hex::decode(acc_address).unwrap_or_default();
    if bytes.len() >= 8 {
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    } else {
        0
    }
}

// ── Incoming note polling ──────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct IncomingNote {
    identifier: String,
    asset_id: String,
    amount: String,
    recipient_address: String,
    sender_address: String,
}

/// Poll the sequencer for notes forwarded to this subpool and insert them
/// as `input_notes` in the local database.
pub async fn poll_incoming_notes(
    pool: &PgPool,
    sequencer_url: &str,
    http: &reqwest::Client,
    subpool_id: u64,
) -> Result<()> {
    let url = format!(
        "{}/pending_notes/{}",
        sequencer_url.trim_end_matches('/'),
        subpool_id
    );

    let resp = http.get(&url).send().await.context("failed to reach sequencer for pending_notes")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("sequencer returned {status} for pending_notes: {body}");
    }

    let notes: Vec<IncomingNote> = resp.json().await.context("invalid JSON from pending_notes")?;

    if notes.is_empty() {
        return Ok(());
    }

    info!(count = notes.len(), subpool_id, "received forwarded notes from sequencer");

    for note in &notes {
        let asset_id_bytes = hex::decode(&note.asset_id)
            .context("invalid asset_id hex in forwarded note")?;
        let amount_bytes = hex::decode(&note.amount)
            .context("invalid amount hex in forwarded note")?;

        insert_input_note(
            pool,
            &note.identifier,
            &asset_id_bytes,
            &amount_bytes,
            &note.recipient_address,
            &note.sender_address,
        )
        .await?;

        info!(
            note_id = %note.identifier,
            recipient = %note.recipient_address,
            "created input note from forwarded note"
        );
    }

    Ok(())
}
