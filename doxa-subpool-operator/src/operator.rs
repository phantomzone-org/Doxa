use std::array;

use anyhow::{Context, Result};
use plonky2_field::types::Field;
use serde::Serialize;
use sqlx::PgPool;
use doxa_client::{
	derive_priv_tx_hash, double_hash_native, sample_dummy_notes,
	schnorr::{schnorr_sign, CompressedPublicKey, PrivateKey, Scalar},
	NoteCommitment, NoteNullifier, SpendAuth, StandardAccount, SubpoolId, NOTE_BATCH,
};
use doxa_subpool_database::convert::{account_to_insert, bytes_to_private_id, hash_to_hex};
use doxa_utils::F;
use tracing::{error, info};

// ── DB row types ────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct PendingFreshAcc {
	id: i64,
	private_acc_address: String,
	spend_auth: Vec<u8>,
	private_identifier: String,
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
	subpool_id: u64,
) -> Result<()> {
	let rows: Vec<PendingFreshAcc> = sqlx::query_as(
		"SELECT id, private_acc_address, spend_auth, \
                private_identifier \
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
		if let Err(e) = process_one(pool, approval_sk, sequencer_url, http, &row, subpool_id).await
		{
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
	subpool_id: u64,
) -> Result<()> {
	// ── 1. Reconstruct accin from freshacc_requests data ──────────────────────
	let pi_bytes =
		hex::decode(&row.private_identifier).context("private_identifier must be valid hex")?;
	let pi_arr: [u8; 16] = pi_bytes
		.as_slice()
		.try_into()
		.context("private_identifier must be 16 bytes")?;
	let private_identifier = bytes_to_private_id(&pi_arr);

	let subpool_id = SubpoolId(F::from_canonical_u64(subpool_id));
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
		anyhow::bail!("sequencer rejected transaction (HTTP {status}): {body}");
	}

	info!(
		id = row.id,
		addr = %row.private_acc_address,
		"FreshAcc transaction submitted to sequencer"
	);

	// ── 6–7. Approve request and create account row atomically ───────────────
	let insert = account_to_insert(&accout, String::new());

	let mut tx = pool
		.begin()
		.await
		.context("failed to begin freshacc transaction")?;

	sqlx::query(
		"UPDATE freshacc_requests \
         SET status = 'APPROVED', approval_signature = $1, updated_at = NOW() \
         WHERE id = $2",
	)
	.bind(sig_bytes.as_ref())
	.bind(row.id)
	.execute(&mut *tx)
	.await
	.context("failed to update freshacc_requests")?;

	sqlx::query(
		r#"
        INSERT INTO accounts
            (private_acc_address, eth_address,
             private_identifier, subpool_id, nonce,
             spend_auth, consume_auth, ast)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
	)
	.bind(&insert.private_acc_address)
	.bind(&insert.eth_address)
	.bind(&insert.private_identifier)
	.bind(&insert.subpool_id)
	.bind(&insert.nonce)
	.bind(&insert.spend_auth)
	.bind(&insert.consume_auth)
	.bind(&insert.ast)
	.execute(&mut *tx)
	.await
	.context("failed to insert account row")?;

	tx.commit()
		.await
		.context("failed to commit freshacc transaction")?;

	info!(
		id = row.id,
		addr = %row.private_acc_address,
		"FreshAcc request approved and account row created in DB"
	);

	Ok(())
}
