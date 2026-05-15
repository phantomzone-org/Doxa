use anyhow::{Context, Result};
use plonky2_field::types::PrimeField64;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tessera_client::{
	derive_priv_tx_hash, double_hash_native,
	schnorr::{schnorr_sign, PrivateKey, Scalar},
	HashOutput, NoteCommitment, NoteNullifier, StandardNote, NOTE_BATCH,
};
use tessera_subpool_database::{
	convert::{account_from_row, hash_to_hex, hex_to_hash_checked},
	db::{insert_approved_input_note, update_account, update_spend_tx_request_to_approved},
	types::{account::AccountRow, spend_tx::SpendTxRow},
};
use tracing::{error, info};

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
		if let Err(e) = process_one_spend_tx(pool, approval_sk, sequencer_url, http, &row).await {
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
) -> Result<()> {
	// ── 1. Sanity check: account exists ────────────────────────────────────────
	let acc_row: AccountRow =
		sqlx::query_as("SELECT * FROM accounts WHERE private_acc_address = $1")
			.bind(&row.priv_acc_address)
			.fetch_one(pool)
			.await
			.context("account not found for spend tx sender")?;

	// ── 2. Sanity check: fetch output notes and verify per-asset balance ────────
	let inotes = row.get_inotes(pool).await?;
	let onotes = row.get_onotes(pool).await?;

	// Get asset ID (all in/out notes have the same asset ID in a given TX)
	let asset_id = if let Some(inote) = onotes.first() {
		inote.asset_id()?
	} else {
		anyhow::bail!("spend tx must contain at least one onput note");
	};

	let accin = account_from_row(&acc_row)?;
	let accin_balance = accin
		.ast
		.assets
		.get(&asset_id)
		.map(|(_, amt)| *amt)
		.unwrap_or(U256::zero());

	let mut inotes_value = U256::zero();

	for inote in &inotes {
		inotes_value += inote.value()?;
	}

	let mut onotes_value = U256::zero();

	for onote in &onotes {
		onotes_value += onote.value()?;
	}

	if inotes_value + accin_balance < onotes_value {
		anyhow::bail!("balance mismatch: inotes({inotes_value}) + accin.amounnt_for({:?}) < onotes({onotes_value})", asset_id.0);
	}

	// ── 5. Derive proper note commitments and nullifiers ────────────────────────
	let sender_nk = accin.nk();

	let mut onotes_comm = [NoteCommitment::zero(); NOTE_BATCH];
	let mut inotes_null = [NoteNullifier::zero(); NOTE_BATCH];

	let inotes_len = inotes.len();
	let onotes_len = onotes.len();

	if inotes_len + row.dinotes.len() != NOTE_BATCH {
		anyhow::bail!(
			"inotes + dinotes len mismatch: {inotes_len} + {} != {NOTE_BATCH}",
			row.dinotes.len()
		);
	}

	if onotes_len + row.donotes.len() != NOTE_BATCH {
		anyhow::bail!(
			"onotes + donotes len mismatch: {onotes_len} + {} != {NOTE_BATCH}",
			row.donotes.len()
		);
	}

	// Real nullifiers: [0..num_inotes]
	for (i, inote) in inotes.iter().enumerate() {
		let commitment = inote.commitment()?;

		// TOOD: investigation. Query returns "faield to find position" even when note commitment
		// derivation is valid.
		//
		// let position = query_note_position(http, sequencer_url,
		// &commitment) 	.await
		// 	.with_context(|| {
		// 		format!(
		// 			"failed to get NCT position for input note '{:?}'",
		// 			inote.identifier
		// 		)
		// 	})?;
		let position = 0usize;

		inotes_null[i] = StandardNote::nullifier(&commitment, position, &sender_nk);
	}

	// Dummy nullifiers: [num_inotes..NOTE_BATCH]
	for (i, dinote) in row.dinotes.iter().enumerate() {
		let val = hex_to_hash_checked(dinote)?;
		let dhash = HashOutput(double_hash_native(val.0));
		inotes_null[i + inotes_len] = NoteNullifier(dhash);
	}

	for (i, onote) in onotes.iter().enumerate() {
		let note = onote.to_standard_note()?;
		onotes_comm[i] = note.commitment();
	}

	for (i, donote) in row.donotes.iter().enumerate() {
		let val = hex_to_hash_checked(donote)?;
		let dhash = HashOutput(double_hash_native(val.0));
		onotes_comm[i + onotes_len] = NoteCommitment(dhash);
	}

	// TODO: check that all inots/onotes share the asset id (although we've already done at
	// submit_spend_tx_handler stage)

	// ── derive account ─────────────────────────────────────
	let mut accout = accin.clone_with_incremented_nonce();
	let accout_balance = (accin_balance + inotes_value) - onotes_value;
	accout.ast.insert_or_update_asset(asset_id, accout_balance);

	let tx_hash = derive_priv_tx_hash(
		accin.nullifier(),
		accout.commitment(),
		inotes_null,
		onotes_comm,
	);

	// ── 6. Sign tx_hash with approval key ──────────────────────────────────────
	let mut rng = rand::rng();
	let k = Scalar::sample(&mut rng);
	let approval_sig = schnorr_sign(approval_sk, &tx_hash.0, k);
	let sig_bytes = approval_sig.encode();

	// ── 7. POST to sequencer ───────────────────────────────────────────────────
	let an = hash_to_hex(&accin.nullifier().0 .0);
	let ac = hash_to_hex(&accout.commitment().0 .0);

	let input_note_hashes: Vec<String> = inotes_null.iter().map(|n| hash_to_hex(&n.0 .0)).collect();
	let output_note_hashes: Vec<String> =
		onotes_comm.iter().map(|c| hash_to_hex(&c.0 .0)).collect();

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
		let already_in_batch = status == reqwest::StatusCode::CONFLICT
			&& body.contains("AN leaf already in current batch");
		if !already_in_batch {
			anyhow::bail!("sequencer rejected spend tx (HTTP {status}): {body}");
		}
		info!(
			id = row.id,
			addr = %row.priv_acc_address,
			"spend tx was already submitted to the current sequencer batch; resuming DB finalization"
		);
	}

	info!(id = row.id, addr = %row.priv_acc_address, "spend tx submitted to sequencer");

	// ── 8–11. Finalize spend atomically: consume inputs, approve request,
	//          update account, and create local output notes in one transaction.

	struct CrossSubpoolNote {
		target_subpool: u64,
		identifier: String,
		asset_id: String,
		amount: String,
		recipient_address: String,
		sender_address: String,
		memo: String,
	}

	let mut cross_subpool_notes = Vec::new();

	let mut tx = pool
		.begin()
		.await
		.context("failed to begin spend finalization transaction")?;

	for inote_id in &row.inote_identifiers {
		sqlx::query(
			"UPDATE input_notes SET consume = true, updated_at = NOW() WHERE identifier = $1",
		)
		.bind(inote_id)
		.execute(&mut *tx)
		.await
		.with_context(|| format!("failed to mark input note '{inote_id}' as consumed"))?;
	}

	update_spend_tx_request_to_approved(&mut *tx, sig_bytes.as_ref(), row.id).await?;

	update_account(
		&mut *tx,
		&accout,
		acc_row.eth_address,
		row.priv_acc_address.clone(),
	)
	.await?;

	for onote in &onotes {
		let local: bool = sqlx::query_scalar(
			"SELECT EXISTS(SELECT 1 FROM accounts WHERE private_acc_address = $1)",
		)
		.bind(&onote.recipient_address)
		.fetch_one(&mut *tx)
		.await
		.unwrap_or(false);

		if local {
			insert_approved_input_note(
				&mut *tx,
				&onote.identifier,
				&onote.asset_id,
				&onote.amount,
				&onote.recipient_address,
				&onote.sender_address,
				&onote.memo,
			)
			.await?;

			info!(
				id = row.id,
				note_id = %onote.identifier,
				recipient = %onote.recipient_address,
				"created input note for local recipient"
			);
		} else {
			let target_subpool = onote.recipient()?.subpool_id.0 .0;
			cross_subpool_notes.push(CrossSubpoolNote {
				target_subpool,
				identifier: onote.identifier.clone(),
				asset_id: hex::encode(&onote.asset_id),
				amount: hex::encode(&onote.amount),
				recipient_address: onote.recipient_address.clone(),
				sender_address: onote.sender_address.clone(),
				memo: hex::encode(&onote.memo),
			});
		}
	}

	tx.commit()
		.await
		.context("failed to commit spend finalization transaction")?;

	// ── 12. Forward cross-subpool notes (after local state is committed) ────
	for note in &cross_subpool_notes {
		let forward_body = serde_json::json!({
			"target_subpool_id": note.target_subpool,
			"identifier": note.identifier,
			"asset_id": note.asset_id,
			"amount": note.amount,
			"recipient_address": note.recipient_address,
			"sender_address": note.sender_address,
			"memo": note.memo,
		});

		let fwd_url = format!("{}/forward_note", sequencer_url.trim_end_matches('/'));
		let resp = http.post(&fwd_url).json(&forward_body).send().await;
		match resp {
			Ok(r) if r.status().is_success() => {
				info!(
					id = row.id,
					note_id = %note.identifier,
					target_subpool = note.target_subpool,
					recipient = %note.recipient_address,
					sender = %note.sender_address,
					"forwarded output note to sequencer"
				);
			},
			Ok(r) => {
				let status = r.status();
				let body = r.text().await.unwrap_or_default();
				anyhow::bail!(
					"sequencer rejected forward_note '{}' (HTTP {status}): {body}",
					note.identifier
				);
			},
			Err(e) => {
				anyhow::bail!(
					"failed to reach sequencer for forward_note '{}': {e}",
					note.identifier
				);
			},
		}
	}

	info!(
		id = row.id,
		addr = %row.priv_acc_address,
		"spend tx approved and settled"
	);

	Ok(())
}
// ── Incoming note polling ──────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct IncomingNote {
	identifier: String,
	asset_id: String,
	amount: String,
	recipient_address: String,
	sender_address: String,
	memo: String,
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

	let resp = http
		.get(&url)
		.send()
		.await
		.context("failed to reach sequencer for pending_notes")?;

	if !resp.status().is_success() {
		let status = resp.status();
		let body = resp.text().await.unwrap_or_default();
		anyhow::bail!("sequencer returned {status} for pending_notes: {body}");
	}

	let notes: Vec<IncomingNote> = resp
		.json()
		.await
		.context("invalid JSON from pending_notes")?;

	if notes.is_empty() {
		return Ok(());
	}

	info!(
		count = notes.len(),
		subpool_id, "received forwarded notes from sequencer"
	);

	let mut acked_ids = Vec::new();

	for note in &notes {
		info!(
			subpool_id,
			note_id = %note.identifier,
			recipient = %note.recipient_address,
			sender = %note.sender_address,
			"processing forwarded note from sequencer"
		);

		let asset_id_bytes =
			hex::decode(&note.asset_id).context("invalid asset_id hex in forwarded note")?;
		let amount_bytes =
			hex::decode(&note.amount).context("invalid amount hex in forwarded note")?;
		let memo_bytes = hex::decode(&note.memo).context("invalid memo hex in forwarded note")?;

		insert_approved_input_note(
			pool,
			&note.identifier,
			&asset_id_bytes,
			&amount_bytes,
			&note.recipient_address,
			&note.sender_address,
			&memo_bytes,
		)
		.await?;

		acked_ids.push(note.identifier.clone());

		info!(
			subpool_id,
			note_id = %note.identifier,
			recipient = %note.recipient_address,
			"inserted forwarded note as local input note"
		);
	}

	// Acknowledge successfully inserted notes so the sequencer can remove them.
	if !acked_ids.is_empty() {
		let ack_url = format!(
			"{}/ack_notes/{}",
			sequencer_url.trim_end_matches('/'),
			subpool_id
		);
		let resp = http.post(&ack_url).json(&acked_ids).send().await;
		match resp {
			Ok(r) if r.status().is_success() => {
				info!(
					subpool_id,
					count = acked_ids.len(),
					"acknowledged forwarded notes"
				);
			},
			Ok(r) => {
				let status = r.status();
				let body = r.text().await.unwrap_or_default();
				info!(
					subpool_id,
					"failed to ack forwarded notes (HTTP {status}): {body} — notes will be re-delivered"
				);
			},
			Err(e) => {
				info!(
					subpool_id,
					"failed to reach sequencer for ack_notes: {e} — notes will be re-delivered"
				);
			},
		}
	}

	Ok(())
}

// ── Note derivation helpers ─────────────────────────────────────────────────

/// Serialize a NoteCommitment to 32 bytes (4 × u64 BE), matching `hash_to_hex` encoding.
fn commitment_to_bytes(nc: &NoteCommitment) -> [u8; 32] {
	let mut out = [0u8; 32];
	for (i, f) in nc.0 .0.iter().enumerate() {
		out[i * 8..(i + 1) * 8].copy_from_slice(&f.to_canonical_u64().to_le_bytes());
	}
	out
}

/// Query the sequencer for the NCT leaf position of a note commitment.
#[derive(Deserialize)]
struct NotePositionResponse {
	position: usize,
}

async fn query_note_position(
	http: &reqwest::Client,
	sequencer_url: &str,
	commitment: &NoteCommitment,
) -> Result<usize> {
	let nc_hex = hex::encode(commitment_to_bytes(commitment));

	let url = format!(
		"{}/note_position/{}",
		sequencer_url.trim_end_matches('/'),
		nc_hex,
	);
	let resp = http
		.get(&url)
		.send()
		.await
		.context("failed to reach sequencer for note_position")?;

	if !resp.status().is_success() {
		let status = resp.status();
		let body = resp.text().await.unwrap_or_default();
		anyhow::bail!("sequencer returned {status} for note_position: {body}");
	}

	let body: NotePositionResponse = resp
		.json()
		.await
		.context("invalid JSON from note_position")?;
	Ok(body.position)
}
