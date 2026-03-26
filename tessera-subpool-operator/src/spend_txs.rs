use std::collections::HashMap;

use anyhow::{Context, Result};
use plonky2_field::types::{Field, PrimeField64};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tessera_client::{
	derive_priv_tx_hash, double_hash_native, sample_dummy_notes,
	schnorr::{schnorr_sign, PrivateKey, Scalar},
	AccountAddress, AssetId, HashOutput, NodeIdentifier, NoteCommitment, NoteNullifier,
	PositionedStandardNode, StandardNote, SubpoolId, NOTE_BATCH,
};
use tessera_subpool_database::{
	convert::{account_from_row, build_ast_json, bytes_to_f, bytes_to_u256, hash_to_hex},
	db::{insert_input_note, insert_input_note_with_commitment, update_account_after_deposit},
	types::{
		account::AccountRow,
		spend_tx::{InputNoteRow, OutputNoteRow, SpendTxRow},
	},
};
use tessera_utils::F;
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
		if let Err(e) =
			process_one_spend_tx(pool, approval_sk, sequencer_url, http, &row, subpool_id).await
		{
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
	let acc_row: AccountRow =
		sqlx::query_as("SELECT * FROM accounts WHERE private_acc_address = $1")
			.bind(&row.priv_acc_address)
			.fetch_one(pool)
			.await
			.context("account not found for spend tx sender")?;

	let sid = SubpoolId(F::from_canonical_u64(subpool_id));
	let accin = account_from_row(&acc_row)?;

	// ── 2. Sanity check: input notes exist and are unconsumed ──────────────────
	// Track per-asset input totals for balance verification.
	//
	// TODO: all input notes and ouput notes share the same asset id
	let mut input_by_asset: HashMap<u64, U256> = HashMap::new();

	for inote_id in &row.inote_identifiers {
		let inote: InputNoteRow = sqlx::query_as("SELECT * FROM input_notes WHERE identifier = $1")
			.bind(inote_id)
			.fetch_one(pool)
			.await
			.with_context(|| format!("input note '{inote_id}' not found"))?;

		if !matches!(
			inote.status,
			tessera_subpool_database::types::spend_tx::InputNoteStatus::Approved
		) {
			anyhow::bail!("input note '{inote_id}' is not in APPROVED status");
		}

		if inote.recipient_address != row.priv_acc_address {
			anyhow::bail!(
				"input note '{inote_id}' recipient '{}' does not match sender '{}'",
				inote.recipient_address,
				row.priv_acc_address
			);
		}

		let amount_arr: [u8; 32] = inote
			.amount
			.as_slice()
			.try_into()
			.with_context(|| format!("input note '{inote_id}' amount must be 32 bytes"))?;
		let asset_id_arr: [u8; 8] = inote
			.asset_id
			.as_slice()
			.try_into()
			.with_context(|| format!("input note '{inote_id}' asset_id must be 8 bytes"))?;
		let asset_id_u64 = bytes_to_f(&asset_id_arr).to_canonical_u64();

		*input_by_asset.entry(asset_id_u64).or_insert(U256::zero()) += bytes_to_u256(&amount_arr);
	}

	// ── 3. Sanity check: fetch output notes and verify per-asset balance ────────
	let mut output_by_asset: HashMap<u64, U256> = HashMap::new();
	let mut output_notes: Vec<OutputNoteRow> = Vec::with_capacity(row.onote_identifiers.len());

	for onote_id in &row.onote_identifiers {
		let onote: OutputNoteRow =
			sqlx::query_as("SELECT * FROM output_notes WHERE identifier = $1")
				.bind(onote_id)
				.fetch_one(pool)
				.await
				.with_context(|| format!("output note '{onote_id}' not found"))?;

		let amount_arr: [u8; 32] = onote
			.amount
			.as_slice()
			.try_into()
			.with_context(|| format!("output note '{onote_id}' amount must be 32 bytes"))?;
		let asset_id_arr: [u8; 8] = onote
			.asset_id
			.as_slice()
			.try_into()
			.with_context(|| format!("output note '{onote_id}' asset_id must be 8 bytes"))?;
		let asset_id_u64 = bytes_to_f(&asset_id_arr).to_canonical_u64();

		*output_by_asset.entry(asset_id_u64).or_insert(U256::zero()) += bytes_to_u256(&amount_arr);

		output_notes.push(onote);
	}

	// Per-asset conservation check: sum(inotes) == sum(onotes) for each asset
	for (&asset_id_u64, &out_total) in &output_by_asset {
		let in_total = input_by_asset
			.get(&asset_id_u64)
			.copied()
			.unwrap_or(U256::zero());
		if in_total != out_total {
			anyhow::bail!(
                "balance mismatch for asset {asset_id_u64}: inotes({in_total}) != onotes({out_total})"
            );
		}
	}

	// ── 4. Build accout with spend applied ─────────────────────────────────────
	let accout = accin.clone_with_incremented_nonce();

	// ── 5. Derive proper note commitments and nullifiers ────────────────────────
	let mut rng = rand::rng();
	let sender_nk = accin.nk();
	let sender_addr = accin.address();

	// Sample random dummy seeds for padding unused note slots.
	// TODO: use dinotes, donotes from SpendTxRow (first parse hex string -> [F;4])
	// The length of dinotes = NOTE_BATCH - len(inotes)
	// The length of donotes = NOTE_BATCH - len(onotes)
	let (dummy_dinotes, dummy_donotes) = sample_dummy_notes(&mut rng);

	// Output note commitments: real notes first, random padding for unused slots.
	let mut donote_comms: [NoteCommitment; NOTE_BATCH] = std::array::from_fn(|i| {
		NoteCommitment(HashOutput::new(double_hash_native(dummy_donotes[i])))
	});
	for (i, onote) in output_notes.iter().enumerate().take(NOTE_BATCH) {
		let note = build_standard_note_from_row(onote, sender_addr)?;
		donote_comms[i] = note.commitment();
	}

	// Input note nullifiers: real nullifiers first, random padding for unused slots.
	let mut dinote_nulls: [NoteNullifier; NOTE_BATCH] = std::array::from_fn(|i| {
		NoteNullifier(HashOutput::new(double_hash_native(dummy_dinotes[i])))
	});
	for (i, inote_id) in row.inote_identifiers.iter().enumerate().take(NOTE_BATCH) {
		let inote: InputNoteRow = sqlx::query_as("SELECT * FROM input_notes WHERE identifier = $1")
			.bind(inote_id)
			.fetch_one(pool)
			.await
			.with_context(|| format!("input note '{inote_id}' not found (nullifier derivation)"))?;

		// Convert row → StandardNote, derive commitment, query position, derive nullifier.
		let note = input_note_to_standard_note(&inote).with_context(|| {
			format!("failed to convert input note '{inote_id}' to StandardNote")
		})?;
		let commitment = note.commitment();
		let nc_hex = hex::encode(commitment_to_bytes(&commitment));
		let position = query_note_position(http, sequencer_url, &nc_hex)
			.await
			.with_context(|| format!("failed to get NCT position for input note '{inote_id}'"))?;
		dinote_nulls[i] = NoteNullifier(
			PositionedStandardNode::from_note(note, F::from_canonical_u64(position))
				.nullifier(&sender_nk)
				.0,
		);
	}

	// TODO: accout must update the account balance using insert_or_update method on
	// AccountStateTree

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

	let input_note_hashes: Vec<String> =
		dinote_nulls.iter().map(|n| hash_to_hex(&n.0 .0)).collect();
	let output_note_hashes: Vec<String> =
		donote_comms.iter().map(|c| hash_to_hex(&c.0 .0)).collect();

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
		// TODO: update to consume=true
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

	// ── 10. Update sender's account in DB (nonce + AST) ─────────────────────
	// Compute per-asset amounts sent to OTHER accounts (not change back to self).
	// TODO: remove this
	let mut sent_by_asset: HashMap<u64, U256> = HashMap::new();
	for onote in &output_notes {
		if onote.recipient_address != row.priv_acc_address {
			let amount_arr: [u8; 32] = onote.amount.as_slice().try_into().unwrap_or([0u8; 32]);
			let asset_id_arr: [u8; 8] = onote.asset_id.as_slice().try_into().unwrap_or([0u8; 8]);
			let asset_id_u64 = bytes_to_f(&asset_id_arr).to_canonical_u64();
			*sent_by_asset.entry(asset_id_u64).or_insert(U256::zero()) +=
				bytes_to_u256(&amount_arr);
		}
	}

	// Update sender's AST: subtract sent amounts per asset
	// TODO: remove this
	let mut sender_ast_json = acc_row.ast.clone();
	for (&asset_id_u64, &sent_amount) in &sent_by_asset {
		let old_balance = parse_ast_balance(&sender_ast_json, asset_id_u64);
		let new_balance = old_balance.saturating_sub(sent_amount);
		sender_ast_json = build_ast_json(&sender_ast_json, asset_id_u64, new_balance);
	}

	// TODO: accout is aready updated with the latest balance. Convert accout (an instance of
	// StandardAccount) to AccountInsert using `account_to_insert` method in convert.rs and then
	// update the account using private_acc_address
	update_account_after_deposit(pool, &row.priv_acc_address, accout.nonce.0, sender_ast_json)
		.await
		.context("failed to update sender account after spend tx")?;

	// ── 11. Create input notes for local recipients ────────────────────────────
	for (onote_idx, onote) in output_notes.iter().enumerate() {
		// Check if the recipient account exists in this subpool
		let local: bool = sqlx::query_scalar(
			"SELECT EXISTS(SELECT 1 FROM accounts WHERE private_acc_address = $1)",
		)
		.bind(&onote.recipient_address)
		.fetch_one(pool)
		.await
		.unwrap_or(false);

		// Serialize the note commitment (32 bytes: 4 × u64 BE) for DB storage.
		let nc_bytes = commitment_to_bytes(&donote_comms[onote_idx]);

		if local {
			insert_input_note_with_commitment(
				pool,
				&onote.identifier,
				&onote.asset_id,
				&onote.amount,
				&onote.recipient_address,
				&onote.sender_address,
				&nc_bytes,
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
				},
				Ok(r) => {
					let status = r.status();
					let body = r.text().await.unwrap_or_default();
					error!(
						id = row.id,
						note_id = %onote.identifier,
						"sequencer rejected forward_note (HTTP {status}): {body}"
					);
				},
				Err(e) => {
					error!(
						id = row.id,
						note_id = %onote.identifier,
						"failed to reach sequencer for forward_note: {e}"
					);
				},
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

	for note in &notes {
		let asset_id_bytes =
			hex::decode(&note.asset_id).context("invalid asset_id hex in forwarded note")?;
		let amount_bytes =
			hex::decode(&note.amount).context("invalid amount hex in forwarded note")?;

		insert_input_note(
			pool,
			&note.identifier,
			&asset_id_bytes,
			&amount_bytes,
			&note.recipient_address,
			&note.sender_address,
		)
		.await?;
	}

	Ok(())
}

// ── Note derivation helpers ─────────────────────────────────────────────────

/// Build a `StandardNote` from an `OutputNoteRow` and the sender's address.
fn build_standard_note_from_row(
	onote: &OutputNoteRow,
	sender_addr: AccountAddress,
) -> Result<StandardNote> {
	// Decode identifier (16 bytes = 2 × u64 LE → [F; 2])
	let id_bytes =
		hex::decode(&onote.identifier).context("invalid identifier hex in output note")?;
	let id_arr: [u8; 16] = id_bytes
		.as_slice()
		.try_into()
		.context("output note identifier must be 16 bytes")?;
	let identifier = NodeIdentifier([
		bytes_to_f(&id_arr[..8].try_into().unwrap()),
		bytes_to_f(&id_arr[8..].try_into().unwrap()),
	]);

	// Decode asset_id (8 bytes → F → AssetId)
	let asset_id_arr: [u8; 8] = onote
		.asset_id
		.as_slice()
		.try_into()
		.context("output note asset_id must be 8 bytes")?;
	let asset_id = AssetId::from_u64(bytes_to_f(&asset_id_arr).to_canonical_u64())?;

	// Decode amount (32 bytes → U256)
	let amount_arr: [u8; 32] = onote
		.amount
		.as_slice()
		.try_into()
		.context("output note amount must be 32 bytes")?;
	let amt = bytes_to_u256(&amount_arr);

	// Decode recipient address (80 hex chars)
	let recipient = AccountAddress::from_hex(&onote.recipient_address)
		.context("invalid recipient address in output note")?;

	Ok(StandardNote::new(
		identifier,
		asset_id,
		amt,
		recipient,
		sender_addr,
	))
}

/// Build a `StandardNote` from an `InputNoteRow`.
fn input_note_to_standard_note(inote: &InputNoteRow) -> Result<StandardNote> {
	let id_bytes =
		hex::decode(&inote.identifier).context("invalid identifier hex in input note")?;
	let id_arr: [u8; 16] = id_bytes
		.as_slice()
		.try_into()
		.context("input note identifier must be 16 bytes")?;
	let identifier = NodeIdentifier([
		bytes_to_f(&id_arr[..8].try_into().unwrap()),
		bytes_to_f(&id_arr[8..].try_into().unwrap()),
	]);

	let asset_id_arr: [u8; 8] = inote
		.asset_id
		.as_slice()
		.try_into()
		.context("input note asset_id must be 8 bytes")?;
	let asset_id = AssetId::from_u64(bytes_to_f(&asset_id_arr).to_canonical_u64())?;

	let amount_arr: [u8; 32] = inote
		.amount
		.as_slice()
		.try_into()
		.context("input note amount must be 32 bytes")?;
	let amt = bytes_to_u256(&amount_arr);

	let recipient = AccountAddress::from_hex(&inote.recipient_address)
		.context("invalid recipient address in input note")?;
	let sender = AccountAddress::from_hex(&inote.sender_address)
		.context("invalid sender address in input note")?;

	let mut memo = [0u8; 512];
	let n = inote.memo.len().min(512);
	memo[..n].copy_from_slice(&inote.memo[..n]);

	Ok(StandardNote {
		identifier,
		asset_id,
		amt,
		recipient,
		sender,
		memo,
	})
}

/// Serialize a NoteCommitment to 32 bytes (4 × u64 BE), matching `hash_to_hex` encoding.
fn commitment_to_bytes(nc: &NoteCommitment) -> [u8; 32] {
	let mut out = [0u8; 32];
	for (i, f) in nc.0 .0.iter().enumerate() {
		out[i * 8..(i + 1) * 8].copy_from_slice(&f.to_canonical_u64().to_be_bytes());
	}
	out
}

/// Query the sequencer for the NCT leaf position of a note commitment.
#[derive(Deserialize)]
struct NotePositionResponse {
	position: u64,
}

async fn query_note_position(
	http: &reqwest::Client,
	sequencer_url: &str,
	commitment_hex: &str,
) -> Result<u64> {
	let url = format!(
		"{}/note_position/{}",
		sequencer_url.trim_end_matches('/'),
		commitment_hex,
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

/// Parse a U256 balance from an AST-format JSON object for a given asset.
fn parse_ast_balance(ast: &serde_json::Value, asset_id: u64) -> U256 {
	let key = asset_id.to_string();
	ast.get(&key)
		.and_then(|e| e.get("amount"))
		.and_then(|v| v.as_str())
		.and_then(|hex_str| {
			let bytes = hex::decode(hex_str).ok()?;
			let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
			Some(bytes_to_u256(&arr))
		})
		.unwrap_or(U256::zero())
}
