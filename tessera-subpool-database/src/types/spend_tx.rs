use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use plonky2_field::types::PrimeField64;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Type};
use tessera_client::{AccountAddress, AssetId, DepositNote, NoteCommitment, NoteIdentifier, StandardNote};

use crate::convert::{bytes_to_f, bytes_to_u256};

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
#[sqlx(type_name = "spend_tx_status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SpendTxStatus {
	Pending,
	Approved,
	Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "input_note_status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InputNoteStatus {
	Pending,
	Approved,
	Rejected,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SpendTxRow {
	pub id: i64,
	pub priv_acc_address: String,
	pub inote_identifiers: Vec<String>,
	pub onote_identifiers: Vec<String>,
	pub dinotes: Vec<String>,
	pub donotes: Vec<String>,
	pub spend_tx_signature: Vec<u8>,
	pub status: SpendTxStatus,
	pub approval_signature: Option<Vec<u8>>,
	pub rejection_reason: Option<String>,
	pub created_at: DateTime<Utc>,
	pub updated_at: DateTime<Utc>,
}

impl SpendTxRow {
	pub async fn get_inotes(&self, pool: &PgPool) -> Result<Vec<InputNoteRow>> {
		let mut inotes = Vec::new();

		for inote_id in &self.inote_identifiers {
			let inote: InputNoteRow =
				sqlx::query_as("SELECT * FROM input_notes WHERE identifier = $1")
					.bind(inote_id)
					.fetch_one(pool)
					.await
					.with_context(|| format!("input note '{inote_id}' not found"))?;

				if !matches!(inote.status, InputNoteStatus::Approved) || inote.consume {
					anyhow::bail!("input note '{inote_id}' is not in APPROVED status");
				}

			if inote.recipient_address != self.priv_acc_address {
				anyhow::bail!(
					"input note '{inote_id}' recipient '{}' does not match sender '{}'",
					inote.recipient_address,
					self.priv_acc_address
				);
			}

			inotes.push(inote);
		}

		Ok(inotes)
	}

	pub async fn get_onotes(&self, pool: &PgPool) -> Result<Vec<OutputNoteRow>> {
		let mut onotes = Vec::new();
		for onote_id in &self.onote_identifiers {
			let onote: OutputNoteRow =
				sqlx::query_as("SELECT * FROM output_notes WHERE identifier = $1")
					.bind(onote_id)
					.fetch_one(pool)
					.await
					.with_context(|| format!("output note '{onote_id}' not found"))?;

			onotes.push(onote)
		}

		Ok(onotes)
	}
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct InputNoteRow {
	pub id: i64,
	pub identifier: String,
	pub asset_id: Vec<u8>,
	pub amount: Vec<u8>,
	pub recipient_address: String,
	pub sender_address: String,
	pub memo: Vec<u8>,
	pub consume: bool,
	pub status: InputNoteStatus,
	pub created_at: DateTime<Utc>,
	pub updated_at: DateTime<Utc>,
}

impl InputNoteRow {
	pub fn value(&self) -> Result<U256> {
		let amount_arr: [u8; 32] = self
			.amount
			.as_slice()
			.try_into()
			.with_context(|| format!("input note '{}' amount must be 32 bytes", self.id))?;
		Ok(bytes_to_u256(&amount_arr))
	}

	pub fn identifier(&self) -> Result<NoteIdentifier> {
		let id_bytes =
			hex::decode(&self.identifier).context("invalid identifier hex in input note")?;
		let id_arr: [u8; 16] = id_bytes
			.as_slice()
			.try_into()
			.context("input note identifier must be 16 bytes")?;
		let identifier = NoteIdentifier([
			bytes_to_f(&id_arr[..8].try_into().unwrap()),
			bytes_to_f(&id_arr[8..].try_into().unwrap()),
		]);

		Ok(identifier)
	}

	pub fn asset_id(&self) -> Result<AssetId> {
		let asset_id_arr: [u8; 8] = self
			.asset_id
			.as_slice()
			.try_into()
			.context("input note asset_id must be 8 bytes")?;
		let asset_id = AssetId::from_u64(bytes_to_f(&asset_id_arr).to_canonical_u64())?;

		Ok(asset_id)
	}

	pub fn recipient(&self) -> Result<AccountAddress> {
		let recipient = AccountAddress::from_hex(&self.recipient_address)
			.context("invalid recipient address in input note")?;
		Ok(recipient)
	}

	pub fn sender(&self) -> Result<AccountAddress> {
		let sender = AccountAddress::from_hex(&self.sender_address)
			.context("invalid sender address in input note")?;
		Ok(sender)
	}

	pub fn memo(&self) -> Result<[u8; 512]> {
		let mut memo = [0u8; 512];
		let n = self.memo.len().min(512);
		memo[..n].copy_from_slice(&self.memo[..n]);

		Ok(memo)
	}

	pub fn to_standard_note(&self) -> Result<StandardNote> {
		let identifier = self.identifier()?;
		let asset_id = self.asset_id()?;
		let amt = self.value()?;
		let recipient = self.recipient()?;
		let sender = self.sender()?;
		let memo = self.memo()?;
		Ok(StandardNote {
			identifier,
			asset_id,
			amt,
			recipient,
			sender,
			memo,
		})
	}

	pub fn commitment(&self) -> Result<NoteCommitment> {
		let identifier = self.identifier()?;
		let asset_id = self.asset_id()?;
		let amt = self.value()?;
		let recipient = self.recipient()?;

		match self.sender() {
			Ok(sender) => Ok(StandardNote {
				identifier,
				asset_id,
				amt,
				recipient,
				sender,
				memo: self.memo()?,
			}
				.commitment()),
			Err(_) => Ok(NoteCommitment(
				DepositNote {
					identifier,
					recipient,
					amount: amt,
					asset_id,
				}
				.commitment()
				.0,
			)),
		}
	}
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct OutputNoteRow {
	pub id: i64,
	pub identifier: String,
	pub asset_id: Vec<u8>,
	pub amount: Vec<u8>,
	pub recipient_address: String,
	pub sender_address: String,
	pub memo: Vec<u8>,
	pub created_at: DateTime<Utc>,
}

impl OutputNoteRow {
	pub fn value(&self) -> Result<U256> {
		let amount_arr: [u8; 32] = self
			.amount
			.as_slice()
			.try_into()
			.with_context(|| format!("output note '{}' amount must be 32 bytes", self.id))?;
		Ok(bytes_to_u256(&amount_arr))
	}

	pub fn identifier(&self) -> Result<NoteIdentifier> {
		let id_bytes =
			hex::decode(&self.identifier).context("invalid identifier hex in input note")?;
		let id_arr: [u8; 16] = id_bytes
			.as_slice()
			.try_into()
			.context("input note identifier must be 16 bytes")?;
		let identifier = NoteIdentifier([
			bytes_to_f(&id_arr[..8].try_into().unwrap()),
			bytes_to_f(&id_arr[8..].try_into().unwrap()),
		]);

		Ok(identifier)
	}

	pub fn asset_id(&self) -> Result<AssetId> {
		let asset_id_arr: [u8; 8] = self
			.asset_id
			.as_slice()
			.try_into()
			.context("input note asset_id must be 8 bytes")?;
		let asset_id = AssetId::from_u64(bytes_to_f(&asset_id_arr).to_canonical_u64())?;

		Ok(asset_id)
	}

	pub fn recipient(&self) -> Result<AccountAddress> {
		let recipient = AccountAddress::from_hex(&self.recipient_address)
			.context("invalid recipient address in input note")?;
		Ok(recipient)
	}

	pub fn sender(&self) -> Result<AccountAddress> {
		let sender = AccountAddress::from_hex(&self.sender_address)
			.context("invalid sender address in input note")?;
		Ok(sender)
	}

	pub fn memo(&self) -> Result<[u8; 512]> {
		let mut memo = [0u8; 512];
		let n = self.memo.len().min(512);
		memo[..n].copy_from_slice(&self.memo[..n]);

		Ok(memo)
	}

	pub fn to_standard_note(&self) -> Result<StandardNote> {
		let identifier = self.identifier()?;
		let asset_id = self.asset_id()?;
		let amt = self.value()?;
		let recipient = self.recipient()?;
		let sender = self.sender()?;
		let memo = self.memo()?;
		Ok(StandardNote {
			identifier,
			asset_id,
			amt,
			recipient,
			sender,
			memo,
		})
	}
}
