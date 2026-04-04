use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use plonky2_field::types::PrimeField64;
use primitive_types::{H160, U256};
use serde::{Deserialize, Serialize};
use sqlx::Type;
use tessera_client::{AccountAddress, AssetId, DepositNote, NoteIdentifier};

use crate::convert::{bytes_to_f, bytes_to_u256, parse_eth_address};

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
#[sqlx(type_name = "deposit_tx_status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DepositTxStatus {
	Pending,
	UnderReview,
	Approved,
	Settled,
	Rejected,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct DepositTxRow {
	pub id: i64,
	pub recipient_address: String,
	pub eth_address: String,
	pub deposit_note_identifier: Vec<u8>,
	pub deposit_amount: Vec<u8>,
	pub asset_id: Vec<u8>,
	pub deposit_type_signature: Vec<u8>,
	pub deposit_tx_hash: Option<String>,
	pub status: DepositTxStatus,
	pub approval_signature: Option<Vec<u8>>,
	pub rejection_reason: Option<String>,
	pub created_at: DateTime<Utc>,
	pub updated_at: DateTime<Utc>,
}

impl DepositTxRow {
	pub fn identifier(&self) -> Result<NoteIdentifier> {
		let note_id_arr: [u8; 16] = self
			.deposit_note_identifier
			.as_slice()
			.try_into()
			.context("deposit_note_identifier must be 16 bytes")?;
		let note_identifier = [
			bytes_to_f(&note_id_arr[..8].try_into().unwrap()),
			bytes_to_f(&note_id_arr[8..].try_into().unwrap()),
		];

		Ok(NoteIdentifier(note_identifier))
	}

	pub fn amount(&self) -> Result<U256> {
		let amount_arr: [u8; 32] = self
			.deposit_amount
			.as_slice()
			.try_into()
			.context("deposit_amount must be 32 bytes")?;
		let deposit_amount = bytes_to_u256(&amount_arr);
		Ok(deposit_amount)
	}

	pub fn asset_id(&self) -> Result<AssetId> {
		let asset_id_arr: [u8; 8] = self
			.asset_id
			.as_slice()
			.try_into()
			.context("asset_id must be 8 bytes")?;
		let asset_id_f = bytes_to_f(&asset_id_arr);
		let asset_id_u64 = asset_id_f.to_canonical_u64();
		let asset_id = AssetId::from_u64(asset_id_u64)?;

		Ok(asset_id)
	}

	pub fn eth_address(&self) -> Result<H160> {
		let eth_address = parse_eth_address(&self.eth_address)?;
		Ok(eth_address)
	}

	pub fn recipient(&self) -> Result<AccountAddress> {
		let recipient = AccountAddress::from_hex(&self.recipient_address)
			.context("invalid recipient address in input note")?;
		Ok(recipient)
	}

	pub fn to_deposite_note(&self) -> Result<DepositNote> {
		let identifier = self.identifier()?;
		let recipient = self.recipient()?;
		let amount = self.amount()?;
		let asset_id = self.asset_id()?;

		Ok(DepositNote {
			identifier,
			recipient,
			amount,
			asset_id,
		})
	}
}
