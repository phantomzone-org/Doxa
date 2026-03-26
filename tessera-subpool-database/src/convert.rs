use anyhow::Context;
use plonky2_field::types::{Field, PrimeField64};
use primitive_types::U256;
use tessera_client::{
	schnorr::CompressedPublicKey, AccountAddress, AccountStateTree, AssetId, Nonce,
	PrivateIdentifier, SpendAuth, StandardAccount, SubpoolId,
};
use tessera_utils::F;

use crate::types::account::AccountRow;

// ── F element ────────────────────────────────────────────────────────────────

/// Serialize a Goldilocks field element as 8 bytes (u64 LE).
pub fn f_to_bytes(f: F) -> [u8; 8] {
	f.to_canonical_u64().to_le_bytes()
}

/// Deserialize 8 bytes (u64 LE) back to a Goldilocks field element.
pub fn bytes_to_f(b: &[u8; 8]) -> F {
	F::from_canonical_u64(u64::from_le_bytes(*b))
}

// ── PrivateIdentifier ─────────────────────────────────────────────────────────

/// Serialize `PrivateIdentifier([F; 2])` as 16 bytes (2 × u64 LE).
pub fn private_id_to_bytes(pi: &PrivateIdentifier) -> [u8; 16] {
	let mut out = [0u8; 16];
	out[..8].copy_from_slice(&f_to_bytes(pi.0[0]));
	out[8..].copy_from_slice(&f_to_bytes(pi.0[1]));
	out
}

/// Deserialize 16 bytes into a `PrivateIdentifier`.
pub fn bytes_to_private_id(b: &[u8; 16]) -> PrivateIdentifier {
	PrivateIdentifier([
		bytes_to_f(b[..8].try_into().unwrap()),
		bytes_to_f(b[8..].try_into().unwrap()),
	])
}

// ── U256 ──────────────────────────────────────────────────────────────────────

/// Serialize `U256` as 32 bytes (4 × u64 LE, matching `U256.0: [u64; 4]`).
pub fn u256_to_bytes(v: U256) -> [u8; 32] {
	let mut out = [0u8; 32];
	for (i, word) in v.0.iter().enumerate() {
		out[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
	}
	out
}

/// Deserialize 32 bytes into a `U256`.
pub fn bytes_to_u256(b: &[u8; 32]) -> U256 {
	let mut words = [0u64; 4];
	for i in 0..4 {
		words[i] = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
	}
	U256(words)
}

// ── zero blob ─────────────────────────────────────────────────────────────────

/// All-zero 40-byte blob used when a `CompressedPublicKey` is absent.
pub fn zero_40() -> [u8; 40] {
	[0u8; 40]
}

// ── AccountInsert ─────────────────────────────────────────────────────────────

/// All column values needed to INSERT a row into the `accounts` table.
pub struct AccountInsert {
	pub private_acc_address: String,
	pub eth_address: String,
	pub private_identifier: Vec<u8>,
	pub subpool_id: Vec<u8>,
	pub nonce: Vec<u8>,
	pub spend_auth: Vec<u8>,
	pub consume_auth: Vec<u8>,
	pub ast: serde_json::Value,
}

/// Convert a `StandardAccount` into the values needed for a DB INSERT.
pub fn account_to_insert(acc: &StandardAccount, eth_address: String) -> AccountInsert {
	let private_acc_address = AccountAddress::from_acc(acc).to_hex();

	let spend_auth = match acc.spend_auth.spend_pk {
		Some(pk) => pk.encode().to_vec(),
		None => zero_40().to_vec(),
	};

	let consume_auth = if acc.consume_auth.config {
		acc.consume_auth
			.pk
			.as_ref()
			.expect("consume_auth.config=true but pk is None")
			.encode()
			.to_vec()
	} else {
		zero_40().to_vec()
	};

	let ast = {
		let mut map = serde_json::Map::new();
		for (asset_id, (leaf_index, amount)) in &acc.ast.assets {
			map.insert(
				asset_id.to_u64().to_string(),
				serde_json::json!({
					"leaf_index": leaf_index,
					"amount": hex::encode(u256_to_bytes(*amount)),
				}),
			);
		}
		serde_json::Value::Object(map)
	};

	AccountInsert {
		private_acc_address,
		eth_address,
		private_identifier: private_id_to_bytes(&acc.private_identifier).to_vec(),
		subpool_id: f_to_bytes(acc.subpool_id.0).to_vec(),
		nonce: f_to_bytes(acc.nonce.0).to_vec(),
		spend_auth,
		consume_auth,
		ast,
	}
}

// ── From DB bytes back to domain types ────────────────────────────────────────

/// Reconstruct `SubpoolId` from 8 stored bytes.
pub fn bytes_to_subpool_id(b: &[u8; 8]) -> SubpoolId {
	SubpoolId(bytes_to_f(b))
}

/// Reconstruct a `StandardAccount` from an `AccountRow`.
///
/// Restores private_identifier, nonce, spend_auth, and AST from the
/// DB-stored byte representations.
pub fn account_from_row(
	row: &AccountRow,
	subpool_id: SubpoolId,
) -> anyhow::Result<StandardAccount> {
	let pi_arr: [u8; 16] = row
		.private_identifier
		.as_slice()
		.try_into()
		.context("private_identifier must be 16 bytes")?;
	let private_identifier = bytes_to_private_id(&pi_arr);

	let mut acc = StandardAccount::new_with(private_identifier, subpool_id);

	let nonce_arr: [u8; 8] = row
		.nonce
		.as_slice()
		.try_into()
		.context("nonce must be 8 bytes")?;
	acc.nonce = Nonce(bytes_to_f(&nonce_arr));

	let spend_pk_bytes: [u8; 40] = row
		.spend_auth
		.as_slice()
		.try_into()
		.context("spend_auth must be 40 bytes")?;
	if spend_pk_bytes != [0u8; 40] {
		let spend_pk = CompressedPublicKey::<F>::decode(&spend_pk_bytes);
		acc.spend_auth = SpendAuth {
			spend_pk: Some(spend_pk),
		};
	}

	if let Some(ast_obj) = row.ast.as_object() {
		let mut asset_map = std::collections::HashMap::new();
		for (key, val) in ast_obj {
			let aid = key.parse::<u64>().context("invalid asset_id key in AST")?;
			let leaf_index = val["leaf_index"]
				.as_u64()
				.context("missing leaf_index in AST entry")? as usize;
			let amount_hex = val["amount"]
				.as_str()
				.context("missing amount in AST entry")?;
			let amount_bytes = hex::decode(amount_hex).context("invalid amount hex in AST")?;
			let amount_arr: [u8; 32] = amount_bytes
				.as_slice()
				.try_into()
				.with_context(|| format!("AST amount for asset_id '{aid}' must be 32 bytes, got {}", amount_bytes.len()))?;
			let amount = bytes_to_u256(&amount_arr);
			let asset_id = AssetId::from_u64(aid)?;
			asset_map.insert(asset_id, (leaf_index, amount));
		}
		acc.ast = AccountStateTree::new_from_asset_map(asset_map)?;
	}

	Ok(acc)
}

// ── Hash / address helpers ───────────────────────────────────────────────────

/// Encode 4 Goldilocks field elements as a 32-byte big-endian hex string
/// (matching the sequencer's `parse_hex_bytes32` format).
pub fn hash_to_hex(h: &[F; 4]) -> String {
	let mut out = [0u8; 32];
	for (i, f) in h.iter().enumerate() {
		out[i * 8..(i + 1) * 8].copy_from_slice(&f.to_canonical_u64().to_be_bytes());
	}
	hex::encode(out)
}

/// Parse an Ethereum address string ("0x…") into a `primitive_types::H160`.
pub fn parse_eth_address(s: &str) -> anyhow::Result<primitive_types::H160> {
	let s = s.strip_prefix("0x").unwrap_or(s);
	let bytes = hex::decode(s).context("invalid eth_address hex")?;
	anyhow::ensure!(bytes.len() == 20, "eth_address must be 20 bytes");
	Ok(primitive_types::H160::from_slice(&bytes))
}

/// Build or update the AST JSON representation with a new asset balance.
///
/// Format: `{"<asset_id_decimal>": {"leaf_index": <u64>, "amount": "<hex_u256_64chars>"}}`
pub fn build_ast_json(
	existing_ast: &serde_json::Value,
	asset_id: u64,
	new_balance: U256,
) -> serde_json::Value {
	let mut ast = existing_ast.as_object().cloned().unwrap_or_default();
	let key = asset_id.to_string();
	let leaf_index = if let Some(entry) = ast.get(&key) {
		entry["leaf_index"].as_u64().unwrap_or(0)
	} else {
		ast.len() as u64
	};
	ast.insert(
		key,
		serde_json::json!({
			"leaf_index": leaf_index,
			"amount": hex::encode(u256_to_bytes(new_balance)),
		}),
	);
	serde_json::Value::Object(ast)
}
