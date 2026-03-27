mod utils;

use std::{cell::RefCell, rc::Rc};

use js_sys::BigInt;
use plonky2_field::{
	goldilocks_field::GoldilocksField,
	types::{Field, Field64, PrimeField64},
};
use primitive_types::U256;
use rand::{distr::Uniform, CryptoRng, Rng, RngExt};
use sha2::{Digest, Sha256};
use tessera_client::{
	derive_priv_tx_hash, double_hash_native,
	schnorr::{schnorr_sign, CompressedPublicKey, PrivateKey, Scalar},
	AccountAddress, AccountNullifier, AccountStateTree, AssetId, DepositNote, HashOutput, Nonce,
	NoteCommitment, NoteIdentifier, NoteNullifier, PositionedStandardNode, PrivateIdentifier,
	PublicIdentifier, SpendAuth, StandardAccount, StandardNote, SubpoolId,
};
use wasm_bindgen::prelude::*;

type F = GoldilocksField;

const DS_WASM_SEEDED_PRIVATE_IDENTIFIER: &[u8] = b"tessera::wasm::seeded_private_identifier";
const DS_WASM_SEEDED_SPEND_AUTH: &[u8] = b"tessera::wasm::seeded_spend_auth";

// ── helpers ──────────────────────────────────────────────────────────────────

/// Serialise a `HashOutput` to a 32-byte Vec (little-endian u64 limbs).
fn hash_to_bytes(h: HashOutput) -> Vec<u8> {
	let mut out = Vec::with_capacity(32);
	for f in h.0 {
		out.extend_from_slice(&f.to_canonical_u64().to_le_bytes());
	}
	out
}

/// Convert a JS BigInt to a Rust U256 via its hex string representation.
fn bigint_to_u256(v: BigInt) -> Result<U256, JsError> {
	let js_str = v
		.to_string(16)
		.map_err(|_| JsError::new("BigInt.toString(16) failed"))?;
	let s = js_str
		.as_string()
		.ok_or_else(|| JsError::new("BigInt hex is not a string"))?;
	U256::from_str_radix(s.trim_start_matches("0x"), 16)
		.map_err(|e| JsError::new(&format!("BigInt parse error: {e}")))
}

/// Parse `asset_id` as a Goldilocks field element, validating the range.
fn parse_asset_id(v: u64) -> Result<AssetId, JsError> {
	AssetId::from_u64(v).map_err(|e| JsError::new(&e.to_string()))
}

/// Generate a random `[F; 4]` hash (for use as a dummy commitment/nullifier).
fn random_hash<R: CryptoRng + Rng>(rng: &mut R) -> HashOutput {
	let dist = Uniform::new(0, F::ORDER).unwrap();
	HashOutput(std::array::from_fn(|_| {
		F::from_canonical_u64(rng.sample(dist))
	}))
}

/// A random dummy note seed: 4 Goldilocks field elements sampled uniformly at random.
/// Converted to a `NoteNullifier` or `NoteCommitment` via `double_hash_native` when building.
#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmDummyNote([F; 4]);

impl WasmDummyNote {
	fn sample<R: CryptoRng + Rng>(rng: &mut R) -> Self {
		Self(random_hash(rng).0)
	}

	fn to_nullifier(&self) -> NoteNullifier {
		NoteNullifier(HashOutput(double_hash_native(self.0)))
	}

	fn to_commitment(&self) -> NoteCommitment {
		NoteCommitment(HashOutput(double_hash_native(self.0)))
	}
}

#[wasm_bindgen]
impl WasmDummyNote {
	/// Returns the raw 32-byte seed (4 × u64 LE) as a 64-char hex string.
	#[wasm_bindgen(js_name = toHex)]
	pub fn to_hex(&self) -> String {
		let mut out = [0u8; 32];
		for (i, f) in self.0.iter().enumerate() {
			out[i * 8..i * 8 + 8].copy_from_slice(&f.to_canonical_u64().to_le_bytes());
		}
		hex::encode(out)
	}
}

/// Derive `PrivateIdentifier([F; 2])` from a seed using domain-separated SHA-256.
/// Returns the canonical 16-byte LE encoding (2 × u64 LE).
fn derive_private_identifier(seed: &[u8]) -> PrivateIdentifier {
	let hash: [u8; 32] = Sha256::new()
		.chain_update(seed)
		.chain_update(DS_WASM_SEEDED_PRIVATE_IDENTIFIER)
		.finalize()
		.into();
	let f0 = F::from_noncanonical_u64(u64::from_le_bytes(hash[0..8].try_into().unwrap()));
	let f1 = F::from_noncanonical_u64(u64::from_le_bytes(hash[8..16].try_into().unwrap()));
	PrivateIdentifier([f0, f1])
}

/// Derive the spend-auth private key from a 32-byte seed using domain-separated SHA-256.
fn derive_spend_key(seed: &[u8]) -> PrivateKey {
	let h0: [u8; 32] = Sha256::new()
		.chain_update(seed)
		.chain_update(DS_WASM_SEEDED_SPEND_AUTH)
		.chain_update([0u8])
		.finalize()
		.into();
	let h1: [u8; 32] = Sha256::new()
		.chain_update(seed)
		.chain_update(DS_WASM_SEEDED_SPEND_AUTH)
		.chain_update([1u8])
		.finalize()
		.into();
	let mut sk_bytes = [0u8; 40];
	sk_bytes[..32].copy_from_slice(&h0);
	sk_bytes[32..].copy_from_slice(&h1[..8]);
	PrivateKey::decode_reduce(&sk_bytes)
}

// ── WasmAccount ──────────────────────────────────────────────────────────────

/// A Tessera account exposed to JavaScript.
#[wasm_bindgen]
pub struct WasmAccount(Rc<RefCell<StandardAccount>>);

#[wasm_bindgen]
impl WasmAccount {
	/// Create a deterministic account from a seed and `subpool_id`.
	///
	/// Derives:
	/// - `private_identifier = sha256(seed || DS_WASM_SEEDED_PRIVATE_IDENTIFIER)`
	/// - spend-auth `sk = decode_reduce(sha256(seed || DS || 0x00) || sha256(seed || DS ||
	///   0x01)[..8])`
	#[wasm_bindgen(js_name = newWithSeed)]
	pub fn new_with_seed(seed: &[u8], subpool_id: u64) -> WasmAccount {
		utils::set_panic_hook();

		let private_identifier = derive_private_identifier(seed);
		let sk = derive_spend_key(seed);
		let spend_pk = CompressedPublicKey::from(sk.public_key::<F>());

		let mut acc = StandardAccount::new_with(
			private_identifier,
			SubpoolId(F::from_canonical_u64(subpool_id)),
		);
		acc.spend_auth = SpendAuth {
			spend_pk: Some(spend_pk),
		};

		WasmAccount(Rc::new(RefCell::new(acc)))
	}

	/// Reconstruct a `WasmAccount` from server-returned account data.
	/// No seed required — the spend-auth private key is not stored;
	/// pass seed to `WasmSpendTx::sign(seed)` separately when signing.
	#[wasm_bindgen(js_name = fromAccountData)]
	pub fn from_account_data(
		private_identifier_hex: &str,
		subpool_id_hex: &str,
		nonce_hex: &str,
		spend_auth_pk_hex: &str,
		ast_json: &str,
	) -> Result<WasmAccount, JsError> {
		// private identifier
		let pi_bytes =
			hex::decode(private_identifier_hex).map_err(|e| JsError::new(&e.to_string()))?;
		let pi = WasmPrivateIdentifier::from_bytes_inner(&pi_bytes)?.0;

		// subpool id
		let sp_bytes = hex::decode(subpool_id_hex).map_err(|e| JsError::new(&e.to_string()))?;
		let sp_arr: [u8; 8] = sp_bytes
			.as_slice()
			.try_into()
			.map_err(|_| JsError::new("subpool_id must be 8 bytes"))?;
		let subpool_id = SubpoolId(F::from_canonical_u64(u64::from_le_bytes(sp_arr)));

		// nonce (8-byte LE)
		let n_bytes = hex::decode(nonce_hex).map_err(|e| JsError::new(&e.to_string()))?;
		let n_arr: [u8; 8] = n_bytes
			.as_slice()
			.try_into()
			.map_err(|_| JsError::new("nonce must be 8 bytes"))?;
		let nonce_val = u64::from_le_bytes(n_arr);

		// spend auth public key (40 bytes)
		let sa_bytes = hex::decode(spend_auth_pk_hex).map_err(|e| JsError::new(&e.to_string()))?;
		let sa_arr: &[u8; 40] = sa_bytes
			.as_slice()
			.try_into()
			.map_err(|_| JsError::new("spend_auth_pk must be 40 bytes"))?;
		let spend_pk = CompressedPublicKey::<F>::decode(sa_arr);

		// AST JSON: keys = decimal asset_id string, values = { leaf_index, amount (LE hex) }
		let ast_val: serde_json::Value = serde_json::from_str(ast_json)
			.map_err(|e| JsError::new(&format!("ast_json parse error: {e}")))?;
		let mut asset_map = std::collections::HashMap::new();
		if let Some(obj) = ast_val.as_object() {
			for (k, v) in obj {
				let asset_id_u64: u64 = k
					.parse()
					.map_err(|_| JsError::new(&format!("invalid asset_id key: {k}")))?;
				let asset = parse_asset_id(asset_id_u64)?;
				let leaf_index = v["leaf_index"]
					.as_u64()
					.ok_or_else(|| JsError::new("missing leaf_index"))? as usize;
				let amount_hex = v["amount"]
					.as_str()
					.ok_or_else(|| JsError::new("missing amount"))?;
				let amount_bytes =
					hex::decode(amount_hex).map_err(|e| JsError::new(&e.to_string()))?;
				let amount = primitive_types::U256::from_little_endian(&amount_bytes);
				asset_map.insert(asset, (leaf_index, amount));
			}
		}
		let ast = AccountStateTree::new_from_asset_map(asset_map)
			.map_err(|e| JsError::new(&e.to_string()))?;

		let mut acc = StandardAccount::new_with(pi, subpool_id);
		acc.nonce = Nonce(F::from_canonical_u64(nonce_val));
		acc.spend_auth = SpendAuth {
			spend_pk: Some(spend_pk),
		};
		acc.ast = ast;

		Ok(WasmAccount(Rc::new(RefCell::new(acc))))
	}

	/// Returns the account commitment.
	pub fn commitment(&self) -> WasmAccountCommitment {
		WasmAccountCommitment(self.0.borrow().commitment().0)
	}

	/// Returns the public identifier.
	#[wasm_bindgen(js_name = publicId)]
	pub fn public_id(&self) -> WasmPublicIdentifier {
		WasmPublicIdentifier(self.0.borrow().public_id())
	}

	/// Returns the 32-byte nullifier key.
	#[wasm_bindgen(js_name = nullifierKey)]
	pub fn nullifier_key(&self) -> Vec<u8> {
		hash_to_bytes(HashOutput(self.0.borrow().nk().0))
	}

	/// Returns whether the account is fresh (nonce = 0, no auth keys, no assets).
	#[wasm_bindgen(js_name = isFresh)]
	pub fn is_fresh(&self) -> bool {
		self.0.borrow().is_fresh()
	}

	/// Returns the account address.
	pub fn address(&self) -> WasmAccountAddress {
		WasmAccountAddress(AccountAddress::from_acc(&self.0.borrow()))
	}

	/// Returns the account nullifier.
	pub fn nullifier(&self) -> WasmAccountNullifier {
		let null: AccountNullifier = self.0.borrow().nullifier();
		WasmAccountNullifier(null.0)
	}

	/// Returns the private identifier as a `WasmPrivateIdentifier`.
	#[wasm_bindgen(js_name = privateIdentifier)]
	pub fn private_identifier(&self) -> WasmPrivateIdentifier {
		WasmPrivateIdentifier(self.0.borrow().private_identifier)
	}

	/// Returns the spend-auth compressed public key.
	/// Returns an all-zeros key if no spend key is set.
	#[wasm_bindgen(js_name = spendAuthPk)]
	pub fn spend_auth_pk(&self) -> WasmSpendAuthPk {
		let acc = self.0.borrow();
		match &acc.spend_auth.spend_pk {
			Some(pk) => WasmSpendAuthPk(*pk),
			None => WasmSpendAuthPk(CompressedPublicKey::<F>::decode(&[0u8; 40])),
		}
	}
}

// ── WasmSubpoolId ────────────────────────────────────────────────────────────

/// A subpool identifier (1 Goldilocks field element, 8 bytes / 16 hex chars).
#[wasm_bindgen]
pub struct WasmSubpoolId(SubpoolId);

#[wasm_bindgen]
impl WasmSubpoolId {
	/// 16 hex chars — 1 × u64 LE (8 bytes).
	#[wasm_bindgen(js_name = toHex)]
	pub fn to_hex(&self) -> String {
		hex::encode(self.0 .0.to_canonical_u64().to_le_bytes())
	}

	/// Parse from a 16-char hex string (u64 LE).
	#[wasm_bindgen(js_name = fromHex)]
	pub fn from_hex(s: &str) -> Result<WasmSubpoolId, JsError> {
		let bytes = hex::decode(s).map_err(|e| JsError::new(&e.to_string()))?;
		Self::from_bytes_inner(&bytes)
	}

	/// Parse from an 8-byte Uint8Array (u64 LE).
	#[wasm_bindgen(js_name = fromBytes)]
	pub fn from_bytes(bytes: &[u8]) -> Result<WasmSubpoolId, JsError> {
		Self::from_bytes_inner(bytes)
	}

	fn from_bytes_inner(bytes: &[u8]) -> Result<WasmSubpoolId, JsError> {
		if bytes.len() != 8 {
			return Err(JsError::new("subpool_id must be 8 bytes (16 hex chars)"));
		}
		let v = u64::from_le_bytes(bytes.try_into().unwrap());
		Ok(WasmSubpoolId(SubpoolId(F::from_canonical_u64(v))))
	}
}

// ── WasmPrivateIdentifier ─────────────────────────────────────────────────────

/// A private account identifier (2 Goldilocks field elements, 16 bytes / 32 hex chars).
#[wasm_bindgen]
pub struct WasmPrivateIdentifier(PrivateIdentifier);

#[wasm_bindgen]
impl WasmPrivateIdentifier {
	/// 32 hex chars — 2 × u64 LE (16 bytes).
	#[wasm_bindgen(js_name = toHex)]
	pub fn to_hex(&self) -> String {
		let [f0, f1] = self.0 .0;
		let mut out = [0u8; 16];
		out[..8].copy_from_slice(&f0.to_canonical_u64().to_le_bytes());
		out[8..].copy_from_slice(&f1.to_canonical_u64().to_le_bytes());
		hex::encode(out)
	}

	/// Parse from a 32-char hex string (2 × u64 LE).
	#[wasm_bindgen(js_name = fromHex)]
	pub fn from_hex(s: &str) -> Result<WasmPrivateIdentifier, JsError> {
		let bytes = hex::decode(s).map_err(|e| JsError::new(&e.to_string()))?;
		Self::from_bytes_inner(&bytes)
	}

	/// Parse from a 16-byte Uint8Array (2 × u64 LE).
	#[wasm_bindgen(js_name = fromBytes)]
	pub fn from_bytes(bytes: &[u8]) -> Result<WasmPrivateIdentifier, JsError> {
		Self::from_bytes_inner(bytes)
	}

	fn from_bytes_inner(bytes: &[u8]) -> Result<WasmPrivateIdentifier, JsError> {
		if bytes.len() != 16 {
			return Err(JsError::new(
				"private_identifier must be 16 bytes (32 hex chars)",
			));
		}
		let f0 = F::from_noncanonical_u64(u64::from_le_bytes(bytes[..8].try_into().unwrap()));
		let f1 = F::from_noncanonical_u64(u64::from_le_bytes(bytes[8..].try_into().unwrap()));
		Ok(WasmPrivateIdentifier(PrivateIdentifier([f0, f1])))
	}
}

// ── WasmPublicIdentifier ──────────────────────────────────────────────────────

/// A public account identifier (4 Goldilocks field elements, 32 bytes / 64 hex chars).
#[wasm_bindgen]
pub struct WasmPublicIdentifier(PublicIdentifier);

#[wasm_bindgen]
impl WasmPublicIdentifier {
	/// 64 hex chars — 4 × u64 LE (32 bytes).
	#[wasm_bindgen(js_name = toHex)]
	pub fn to_hex(&self) -> String {
		let mut out = [0u8; 32];
		for (i, f) in self.0 .0 .0.iter().enumerate() {
			out[i * 8..i * 8 + 8].copy_from_slice(&f.to_canonical_u64().to_le_bytes());
		}
		hex::encode(out)
	}

	/// Parse from a 64-char hex string (4 × u64 LE).
	#[wasm_bindgen(js_name = fromHex)]
	pub fn from_hex(s: &str) -> Result<WasmPublicIdentifier, JsError> {
		let bytes = hex::decode(s).map_err(|e| JsError::new(&e.to_string()))?;
		Self::from_bytes_inner(&bytes)
	}

	/// Parse from a 32-byte Uint8Array (4 × u64 LE).
	#[wasm_bindgen(js_name = fromBytes)]
	pub fn from_bytes(bytes: &[u8]) -> Result<WasmPublicIdentifier, JsError> {
		Self::from_bytes_inner(bytes)
	}

	fn from_bytes_inner(bytes: &[u8]) -> Result<WasmPublicIdentifier, JsError> {
		if bytes.len() != 32 {
			return Err(JsError::new(
				"public_identifier must be 32 bytes (64 hex chars)",
			));
		}
		let mut elems = [F::ZERO; 4];
		for (i, chunk) in bytes.chunks_exact(8).enumerate() {
			elems[i] = F::from_canonical_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
		}
		Ok(WasmPublicIdentifier(PublicIdentifier(HashOutput(elems))))
	}
}

// ── WasmSpendAuthPk ──────────────────────────────────────────────────────────

/// A spend-auth compressed public key (5 × u64 LE, 40 bytes / 80 hex chars).
#[wasm_bindgen]
pub struct WasmSpendAuthPk(CompressedPublicKey<F>);

#[wasm_bindgen]
impl WasmSpendAuthPk {
	/// 80 hex chars — 5 × u64 LE (40 bytes).
	#[wasm_bindgen(js_name = toHex)]
	pub fn to_hex(&self) -> String {
		hex::encode(self.0.encode())
	}

	/// Parse from an 80-char hex string (5 × u64 LE).
	#[wasm_bindgen(js_name = fromHex)]
	pub fn from_hex(s: &str) -> Result<WasmSpendAuthPk, JsError> {
		let bytes = hex::decode(s).map_err(|e| JsError::new(&e.to_string()))?;
		Self::from_bytes_inner(&bytes)
	}

	/// Parse from a 40-byte Uint8Array (5 × u64 LE).
	#[wasm_bindgen(js_name = fromBytes)]
	pub fn from_bytes(bytes: &[u8]) -> Result<WasmSpendAuthPk, JsError> {
		Self::from_bytes_inner(bytes)
	}

	fn from_bytes_inner(bytes: &[u8]) -> Result<WasmSpendAuthPk, JsError> {
		let arr: &[u8; 40] = bytes
			.try_into()
			.map_err(|_| JsError::new("spend_auth_pk must be 40 bytes (80 hex chars)"))?;
		Ok(WasmSpendAuthPk(CompressedPublicKey::<F>::decode(arr)))
	}
}

// ── WasmAccountCommitment ────────────────────────────────────────────────────

/// An account commitment (4 Goldilocks field elements, 32 bytes / 64 hex chars).
#[wasm_bindgen]
pub struct WasmAccountCommitment(HashOutput);

#[wasm_bindgen]
impl WasmAccountCommitment {
	/// 64 hex chars — 4 × u64 LE (32 bytes).
	#[wasm_bindgen(js_name = toHex)]
	pub fn to_hex(&self) -> String {
		hex::encode(hash_to_bytes(self.0))
	}

	/// 32 bytes (4 × u64 little-endian).
	#[wasm_bindgen(js_name = toBytes)]
	pub fn to_bytes(&self) -> Vec<u8> {
		hash_to_bytes(self.0)
	}

	/// Parse from a 64-char hex string (4 × u64 LE).
	#[wasm_bindgen(js_name = fromHex)]
	pub fn from_hex(s: &str) -> Result<WasmAccountCommitment, JsError> {
		let bytes = hex::decode(s).map_err(|e| JsError::new(&e.to_string()))?;
		Self::from_bytes_inner(&bytes)
	}

	/// Parse from a 32-byte Uint8Array (4 × u64 LE).
	#[wasm_bindgen(js_name = fromBytes)]
	pub fn from_bytes(bytes: &[u8]) -> Result<WasmAccountCommitment, JsError> {
		Self::from_bytes_inner(bytes)
	}

	fn from_bytes_inner(bytes: &[u8]) -> Result<WasmAccountCommitment, JsError> {
		if bytes.len() != 32 {
			return Err(JsError::new("commitment must be 32 bytes (64 hex chars)"));
		}
		let mut elems = [F::ZERO; 4];
		for (i, chunk) in bytes.chunks_exact(8).enumerate() {
			elems[i] = F::from_canonical_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
		}
		Ok(WasmAccountCommitment(HashOutput(elems)))
	}
}

// ── WasmAccountNullifier ─────────────────────────────────────────────────────

/// An account nullifier (4 Goldilocks field elements, 32 bytes / 64 hex chars).
#[wasm_bindgen]
pub struct WasmAccountNullifier(HashOutput);

#[wasm_bindgen]
impl WasmAccountNullifier {
	/// 64 hex chars — 4 × u64 LE (32 bytes).
	#[wasm_bindgen(js_name = toHex)]
	pub fn to_hex(&self) -> String {
		hex::encode(hash_to_bytes(self.0))
	}

	/// 32 bytes (4 × u64 little-endian).
	#[wasm_bindgen(js_name = toBytes)]
	pub fn to_bytes(&self) -> Vec<u8> {
		hash_to_bytes(self.0)
	}

	/// Parse from a 64-char hex string (4 × u64 LE).
	#[wasm_bindgen(js_name = fromHex)]
	pub fn from_hex(s: &str) -> Result<WasmAccountNullifier, JsError> {
		let bytes = hex::decode(s).map_err(|e| JsError::new(&e.to_string()))?;
		Self::from_bytes_inner(&bytes)
	}

	/// Parse from a 32-byte Uint8Array (4 × u64 LE).
	#[wasm_bindgen(js_name = fromBytes)]
	pub fn from_bytes(bytes: &[u8]) -> Result<WasmAccountNullifier, JsError> {
		Self::from_bytes_inner(bytes)
	}

	fn from_bytes_inner(bytes: &[u8]) -> Result<WasmAccountNullifier, JsError> {
		if bytes.len() != 32 {
			return Err(JsError::new("nullifier must be 32 bytes (64 hex chars)"));
		}
		let mut elems = [F::ZERO; 4];
		for (i, chunk) in bytes.chunks_exact(8).enumerate() {
			elems[i] = F::from_canonical_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
		}
		Ok(WasmAccountNullifier(HashOutput(elems)))
	}
}

// ── WasmAccountAddress ───────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct WasmAccountAddress(AccountAddress);

#[wasm_bindgen]
impl WasmAccountAddress {
	/// Returns the address as `hex(subpool_id) | hex(public_id)` (80 hex chars).
	#[wasm_bindgen(js_name = toHex)]
	pub fn to_hex(&self) -> String {
		self.0.to_hex()
	}

	/// Parse an 80-hex-char address string (16 hex subpool_id + 64 hex public_id).
	#[wasm_bindgen(js_name = fromHex)]
	pub fn from_hex(hex: &str) -> Result<WasmAccountAddress, JsError> {
		AccountAddress::from_hex(hex)
			.map(WasmAccountAddress)
			.map_err(|e| JsError::new(&e.to_string()))
	}

	/// Construct an address from a `WasmSubpoolId` and a `WasmPublicIdentifier`.
	#[wasm_bindgen(js_name = fromParts)]
	pub fn from_parts(
		subpool_id: &WasmSubpoolId,
		public_id: &WasmPublicIdentifier,
	) -> WasmAccountAddress {
		WasmAccountAddress(AccountAddress::new(subpool_id.0, public_id.0))
	}
}

// ── WasmHashOutput ───────────────────────────────────────────────────────────

/// A Goldilocks hash output (4 field elements).
#[wasm_bindgen]
pub struct WasmHashOutput(HashOutput);

#[wasm_bindgen]
impl WasmHashOutput {
	/// 32 bytes (4 × u64 little-endian).
	#[wasm_bindgen(js_name = toBytes)]
	pub fn to_bytes(&self) -> Vec<u8> {
		hash_to_bytes(self.0)
	}

	/// 4 × u64 limbs (canonical representation).
	pub fn limbs(&self) -> Vec<u64> {
		self.0 .0.iter().map(|f| f.to_canonical_u64()).collect()
	}
}

// ── WasmInputNote ─────────────────────────────────────────────────────────────

/// A standard note together with its NCT position and asset_id.
/// Add to a `WasmSpendTxBuilder` via `addInputNote`.
/// TODO: remove asset_id field since note has asset_id
#[wasm_bindgen]
pub struct WasmInputNote {
	note: StandardNote,
	position: u64,
	asset_id: u64,
}

#[wasm_bindgen]
impl WasmInputNote {
	/// Create an input note.
	///
	/// - `identifier`: 16 bytes (2 × u64 little-endian, each < Goldilocks ORDER)
	/// - `asset_id`: Goldilocks field element (< ORDER)
	/// - `amount`: JS BigInt
	/// - `recipient`: address of the account that owns this note
	/// - `sender`: address of the account that sent this note
	/// - `position`: position in the NCT
	#[wasm_bindgen(constructor)]
	pub fn new(
		identifier: &[u8],
		asset_id: u64,
		amount: BigInt,
		recipient: &WasmAccountAddress,
		sender: &WasmAccountAddress,
		position: u64,
	) -> Result<WasmInputNote, JsError> {
		// Validate and parse identifier bytes into two Goldilocks field elements.
		if identifier.len() != 16 {
			return Err(JsError::new("identifier must be exactly 16 bytes"));
		}
		let id0_raw = u64::from_le_bytes(identifier[0..8].try_into().unwrap());
		let id1_raw = u64::from_le_bytes(identifier[8..16].try_into().unwrap());
		if id0_raw >= F::ORDER {
			return Err(JsError::new(&format!(
				"identifier[0..8] value {id0_raw} is out of Goldilocks field range"
			)));
		}
		if id1_raw >= F::ORDER {
			return Err(JsError::new(&format!(
				"identifier[8..16] value {id1_raw} is out of Goldilocks field range"
			)));
		}

		let asset = parse_asset_id(asset_id)?;
		let amt = bigint_to_u256(amount)?;

		let note = StandardNote::new(
			NoteIdentifier([
				F::from_canonical_u64(id0_raw),
				F::from_canonical_u64(id1_raw),
			]),
			asset,
			amt,
			recipient.0,
			sender.0,
		);
		Ok(WasmInputNote {
			note,
			position,
			asset_id,
		})
	}
}

// ── WasmOutputNote ────────────────────────────────────────────────────────────

/// An output note produced by `WasmSpendTxBuilder::build`.
#[wasm_bindgen]
pub struct WasmOutputNote(StandardNote);

#[wasm_bindgen]
impl WasmOutputNote {
	/// Identifier as 32 hex chars (2 × u64 LE).
	#[wasm_bindgen(js_name = identifierHex)]
	pub fn identifier_hex(&self) -> String {
		let mut out = [0u8; 16];
		out[..8].copy_from_slice(&self.0.identifier.0[0].to_canonical_u64().to_le_bytes());
		out[8..].copy_from_slice(&self.0.identifier.0[1].to_canonical_u64().to_le_bytes());
		hex::encode(out)
	}

	/// Asset id as a raw u64 Goldilocks field element.
	#[wasm_bindgen(js_name = assetId)]
	pub fn asset_id(&self) -> u64 {
		self.0.asset_id.0.to_canonical_u64()
	}

	/// Amount as 64 hex chars (U256, 32 bytes LE).
	#[wasm_bindgen(js_name = amountHex)]
	pub fn amount_hex(&self) -> String {
		let buf: [u8; 32] = self.0.amt.to_little_endian();
		hex::encode(buf)
	}

	/// Recipient address as 80 hex chars.
	#[wasm_bindgen(js_name = recipientHex)]
	pub fn recipient_hex(&self) -> String {
		self.0.recipient.to_hex()
	}

	/// Sender address as 80 hex chars.
	#[wasm_bindgen(js_name = senderHex)]
	pub fn sender_hex(&self) -> String {
		self.0.sender.to_hex()
	}

	/// Memo as hex (full 512 bytes = 1024 hex chars).
	#[wasm_bindgen(js_name = memoHex)]
	pub fn memo_hex(&self) -> String {
		hex::encode(self.0.memo)
	}
}

// ── WasmSpendTx ──────────────────────────────────────────────────────────────

/// Result of `WasmSpendTxBuilder::build`.
///
/// Stores all transaction components so individual fields can be inspected and
/// the tx hash can be (re-)derived on demand via `txHash()`.
#[wasm_bindgen]
pub struct WasmSpendTx {
	accin: StandardAccount,
	accout: StandardAccount,
	accin_null: AccountNullifier,
	/// Real input notes with their NCT positions.
	inotes: Vec<(StandardNote, u64)>,
	/// Random dummy seeds for unfilled input-note slots; converted to nullifiers via double_hash.
	dummy_inotes: Vec<WasmDummyNote>,
	/// Real output notes.
	onotes: Vec<StandardNote>,
	/// Random dummy seeds for unfilled output-note slots; converted to commitments via
	/// double_hash.
	dummy_onotes: Vec<WasmDummyNote>,
}

impl WasmSpendTx {
	fn compute_tx_hash(&self) -> HashOutput {
		use tessera_client::NOTE_BATCH;
		let nk = self.accin.nk();

		let inotes_null: [NoteNullifier; NOTE_BATCH] = std::array::from_fn(|i| {
			if i < self.inotes.len() {
				let (note, pos) = &self.inotes[i];
				PositionedStandardNode::from_note(*note, F::from_canonical_u64(*pos)).nullifier(&nk)
			} else {
				self.dummy_inotes[i - self.inotes.len()].to_nullifier()
			}
		});

		let onotes_comm: [NoteCommitment; NOTE_BATCH] = std::array::from_fn(|i| {
			if i < self.onotes.len() {
				self.onotes[i].commitment()
			} else {
				self.dummy_onotes[i - self.onotes.len()].to_commitment()
			}
		});

		derive_priv_tx_hash(
			self.accin_null,
			self.accout.commitment(),
			inotes_null,
			onotes_comm,
		)
	}
}

#[wasm_bindgen]
impl WasmSpendTx {
	/// Derive the 32-byte transaction hash (4 × u64 little-endian).
	/// This is the value that must be signed with the spend-auth key.
	#[wasm_bindgen(js_name = txHash)]
	pub fn tx_hash(&self) -> Vec<u8> {
		hash_to_bytes(self.compute_tx_hash())
	}

	/// Sign the transaction hash with the spend-auth key derived from `seed`.
	/// Returns an 80-byte Schnorr signature: 40 bytes `r` + 40 bytes `s`.
	pub fn sign(&self, seed: &[u8]) -> Vec<u8> {
		let sk = derive_spend_key(seed);
		let hash = self.compute_tx_hash();
		let k = Scalar::sample(&mut rand::rng());
		schnorr_sign(&sk, &hash.0, k).encode().to_vec()
	}

	/// Number of real output notes.
	#[wasm_bindgen(js_name = outputNoteCount)]
	pub fn output_note_count(&self) -> usize {
		self.onotes.len()
	}

	/// Return the i-th real output note.
	#[wasm_bindgen(js_name = outputNoteAt)]
	pub fn output_note_at(&self, i: usize) -> WasmOutputNote {
		WasmOutputNote(self.onotes[i])
	}

	/// Number of dummy input notes.
	#[wasm_bindgen(js_name = diNoteCount)]
	pub fn di_note_count(&self) -> usize {
		self.dummy_inotes.len()
	}

	/// Return the i-th dummy input note seed.
	#[wasm_bindgen(js_name = diNoteAt)]
	pub fn di_note_at(&self, i: usize) -> WasmDummyNote {
		self.dummy_inotes[i].clone()
	}

	/// Number of dummy output notes.
	#[wasm_bindgen(js_name = doNoteCount)]
	pub fn do_note_count(&self) -> usize {
		self.dummy_onotes.len()
	}

	/// Return the i-th dummy output note seed.
	#[wasm_bindgen(js_name = doNoteAt)]
	pub fn do_note_at(&self, i: usize) -> WasmDummyNote {
		self.dummy_onotes[i].clone()
	}
}

// ── WasmSpendTxBuilder ───────────────────────────────────────────────────────

/// Builder for a spend transaction.
///
/// ```js
/// const builder = new WasmSpendTxBuilder(accin, 1n); // asset_id
/// builder.addOutputNote(recipient, 100n);
/// const tx = builder.build(undefined);  // undefined = fresh account
/// ```
#[wasm_bindgen]
pub struct WasmSpendTxBuilder {
	accin: Rc<RefCell<StandardAccount>>,
	asset_id: u64,
	inotes: Vec<(StandardNote, u64)>,
	onotes: Vec<StandardNote>,
}

#[wasm_bindgen]
impl WasmSpendTxBuilder {
	#[wasm_bindgen(constructor)]
	pub fn new(accin: &WasmAccount, asset_id: u64) -> Result<WasmSpendTxBuilder, JsError> {
		// Validate asset_id at construction time
		parse_asset_id(asset_id)?;
		Ok(WasmSpendTxBuilder {
			accin: Rc::clone(&accin.0),
			asset_id,
			inotes: Vec::new(),
			onotes: Vec::new(),
		})
	}

	/// Add an input note to consume.
	/// Rejected if: NOTE_BATCH limit reached, or asset_id doesn't match.
	#[wasm_bindgen(js_name = addInputNote)]
	pub fn add_input_note(&mut self, note: WasmInputNote) -> Result<(), JsError> {
		use tessera_client::NOTE_BATCH;
		if self.inotes.len() >= NOTE_BATCH {
			return Err(JsError::new(&format!(
				"input notes already full (max {NOTE_BATCH})"
			)));
		}
		if note.asset_id != self.asset_id {
			return Err(JsError::new(&format!(
				"input note asset_id {} does not match builder asset_id {}",
				note.asset_id, self.asset_id
			)));
		}
		self.inotes.push((note.note, note.position));
		Ok(())
	}

	/// Add an output note. Rejected if NOTE_BATCH limit is already reached.
	#[wasm_bindgen(js_name = addOutputNote)]
	pub fn add_output_note(
		&mut self,
		recipient: &WasmAccountAddress,
		amount: BigInt,
		memo: &[u8],
	) -> Result<(), JsError> {
		use tessera_client::NOTE_BATCH;
		if self.onotes.len() >= NOTE_BATCH {
			return Err(JsError::new(&format!(
				"output notes already full (max {NOTE_BATCH})"
			)));
		}
		if memo.len() > 512 {
			return Err(JsError::new("memo must be at most 512 bytes"));
		}
		let mut memo_arr = [0u8; 512];
		memo_arr[..memo.len()].copy_from_slice(memo);
		let amt = bigint_to_u256(amount)?;
		let asset = parse_asset_id(self.asset_id).unwrap(); // validated at `new`
		let sender_addr = AccountAddress::from_acc(&self.accin.borrow());
		let recipient_addr = recipient.0;
		let mut rng = rand::rng();
		let note =
			StandardNote::create(&mut rng, recipient_addr, sender_addr, amt, asset, memo_arr);
		self.onotes.push(note);
		Ok(())
	}

	/// Compute the spend tx hash.
	pub fn build(&self) -> Result<WasmSpendTx, JsError> {
		use tessera_client::NOTE_BATCH;

		if self.onotes.is_empty() {
			return Err(JsError::new("at least one output note is required"));
		}

		let accin_ref = self.accin.borrow();
		let asset = parse_asset_id(self.asset_id).unwrap();
		let mut rng = rand::rng();

		// Dummy seeds for unfilled output-note and input-note slots.
		let dummy_onotes: Vec<WasmDummyNote> = (0..NOTE_BATCH - self.onotes.len())
			.map(|_| WasmDummyNote::sample(&mut rng))
			.collect();
		let dummy_inotes: Vec<WasmDummyNote> = (0..NOTE_BATCH - self.inotes.len())
			.map(|_| WasmDummyNote::sample(&mut rng))
			.collect();

		// Derive accout.
		let delta_in: U256 = self
			.inotes
			.iter()
			.map(|(n, _)| n.amt())
			.fold(U256::zero(), |a, b| a + b);
		let delta_out: U256 = self
			.onotes
			.iter()
			.map(|n| n.amt())
			.fold(U256::zero(), |a, b| a + b);
		let old_bal = accin_ref
			.ast
			.amount_for(asset)
			.map(|(_, b)| b)
			.unwrap_or(U256::zero());
		let new_bal = old_bal + delta_in - delta_out;

		let mut accout = accin_ref.clone_with_incremented_nonce();
		accout.ast.insert_or_update_asset(asset, new_bal);

		let accin_null = accin_ref.nullifier();
		let accin = accin_ref.clone();

		Ok(WasmSpendTx {
			accin,
			accout,
			accin_null,
			inotes: self.inotes.clone(),
			dummy_inotes,
			onotes: self.onotes.clone(),
			dummy_onotes,
		})
	}
}

// ── free functions ────────────────────────────────────────────────────────────

/// Derive a `WasmPrivateIdentifier` from a seed (domain-separated SHA-256).
#[wasm_bindgen(js_name = derivePrivateIdentifier)]
pub fn wasm_derive_private_identifier(seed: &[u8]) -> WasmPrivateIdentifier {
	WasmPrivateIdentifier(derive_private_identifier(seed))
}

/// Derive a `WasmPublicIdentifier` from a `WasmPrivateIdentifier`.
///
/// Implements `Poseidon(DS_PUBLIC_IDENTIFIER || private_identifier)`,
/// matching `StandardAccount::public_id()` in tessera-client.
#[wasm_bindgen(js_name = derivePublicIdentifier)]
pub fn wasm_derive_public_identifier(private_id: &WasmPrivateIdentifier) -> WasmPublicIdentifier {
	// SubpoolId value does not affect the public_id computation.
	let acc = StandardAccount::new_with(private_id.0, SubpoolId(F::from_canonical_u64(1)));
	WasmPublicIdentifier(acc.public_id())
}

/// Derive the spend-auth public key from a seed.
#[wasm_bindgen(js_name = deriveSpendAuthPk)]
pub fn wasm_derive_spend_auth_pk(seed: &[u8]) -> WasmSpendAuthPk {
	let sk = derive_spend_key(seed);
	WasmSpendAuthPk(CompressedPublicKey::from(sk.public_key::<F>()))
}

/// Decode 32 bytes into a `WasmHashOutput` (validates each limb is in Goldilocks range).
#[wasm_bindgen(js_name = decodeHash)]
pub fn decode_hash(bytes: &[u8]) -> Result<WasmHashOutput, JsError> {
	if bytes.len() != 32 {
		return Err(JsError::new("expected exactly 32 bytes"));
	}
	let mut elems = [F::ZERO; 4];
	for (i, chunk) in bytes.chunks_exact(8).enumerate() {
		let v = u64::from_le_bytes(chunk.try_into().unwrap());
		if v >= F::ORDER {
			return Err(JsError::new(&format!(
				"limb {i} value {v} is out of Goldilocks field range"
			)));
		}
		elems[i] = F::from_canonical_u64(v);
	}
	Ok(WasmHashOutput(HashOutput(elems)))
}

// ── WasmAssetId ───────────────────────────────────────────────────────────────

/// A Goldilocks field element identifying an asset type (u64 < `F::ORDER`).
#[wasm_bindgen]
pub struct WasmAssetId(u64);

#[wasm_bindgen]
impl WasmAssetId {
	/// Construct from a `u64`, validating that it is within the Goldilocks field range.
	#[wasm_bindgen(js_name = fromU64)]
	pub fn from_u64(v: u64) -> Result<WasmAssetId, JsError> {
		parse_asset_id(v)?;
		Ok(WasmAssetId(v))
	}

	/// Return the asset id as a `u64`.
	#[wasm_bindgen(js_name = toU64)]
	pub fn to_u64(&self) -> u64 {
		self.0
	}
}

// ── WasmDepositNoteCommitment ─────────────────────────────────────────────────

/// A deposit-note commitment (4 Goldilocks field elements, 32 bytes / 64 hex chars).
#[wasm_bindgen]
pub struct WasmDepositNoteCommitment(HashOutput);

#[wasm_bindgen]
impl WasmDepositNoteCommitment {
	/// 64 hex chars — 4 × u64 LE (32 bytes).
	#[wasm_bindgen(js_name = toHex)]
	pub fn to_hex(&self) -> String {
		hex::encode(hash_to_bytes(self.0))
	}

	/// 32 bytes (4 × u64 little-endian).
	#[wasm_bindgen(js_name = toBytes)]
	pub fn to_bytes(&self) -> Vec<u8> {
		hash_to_bytes(self.0)
	}

	/// Parse from a 64-char hex string (4 × u64 LE).
	#[wasm_bindgen(js_name = fromHex)]
	pub fn from_hex(s: &str) -> Result<WasmDepositNoteCommitment, JsError> {
		let bytes = hex::decode(s).map_err(|e| JsError::new(&e.to_string()))?;
		Self::from_bytes_inner(&bytes)
	}

	/// Parse from a 32-byte Uint8Array (4 × u64 LE).
	#[wasm_bindgen(js_name = fromBytes)]
	pub fn from_bytes(bytes: &[u8]) -> Result<WasmDepositNoteCommitment, JsError> {
		Self::from_bytes_inner(bytes)
	}

	fn from_bytes_inner(bytes: &[u8]) -> Result<WasmDepositNoteCommitment, JsError> {
		if bytes.len() != 32 {
			return Err(JsError::new("commitment must be 32 bytes (64 hex chars)"));
		}
		let mut elems = [F::ZERO; 4];
		for (i, chunk) in bytes.chunks_exact(8).enumerate() {
			elems[i] = F::from_canonical_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
		}
		Ok(WasmDepositNoteCommitment(HashOutput(elems)))
	}
}

// ── WasmDepositNote ───────────────────────────────────────────────────────────

/// A deposit note with a randomly-sampled identifier.
#[wasm_bindgen]
pub struct WasmDepositNote {
	note: DepositNote,
	/// Cached raw asset id to avoid needing access to `AssetId`'s private field.
	asset_id_raw: u64,
}

#[wasm_bindgen]
impl WasmDepositNote {
	/// Construct a deposit note.
	///
	/// The identifier (`[F; 2]`) is sampled uniformly in `[0, F::ORDER)` inside
	/// this call — no identifier parameter is needed from JS.
	///
	/// - `recipient`: the Tessera account address that will receive the deposit.
	/// - `amount`: deposit amount as a JS `BigInt` (U256).
	/// - `asset_id`: validated Goldilocks asset id.
	#[wasm_bindgen(js_name = fromParts)]
	pub fn from_parts(
		recipient: &WasmAccountAddress,
		amount: BigInt,
		asset_id: &WasmAssetId,
	) -> Result<WasmDepositNote, JsError> {
		let mut rng = rand::rng();
		let dist = Uniform::new(0, F::ORDER).unwrap();
		let identifier = [
			F::from_canonical_u64(rng.sample(dist)),
			F::from_canonical_u64(rng.sample(dist)),
		];
		let amount = bigint_to_u256(amount)?;
		let asset = parse_asset_id(asset_id.0)?;
		Ok(WasmDepositNote {
			note: DepositNote {
				identifier,
				recipient: recipient.0,
				amount,
				asset_id: asset,
			},
			asset_id_raw: asset_id.0,
		})
	}

	/// Poseidon commitment to this deposit note.
	pub fn commitment(&self) -> WasmDepositNoteCommitment {
		WasmDepositNoteCommitment(self.note.commitment().0)
	}

	/// Hex-encoded identifier (`[F; 2]` = 16 bytes = 32 hex chars).
	#[wasm_bindgen(js_name = identifierHex)]
	pub fn identifier_hex(&self) -> String {
		hex::encode(self.identifier_bytes())
	}

	/// Identifier as raw bytes (16 bytes, 2 × u64 LE).
	#[wasm_bindgen(js_name = identifierBytes)]
	pub fn identifier_bytes(&self) -> Vec<u8> {
		let mut bytes = vec![0u8; 16];
		bytes[0..8].copy_from_slice(&self.note.identifier[0].to_canonical_u64().to_le_bytes());
		bytes[8..16].copy_from_slice(&self.note.identifier[1].to_canonical_u64().to_le_bytes());
		bytes
	}

	/// Deposit amount as a JS `BigInt`.
	pub fn amount(&self) -> BigInt {
		let hex = format!("{:x}", self.note.amount);
		BigInt::new(&JsValue::from_str(&format!("0x{hex}"))).unwrap_or_else(|_| BigInt::from(0u64))
	}

	/// Asset id.
	#[wasm_bindgen(js_name = assetId)]
	pub fn asset_id(&self) -> WasmAssetId {
		WasmAssetId(self.asset_id_raw)
	}
}
