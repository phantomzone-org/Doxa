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
	AccountAddress, AccountNullifier, AssetId, HashOutput, NodeIdentifier, NoteCommitment,
	NoteNullifier, PositionedStandardNode, PrivateIdentifier, SpendAuth, StandardAccount,
	StandardNote, SubpoolId,
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
struct WasmDummyNote([F; 4]);

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

	/// Returns the 32-byte account commitment.
	pub fn commitment(&self) -> Vec<u8> {
		hash_to_bytes(self.0.borrow().commitment().0)
	}

	/// Returns the 32-byte public identifier.
	#[wasm_bindgen(js_name = publicId)]
	pub fn public_id(&self) -> Vec<u8> {
		hash_to_bytes(self.0.borrow().public_id().0)
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
	/// Pass `undefined` for fresh accounts (nonce = 0).
	pub fn nullifier(&self) -> Vec<u8> {
		let null: AccountNullifier = self.0.borrow().nullifier();
		hash_to_bytes(null.0)
	}

	/// Returns the 16-byte little-endian encoding of PrivateIdentifier([F; 2]).
	/// Used as `private_identifier` in the backend register request.
	#[wasm_bindgen(js_name = privateIdentifierBytes)]
	pub fn private_identifier_bytes(&self) -> Vec<u8> {
		let acc = self.0.borrow();
		let [f0, f1] = acc.private_identifier.0;
		let mut out = [0u8; 16];
		out[0..8].copy_from_slice(&f0.to_canonical_u64().to_le_bytes());
		out[8..16].copy_from_slice(&f1.to_canonical_u64().to_le_bytes());
		out.to_vec()
	}

	/// Returns the 40-byte little-endian encoding of the spend-auth CompressedPublicKey.
	/// Used as `spend_auth_pk` in the backend register request.
	/// Returns all-zeros if no spend key is set.
	#[wasm_bindgen(js_name = spendAuthPkBytes)]
	pub fn spend_auth_pk_bytes(&self) -> Vec<u8> {
		let acc = self.0.borrow();
		match &acc.spend_auth.spend_pk {
			Some(pk) => pk.encode().to_vec(),
			None => vec![0u8; 40],
		}
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
	/// - `recipient`: account that owns this note
	/// - `sender`: account that sent this note
	/// - `position`: position in the NCT
	#[wasm_bindgen(constructor)]
	pub fn new(
		identifier: &[u8],
		asset_id: u64,
		amount: BigInt,
		recipient: &WasmAccount,
		sender: &WasmAccount,
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
			NodeIdentifier([
				F::from_canonical_u64(id0_raw),
				F::from_canonical_u64(id1_raw),
			]),
			asset,
			amt,
			AccountAddress::from_acc(&recipient.0.borrow()),
			AccountAddress::from_acc(&sender.0.borrow()),
		);
		Ok(WasmInputNote {
			note,
			position,
			asset_id,
		})
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

		derive_priv_tx_hash(self.accin_null, self.accout.commitment(), inotes_null, onotes_comm)
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
	) -> Result<(), JsError> {
		use tessera_client::NOTE_BATCH;
		if self.onotes.len() >= NOTE_BATCH {
			return Err(JsError::new(&format!(
				"output notes already full (max {NOTE_BATCH})"
			)));
		}
		let amt = bigint_to_u256(amount)?;
		let asset = parse_asset_id(self.asset_id).unwrap(); // validated at `new`
		let sender_addr = AccountAddress::from_acc(&self.accin.borrow());
		let recipient_addr = recipient.0;
		let mut rng = rand::rng();
		let note = StandardNote::create(&mut rng, recipient_addr, sender_addr, amt, asset);
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

/// Derive the private identifier bytes from a seed.
/// Returns 16 bytes (2 × u64 LE canonical encoding of PrivateIdentifier([F; 2])).
/// This is the value used as `private_identifier` in the backend register request.
#[wasm_bindgen(js_name = derivePrivateIdentifier)]
pub fn wasm_derive_private_identifier(seed: &[u8]) -> Vec<u8> {
	let pi = derive_private_identifier(seed);
	let [f0, f1] = pi.0;
	let mut out = [0u8; 16];
	out[0..8].copy_from_slice(&f0.to_canonical_u64().to_le_bytes());
	out[8..16].copy_from_slice(&f1.to_canonical_u64().to_le_bytes());
	out.to_vec()
}

/// Derive the spend-auth public key bytes from a seed.
/// Returns 40 bytes (5 × u64 LE encoding of CompressedPublicKey via `encode()`).
/// This is the value used as `spend_auth_pk` in the backend register request.
#[wasm_bindgen(js_name = deriveSpendAuthPk)]
pub fn wasm_derive_spend_auth_pk(seed: &[u8]) -> Vec<u8> {
	let sk = derive_spend_key(seed);
	let pk = CompressedPublicKey::from(sk.public_key::<F>());
	pk.encode().to_vec()
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
