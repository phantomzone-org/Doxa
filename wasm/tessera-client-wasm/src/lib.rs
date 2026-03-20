mod utils;

use std::{cell::RefCell, rc::Rc};

use plonky2_field::{
	goldilocks_field::GoldilocksField,
	types::{Field, PrimeField64},
};
use sha2::{Digest, Sha256};
use tessera_client::{
	AccountNullifier, PrivateIdentifier, SpendAuth, StandardAccount, SubpoolId,
	schnorr::{CompressedPublicKey, PrivateKey},
};
use wasm_bindgen::prelude::*;

type F = GoldilocksField;

const DS_WASM_SEEDED_PRIVATE_IDENTIFIER: &[u8] = b"tessera::wasm::seeded_private_identifier";
const DS_WASM_SEEDED_SPEND_AUTH: &[u8] = b"tessera::wasm::seeded_spend_auth";

// ── helpers ──────────────────────────────────────────────────────────────────

/// Serialise a `[F; 4]` hash output to a 32-byte Vec (little-endian u64 limbs).
fn hash_to_bytes(elements: &[F; 4]) -> Vec<u8> {
	let mut out = Vec::with_capacity(32);
	for f in elements {
		out.extend_from_slice(&f.to_canonical_u64().to_le_bytes());
	}
	out
}

// ── WasmAccount ──────────────────────────────────────────────────────────────

/// A Tessera account exposed to JavaScript.
///
/// Internally uses `Rc<RefCell<StandardAccount>>` so that methods take `&self`
/// and never consume the JS handle (see guide: prefer passing by reference).
#[wasm_bindgen]
pub struct WasmAccount(Rc<RefCell<StandardAccount>>);

#[wasm_bindgen]
impl WasmAccount {
	/// Create a deterministic account from a seed and `subpool_id`.
	///
	/// Derives:
	/// - `private_identifier = sha256(seed || DS_WASM_SEEDED_PRIVATE_IDENTIFIER)`
	/// - spend-auth `sk = sha256(seed || DS_WASM_SEEDED_SPEND_AUTH)`
	#[wasm_bindgen(js_name = newWithSeed)]
	pub fn new_with_seed(seed: &[u8], subpool_id: u64) -> WasmAccount {
		utils::set_panic_hook();

		// private_identifier = sha256(seed || DS_WASM_SEEDED_PRIVATE_IDENTIFIER)
		let hash_pi: [u8; 32] = Sha256::new()
			.chain_update(seed)
			.chain_update(DS_WASM_SEEDED_PRIVATE_IDENTIFIER)
			.finalize()
			.into();
		let f0 = F::from_noncanonical_u64(u64::from_le_bytes(hash_pi[0..8].try_into().unwrap()));
		let f1 = F::from_noncanonical_u64(u64::from_le_bytes(hash_pi[8..16].try_into().unwrap()));
		let private_identifier = PrivateIdentifier([f0, f1]);

		// sk = decode_reduce(sha256(seed || DS || 0x00) || sha256(seed || DS || 0x01)[..8])
		// Two SHA-256 calls with a counter suffix give 40 bytes for decode_reduce.
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
		let sk = PrivateKey::decode_reduce(&sk_bytes);
		let spend_pk = CompressedPublicKey::from(sk.public_key::<F>());

		let mut acc = StandardAccount::new_with(
			private_identifier,
			SubpoolId(F::from_canonical_u64(subpool_id)),
		);
		acc.spend_auth = SpendAuth { spend_pk: Some(spend_pk) };

		WasmAccount(Rc::new(RefCell::new(acc)))
	}

	/// Returns the 32-byte account commitment (Poseidon hash of account state).
	pub fn commitment(&self) -> Vec<u8> {
		let acc = self.0.borrow();
		hash_to_bytes(&acc.commitment().0 .0)
	}

	/// Returns the 32-byte public identifier derived from the private identifier.
	#[wasm_bindgen(js_name = publicId)]
	pub fn public_id(&self) -> Vec<u8> {
		let acc = self.0.borrow();
		hash_to_bytes(&acc.public_id().0 .0)
	}

	/// Returns the 32-byte nullifier key (`nk`).
	#[wasm_bindgen(js_name = nullifierKey)]
	pub fn nullifier_key(&self) -> Vec<u8> {
		let acc = self.0.borrow();
		hash_to_bytes(&acc.nk().0)
	}

	/// Returns whether the account is fresh (nonce = 0, no auth keys, no assets).
	#[wasm_bindgen(js_name = isFresh)]
	pub fn is_fresh(&self) -> bool {
		self.0.borrow().is_fresh()
	}

	/// Returns the account nullifier.
	///
	/// - Fresh accounts (nonce = 0, no auth): pass `position = undefined`.
	/// - Existing accounts: pass their position in the Account Commitment Tree.
	pub fn nullifier(&self, position: Option<u64>) -> Vec<u8> {
		let acc = self.0.borrow();
		let null: AccountNullifier = acc.nullifier(position);
		hash_to_bytes(&null.0 .0)
	}
}

// ── free functions ────────────────────────────────────────────────────────────

/// Decode a 32-byte commitment/nullifier back into 4 × u64 limbs (for debugging).
#[wasm_bindgen(js_name = decodeHash)]
pub fn decode_hash(bytes: &[u8]) -> Result<Vec<u64>, JsError> {
	if bytes.len() != 32 {
		return Err(JsError::new("expected exactly 32 bytes"));
	}
	let limbs: Vec<u64> = bytes
		.chunks_exact(8)
		.map(|c| u64::from_le_bytes(c.try_into().unwrap()))
		.collect();
	Ok(limbs)
}
