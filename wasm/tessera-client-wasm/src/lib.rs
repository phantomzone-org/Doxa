mod utils;

use std::{cell::RefCell, rc::Rc};

use plonky2_field::{
	goldilocks_field::GoldilocksField,
	types::{Field, PrimeField64},
};
use tessera_client::{AccountNullifier, StandardAccount, SubpoolId};
use wasm_bindgen::prelude::*;

type F = GoldilocksField;

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
	/// Create a new random account for the given `subpool_id`.
	#[wasm_bindgen(constructor)]
	pub fn new(subpool_id: u64) -> WasmAccount {
		// Route Rust panics to console.error in the browser.
		utils::set_panic_hook();

		let mut rng = rand::rng();
		let acc = StandardAccount::sample(&mut rng, SubpoolId(F::from_canonical_u64(subpool_id)));
		WasmAccount(Rc::new(RefCell::new(acc)))
	}

	/// Returns the 32-byte account commitment (Poseidon hash of account state).
	pub fn commitment(&self) -> Vec<u8> {
		let acc = self.0.borrow();
		hash_to_bytes(&acc.commitment().0 .0)
	}

	/// Returns the 32-byte public identifier derived from the private identifier.
	pub fn public_id(&self) -> Vec<u8> {
		let acc = self.0.borrow();
		hash_to_bytes(&acc.public_id().0 .0)
	}

	/// Returns the 32-byte nullifier key (`nk`).
	pub fn nullifier_key(&self) -> Vec<u8> {
		let acc = self.0.borrow();
		hash_to_bytes(&acc.nk().0)
	}

	/// Returns whether the account is fresh (nonce = 0, no auth keys, no assets).
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
#[wasm_bindgen]
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
