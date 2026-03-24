use plonky2_field::types::{Field, PrimeField64};
use primitive_types::U256;
use tessera_client::{
    AccountAddress, PrivateIdentifier, StandardAccount, SubpoolId,
};
use tessera_utils::F;

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
    pub balance: Vec<u8>,
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

    AccountInsert {
        private_acc_address,
        eth_address,
        private_identifier: private_id_to_bytes(&acc.private_identifier).to_vec(),
        subpool_id: f_to_bytes(acc.subpool_id.0).to_vec(),
        balance: u256_to_bytes(acc.balance).to_vec(),
        nonce: f_to_bytes(acc.nonce.0).to_vec(),
        spend_auth,
        consume_auth,
        ast: serde_json::json!({}),
    }
}

// ── From DB bytes back to domain types (for future read routes) ───────────────

/// Reconstruct `SubpoolId` from 8 stored bytes.
pub fn bytes_to_subpool_id(b: &[u8; 8]) -> SubpoolId {
    SubpoolId(bytes_to_f(b))
}
