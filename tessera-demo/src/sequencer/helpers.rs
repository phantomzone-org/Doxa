use alloy::primitives::U256;
use tessera_server::contract::ITesseraRollupV2;

pub(crate) fn parse_hex_bytes32(s: &str) -> Result<[u8; 32], String> {
	let s = s.strip_prefix("0x").unwrap_or(s);
	let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
	if bytes.len() != 32 {
		return Err(format!("expected 32 bytes, got {}", bytes.len()));
	}
	let mut out = [0u8; 32];
	out.copy_from_slice(&bytes);
	Ok(out)
}

pub(crate) fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
	let s = s.strip_prefix("0x").unwrap_or(s);
	hex::decode(s).map_err(|e| format!("invalid hex: {e}"))
}

/// Generate a random fake Groth16 proof (accepted by AcceptAllVerifier).
pub(crate) fn random_proof() -> ITesseraRollupV2::Proof {
	use std::time::{SystemTime, UNIX_EPOCH};
	// Simple deterministic-ish seed from system time; not cryptographic, just unique per call.
	let seed = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_nanos();
	let rand_u256 = |i: u64| {
		let mut bytes = [0u8; 32];
		let v = seed
			.wrapping_mul(6364136223846793005)
			.wrapping_add(i as u128);
		bytes[..16].copy_from_slice(&v.to_le_bytes());
		bytes[16..].copy_from_slice(&v.wrapping_mul(1442695040888963407).to_le_bytes());
		U256::from_le_bytes(bytes)
	};
	ITesseraRollupV2::Proof {
		proof: std::array::from_fn(|i| rand_u256(i as u64)),
		commitments: std::array::from_fn(|i| rand_u256((i + 8) as u64)),
		commitmentPok: std::array::from_fn(|i| rand_u256((i + 10) as u64)),
	}
}
