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

pub(crate) fn zero_proof() -> ITesseraRollupV2::Proof {
	ITesseraRollupV2::Proof {
		proof: [U256::ZERO; 8],
		commitments: [U256::ZERO; 2],
		commitmentPok: [U256::ZERO; 2],
	}
}
