use anyhow::Result;
use plonky2::{iop::target::Target, plonk::circuit_builder::CircuitBuilder};
use tessera_utils::{D, F, plonky2_gadgets::keccak256::field_decompose::decompose_field_to_u32_pair};

use crate::types::SolidityProof;

/// Parse the Groth16 solidity JSON (produced by `Groth16Wrapper::proof_to_solidity_json`)
/// into a [`SolidityProof`].
pub(crate) fn parse_solidity_proof_json(json: &str) -> Result<SolidityProof> {
	let v: serde_json::Value = serde_json::from_str(json)?;

	let parse_u256_array = |key: &str, len: usize| -> Result<Vec<alloy::primitives::U256>> {
		let arr = v[key]
			.as_array()
			.ok_or_else(|| anyhow::anyhow!("missing {key}"))?;
		arr.iter()
			.take(len)
			.map(|s| {
				let hex_str = s
					.as_str()
					.ok_or_else(|| anyhow::anyhow!("expected string in {key}"))?;
				let hex_str = hex_str.trim_start_matches("0x");
				Ok(alloy::primitives::U256::from_str_radix(hex_str, 16)?)
			})
			.collect()
	};

	let proof_vec = parse_u256_array("proof", 8)?;
	let comm_vec = parse_u256_array("commitments", 2)?;
	let pok_vec = parse_u256_array("commitmentPok", 2)?;

	Ok(SolidityProof {
		proof: proof_vec
			.try_into()
			.map_err(|_| anyhow::anyhow!("proof: expected 8 elements"))?,
		commitments: comm_vec
			.try_into()
			.map_err(|_| anyhow::anyhow!("commitments: expected 2 elements"))?,
		commitment_pok: pok_vec
			.try_into()
			.map_err(|_| anyhow::anyhow!("commitmentPok: expected 2 elements"))?,
	})
}


// ---------------------------------------------------------------------------
// Shared circuit helpers
// ---------------------------------------------------------------------------

/// Encode one Goldilocks field target as `[lo_u32, hi_u32]`, matching
/// `BatchHelper::push_fields` encoding.
pub(crate) fn field_to_u32_pair(
	builder: &mut CircuitBuilder<F, D>,
	f: Target,
	lut: usize,
) -> [Target; 2] {
	let [hi, lo] = decompose_field_to_u32_pair(builder, f, lut);
	[lo.0, hi.0]
}

/// Encode a slice of Goldilocks field targets as flat `[lo, hi, lo, hi, …]` u32 words.
pub(crate) fn fields_to_u32_words(
	builder: &mut CircuitBuilder<F, D>,
	fields: &[Target],
	lut: usize,
) -> Vec<Target> {
	fields
		.iter()
		.flat_map(|&f| field_to_u32_pair(builder, f, lut))
		.collect()
}