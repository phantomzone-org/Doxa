use alloy::primitives::keccak256;

/// Deterministically pad a batch of real leaves up to `batch_size`.
///
/// Dummy leaves are derived as `field_safe_keccak256(leaf_index || current_root)`.
pub fn pad_leaves(
	current_root: &[u8; 32],
	batch_start_index: usize,
	batch_size: usize,
	real_leaves: &[[u8; 32]],
) -> anyhow::Result<Vec<[u8; 32]>> {
	anyhow::ensure!(
		real_leaves.len() <= batch_size,
		"real leaves exceed batch size: got {}, batch_size {}",
		real_leaves.len(),
		batch_size
	);
	anyhow::ensure!(batch_size > 0, "batch_size must be > 0");

	let mut out = Vec::with_capacity(batch_size);
	out.extend_from_slice(real_leaves);

	for i in out.len()..batch_size {
		let leaf_index = batch_start_index
			.checked_add(i)
			.ok_or_else(|| anyhow::anyhow!("leaf index overflow during dummy derivation"))?;
		out.push(derive_dummy_leaf(leaf_index, current_root));
	}
	Ok(out)
}

/// Derive a single deterministic dummy leaf.
///
/// ```text
/// dummy_leaf = field_safe_keccak256(leaf_index || current_root)
/// ```
///
/// - `leaf_index`: absolute index in the tree, encoded as `uint256` big-endian (32 bytes).
/// - `current_root`: the tree's root hash at batch-assembly time, encoded as `bytes32` (32 bytes).
/// - The result has the MSB of each 8-byte limb cleared so every limb is a valid Goldilocks field
///   element (< 2^63 < p).
pub fn derive_dummy_leaf(leaf_index: usize, current_root: &[u8; 32]) -> [u8; 32] {
	let mut preimage = [0u8; 64];
	// leaf_index as uint256 big-endian (high 24 bytes zero, low 8 = u64 BE).
	preimage[24..32].copy_from_slice(&(leaf_index as u64).to_be_bytes());
	preimage[32..64].copy_from_slice(current_root);
	field_safe_digest(keccak256(preimage).0)
}

/// Clear the most-significant bit of each 8-byte limb in a 32-byte digest.
///
/// A Goldilocks field element fits in 64 bits with a maximum of
/// `2^64 - 2^32` (the prime is `2^64 - 2^32 + 1`).  Clearing bit 63 of
/// each limb guarantees the result is strictly less than `2^63` < Goldilocks
/// prime, making it unconditionally valid without a modular reduction.
fn field_safe_digest(mut digest: [u8; 32]) -> [u8; 32] {
	for i in 0..4 {
		digest[i * 8] &= 0x7f;
	}
	digest
}

#[cfg(test)]
mod tests {
	use super::derive_dummy_leaf;

	#[test]
	fn dummy_leaf_is_field_safe() {
		let root = [0xABu8; 32];
		for idx in [0usize, 1, 7, 255, 1024] {
			let leaf = derive_dummy_leaf(idx, &root);
			// Each 64-bit limb has the top bit cleared.
			assert_eq!(leaf[0] & 0x80, 0, "limb 0 MSB set for idx {idx}");
			assert_eq!(leaf[8] & 0x80, 0, "limb 1 MSB set for idx {idx}");
			assert_eq!(leaf[16] & 0x80, 0, "limb 2 MSB set for idx {idx}");
			assert_eq!(leaf[24] & 0x80, 0, "limb 3 MSB set for idx {idx}");
		}
	}

	#[test]
	fn different_indices_produce_different_leaves() {
		let root = [0x42u8; 32];
		let a = derive_dummy_leaf(0, &root);
		let b = derive_dummy_leaf(1, &root);
		assert_ne!(a, b);
	}

	#[test]
	fn different_roots_produce_different_leaves() {
		let root_a = [0x01u8; 32];
		let root_b = [0x02u8; 32];
		let a = derive_dummy_leaf(0, &root_a);
		let b = derive_dummy_leaf(0, &root_b);
		assert_ne!(a, b);
	}
}
