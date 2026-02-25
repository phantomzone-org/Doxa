use alloy::primitives::{keccak256, B256};

/// Tree discriminator used in dummy-leaf derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DummyTreeType {
	NotesCommitment    = 0,
	NotesNullifier     = 1,
	AccountsCommitment = 2,
	AccountsNullifier  = 3,
}

/// Deterministically pad a batch of real leaves up to `batch_size`.
///
/// Dummy leaves are derived as:
/// `H(leaf_index || H(public_value))`,
/// where:
/// `H(public_value) = H(tree_type || batch_start_index || packed_real_leaves)`.
pub fn pad_leaves(
	tree_type: DummyTreeType,
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

	if out.len() == batch_size {
		return Ok(out);
	}

	let public_value_hash = public_value_hash(tree_type, batch_start_index, real_leaves)?;
	for i in out.len()..batch_size {
		let leaf_index = batch_start_index
			.checked_add(i)
			.ok_or_else(|| anyhow::anyhow!("leaf index overflow during dummy derivation"))?;
		out.push(derive_dummy_leaf(leaf_index, public_value_hash));
	}
	Ok(out)
}

/// Compute the per-batch public-value hash that seeds all dummy leaves.
///
/// `H(tree_type_byte || batch_start_index_be32 || real_leaf_0 || … || real_leaf_n)`
///
/// Including all real leaves in the hash ensures the dummy values are
/// unpredictable without knowing the batch contents, preventing front-running
/// on padding positions.
///
/// # Errors
/// Returns `Err` if `batch_start_index` overflows `u64`.
fn public_value_hash(
	tree_type: DummyTreeType,
	batch_start_index: usize,
	real_leaves: &[[u8; 32]],
) -> anyhow::Result<B256> {
	let mut preimage = Vec::with_capacity(1 + 32 + real_leaves.len() * 32);
	preimage.push(tree_type as u8);
	preimage.extend_from_slice(&u256_be_from_usize(batch_start_index)?);
	for leaf in real_leaves {
		preimage.extend_from_slice(leaf);
	}
	Ok(keccak256(preimage))
}

/// Derive a single dummy leaf for position `leaf_index`.
///
/// `field_safe_digest(keccak256(leaf_index_be32 || public_value_hash))`
///
/// The `field_safe_digest` step clears the MSB of each 64-bit limb so the
/// result is a valid Goldilocks field element in every 8-byte chunk.
fn derive_dummy_leaf(leaf_index: usize, public_value_hash: B256) -> [u8; 32] {
	let mut preimage = Vec::with_capacity(64);
	preimage.extend_from_slice(&u256_be_from_usize_infallible(leaf_index));
	preimage.extend_from_slice(public_value_hash.as_slice());
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
		let limb_start = i * 8;
		digest[limb_start] &= 0x7f;
	}
	digest
}

/// Encode `value` as a 32-byte big-endian uint256, returning `Err` if it
/// exceeds `u64::MAX` (current deployments never exceed this range).
fn u256_be_from_usize(value: usize) -> anyhow::Result<[u8; 32]> {
	// Current deployments fit in u64; encode as uint256 big-endian for ABI parity.
	let value_u64 = u64::try_from(value)
		.map_err(|_| anyhow::anyhow!("value too large for uint64-backed encoding: {value}"))?;
	Ok(u256_be_from_usize_infallible(value_u64 as usize))
}

/// Encode `value` as a 32-byte big-endian uint256 (infallible; truncates to u64).
///
/// The high 24 bytes are zeroed; bytes 24–31 contain the big-endian u64
/// encoding.  Callers that can statically guarantee the value fits in u64
/// may use this variant to avoid an `anyhow::Result`.
fn u256_be_from_usize_infallible(value: usize) -> [u8; 32] {
	let mut out = [0u8; 32];
	let be = (value as u64).to_be_bytes();
	out[24..].copy_from_slice(&be);
	out
}

#[cfg(test)]
mod tests {
	use super::{pad_leaves, DummyTreeType};

	#[test]
	fn pad_keeps_full_batch_unchanged() {
		let leaves = vec![[7u8; 32], [9u8; 32]];
		let padded = pad_leaves(DummyTreeType::NotesCommitment, 0, 2, &leaves).unwrap();
		assert_eq!(padded, leaves);
	}

	#[test]
	fn pad_appends_field_safe_dummies() {
		let leaves = vec![[1u8; 32]];
		let padded = pad_leaves(DummyTreeType::AccountsNullifier, 11, 4, &leaves).unwrap();
		assert_eq!(padded.len(), 4);
		assert_eq!(padded[0], [1u8; 32]);
		for dummy in &padded[1..] {
			// Each 64-bit limb has the top bit cleared.
			assert_eq!(dummy[0] & 0x80, 0);
			assert_eq!(dummy[8] & 0x80, 0);
			assert_eq!(dummy[16] & 0x80, 0);
			assert_eq!(dummy[24] & 0x80, 0);
		}
	}
}
