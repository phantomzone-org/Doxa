use alloy::{primitives::B256, sol};
use plonky2::field::types::Field;
use doxa_utils::{hasher::HashOutput, F};

/// Convert a `HashOutput` (4 Goldilocks field elements) to `bytes32`.
///
/// Encoding: each element as 8-byte big-endian uint64, concatenated.
pub fn hash_to_bytes32(h: &HashOutput) -> B256 {
	let mut bytes = [0u8; 32];
	for i in 0..4 {
		bytes[i * 8..(i + 1) * 8].copy_from_slice(&h.0[i].0.to_be_bytes());
	}
	B256::from(bytes)
}

/// The Goldilocks prime: 2^64 - 2^32 + 1.
pub const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

/// Convert a `bytes32` (from on-chain commitment) to a `Hash`.
///
/// Inverse of `hash_to_bytes32`. Each 8-byte big-endian chunk becomes a
/// Goldilocks field element.
///
/// # Errors
/// Returns `Err` if any of the four 64-bit limbs is ≥ `GOLDILOCKS_PRIME`
/// (2^64 - 2^32 + 1). Such values are outside the Goldilocks field and would
/// silently produce an incorrect element if passed to
/// `F::from_canonical_u64`, breaking root derivation and proof verification.
pub fn bytes32_to_hash(b: &B256) -> anyhow::Result<HashOutput> {
	let bytes = b.as_slice();
	let mut elems = [F::ZERO; 4];
	for i in 0..4 {
		let val = u64::from_be_bytes(
			bytes[i * 8..(i + 1) * 8]
				.try_into()
				.expect("slice is always 8 bytes"),
		);
		anyhow::ensure!(
			val < GOLDILOCKS_PRIME,
			"bytes32 limb {} out of Goldilocks field range: {:#018x} >= {:#018x}",
			i,
			val,
			GOLDILOCKS_PRIME
		);
		elems[i] = F::from_canonical_u64(val);
	}
	Ok(HashOutput(elems))
}

/// Convert a slice of raw 32-byte commitments to validated Goldilocks `Hash`
/// values, failing immediately if any limb is out of range.
///
/// This is the preferred helper for the many `.map(bytes32_to_hash).collect()`
/// patterns in the sequencer so that error propagation is uniform.
pub fn bytes_slice_to_hashes(raw: &[[u8; 32]]) -> anyhow::Result<Vec<HashOutput>> {
	raw.iter()
		.map(|b| bytes32_to_hash(&B256::from(*b)))
		.collect()
}

// ---------------------------------------------------------------------------
// V2 helpers — Goldilocks LE-packed uint256 encoding
// ---------------------------------------------------------------------------

/// Pack a `HashOutput` into an EVM `uint256` using little-endian Goldilocks limb order.
///
/// Layout: `e0 | (e1 << 64) | (e2 << 128) | (e3 << 192)` — little-endian limbs.
/// Matches `PoseidonGoldilocks.compress` input/output convention in `DoxaContract`.
pub fn hash_to_u256_le(h: &HashOutput) -> alloy::primitives::U256 {
	alloy::primitives::U256::from_limbs([h.0[0].0, h.0[1].0, h.0[2].0, h.0[3].0])
}

/// Convert a big-endian `[u8; 32]` hash (4 × u64 BE) to a LE-packed `uint256`.
///
/// Inverse of `hash_to_bytes32` composed with `hash_to_u256_le`: interprets each
/// 8-byte chunk as a big-endian u64, then packs them LE into a `uint256`.
pub fn bytes32_be_to_u256_le(b: &[u8; 32]) -> alloy::primitives::U256 {
	alloy::primitives::U256::from_limbs([
		u64::from_be_bytes(b[0..8].try_into().unwrap()),
		u64::from_be_bytes(b[8..16].try_into().unwrap()),
		u64::from_be_bytes(b[16..24].try_into().unwrap()),
		u64::from_be_bytes(b[24..32].try_into().unwrap()),
	])
}

/// Convert a LE-packed `uint256` back to a `HashOutput`.
///
/// # Errors
/// Returns `Err` if any 64-bit limb is ≥ `GOLDILOCKS_PRIME`.
pub fn u256_le_to_hash(v: alloy::primitives::U256) -> anyhow::Result<HashOutput> {
	let limbs = v.into_limbs();
	let mut elems = [F::ZERO; 4];
	for (i, &l) in limbs.iter().enumerate() {
		anyhow::ensure!(
			l < GOLDILOCKS_PRIME,
			"U256 limb {i} out of Goldilocks range: {l:#018x}"
		);
		elems[i] = F::from_canonical_u64(l);
	}
	Ok(HashOutput(elems))
}

/// Convert a `HashOutput` to the 32-byte GL-preimage format used by the contract's
/// Keccak piCommitment computation.
///
/// Encoding per field element `f` (canonical u64):
///   `[lo_u32_BE(4B), hi_u32_BE(4B)]`
/// where `lo = f & 0xFFFF_FFFF`, `hi = f >> 32`.
///
/// This is the inverse of `_glHashToU256` in `DoxaContract.sol`.
pub fn hash_to_preimage_bytes32(h: &HashOutput) -> B256 {
	let mut out = [0u8; 32];
	for (i, &f) in h.0.iter().enumerate() {
		let v: u64 = f.0; // GoldilocksField inner u64 (canonical value)
		let lo = (v & 0xFFFF_FFFF) as u32;
		let hi = (v >> 32) as u32;
		out[i * 8..i * 8 + 4].copy_from_slice(&lo.to_be_bytes());
		out[i * 8 + 4..i * 8 + 8].copy_from_slice(&hi.to_be_bytes());
	}
	B256::from(out)
}

/// Convert a raw `[u8; 32]` leaf (4 × u64 big-endian, as written by `hash_to_bytes32`)
/// to the GL-preimage bytes32 format expected by the contract structs.
///
/// `hash_to_bytes32` layout: `[hi_BE4][lo_BE4]` per field element.
/// GL-preimage layout:        `[lo_BE4][hi_BE4]` per field element.
/// → swap the two 4-byte halves for each of the 4 elements.
///
/// Note: this function is its own inverse (the swap is symmetric), so applying
/// it twice restores the original bytes.  Use `preimage_bytes32_to_raw` when
/// you want the inverse direction for clarity.
pub fn raw_to_preimage_bytes32(raw: &[u8; 32]) -> B256 {
	let mut out = [0u8; 32];
	for i in 0..4 {
		out[i * 8..i * 8 + 4].copy_from_slice(&raw[i * 8 + 4..i * 8 + 8]); // lo
		out[i * 8 + 4..i * 8 + 8].copy_from_slice(&raw[i * 8..i * 8 + 4]); // hi
	}
	B256::from(out)
}

/// Convert a GL-preimage-encoded `B256` (as stored in contract batch structs) back to
/// the raw `[u8; 32]` format used by the state service and prover (`hash_to_bytes32`).
///
/// The swap is symmetric, so this is identical to `raw_to_preimage_bytes32` in
/// implementation — it just exists for naming clarity at call sites.
pub fn preimage_bytes32_to_raw(b: &B256) -> [u8; 32] {
	raw_to_preimage_bytes32(&b.0).0
}

// ---------------------------------------------------------------------------
// V2 Alloy bindings — DoxaContract
// ---------------------------------------------------------------------------

sol! {
	#[sol(rpc)]
	interface IDoxaRollupV2 {
		enum DepositStatus { None, Pending, Validated, Withdrawn }

		struct Deposit {
			uint256 value;
			address recipient;
			DepositStatus status;
		}

		struct Proof {
			uint256[8] proof;
			uint256[2] commitments;
			uint256[2] commitmentPok;
		}

		function submitTransactionBatch(bytes calldata batchPreimage) external;
		function proveTransactionBatch(bytes calldata batchPreimage, Proof calldata proof) external;
		function submitBridgeTxBatch(bytes calldata batchPreimage) external;
		function proveBridgeTxBatch(bytes calldata batchPreimage, Proof calldata proof) external;
		function depositAndRegister(bytes32 noteCommitment, uint256 maxAmount) external;
		function withdrawPendingDeposit(bytes32 noteCommitment) external;
		function currentRoot() external view returns (uint256);
		function confirmedRoots(uint256 root) external view returns (bool);
		function poolConfigRoot() external view returns (uint256);
		function nullifiers(uint256 nullifier) external view returns (bool);
		function leaves(uint256 index) external view returns (uint256);
		function validatedBatchRoots(uint256 batchRoot) external view returns (bool);
		function leafCount() external view returns (uint256);
		function zeros(uint256 level) external view returns (uint256);
		function treeDepth() external view returns (uint256);
		function verifyBatchLeaf(uint256 batchRoot, uint256 leaf, uint256 leafIndex, uint256[] calldata siblings) external view returns (bool);
		function getDeposit(bytes32 noteCommitment) external view returns (Deposit memory);
		function keccakToPublicInputs(bytes32 piCommitment) external pure returns (uint256[8] memory);
		function operator() external view returns (address);
		function paused() external view returns (bool);
		function setOperator(address newOperator) external;
		function setPaused(bool _paused) external;
		function setPoolConfigRoot(uint256 newRoot) external;

		event TransactionBatchSubmitted(bytes32 indexed piCommitment, bytes32 batchPoseidonRoot);
		event TransactionBatchProven(bytes32 indexed piCommitment, uint256 newTreeRoot, uint256 leafIndex);
		event BridgeTxBatchSubmitted(bytes32 indexed piCommitment, bytes32 batchPoseidonRoot);
		event BridgeTxBatchProven(bytes32 indexed piCommitment, uint256 newTreeRoot, uint256 leafIndex);
		event DepositAvailable(bytes32 indexed noteCommitment, uint256 value, address recipient);
		event DepositValidated(bytes32 indexed noteCommitment);
	}
}
