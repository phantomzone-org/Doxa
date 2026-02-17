use alloy::{primitives::B256, sol};
use plonky2::field::types::Field;
use tessera_trees::{tree::hasher::Hash, F};

sol! {
	#[sol(rpc)]
	interface IDepositsRollupBridge {
		// Keep this aligned with `DepositsRollupBridge.DepositStatus` in Solidity.
		enum DepositStatus { None, Pending, Validated, Withdrawn }

		// Keep this aligned with `DepositsRollupBridge.TreeType` in Solidity.
		// Do NOT reorder variants — values are stable across ABI versions.
		enum TreeType { NotesCommitment, NotesNullifier, AccountsCommitment, AccountsNullifier }

		struct Proof {
			uint256[8] proof;
			uint256[2] commitments;
			uint256[2] commitmentPok;
		}

		struct Deposit {
			uint256 value;
			address recipient;
			DepositStatus status;
		}

		function notesNullifierRoot() external view returns (bytes32);
		function notesCommitmentRoot() external view returns (bytes32);
		function accountsNullifierRoot() external view returns (bytes32);
		function accountsCommitmentRoot() external view returns (bytes32);
		function batchSize() external view returns (uint256);
		function getDeposit(bytes32 noteCommitment) external view returns (Deposit memory);
		function getDepositStatus(bytes32 noteCommitment) external view returns (DepositStatus);
		function recordNotesNullifierTreeUpdate(
			bytes32 newRoot,
			bytes32[] calldata noteCommitments,
			Proof calldata proof,
			Proof calldata aggregatedInputProof
		) external;
		function recordNotesCommitmentTreeUpdate(
			bytes32 newRoot,
			bytes32[] calldata noteCommitments,
			Proof calldata proof,
			Proof calldata aggregatedInputProof
		) external;
		function recordAccountsCommitmentTreeUpdate(
			bytes32 newRoot,
			bytes32[] calldata accountCommitments,
			Proof calldata proof,
			Proof calldata aggregatedInputProof
		) external;
		function recordAccountsNullifierTreeUpdate(
			bytes32 newRoot,
			bytes32[] calldata accountCommitments,
			Proof calldata proof,
			Proof calldata aggregatedInputProof
		) external;

		event DepositAvailable(
			bytes32 indexed noteCommitment,
			uint256 value,
			address recipient
		);

		/// `treeType` is indexed so indexers can filter by tree without decoding calldata.
		event ValidatedBatchFinalized(
			TreeType indexed treeType,
			uint256 batchSize,
			bytes32 oldRoot,
			bytes32 newRoot
		);

		event DepositValidated(
			bytes32 indexed noteCommitment
		);
	}
}

/// Convert a `Hash` (4 Goldilocks field elements) to `bytes32`.
///
/// Encoding: each element as 8-byte big-endian uint64, concatenated.
/// Matches the convention in `groth16_wrapper.rs` and `DepositsRollupBridge.sol`.
pub fn hash_to_bytes32(h: &Hash) -> B256 {
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
pub fn bytes32_to_hash(b: &B256) -> anyhow::Result<Hash> {
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
	Ok(Hash(elems))
}

/// Convert a slice of raw 32-byte commitments to validated Goldilocks `Hash`
/// values, failing immediately if any limb is out of range.
///
/// This is the preferred helper for the many `.map(bytes32_to_hash).collect()`
/// patterns in the sequencer so that error propagation is uniform.
pub fn bytes_slice_to_hashes(raw: &[[u8; 32]]) -> anyhow::Result<Vec<Hash>> {
	raw.iter()
		.map(|b| bytes32_to_hash(&B256::from(*b)))
		.collect()
}
