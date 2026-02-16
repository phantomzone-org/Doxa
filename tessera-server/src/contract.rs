use alloy::{primitives::B256, sol};
use plonky2::field::types::Field;
use tessera_trees::{tree::hasher::Hash, F};

sol! {
	#[sol(rpc)]
	interface IDepositsRollupBridge {
		// Keep this aligned with `DepositsRollupBridge.DepositStatus` in Solidity.
		enum DepositStatus { Pending, Validated, Withdrawn }

		struct Proof {
			uint256[8] proof;
			uint256[2] commitments;
			uint256[2] commitmentPok;
		}

		struct AggregatedInputProof {
			bytes proofData;
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
			Proof calldata proof
		) external;
		function recordAccountsCommitmentTreeUpdate(
			bytes32 newRoot,
			bytes32[] calldata accountCommitments,
			Proof calldata proof
		) external;
		function recordAccountsNullifierTreeUpdate(
			bytes32 newRoot,
			bytes32[] calldata accountCommitments,
			Proof calldata proof
		) external;
		function validateDepositBatch(
			bytes32 newNotesCommitmentRoot,
			bytes32[] calldata noteCommitments,
			Proof calldata proof,
			AggregatedInputProof calldata aggregatedInputProof
		) external;

		function loadValidateDepositBatch(
			bytes32 newNotesCommitmentRoot,
			bytes32[] calldata noteCommitments,
			Proof calldata proof,
			AggregatedInputProof calldata aggregatedInputProof
		) external returns (bytes32);

		function executeValidateDepositBatch(
			bytes32 newNotesCommitmentRoot,
			bytes32[] calldata noteCommitments
		) external returns (bytes32);

		function cancelLoadedValidateDepositBatch(
			bytes32 oldNotesCommitmentRoot,
			bytes32 newNotesCommitmentRoot,
			bytes32[] calldata noteCommitments
		) external returns (bytes32);

		event DepositAvailable(
			bytes32 indexed noteCommitment,
			uint256 value,
			address recipient
		);

		event ValidatedBatchFinalized(
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

/// Convert a `bytes32` (from on-chain commitment) to a `Hash`.
///
/// Inverse of `hash_to_bytes32`. Each 8-byte big-endian chunk becomes a
/// Goldilocks field element. The commitment's MSB-cleared encoding ensures
/// each element fits in the Goldilocks field.
pub fn bytes32_to_hash(b: &B256) -> Hash {
	let bytes = b.as_slice();
	let mut elems = [F::ZERO; 4];
	for i in 0..4 {
		let val = u64::from_be_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
		elems[i] = F::from_canonical_u64(val);
	}
	Hash(elems)
}
