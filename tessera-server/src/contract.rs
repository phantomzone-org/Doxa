use alloy::{primitives::B256, sol};
use plonky2::field::types::Field;
use tessera_trees::{tree::hasher::Hash, F};

sol! {
	#[sol(rpc)]
	interface IDepositsRollupBridge {
		enum DepositStatus { Available, Withdrawn, Consumed }

		struct Proof {
			uint256[8] proof;
			uint256[2] commitments;
			uint256[2] commitmentPok;
		}

		struct Deposit {
			bytes32 commitment;
			uint256 value;
			address depositor;
			address recipient;
			DepositStatus status;
		}

			function consumedRoot() external view returns (bytes32);
			function consumeBatchSize() external view returns (uint256);
			function nextDepositId() external view returns (uint256);
			function getDeposit(uint256 depositId) external view returns (Deposit memory);
			function consumeRequested(bytes32 commitment) external view returns (bool);

		function requestConsume(bytes32 commitment) external;
		function finalizeConsumeBatch(
			bytes32 newConsumedRoot,
			bytes32[] calldata commitments,
			Proof calldata proof
		) external;

		event DepositAvailable(
			uint256 indexed depositId,
			bytes32 commitment,
			address depositor,
			uint256 value,
			address recipient
		);

		event ConsumeRequested(
			bytes32 indexed commitment,
			uint256 indexed depositId,
			address indexed requester
		);

		event ConsumeBatchFinalized(
			uint256 batchSize,
			bytes32 oldRoot,
			bytes32 newRoot
		);

		event DepositConsumed(
			uint256 indexed depositId,
			bytes32 indexed commitment
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
