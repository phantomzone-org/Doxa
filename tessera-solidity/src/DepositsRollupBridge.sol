// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Interface matching the gnark-generated Groth16 verifier.
///         The verifier **reverts** on invalid proofs (no bool return).
interface IGroth16Verifier {
    function verifyProof(
        uint256[8] calldata proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok,
        uint256[8] calldata input
    ) external view;
}

/// @title  DepositsRollupBridge
/// @notice Centralized zk-rollup batch finalizer.  Batches are submitted in
///         one transaction, then finalized with a Groth16 proof in a second.
///
/// @dev    Root encoding
///         A Merkle root is four Goldilocks field elements (each ≤ 2^64 − 2^32 + 1).
///         On-chain they are packed into a single `bytes32`:
///           bytes[0..8]   = f[0] big-endian uint64
///           bytes[8..16]  = f[1] big-endian uint64
///           bytes[16..24] = f[2] big-endian uint64
///           bytes[24..32] = f[3] big-endian uint64
///
/// @dev    SHA-256 commitment (matches the circuit)
///         The plonky2 circuit commits its public data via SHA-256:
///           SHA256(root_old ‖ root_new ‖ leaf_0 ‖ … ‖ leaf_{N−1})
///         where each element is a Goldilocks field element encoded as an
///         8-byte big-endian uint64.  The resulting 256-bit digest is split
///         into 8 big-endian uint32 words, which become the Groth16 public
///         inputs (each zero-extended to uint256).
///
/// @dev    Domain separation
///         The Merkle tree uses Poseidon for `hash_2_to_1`, which is not
///         available as an EVM precompile.  The contract therefore accepts
///         both raw deposits (for data availability) and pre-hashed leaves
///         (for the SHA-256 commitment).
///
///         The storage key (`commit`) is domain-separated via an outer
///         keccak256 wrapper:
///           sha256Commit = sha256(oldRoot ‖ newRoot ‖ leaves)
///           commit       = keccak256(chainid, address(this), PROTOCOL_VERSION, sha256Commit)
///         This prevents cross-chain and cross-contract replay.
contract DepositsRollupBridge {
    // ----------------------------------------------------------------
    // Types
    // ----------------------------------------------------------------

    /// @dev Mirrors tessera-server's PendingDeposit.
    struct Deposit {
        bytes32 noteCommitment; // Hash = [F;4] packed as 4×8-byte big-endian
        uint64  addr0;          // address[0] as Goldilocks element
        uint64  addr1;          // address[1]
        uint64  addr2;          // address[2]
        uint64  amount;         // amount as Goldilocks element
    }

    /// @dev Batch lifecycle status.
    enum BatchStatus { None, Pending, Validated }

    /// @dev Single struct for both pending and validated pools.
    ///      Using a status discriminator avoids the cost of copying a
    ///      Deposit[] array between two separate mappings.
    struct Batch {
        bytes32     oldRoot;
        bytes32     newRoot;
        bytes32     sha256Commit;   // circuit-matching SHA-256 commitment
        uint64      blockNumber;    // block when submitted (Pending) or finalized (Validated)
        BatchStatus status;
        Deposit[]   deposits;       // mirrors PendingDepositsBatch.deposits
    }

    /// @dev Matches the gnark verifier's calldata layout.
    struct Proof {
        uint256[8] proof;          // Groth16 A (2), B (4), C (2) in EIP-197 format
        uint256[2] commitments;    // Pedersen commitment G1 point
        uint256[2] commitmentPok;  // Proof of knowledge for the Pedersen commitment
    }

    // ----------------------------------------------------------------
    // Constants
    // ----------------------------------------------------------------

    /// @notice Number of leaves (deposits) per batch.
    uint256 public constant BATCH_SIZE = 128;

    /// @notice Number of Goldilocks field elements per hash (root / leaf).
    uint256 public constant HASH_SIZE = 4;

    /// @notice Byte width of a single Goldilocks field element (big-endian uint64).
    uint256 public constant FIELD_ELEMENT_BYTES = 8;

    /// @notice Expected byte length of the `leaves` parameter.
    ///         BATCH_SIZE * HASH_SIZE * FIELD_ELEMENT_BYTES = 128 * 4 * 8 = 4096
    uint256 public constant LEAVES_BYTE_LEN = BATCH_SIZE * HASH_SIZE * FIELD_ELEMENT_BYTES;

    /// @notice Protocol version for domain separation.
    uint8 public constant PROTOCOL_VERSION = 1;

    // ----------------------------------------------------------------
    // Config / State
    // ----------------------------------------------------------------

    /// @notice Address of the gnark-generated Groth16 verifier contract.
    IGroth16Verifier public immutable verifier;

    /// @notice Centralized operator (sequencer).
    address public operator;

    /// @notice Current committed Merkle root.
    bytes32 public stateRoot;

    /// @notice Monotonic batch counter.
    uint256 public batchNumber;

    /// @notice Emergency pause switch.
    bool public paused;

    /// @notice Single mapping for both pending and validated batches.
    ///         Key is the domain-separated commit.
    mapping(bytes32 => Batch) internal _batches;

    // ----------------------------------------------------------------
    // Events
    // ----------------------------------------------------------------

    event OperatorChanged(address indexed oldOp, address indexed newOp);
    event PausedChanged(bool isPaused);
    event BatchSubmitted(
        bytes32 indexed commit,
        bytes32 sha256Commit,
        bytes32 oldRoot,
        bytes32 newRoot,
        Deposit[] deposits,
        bytes leaves
    );
    event BatchFinalized(
        bytes32 indexed commit,
        bytes32 oldRoot,
        bytes32 newRoot,
        uint256 batchNumber
    );
    event BatchCancelled(bytes32 indexed commit);

    // ----------------------------------------------------------------
    // Errors
    // ----------------------------------------------------------------

    error NotOperator();
    error PausedErr();
    error InvalidDepositsLength();
    error InvalidLeavesLength();
    error BatchAlreadyExists(bytes32 commit);
    error BatchNotPending(bytes32 commit);
    error StaleRoot(bytes32 current, bytes32 expected);
    error InvalidProof();

    // ----------------------------------------------------------------
    // Constructor / Admin
    // ----------------------------------------------------------------

    constructor(
        address _verifier,
        address _operator,
        bytes32 _genesisRoot
    ) {
        verifier = IGroth16Verifier(_verifier);
        operator = _operator;
        stateRoot = _genesisRoot;
    }

    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert PausedErr();
        _;
    }

    /// @notice Transfer the operator role to a new address.
    function setOperator(address newOperator) external onlyOperator {
        emit OperatorChanged(operator, newOperator);
        operator = newOperator;
    }

    /// @notice Toggle the pause switch.
    function setPaused(bool _paused) external onlyOperator {
        paused = _paused;
        emit PausedChanged(_paused);
    }

    // ----------------------------------------------------------------
    // Batch submission
    // ----------------------------------------------------------------

    /// @notice Submit a batch of pending deposits.
    ///
    /// @param newRoot   Proposed next Merkle root.
    /// @param deposits  Raw deposit data (for data availability).
    /// @param leaves    Pre-hashed leaves (Poseidon hashes, 4096 bytes).
    ///                  Used for the SHA-256 commitment that the circuit proves.
    /// @return commit   Domain-separated commitment key.
    function submitBatch(
        bytes32 newRoot,
        Deposit[] calldata deposits,
        bytes calldata leaves
    )
        external
        onlyOperator
        whenNotPaused
        returns (bytes32 commit)
    {
        // 1. Validate inputs.
        if (deposits.length != BATCH_SIZE) revert InvalidDepositsLength();
        if (leaves.length != LEAVES_BYTE_LEN) revert InvalidLeavesLength();

        bytes32 oldRoot = stateRoot;

        // 2. Compute the SHA-256 commitment matching the circuit.
        bytes32 sha256Commit = sha256(abi.encodePacked(oldRoot, newRoot, leaves));

        // 3. Compute domain-separated storage key.
        commit = computeDomainCommitment(sha256Commit);

        // 4. Reject if a batch with this commit already exists.
        if (_batches[commit].status != BatchStatus.None) {
            revert BatchAlreadyExists(commit);
        }

        // 5. Store batch metadata.
        Batch storage b = _batches[commit];
        b.oldRoot = oldRoot;
        b.newRoot = newRoot;
        b.sha256Commit = sha256Commit;
        b.blockNumber = uint64(block.number);
        b.status = BatchStatus.Pending;

        // 6. Copy deposits to storage.
        for (uint256 i = 0; i < BATCH_SIZE; i++) {
            b.deposits.push(deposits[i]);
        }

        // 7. Emit full data for indexers / data availability.
        emit BatchSubmitted(commit, sha256Commit, oldRoot, newRoot, deposits, leaves);
    }

    // ----------------------------------------------------------------
    // Batch finalization
    // ----------------------------------------------------------------

    /// @notice Finalize a pending batch by verifying its Groth16 proof.
    ///
    /// @param commit  Domain-separated commitment key (from submitBatch).
    /// @param proof   Groth16 proof with Pedersen commitments.
    function finalizeBatch(
        bytes32 commit,
        Proof calldata proof
    )
        external
        onlyOperator
        whenNotPaused
    {
        Batch storage b = _batches[commit];

        // 1. Must be a pending batch.
        if (b.status != BatchStatus.Pending) revert BatchNotPending(commit);

        // 2. Stale root check.
        if (b.oldRoot != stateRoot) revert StaleRoot(stateRoot, b.oldRoot);

        // 3. Derive public inputs from the stored SHA-256 commitment.
        uint256[8] memory pubInputs = sha256ToPublicInputs(b.sha256Commit);

        // 4. Verify the Groth16 proof.
        try verifier.verifyProof(
            proof.proof,
            proof.commitments,
            proof.commitmentPok,
            pubInputs
        ) {
            // valid
        } catch {
            revert InvalidProof();
        }

        // 5. Transition: Pending → Validated.
        b.status = BatchStatus.Validated;
        b.blockNumber = uint64(block.number);

        // 6. Advance state.
        bytes32 oldRoot = b.oldRoot;
        bytes32 newRoot = b.newRoot;
        stateRoot = newRoot;
        uint256 currentBatch = batchNumber;
        batchNumber = currentBatch + 1;

        emit BatchFinalized(commit, oldRoot, newRoot, currentBatch);
    }

    // ----------------------------------------------------------------
    // Batch cancellation
    // ----------------------------------------------------------------

    /// @notice Cancel a pending batch (e.g. stale after another batch was
    ///         finalized, changing the stateRoot).
    function cancelPendingBatch(bytes32 commit) external onlyOperator {
        if (_batches[commit].status != BatchStatus.Pending) {
            revert BatchNotPending(commit);
        }
        delete _batches[commit];
        emit BatchCancelled(commit);
    }

    // ----------------------------------------------------------------
    // Public input mapping
    // ----------------------------------------------------------------

    /// @notice Splits a SHA-256 digest into the 8 uint32 words expected by
    ///         the Groth16 verifier as public inputs.
    ///
    ///         Word order is big-endian:
    ///           inputs[0] = most-significant 32 bits
    ///           inputs[7] = least-significant 32 bits
    function sha256ToPublicInputs(bytes32 hash)
        public
        pure
        returns (uint256[8] memory inputs)
    {
        uint256 h = uint256(hash);
        inputs[0] = (h >> 224) & 0xFFFFFFFF;
        inputs[1] = (h >> 192) & 0xFFFFFFFF;
        inputs[2] = (h >> 160) & 0xFFFFFFFF;
        inputs[3] = (h >> 128) & 0xFFFFFFFF;
        inputs[4] = (h >> 96)  & 0xFFFFFFFF;
        inputs[5] = (h >> 64)  & 0xFFFFFFFF;
        inputs[6] = (h >> 32)  & 0xFFFFFFFF;
        inputs[7] = h & 0xFFFFFFFF;
    }

    // ----------------------------------------------------------------
    // View helpers
    // ----------------------------------------------------------------

    /// @notice Compute the SHA-256 commitment for a given transition.
    function computeSha256Commitment(
        bytes32 oldRoot,
        bytes32 newRoot,
        bytes calldata leaves
    ) external pure returns (bytes32) {
        return sha256(abi.encodePacked(oldRoot, newRoot, leaves));
    }

    /// @notice Compute the domain-separated storage key.
    function computeDomainCommitment(bytes32 sha256Commit)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                PROTOCOL_VERSION,
                sha256Commit
            )
        );
    }

    /// @notice Read a batch by its domain-separated commit key.
    function getBatch(bytes32 commit)
        external
        view
        returns (
            bytes32 oldRoot,
            bytes32 newRoot,
            bytes32 sha256Commit,
            uint64  blockNumber,
            BatchStatus status,
            uint256 depositsCount
        )
    {
        Batch storage b = _batches[commit];
        return (b.oldRoot, b.newRoot, b.sha256Commit, b.blockNumber, b.status, b.deposits.length);
    }

    /// @notice Read a single deposit from a batch.
    function getBatchDeposit(bytes32 commit, uint256 index)
        external
        view
        returns (Deposit memory)
    {
        return _batches[commit].deposits[index];
    }
}
