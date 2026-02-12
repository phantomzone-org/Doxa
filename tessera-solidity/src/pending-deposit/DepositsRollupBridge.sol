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
/// @notice Batched deposit validation protocol for on-chain deposit recording
///         with off-chain Merkle root anchoring via zero-knowledge proofs.
///
///         Users call `deposit()` to record a pending deposit on-chain.
///         The sequencer watches `DepositPending` events, aggregates deposits
///         into a Merkle tree off-chain, and finalizes batches via `finalizeBatch()`
///         with a Groth16 proof.
///
/// @dev    Commitment encoding
///         Each deposit's commitment is computed as:
///           sha256(DOMAIN_SEP ‖ noteCommitment ‖ value ‖ recipient)
///         with the MSB of each 64-bit chunk cleared so every chunk fits in the
///         Goldilocks field (< 2^63 < p). This is an injective mapping on the
///         252-bit truncated digest, providing 126-bit collision security.
///
/// @dev    SHA-256 circuit commitment
///         The plonky2 circuit commits its public data via SHA-256:
///           SHA256(merkleRoot_old ‖ merkleRoot_new ‖ commitment_0 ‖ … ‖ commitment_{N−1})
///         where each commitment is 32 bytes. The resulting 256-bit digest is split
///         into 8 big-endian uint32 words, which become the Groth16 public inputs.
contract DepositsRollupBridge {
    // ----------------------------------------------------------------
    // Types
    // ----------------------------------------------------------------

    /// @dev Deposit lifecycle status.
    enum DepositStatus { Pending, Validated }

    /// @dev On-chain deposit record.
    struct Deposit {
        bytes32       commitment;  // sha256(DOMAIN_SEP ‖ noteCommitment ‖ value ‖ recipient) w/ MSB clearing
        uint256       value;       // deposit value
        address       recipient;   // recipient address
        DepositStatus status;
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

    /// @notice Domain separator for commitment hashing.
    bytes32 public constant DOMAIN_SEP = sha256("tessera.pending-deposit.v1");

    // ----------------------------------------------------------------
    // Config / State
    // ----------------------------------------------------------------

    /// @notice Address of the gnark-generated Groth16 verifier contract.
    IGroth16Verifier public immutable verifier;

    /// @notice Number of deposits per batch.
    uint256 public immutable batchSize;

    /// @notice Centralized operator (sequencer).
    address public operator;

    /// @notice Current committed Merkle root.
    bytes32 public merkleRoot;

    /// @notice Monotonic deposit counter (next available ID).
    uint256 public nextDepositId;

    /// @notice Emergency pause switch.
    bool public paused;

    /// @notice The deposit start index expected for the next batch finalization.
    uint256 public nextBatchStartIndex;

    /// @notice Deposit records indexed by deposit ID.
    mapping(uint256 => Deposit) public deposits;

    // ----------------------------------------------------------------
    // Events
    // ----------------------------------------------------------------

    event OperatorChanged(address indexed oldOp, address indexed newOp);
    event PausedChanged(bool isPaused);
    event DepositPending(
        uint256 indexed depositId,
        bytes32 commitment,
        uint256 value,
        address recipient
    );
    event BatchValidated(uint256 indexed batchId, bytes32 newRoot);

    // ----------------------------------------------------------------
    // Errors
    // ----------------------------------------------------------------

    error NotOperator();
    error PausedErr();
    error InvalidProof();
    error InsufficientDeposits();
    error DepositNotPending(uint256 depositId);
    error InvalidDepositStartIndex();
    error ZeroAddress();

    // ----------------------------------------------------------------
    // Constructor / Admin
    // ----------------------------------------------------------------

    constructor(
        address _verifier,
        address _operator,
        bytes32 _genesisRoot,
        uint256 _batchSize
    ) {
        verifier = IGroth16Verifier(_verifier);
        operator = _operator;
        merkleRoot = _genesisRoot;
        batchSize = _batchSize;
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
        if (newOperator == address(0)) revert ZeroAddress();
        emit OperatorChanged(operator, newOperator);
        operator = newOperator;
    }

    /// @notice Toggle the pause switch.
    function setPaused(bool _paused) external onlyOperator {
        paused = _paused;
        emit PausedChanged(_paused);
    }

    // ----------------------------------------------------------------
    // Deposit submission (permissionless)
    // ----------------------------------------------------------------

    /// @notice Record a pending deposit.
    ///
    /// @param noteCommitment  User-provided privacy note commitment.
    /// @param value           Deposit value.
    /// @param recipient       Recipient address.
    /// @return depositId      Assigned deposit ID.
    function deposit(
        bytes32 noteCommitment,
        uint256 value,
        address recipient
    )
        external
        whenNotPaused
        returns (uint256 depositId)
    {
        bytes32 commitment = computeCommitment(noteCommitment, value, recipient);

        depositId = nextDepositId++;
        deposits[depositId] = Deposit({
            commitment: commitment,
            value: value,
            recipient: recipient,
            status: DepositStatus.Pending
        });

        emit DepositPending(depositId, commitment, value, recipient);
    }

    // ----------------------------------------------------------------
    // Batch finalization
    // ----------------------------------------------------------------

    /// @notice Finalize a batch of pending deposits by verifying a Groth16 proof.
    ///
    /// @param newRoot            Proposed next Merkle root.
    /// @param depositStartIndex  First deposit ID in the batch.
    /// @param proof              Groth16 proof with Pedersen commitments.
    function finalizeBatch(
        bytes32 newRoot,
        uint256 depositStartIndex,
        Proof calldata proof
    )
        external
        onlyOperator
        whenNotPaused
    {
        uint256 _batchSize = batchSize;

        // 1. Enforce sequential finalization order.
        if (depositStartIndex != nextBatchStartIndex) revert InvalidDepositStartIndex();

        uint256 end = depositStartIndex + _batchSize;

        // 2. Ensure enough deposits exist.
        if (end > nextDepositId) revert InsufficientDeposits();

        // 3. Collect commitments and verify all are Pending.
        bytes memory commitmentBytes = new bytes(_batchSize * 32);
        for (uint256 i = 0; i < _batchSize; i++) {
            uint256 id = depositStartIndex + i;
            Deposit storage d = deposits[id];
            if (d.status != DepositStatus.Pending) revert DepositNotPending(id);
            bytes32 c = d.commitment;
            assembly {
                mstore(add(add(commitmentBytes, 32), mul(i, 32)), c)
            }
        }

        // 4. Compute SHA-256 commitment matching the circuit.
        bytes32 sha256Commit = sha256(abi.encodePacked(merkleRoot, newRoot, commitmentBytes));

        // 5. Derive public inputs.
        uint256[8] memory pubInputs = sha256ToPublicInputs(sha256Commit);

        // 6. Verify the Groth16 proof.
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

        // 7. Mark deposits as Validated.
        for (uint256 i = 0; i < _batchSize; i++) {
            deposits[depositStartIndex + i].status = DepositStatus.Validated;
        }

        // 8. Advance state.
        uint256 batchId = nextBatchStartIndex / _batchSize;
        nextBatchStartIndex += _batchSize;
        merkleRoot = newRoot;

        emit BatchValidated(batchId, newRoot);
    }

    // ----------------------------------------------------------------
    // Commitment computation
    // ----------------------------------------------------------------

    /// @notice Compute the deposit commitment.
    ///
    /// @dev Encoding: sha256(DOMAIN_SEP ‖ noteCommitment ‖ value ‖ recipient)
    ///      The MSB of each 64-bit chunk is cleared so that every chunk
    ///      fits in the Goldilocks field (< 2^63 < p).
    function computeCommitment(
        bytes32 noteCommitment,
        uint256 value,
        address recipient
    ) public pure returns (bytes32) {
        bytes32 digest = sha256(abi.encodePacked(
            DOMAIN_SEP,
            noteCommitment,
            value,
            recipient
        ));

        // Clear MSB of each 64-bit chunk: bits 255, 191, 127, 63
        uint256 mask = ~(
            uint256(1) << 255 |
            uint256(1) << 191 |
            uint256(1) << 127 |
            uint256(1) << 63
        );
        return bytes32(uint256(digest) & mask);
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

    /// @notice Read a deposit by ID.
    function getDeposit(uint256 depositId)
        external
        view
        returns (Deposit memory)
    {
        return deposits[depositId];
    }
}
