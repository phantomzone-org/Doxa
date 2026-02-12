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
/// @notice Deposit bridge for trusted-source ingestion with lifecycle:
///         Available -> Withdrawn / Consumed.
///
/// @dev    Commitment encoding
///         Each deposit's commitment is computed as:
///           sha256(DOMAIN_SEP ‖ noteCommitment ‖ value ‖ recipient)
///         with the MSB of each 64-bit chunk cleared so every chunk fits in the
///         Goldilocks field (< 2^63 < p). This is an injective mapping on the
///         252-bit truncated digest, providing 126-bit collision security.
///
/// @dev    Consume proof commitment
///         The circuit public commitment is:
///           SHA256(consumedRoot_old ‖ consumedRoot_new ‖ deposit_commitment)
///         then split into 8 big-endian uint32 words as verifier public inputs.
contract DepositsRollupBridge {
    // ----------------------------------------------------------------
    // Types
    // ----------------------------------------------------------------

    /// @dev Deposit lifecycle status.
    enum DepositStatus { Available, Withdrawn, Consumed }

    /// @dev On-chain deposit record.
    struct Deposit {
        bytes32       commitment;  // sha256(DOMAIN_SEP ‖ noteCommitment ‖ value ‖ recipient) w/ MSB clearing
        uint256       value;       // deposit value
        address       depositor;   // original user account (authorized withdrawer)
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

    /// @notice Centralized operator (sequencer).
    address public operator;

    /// @notice Trusted source allowed to record deposits.
    address public trustedSource;

    /// @notice Current consumed/nullifier tree root.
    bytes32 public consumedRoot;

    /// @notice Number of consume requests per finalized batch.
    uint256 public immutable consumeBatchSize;

    /// @notice Monotonic deposit counter (next available ID).
    uint256 public nextDepositId;

    /// @notice Emergency pause switch.
    bool public paused;

    /// @notice Deposit records indexed by deposit ID.
    mapping(uint256 => Deposit) public deposits;

    /// @notice Tracks whether a note commitment has ever been used.
    mapping(bytes32 => bool) public noteCommitmentUsed;

    /// @notice Lookup from deposit commitment to deposit ID.
    mapping(bytes32 => uint256) public commitmentToDepositId;

    /// @notice Tracks whether a commitment has been recorded.
    mapping(bytes32 => bool) public commitmentExists;

    /// @notice Tracks whether a commitment currently has a pending consume request.
    mapping(bytes32 => bool) public consumeRequested;

    // ----------------------------------------------------------------
    // Events
    // ----------------------------------------------------------------

    event OperatorChanged(address indexed oldOp, address indexed newOp);
    event TrustedSourceChanged(address indexed oldSource, address indexed newSource);
    event PausedChanged(bool isPaused);
    event DepositAvailable(
        uint256 indexed depositId,
        bytes32 commitment,
        address depositor,
        uint256 value,
        address recipient
    );
    event ConsumeRequested(bytes32 indexed commitment, uint256 indexed depositId, address indexed requester);
    event DepositWithdrawn(uint256 indexed depositId, address indexed depositor);
    event ConsumeBatchFinalized(uint256 batchSize, bytes32 oldRoot, bytes32 newRoot);
    event DepositConsumed(uint256 indexed depositId, bytes32 indexed commitment);

    // ----------------------------------------------------------------
    // Errors
    // ----------------------------------------------------------------

    error NotOperator();
    error NotTrustedSource();
    error PausedErr();
    error InvalidProof();
    error DepositNotFound(uint256 depositId);
    error CommitmentNotFound(bytes32 commitment);
    error CommitmentNotRequested(bytes32 commitment);
    error ConsumeAlreadyRequested(bytes32 commitment);
    error InvalidDepositState(uint256 depositId);
    error NotDepositor(uint256 depositId);
    error DuplicateNoteCommitment(bytes32 noteCommitment);
    error InvalidBatchSize();
    error InvalidConsumeBatchLength(uint256 got, uint256 expected);
    error ZeroAddress();

    // ----------------------------------------------------------------
    // Constructor / Admin
    // ----------------------------------------------------------------

    constructor(
        address _verifier,
        address _operator,
        address _trustedSource,
        bytes32 _consumedRoot,
        uint256 _consumeBatchSize
    ) {
        if (_operator == address(0) || _trustedSource == address(0)) revert ZeroAddress();
        if (_consumeBatchSize == 0) revert InvalidBatchSize();
        verifier = IGroth16Verifier(_verifier);
        operator = _operator;
        trustedSource = _trustedSource;
        consumedRoot = _consumedRoot;
        consumeBatchSize = _consumeBatchSize;
    }

    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert PausedErr();
        _;
    }

    modifier onlyTrustedSource() {
        if (msg.sender != trustedSource) revert NotTrustedSource();
        _;
    }

    /// @notice Transfer the operator role to a new address.
    function setOperator(address newOperator) external onlyOperator {
        if (newOperator == address(0)) revert ZeroAddress();
        emit OperatorChanged(operator, newOperator);
        operator = newOperator;
    }

    /// @notice Update the trusted source contract.
    function setTrustedSource(address newTrustedSource) external onlyOperator {
        if (newTrustedSource == address(0)) revert ZeroAddress();
        emit TrustedSourceChanged(trustedSource, newTrustedSource);
        trustedSource = newTrustedSource;
    }

    /// @notice Toggle the pause switch.
    function setPaused(bool _paused) external onlyOperator {
        paused = _paused;
        emit PausedChanged(_paused);
    }

    // ----------------------------------------------------------------
    // Deposit ingest (trusted source)
    // ----------------------------------------------------------------

    /// @notice Record an available deposit from the trusted source.
    ///
    /// @param noteCommitment  User-provided privacy note commitment.
    /// @param value           Deposit value.
    /// @param depositor       Original user account that can withdraw.
    /// @param recipient       Recipient address.
    /// @return depositId      Assigned deposit ID.
    function recordDeposit(
        bytes32 noteCommitment,
        uint256 value,
        address depositor,
        address recipient
    )
        external
        onlyTrustedSource
        whenNotPaused
        returns (uint256 depositId)
    {
        if (depositor == address(0)) revert ZeroAddress();
        if (noteCommitmentUsed[noteCommitment]) revert DuplicateNoteCommitment(noteCommitment);
        noteCommitmentUsed[noteCommitment] = true;
        bytes32 commitment = computeCommitment(noteCommitment, value, recipient);

        depositId = nextDepositId++;
        deposits[depositId] = Deposit({
            commitment: commitment,
            value: value,
            depositor: depositor,
            recipient: recipient,
            status: DepositStatus.Available
        });
        commitmentToDepositId[commitment] = depositId;
        commitmentExists[commitment] = true;

        emit DepositAvailable(depositId, commitment, depositor, value, recipient);
    }

    // ----------------------------------------------------------------
    // State transitions
    // ----------------------------------------------------------------

    /// @notice Withdraw an available deposit back to the original depositor.
    function withdraw(uint256 depositId)
        external
        whenNotPaused
    {
        Deposit storage d = deposits[depositId];
        if (depositId >= nextDepositId) revert DepositNotFound(depositId);
        if (d.status != DepositStatus.Available) revert InvalidDepositState(depositId);
        if (msg.sender != d.depositor) revert NotDepositor(depositId);

        d.status = DepositStatus.Withdrawn;
        emit DepositWithdrawn(depositId, d.depositor);
    }

    /// @notice Request consumption by commitment (leaf value).
    ///
    /// @dev Requests are set-based and can arrive in any order.
    function requestConsume(bytes32 commitment)
        external
        whenNotPaused
    {
        if (!commitmentExists[commitment]) revert CommitmentNotFound(commitment);
        if (consumeRequested[commitment]) revert ConsumeAlreadyRequested(commitment);

        uint256 depositId = commitmentToDepositId[commitment];
        Deposit storage d = deposits[depositId];
        if (d.status != DepositStatus.Available) revert InvalidDepositState(depositId);

        consumeRequested[commitment] = true;
        emit ConsumeRequested(commitment, depositId, msg.sender);
    }

    /// @notice Finalize a consume batch after verifying the consume proof.
    ///
    /// @param newConsumedRoot   Proposed consumed tree root after insertion.
    /// @param commitments       Commitments consumed in this batch (ordered as in proof).
    /// @param proof             Groth16 proof with Pedersen commitments.
    function finalizeConsumeBatch(
        bytes32 newConsumedRoot,
        bytes32[] calldata commitments,
        Proof calldata proof
    )
        external
        onlyOperator
        whenNotPaused
    {
        uint256 batchLen = commitments.length;
        if (batchLen != consumeBatchSize) revert InvalidConsumeBatchLength(batchLen, consumeBatchSize);

        bytes32 oldConsumedRoot = consumedRoot;
        uint256[] memory depositIds = new uint256[](batchLen);

        // Validate request set membership and status; clear requests to also reject duplicates.
        for (uint256 i = 0; i < batchLen; i++) {
            bytes32 c = commitments[i];
            if (!commitmentExists[c]) revert CommitmentNotFound(c);
            if (!consumeRequested[c]) revert CommitmentNotRequested(c);
            consumeRequested[c] = false;

            uint256 depositId = commitmentToDepositId[c];
            Deposit storage d = deposits[depositId];
            if (d.status != DepositStatus.Available) revert InvalidDepositState(depositId);
            depositIds[i] = depositId;
        }

        bytes memory commitmentBytes = new bytes(batchLen * 32);
        for (uint256 i = 0; i < batchLen; i++) {
            bytes32 c = commitments[i];
            assembly {
                mstore(add(add(commitmentBytes, 32), mul(i, 32)), c)
            }
        }

        // Compute SHA-256 commitment expected by the consume circuit.
        bytes32 sha256Commit = sha256(abi.encodePacked(oldConsumedRoot, newConsumedRoot, commitmentBytes));

        // Derive public inputs.
        uint256[8] memory pubInputs = sha256ToPublicInputs(sha256Commit);

        // Verify the Groth16 proof.
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

        for (uint256 i = 0; i < batchLen; i++) {
            uint256 depositId = depositIds[i];
            bytes32 c = commitments[i];
            deposits[depositId].status = DepositStatus.Consumed;
            emit DepositConsumed(depositId, c);
        }

        consumedRoot = newConsumedRoot;
        emit ConsumeBatchFinalized(batchLen, oldConsumedRoot, newConsumedRoot);
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
