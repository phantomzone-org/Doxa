// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20BalanceOf {
    function balanceOf(address account) external view returns (uint256);
}

/// @notice Interface matching the gnark-generated Groth16 verifier.
///         The verifier reverts on invalid proofs (no bool return).
interface IGroth16Verifier {
    function verifyProof(
        uint256[8] calldata proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok,
        uint256[8] calldata input
    ) external view;
}

/// @title DepositsRollupBridge
/// @notice Deposit bridge with lifecycle: Available -> Consumed.
contract DepositsRollupBridge {
    enum DepositStatus {
        Available,
        Consumed
    }

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

    bytes32 public constant DOMAIN_SEP = sha256("tessera.pending-deposit.v1");

    IGroth16Verifier public immutable verifier;
    address public operator;
    address public trustedSource;

    bytes32 public consumedRoot;
    uint256 public immutable consumeBatchSize;

    /// @notice ERC20 token monitored for balance-delta deposit value.
    address public immutable monitoredToken;
    uint256 public lastMonitoredBalance;

    bool public paused;

    /// @notice Canonical on-chain state keyed by note commitment.
    mapping(bytes32 => Deposit) public deposits;
    mapping(bytes32 => bool) public noteExists;

    event OperatorChanged(address indexed oldOp, address indexed newOp);
    event TrustedSourceChanged(address indexed oldSource, address indexed newSource);
    event PausedChanged(bool isPaused);
    event DepositAvailable(bytes32 indexed noteCommitment, uint256 value, address recipient);
    event ConsumeBatchFinalized(uint256 batchSize, bytes32 oldRoot, bytes32 newRoot);
    event DepositConsumed(bytes32 indexed noteCommitment);

    error NotOperator();
    error NotTrustedSource();
    error PausedErr();
    error InvalidProof();
    error NoteNotFound(bytes32 noteCommitment);
    error InvalidDepositState(bytes32 noteCommitment);
    error DuplicateNoteCommitment(bytes32 noteCommitment);
    error InvalidBatchSize();
    error InvalidConsumeBatchLength(uint256 got, uint256 expected);
    error InvalidMonitoredToken();
    error NoTokenIncrease(uint256 previousBalance, uint256 newBalance);
    error ZeroAddress();

    constructor(
        address _verifier,
        address _operator,
        address _trustedSource,
        bytes32 _consumedRoot,
        uint256 _consumeBatchSize,
        address _monitoredToken
    ) {
        if (_operator == address(0) || _trustedSource == address(0)) revert ZeroAddress();
        if (_consumeBatchSize == 0) revert InvalidBatchSize();
        if (_monitoredToken == address(0)) revert InvalidMonitoredToken();

        verifier = IGroth16Verifier(_verifier);
        operator = _operator;
        trustedSource = _trustedSource;
        consumedRoot = _consumedRoot;
        consumeBatchSize = _consumeBatchSize;
        monitoredToken = _monitoredToken;
        lastMonitoredBalance = IERC20BalanceOf(_monitoredToken).balanceOf(address(this));
    }

    modifier onlyOperator() {
        _onlyOperator();
        _;
    }

    modifier whenNotPaused() {
        _whenNotPaused();
        _;
    }

    modifier onlyTrustedSource() {
        _onlyTrustedSource();
        _;
    }

    function _onlyOperator() internal view {
        if (msg.sender != operator) revert NotOperator();
    }

    function _whenNotPaused() internal view {
        if (paused) revert PausedErr();
    }

    function _onlyTrustedSource() internal view {
        if (msg.sender != trustedSource) revert NotTrustedSource();
    }

    function setOperator(address newOperator) external onlyOperator {
        if (newOperator == address(0)) revert ZeroAddress();
        emit OperatorChanged(operator, newOperator);
        operator = newOperator;
    }

    function setTrustedSource(address newTrustedSource) external onlyOperator {
        if (newTrustedSource == address(0)) revert ZeroAddress();
        emit TrustedSourceChanged(trustedSource, newTrustedSource);
        trustedSource = newTrustedSource;
    }

    function setPaused(bool _paused) external onlyOperator {
        paused = _paused;
        emit PausedChanged(_paused);
    }

    /// @notice Record an available deposit for a note commitment.
    /// @dev Value is inferred from monitored token balance delta.
    ///      recipient is the caller address of this function.
    function recordDeposit(bytes32 noteCommitment) external onlyTrustedSource whenNotPaused returns (bytes32) {
        if (noteExists[noteCommitment]) revert DuplicateNoteCommitment(noteCommitment);

        uint256 previousBalance = lastMonitoredBalance;
        uint256 newBalance = IERC20BalanceOf(monitoredToken).balanceOf(address(this));
        if (newBalance <= previousBalance) revert NoTokenIncrease(previousBalance, newBalance);

        uint256 value = newBalance - previousBalance;
        lastMonitoredBalance = newBalance;

        deposits[noteCommitment] = Deposit({value: value, recipient: msg.sender, status: DepositStatus.Available});
        noteExists[noteCommitment] = true;

        emit DepositAvailable(noteCommitment, value, msg.sender);
        return noteCommitment;
    }

    /// @notice Finalize a consume batch after verifying the append proof.
    /// @param newConsumedRoot Proposed consumed tree root after appending notes.
    /// @param noteCommitments Notes consumed in this batch (proof order).
    function finalizeConsumeBatch(
        bytes32 newConsumedRoot,
        bytes32[] calldata noteCommitments,
        Proof calldata proof
    ) external onlyOperator whenNotPaused {
        uint256 batchLen = noteCommitments.length;
        if (batchLen != consumeBatchSize) revert InvalidConsumeBatchLength(batchLen, consumeBatchSize);

        bytes32 oldConsumedRoot = consumedRoot;

        // Validate availability before verification/submission side effects.
        for (uint256 i = 0; i < batchLen; i++) {
            bytes32 note = noteCommitments[i];
            if (!noteExists[note]) revert NoteNotFound(note);
            if (deposits[note].status != DepositStatus.Available) revert InvalidDepositState(note);
        }

        bytes memory noteBytes = new bytes(batchLen * 32);
        for (uint256 i = 0; i < batchLen; i++) {
            bytes32 note = noteCommitments[i];
            assembly {
                mstore(add(add(noteBytes, 32), mul(i, 32)), note)
            }
        }

        bytes32 sha256Commit = sha256(abi.encodePacked(oldConsumedRoot, newConsumedRoot, noteBytes));
        uint256[8] memory pubInputs = sha256ToPublicInputs(sha256Commit);

        try verifier.verifyProof(proof.proof, proof.commitments, proof.commitmentPok, pubInputs) {
            // valid
        } catch {
            revert InvalidProof();
        }

        for (uint256 i = 0; i < batchLen; i++) {
            bytes32 note = noteCommitments[i];
            deposits[note].status = DepositStatus.Consumed;
            emit DepositConsumed(note);
        }

        consumedRoot = newConsumedRoot;
        emit ConsumeBatchFinalized(batchLen, oldConsumedRoot, newConsumedRoot);
    }

    /// @notice Legacy helper kept for compatibility/debugging.
    function computeCommitment(bytes32 noteCommitment, uint256 value, address recipient) public pure returns (bytes32) {
        bytes32 digest = sha256(abi.encodePacked(DOMAIN_SEP, noteCommitment, value, recipient));

        uint256 mask = ~(uint256(1) << 255 | uint256(1) << 191 | uint256(1) << 127 | uint256(1) << 63);
        return bytes32(uint256(digest) & mask);
    }

    function sha256ToPublicInputs(bytes32 hash) public pure returns (uint256[8] memory inputs) {
        uint256 h = uint256(hash);
        inputs[0] = (h >> 224) & 0xFFFFFFFF;
        inputs[1] = (h >> 192) & 0xFFFFFFFF;
        inputs[2] = (h >> 160) & 0xFFFFFFFF;
        inputs[3] = (h >> 128) & 0xFFFFFFFF;
        inputs[4] = (h >> 96) & 0xFFFFFFFF;
        inputs[5] = (h >> 64) & 0xFFFFFFFF;
        inputs[6] = (h >> 32) & 0xFFFFFFFF;
        inputs[7] = h & 0xFFFFFFFF;
    }

    function getDeposit(bytes32 noteCommitment) external view returns (Deposit memory) {
        if (!noteExists[noteCommitment]) revert NoteNotFound(noteCommitment);
        return deposits[noteCommitment];
    }

    function getDepositStatus(bytes32 noteCommitment) external view returns (DepositStatus) {
        if (!noteExists[noteCommitment]) revert NoteNotFound(noteCommitment);
        return deposits[noteCommitment].status;
    }
}
