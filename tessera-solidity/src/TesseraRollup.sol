// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20MonitoredToken {
    /// @notice Returns token balance for `account`.
    function balanceOf(address account) external view returns (uint256);
    /// @notice Moves `value` tokens from `from` to `to` using allowance.
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    /// @notice Moves `value` tokens from caller to `to`.
    function transfer(address to, uint256 value) external returns (bool);
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
/// @notice Deposit bridge with lifecycle: `Pending -> (Validated | Withdrawn)`.
/// @dev Notes:
///      - Deposits are keyed by note commitment and created once.
///      - A deposit is measured from the token balance delta within the same call
///        to avoid global balance-delta races across transactions.
///      - Validation and nullifier updates are gated by separate verifiers.
contract DepositsRollupBridge {
    /// @notice Current lifecycle state of a deposit note.
    enum DepositStatus {
        /// @notice Funds are escrowed and may either be validated or withdrawn.
        Pending,
        /// @notice Deposit was accepted into the validated batch.
        Validated,
        /// @notice Pending deposit was withdrawn by its recipient.
        Withdrawn
    }

    /// @notice Canonical deposit metadata stored by note commitment.
    struct Deposit {
        /// @notice Token amount received for this note.
        uint256 value;
        /// @notice Address allowed to withdraw while status is `Pending`.
        address recipient;
        /// @notice Current lifecycle state.
        DepositStatus status;
    }

    /// @notice Groth16 proof container used by both verifier calls.
    struct Proof {
        uint256[8] proof;
        uint256[2] commitments;
        uint256[2] commitmentPok;
    }

    bytes32 public constant DOMAIN_SEP = sha256("tessera.rollup.v1");

    IGroth16Verifier public immutable commitmentVerifier;
    IGroth16Verifier public immutable nullifierVerifier;

    /// @notice Governance/operator address for config and validation actions.
    address public operator;
    /// @notice Optional trusted source for delegated user deposits and nullifier updates.
    address public trustedSource;

    bytes32 public notesNullifierRoot;
    bytes32 public notesCommitmentRoot;
    uint256 public immutable batchSize;

    /// @notice ERC20 token escrowed by this bridge.
    address public immutable monitoredToken;
    /// @notice Internal accounting tracker for total pending/validated escrow observed by bridge flows.
    /// @dev Updated on deposit creation and pending withdrawals.
    uint256 public lastMonitoredBalance;

    bool public paused;

    /// @notice Canonical on-chain deposit state keyed by note commitment.
    mapping(bytes32 => Deposit) public deposits;
    /// @notice Existence flag to distinguish unset mapping slots.
    mapping(bytes32 => bool) public noteExists;

    event OperatorChanged(address indexed oldOp, address indexed newOp);
    event TrustedSourceChanged(address indexed oldSource, address indexed newSource);
    event PausedChanged(bool isPaused);
    event DepositAvailable(bytes32 indexed noteCommitment, uint256 value, address recipient);
    event DepositWithdrawn(bytes32 indexed noteCommitment, uint256 value, address recipient);
    event ValidatedBatchFinalized(uint256 batchSize, bytes32 oldRoot, bytes32 newRoot);
    event DepositValidated(bytes32 indexed noteCommitment);

    error NotOperator();
    error NotTrustedSource();
    error PausedErr();
    error InvalidProof();
    error NoteNotFound(bytes32 noteCommitment);
    error InvalidDepositState(bytes32 noteCommitment);
    error DuplicateNoteCommitment(bytes32 noteCommitment);
    error InvalidBatchSize();
    error InvalidBatchLength(uint256 got, uint256 expected);
    error InvalidMonitoredToken();
    error InvalidAmount();
    error NoTokenReceived();
    error NotDepositRecipient();
    error TokenTransferFailed();
    error InsufficientTrackedBalance(uint256 trackedBalance, uint256 withdrawalValue);
    error ZeroAddress();

    /// @notice Deploy bridge with verifier addresses and initial roots.
    constructor(
        address _commitmentVerifier,
        address _nullifierVerifier,
        address _operator,
        address _trustedSource,
        bytes32 _notesNullifierRoot,
        bytes32 _notesCommitmentRoot,
        uint256 _batchSize,
        address _monitoredToken
    ) {
        if (_operator == address(0) || _trustedSource == address(0)) revert ZeroAddress();
        if (_batchSize == 0) revert InvalidBatchSize();
        if (_monitoredToken == address(0)) revert InvalidMonitoredToken();

        commitmentVerifier = IGroth16Verifier(_commitmentVerifier);
        nullifierVerifier = IGroth16Verifier(_nullifierVerifier);
        operator = _operator;
        trustedSource = _trustedSource;
        notesNullifierRoot = _notesNullifierRoot;
        notesCommitmentRoot = _notesCommitmentRoot;
        batchSize = _batchSize;
        monitoredToken = _monitoredToken;
        lastMonitoredBalance = IERC20MonitoredToken(_monitoredToken).balanceOf(address(this));
    }

    /// @dev Restricts caller to `operator`.
    modifier onlyOperator() {
        _onlyOperator();
        _;
    }

    /// @dev Restricts actions while paused.
    modifier whenNotPaused() {
        _whenNotPaused();
        _;
    }

    /// @dev Restricts caller to `trustedSource`.
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

    /// @notice Updates the operator address.
    function setOperator(address newOperator) external onlyOperator {
        if (newOperator == address(0)) revert ZeroAddress();
        emit OperatorChanged(operator, newOperator);
        operator = newOperator;
    }

    /// @notice Updates the trusted source address.
    function setTrustedSource(address newTrustedSource) external onlyOperator {
        if (newTrustedSource == address(0)) revert ZeroAddress();
        emit TrustedSourceChanged(trustedSource, newTrustedSource);
        trustedSource = newTrustedSource;
    }

    /// @notice Pauses/unpauses mutating entry points.
    function setPaused(bool _paused) external onlyOperator {
        paused = _paused;
        emit PausedChanged(_paused);
    }

    /// @notice Pulls ERC20 funds from caller and creates a pending note deposit.
    /// @param noteCommitment Unique note commitment key for this deposit.
    /// @param maxAmount Amount attempted via `transferFrom`.
    /// @return The created note commitment.
    /// @dev Stored value is measured from in-call balance delta (`after - before`),
    ///      so the bridge records actual received amount.
    function depositAndRegister(bytes32 noteCommitment, uint256 maxAmount) external whenNotPaused returns (bytes32) {
        return _depositAndRegister(noteCommitment, msg.sender, msg.sender, maxAmount);
    }

    /// @notice Trusted-source variant that pulls from a user and records their pending deposit.
    /// @param noteCommitment Unique note commitment key for this deposit.
    /// @param payer User address that granted token allowance.
    /// @param maxAmount Amount attempted via `transferFrom`.
    /// @return The created note commitment.
    function depositAndRegisterFor(
        bytes32 noteCommitment,
        address payer,
        uint256 maxAmount
    ) external onlyTrustedSource whenNotPaused returns (bytes32) {
        return _depositAndRegister(noteCommitment, payer, payer, maxAmount);
    }

    /// @dev Shared deposit implementation for direct and trusted-source flows.
    function _depositAndRegister(
        bytes32 noteCommitment,
        address payer,
        address recipient,
        uint256 maxAmount
    ) internal returns (bytes32) {
        if (noteExists[noteCommitment]) revert DuplicateNoteCommitment(noteCommitment);
        if (payer == address(0) || recipient == address(0)) revert ZeroAddress();
        if (maxAmount == 0) revert InvalidAmount();

        uint256 previousBalance = IERC20MonitoredToken(monitoredToken).balanceOf(address(this));
        bool ok = IERC20MonitoredToken(monitoredToken).transferFrom(payer, address(this), maxAmount);
        if (!ok) revert TokenTransferFailed();
        uint256 newBalance = IERC20MonitoredToken(monitoredToken).balanceOf(address(this));
        if (newBalance <= previousBalance) revert NoTokenReceived();

        uint256 value = newBalance - previousBalance;

        deposits[noteCommitment] = Deposit({value: value, recipient: recipient, status: DepositStatus.Pending});
        noteExists[noteCommitment] = true;
        // Keep tracker aligned with bridge-managed escrow flow.
        lastMonitoredBalance += value;

        emit DepositAvailable(noteCommitment, value, recipient);
        return noteCommitment;
    }

    /// @notice Withdraws a pending deposit back to its designated recipient.
    /// @param noteCommitment Deposit note to withdraw.
    /// @dev Effects are applied before external token transfer.
    function withdrawPendingDeposit(bytes32 noteCommitment) external whenNotPaused {
        if (!noteExists[noteCommitment]) revert NoteNotFound(noteCommitment);

        Deposit storage dep = deposits[noteCommitment];
        if (dep.status != DepositStatus.Pending) revert InvalidDepositState(noteCommitment);
        if (msg.sender != dep.recipient) revert NotDepositRecipient();

        uint256 value = dep.value;
        uint256 trackedBalance = lastMonitoredBalance;
        if (trackedBalance < value) revert InsufficientTrackedBalance(trackedBalance, value);

        dep.status = DepositStatus.Withdrawn;
        lastMonitoredBalance = trackedBalance - value;

        bool ok = IERC20MonitoredToken(monitoredToken).transfer(dep.recipient, value);
        if (!ok) revert TokenTransferFailed();

        emit DepositWithdrawn(noteCommitment, value, dep.recipient);
    }

    /// @notice Finalizes a nullifier tree update after proof verification.
    /// @param newRoot Proposed nullifier tree root after consuming notes.
    /// @param noteCommitments Note commitments consumed in this batch (proof order).
    /// @param proof Groth16 proof of correct nullifier tree update.
    function recordNotesNullifierTreeUpdate(bytes32 newRoot, bytes32[] calldata noteCommitments, Proof calldata proof) external onlyTrustedSource whenNotPaused {
        
        uint256 batchLen = noteCommitments.length;
        if (batchLen != batchSize) revert InvalidBatchLength(batchLen, batchSize);

        bytes32 oldRoot = notesNullifierRoot;

        bytes memory noteBytes = new bytes(noteCommitments.length * 32);
        for (uint256 i = 0; i < noteCommitments.length; i++) {
            bytes32 note = noteCommitments[i];
            assembly {
                mstore(add(add(noteBytes, 32), mul(i, 32)), note)
            }
        }

        bytes32 sha256Commit = sha256(abi.encodePacked(oldRoot, newRoot, noteBytes));
        uint256[8] memory pubInputs = sha256ToPublicInputs(sha256Commit);

        try nullifierVerifier.verifyProof(proof.proof, proof.commitments, proof.commitmentPok, pubInputs) {
            // valid
        } catch {
            revert InvalidProof();
        }

        notesNullifierRoot = newRoot;
        emit ValidatedBatchFinalized(batchLen, oldRoot, newRoot);
    }

    /// @notice Finalizes a deposit-validation batch after append-proof verification.
    /// @param newNotesCommitmentRoot Proposed consumed tree root after appending notes.
    /// @param noteCommitments Notes consumed in this batch (proof order).
    function validateDepositBatch(
        bytes32 newNotesCommitmentRoot,
        bytes32[] calldata noteCommitments,
        Proof calldata proof
    ) external onlyOperator whenNotPaused {
        uint256 batchLen = noteCommitments.length;
        if (batchLen != batchSize) revert InvalidBatchLength(batchLen, batchSize);

        bytes32 oldNotesCommitmentRoot = notesCommitmentRoot;

        // Validate note availability before verifier call / state changes.
        for (uint256 i = 0; i < batchLen; i++) {
            bytes32 note = noteCommitments[i];
            if (!noteExists[note]) revert NoteNotFound(note);
            if (deposits[note].status != DepositStatus.Pending) revert InvalidDepositState(note);
        }

        bytes memory noteBytes = new bytes(batchLen * 32);
        for (uint256 i = 0; i < batchLen; i++) {
            bytes32 note = noteCommitments[i];
            assembly {
                mstore(add(add(noteBytes, 32), mul(i, 32)), note)
            }
        }

        bytes32 sha256Commit = sha256(abi.encodePacked(oldNotesCommitmentRoot, newNotesCommitmentRoot, noteBytes));
        uint256[8] memory pubInputs = sha256ToPublicInputs(sha256Commit);

        try commitmentVerifier.verifyProof(proof.proof, proof.commitments, proof.commitmentPok, pubInputs) {
            // valid
        } catch {
            revert InvalidProof();
        }

        for (uint256 i = 0; i < batchLen; i++) {
            bytes32 note = noteCommitments[i];
            deposits[note].status = DepositStatus.Validated;
            emit DepositValidated(note);
        }

        notesCommitmentRoot = newNotesCommitmentRoot;
        emit ValidatedBatchFinalized(batchLen, oldNotesCommitmentRoot, newNotesCommitmentRoot);
    }

    /// @notice Legacy helper retained for compatibility/debugging.
    function computeDepositCommitment(bytes32 noteCommitment, uint256 value, address recipient) public pure returns (bytes32) {
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

    /// @notice Reads full deposit record for `noteCommitment`.
    function getDeposit(bytes32 noteCommitment) external view returns (Deposit memory) {
        if (!noteExists[noteCommitment]) revert NoteNotFound(noteCommitment);
        return deposits[noteCommitment];
    }

    /// @notice Reads deposit status for `noteCommitment`.
    function getDepositStatus(bytes32 noteCommitment) external view returns (DepositStatus) {
        if (!noteExists[noteCommitment]) revert NoteNotFound(noteCommitment);
        return deposits[noteCommitment].status;
    }
}
