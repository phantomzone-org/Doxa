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
    /// @notice Verifies a Groth16 proof for the configured circuit.
    /// @dev The verifier reverts on invalid proofs; callers typically wrap this call in `try/catch`
    ///      and translate it to a typed error.
    function verifyProof(
        uint256[8] calldata proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok,
        uint256[8] calldata input
    ) external view;
}

/// @title DepositsRollupBridge
/// @notice ERC20 deposit escrow + ZK-proven rollup root updates for notes/accounts trees.
/// @dev High-level model:
///      - Users (or any relayer/adapter) create deposits keyed by `noteCommitment`.
///      - While still `Pending`, the recipient can withdraw escrowed tokens.
///      - The contract tracks four independent roots:
///        1) `notesCommitmentRoot`    (append-style note outputs / validated deposits)
///        2) `notesNullifierRoot`     (consumed/spent note nullifiers)
///        3) `accountsCommitmentRoot` (append-style account outputs)
///        4) `accountsNullifierRoot`  (consumed/spent account nullifiers)
///      - The operator proves and records root transitions for each tree using the
///        corresponding verifier (`commitmentVerifier` or `nullifierVerifier`).
///
///      Notes-commitment updates use a single-phase entry point:
///      - `recordNotesCommitmentTreeUpdate(newRoot, notes, treeProof, inputsProof)`
///      which verifies proof, validates tracked-note state, marks tracked notes as `Validated`,
///      and advances `notesCommitmentRoot` atomically.
///
///
///      Proof binding:
///      - For batch validation and tree updates, the verifier input is derived from
///        `keccak256(oldRoot || newRoot || packedLeaves)` converted to 8x uint32 public inputs.
///      - Tree update entry points are:
///        `recordNotesCommitmentTreeUpdate`,
///        `recordNotesNullifierTreeUpdate`,
///        `recordAccountsCommitmentTreeUpdate`,
///        `recordAccountsNullifierTreeUpdate`,
///
///      Important safety note:
///      - For notes commitment updates, tracked notes are checked to be `Pending` at execution time.
///      - Notes absent from bridge storage are treated as external/network-native leaves and are allowed.
contract DepositsRollupBridge {
    /// @notice Current lifecycle state of a deposit note.
    enum DepositStatus {
        /// @notice No deposit exists for this note commitment (default value).
        None,
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

    /// @notice Domain separator used for off-chain commitments and action hashing.
    /// @dev Chosen to be stable across deployments of this contract family.
    bytes32 public constant DOMAIN_SEP = sha256("tessera.rollup.v1");

    /// @notice Groth16 verifier for commitment-style circuits (append/commitment tree updates).
    IGroth16Verifier public immutable commitmentVerifier;
    /// @notice Groth16 verifier for nullifier-style circuits (chained/consuming updates).
    IGroth16Verifier public immutable nullifierVerifier;
    /// @notice Groth16 verifier for aggregated public-input validity checks.
    IGroth16Verifier public immutable aggregatedInputVerifier;

    /// @notice Governance/operator address for configuration and proof-verification entry points.
    address public operator;
    /// @notice Notes nullifier tree root (proven by `nullifierVerifier`).
    bytes32 public notesNullifierRoot;
    /// @notice Notes commitment tree root (proven by `commitmentVerifier`).
    bytes32 public notesCommitmentRoot;
    /// @notice Accounts nullifier tree root (proven by `nullifierVerifier`).
    bytes32 public accountsNullifierRoot;
    /// @notice Accounts commitment tree root (proven by `commitmentVerifier`).
    bytes32 public accountsCommitmentRoot;
    /// @notice Fixed batch size required by the circuits/verifiers.
    /// @dev Circuits/verifiers are fixed-width and always bind to `batchSize` leaves.
    uint256 public immutable batchSize;
    /// @notice Number of leaves committed in notes commitment tree.
    uint256 public notesCommitmentLeafCount;
    /// @notice Number of leaves committed in notes nullifier tree.
    uint256 public notesNullifierLeafCount;
    /// @notice Number of leaves committed in accounts commitment tree.
    uint256 public accountsCommitmentLeafCount;
    /// @notice Number of leaves committed in accounts nullifier tree.
    uint256 public accountsNullifierLeafCount;

    /// @notice ERC20 token escrowed by this bridge for pending deposits.
    address public immutable monitoredToken;

    /// @notice Global pause flag for mutating entry points.
    bool public paused;

    /// @notice Canonical on-chain deposit state keyed by note commitment.
    /// @dev Existence is encoded by `status != DepositStatus.None`.
    mapping(bytes32 => Deposit) public deposits;

    // -------------------------------------------------------------------------
    // Two-phase transaction-batch state
    // -------------------------------------------------------------------------

    /// @notice Tree index constants used by registerTransactionBatchUpdate / confirmTreeUpdate.
    uint8 public constant TREE_NOTES_COMMITMENT    = 0;
    uint8 public constant TREE_NOTES_NULLIFIER     = 1;
    uint8 public constant TREE_ACCOUNTS_COMMITMENT = 2;
    uint8 public constant TREE_ACCOUNTS_NULLIFIER  = 3;

    /// @notice Maximum number of simultaneously in-flight transaction batches.
    /// @dev Sized to pre-allocate a fixed-size storage buffer so every register/confirm
    ///      writes into an already-warm slot (2,900 gas) rather than cold (20,000 gas).
    uint256 public constant MAX_PENDING_BATCHES = 128;

    /// @notice On-chain record for a pending transaction batch (registered but not yet fully confirmed).
    struct PendingBatch {
        /// @notice 0 = free slot; set on register, cleared on full confirmation.
        uint256 batchId;
        bytes32 newNotesCommitmentRoot;
        bytes32 newNotesNullifierRoot;
        bytes32 newAccountsCommitmentRoot;
        bytes32 newAccountsNullifierRoot;
        /// @notice One PI commitment per tree (index matches TREE_* constants).
        ///         Each = keccak256 digest of (oldRoot || newRoot || packedLeaves), used as
        ///         Groth16 public inputs at confirm time.
        bytes32[4] piCommitments;
        /// @notice Bit i is set when tree i's proof has been confirmed. Batch complete at 0xF.
        uint8 confirmedMask;
    }

    /// @notice Fixed-size pre-warmed pending-batch buffer. Indexed by batchId % MAX_PENDING_BATCHES.
    PendingBatch[MAX_PENDING_BATCHES] public pendingBatches;
    /// @notice Number of currently occupied slots in pendingBatches.
    uint256 private _pendingCount;
    /// @notice Monotonically increasing batch ID counter; 1-based (0 = unset/free).
    uint256 private _nextBatchId;

    /// @notice Confirmed roots — advance per-tree as each tree's proof is verified.
    ///         For the deposit-only record*TreeUpdate path these always match notesXxxRoot.
    bytes32 public confirmedNotesCommitmentRoot;
    bytes32 public confirmedNotesNullifierRoot;
    bytes32 public confirmedAccountsCommitmentRoot;
    bytes32 public confirmedAccountsNullifierRoot;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    event OperatorChanged(address indexed oldOp, address indexed newOp);
    event PausedChanged(bool isPaused);
    event DepositAvailable(bytes32 indexed noteCommitment, uint256 value, address recipient);
    event DepositWithdrawn(bytes32 indexed noteCommitment, uint256 value, address recipient);
    /// @notice Tree type discriminator used in ValidatedBatchFinalized.
    /// @dev Explicit uint8 values are stable across ABI versions; do not reorder.
    enum TreeType { NotesCommitment, NotesNullifier, AccountsCommitment, AccountsNullifier }

    /// @dev Emitted for every successful root update regardless of which tree changed.
    ///      `treeType` distinguishes the four trees so indexers and the off-chain
    ///      sequencer do not need to decode transaction calldata to determine which
    ///      tree was updated.
    event ValidatedBatchFinalized(
        TreeType indexed treeType,
        uint256 batchSize,
        bytes32 oldRoot,
        bytes32 newRoot
    );
    event DepositValidated(bytes32 indexed noteCommitment);

    /// @dev Emitted when all four tree roots are registered optimistically as a batch.
    event TransactionBatchRegistered(
        uint256 indexed batchId,
        bytes32 newNotesCommitmentRoot,
        bytes32 newNotesNullifierRoot,
        bytes32 newAccountsCommitmentRoot,
        bytes32 newAccountsNullifierRoot,
        bytes32[4] piCommitments
    );
    /// @dev Emitted each time one tree's proof is confirmed within a batch.
    event TreeUpdateConfirmed(uint256 indexed batchId, uint8 treeIndex);
    /// @dev Emitted once all four trees in a batch are confirmed (confirmedMask == 0xF).
    event TransactionBatchConfirmed(uint256 indexed batchId);

    error NotOperator();
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
    error ZeroAddress();
    error InvalidinputsProof();
    error PendingQueueFull();
    error SlotConflict(uint256 slotIndex);
    error UnknownBatch(uint256 batchId);
    error AlreadyConfirmed(uint256 batchId, uint8 treeIndex);
    error InvalidTreeIndex(uint8 treeIndex);

    /// @notice Deploy bridge with verifier addresses, initial roots, and access-control parameters.
    /// @dev Why these parameters exist:
    ///      - Verifiers are immutable: the deployed circuit/vk is part of the security boundary.
    ///      - Roots are initialized to the agreed genesis values shared with the off-chain prover.
    ///      - `operator` is the only entity allowed to verify proofs on-chain (load/record functions).
    ///
    ///      Usage constraints:
    ///      - `_batchSize` must match the circuit's expected batch size (immutable once deployed).
    ///      - `_monitoredToken` must be the ERC20 whose balance this bridge escrows.
    constructor(
        address _commitmentVerifier,
        address _nullifierVerifier,
        address _aggregatedInputVerifier,
        address _operator,
        bytes32 _notesNullifierRoot,
        bytes32 _notesCommitmentRoot,
        bytes32 _accountsNullifierRoot,
        bytes32 _accountsCommitmentRoot,
        uint256 _batchSize,
        address _monitoredToken
    ) {
        if (_operator == address(0)) revert ZeroAddress();
        if (_batchSize == 0  || _batchSize & (_batchSize - 1) != 0) revert InvalidBatchSize();
        if (_monitoredToken == address(0)) revert InvalidMonitoredToken();

        // Store immutable verifier addresses. These define the circuits that can update roots.
        commitmentVerifier = IGroth16Verifier(_commitmentVerifier);
        nullifierVerifier = IGroth16Verifier(_nullifierVerifier);
        aggregatedInputVerifier = IGroth16Verifier(_aggregatedInputVerifier);

        // Initialize roles.
        operator = _operator;
        // Initialize roots to the agreed genesis state.
        notesNullifierRoot = _notesNullifierRoot;
        notesCommitmentRoot = _notesCommitmentRoot;
        accountsNullifierRoot = _accountsNullifierRoot;
        accountsCommitmentRoot = _accountsCommitmentRoot;

        // Batch size is circuit-defined and must match the prover configuration.
        batchSize = _batchSize;
        // Commitment trees start empty; nullifier trees start with one sentinel node.
        notesCommitmentLeafCount = 0;
        notesNullifierLeafCount = 1;
        accountsCommitmentLeafCount = 0;
        accountsNullifierLeafCount = 1;

        // Token escrow configuration.
        monitoredToken = _monitoredToken;

        // Two-phase batch state initialisation.
        _nextBatchId = 1;

        // Mirror genesis roots into confirmed roots (no pending proofs at deploy time).
        confirmedNotesCommitmentRoot    = _notesCommitmentRoot;
        confirmedNotesNullifierRoot     = _notesNullifierRoot;
        confirmedAccountsCommitmentRoot = _accountsCommitmentRoot;
        confirmedAccountsNullifierRoot  = _accountsNullifierRoot;

        // Pre-warm all pending-batch slots so every future register/confirm is a warm SSTORE.
        // Write then immediately clear confirmedMask on each slot: cold write (20k gas) done
        // once here so register/confirm only pay 2,900 gas for warm rewrites.
        for (uint256 i = 0; i < MAX_PENDING_BATCHES; i++) {
            pendingBatches[i].confirmedMask = 0xFF;
            pendingBatches[i].confirmedMask = 0;
        }
    }

    /// @dev Restricts caller to `operator`.
    ///      Why: proof verification and config changes must be tightly controlled.
    modifier onlyOperator() {
        _onlyOperator();
        _;
    }

    /// @dev Restricts actions while paused.
    ///      Why: a global pause is useful during incident response or upgrades of off-chain infra.
    modifier whenNotPaused() {
        _whenNotPaused();
        _;
    }

    /// @dev Internal check for `operator` gated calls.
    function _onlyOperator() internal view {
        if (msg.sender != operator) revert NotOperator();
    }

    /// @dev Internal check for pause-gated calls.
    function _whenNotPaused() internal view {
        if (paused) revert PausedErr();
    }

    /// @notice Updates the operator address.
    /// @dev Why needed: operator key rotation and operational handoffs.
    ///      How to use: only current operator can call; new operator must be non-zero.
    function setOperator(address newOperator) external onlyOperator {
        if (newOperator == address(0)) revert ZeroAddress();
        emit OperatorChanged(operator, newOperator);
        operator = newOperator;
    }

    /// @notice Pauses/unpauses mutating entry points.
    /// @dev Why needed: emergency stop for deposits/withdrawals/proof-application.
    ///      How to use: only operator can call.
    function setPaused(bool _paused) external onlyOperator {
        paused = _paused;
        emit PausedChanged(_paused);
    }

    /// @notice Pulls ERC20 funds from caller and creates a `Pending` deposit keyed by `noteCommitment`.
    /// @param noteCommitment Unique note commitment key for this deposit.
    /// @param maxAmount Amount attempted via `transferFrom`.
    /// @return The created note commitment.
    /// @dev Why needed:
    ///      - This is the canonical deposit creation entry point for EOAs.
    ///      - The bridge must control escrow to later allow withdrawal or validation.
    ///
    ///      How it must be used:
    ///      - Caller MUST `approve(bridge, maxAmount)` on the monitored ERC20 first.
    ///      - `noteCommitment` MUST be unique (reusing it reverts).
    ///
    ///      Accounting note:
    ///      - Stored value is measured from in-call balance delta (`after - before`) so the bridge records
    ///        actual received amount (handles fee-on-transfer / non-standard ERC20 behavior better than trusting `maxAmount`).
    function depositAndRegister(bytes32 noteCommitment, uint256 maxAmount) external whenNotPaused returns (bytes32) {
        return _depositAndRegister(noteCommitment, msg.sender, msg.sender, maxAmount);
    }

    /// @notice Delegated variant that pulls from `payer` and records their `Pending` deposit.
    /// @param noteCommitment Unique note commitment key for this deposit.
    /// @param payer User address that granted token allowance.
    /// @param maxAmount Amount attempted via `transferFrom`.
    /// @return The created note commitment.
    /// @dev Why needed:
    ///      - Enables relayers/adapters to provide better UX (e.g., permit flows, batching, meta-txs).
    ///
    ///      How it must be used:
    ///      - `payer` MUST have approved the bridge to spend tokens.
    ///      - The recipient is set to `payer` (the withdraw right follows the payer).
    ///      - Method is permissionless; unauthorized callers cannot steal funds because
    ///        tokens are transferred from `payer` and withdrawal rights remain with `payer`.
    function depositAndRegisterFor(
        bytes32 noteCommitment,
        address payer,
        uint256 maxAmount
    ) external whenNotPaused returns (bytes32) {
        return _depositAndRegister(noteCommitment, payer, payer, maxAmount);
    }

    /// @dev Shared deposit implementation for direct and delegated flows.
    ///      Step-by-step:
    ///      1) Enforce uniqueness and input sanity.
    ///      2) Snapshot token balance, execute `transferFrom`, re-snapshot balance.
    ///      3) Derive `value = newBalance - oldBalance` and store deposit.
    ///      4) Emit event.
    function _depositAndRegister(
        bytes32 noteCommitment,
        address payer,
        address recipient,
        uint256 maxAmount
    ) internal returns (bytes32) {
        if (deposits[noteCommitment].status != DepositStatus.None) revert DuplicateNoteCommitment(noteCommitment);
        if (payer == address(0) || recipient == address(0)) revert ZeroAddress();
        if (maxAmount == 0) revert InvalidAmount();

        // Measure received amount using in-call balance delta.
        uint256 previousBalance = IERC20MonitoredToken(monitoredToken).balanceOf(address(this));
        bool ok = IERC20MonitoredToken(monitoredToken).transferFrom(payer, address(this), maxAmount);
        if (!ok) revert TokenTransferFailed();
        uint256 newBalance = IERC20MonitoredToken(monitoredToken).balanceOf(address(this));
        if (newBalance <= previousBalance) revert NoTokenReceived();

        uint256 value = newBalance - previousBalance;

        // Persist canonical deposit record.
        deposits[noteCommitment] = Deposit({value: value, recipient: recipient, status: DepositStatus.Pending});

        emit DepositAvailable(noteCommitment, value, recipient);
        return noteCommitment;
    }

    /// @notice Withdraws a pending deposit back to its designated recipient.
    /// @param noteCommitment Deposit note to withdraw.
    /// @dev Why needed:
    ///      - Provides an exit hatch for users if the operator never validates their note.
    ///
    ///      How it must be used:
    ///      - Only the stored `recipient` can withdraw.
    ///      - Only allowed while the note is still `Pending`.
    ///
    ///      Step-by-step:
    ///      1) Validate existence, status, and caller authorization.
    ///      2) Update state.
    ///      3) Transfer tokens out.
    ///
    ///      Effects are applied before external token transfer to follow checks-effects-interactions.
    function withdrawPendingDeposit(bytes32 noteCommitment) external whenNotPaused {
        Deposit storage dep = deposits[noteCommitment];
        if (dep.status == DepositStatus.None) revert NoteNotFound(noteCommitment);
        if (dep.status != DepositStatus.Pending) revert InvalidDepositState(noteCommitment);
        if (msg.sender != dep.recipient) revert NotDepositRecipient();

        uint256 value = dep.value;
        // Effects: mark withdrawn.
        dep.status = DepositStatus.Withdrawn;

        // Interaction: move escrowed tokens back to the recipient.
        bool ok = IERC20MonitoredToken(monitoredToken).transfer(dep.recipient, value);
        if (!ok) revert TokenTransferFailed();

        emit DepositWithdrawn(noteCommitment, value, dep.recipient);
    }

    /// @notice Records a notes-nullifier tree update after proof verification.
    /// @param newRoot Proposed nullifier tree root after consuming notes.
    /// @param noteCommitments Note commitments consumed in this batch (proof order).
    /// @param treeProof Groth16 proof of correct nullifier tree update.
    /// @param inputsProof Groth16 proof for aggregated public-input validity.
    /// @dev Why needed:
    ///      - This is the canonical on-chain state transition for the notes nullifier tree.
    ///      - The bridge must not accept arbitrary roots; it must enforce ZK correctness.
    ///
    ///      How it must be used:
    ///      - Only operator can call.
    ///      - `0 < noteCommitments.length <= batchSize`.
    ///      - `noteCommitments` order MUST match the prover's circuit order.
    ///      - Missing leaves are deterministically reconstructed on-chain as dummies.
    ///
    ///      Step-by-step:
    ///      1) Snapshot `oldRoot`.
    ///      2) Pack leaves and hash `(oldRoot, newRoot, packedLeaves)` with keccak256.
    ///      3) Convert keccak256 digest to the verifier's 8x uint32 public inputs.
    ///      4) Verify Groth16 proof and, if valid, update the stored root.
    function recordNotesNullifierTreeUpdate(
        bytes32 newRoot,
        bytes32[] calldata noteCommitments,
        Proof calldata treeProof,
        Proof calldata inputsProof
    ) external onlyOperator whenNotPaused {
        uint256 realLen = noteCommitments.length;
        if (realLen == 0 || realLen > batchSize) revert InvalidBatchLength(realLen, batchSize);

        bytes32 oldRoot = notesNullifierRoot;
        bytes32[] memory fullBatch =
            _reconstructBatchWithDummies(TreeType.NotesNullifier, notesNullifierLeafCount, noteCommitments);

        // Pack leaves into bytes for the commitment hash.
        bytes memory noteBytes = _packBytes32ArrayMemory(fullBatch);

        // Public input is keccak256(oldRoot || newRoot || packedLeaves), split into 8x uint32.
        bytes32 keccakCommit = keccak256(abi.encodePacked(oldRoot, newRoot, noteBytes));
        uint256[8] memory pubInputs = keccakToPublicInputs(keccakCommit);

        try aggregatedInputVerifier.verifyProof(
            inputsProof.proof, inputsProof.commitments, inputsProof.commitmentPok, pubInputs
        ) {
            // valid
        } catch {
            revert InvalidinputsProof();
        }

        try nullifierVerifier.verifyProof(treeProof.proof, treeProof.commitments, treeProof.commitmentPok, pubInputs) {
            // valid
        } catch {
            revert InvalidProof();
        }

        // Apply the verified root update (deposit-only path: both latest and confirmed advance).
        notesNullifierRoot = newRoot;
        confirmedNotesNullifierRoot = newRoot;
        notesNullifierLeafCount += batchSize;
        emit ValidatedBatchFinalized(TreeType.NotesNullifier, batchSize, oldRoot, newRoot);
    }

    /// @notice Records a notes-commitment tree update after proof verification.
    /// @param newRoot Proposed commitment tree root after appending notes.
    /// @param noteCommitments Note commitments appended in this batch (proof order).
    /// @param treeProof Groth16 proof of correct commitment tree update.
    /// @param inputsProof Groth16 proof for aggregated public-input validity.
    /// @dev Why needed:
    ///      - Unifies notes-commitment updates with the single-phase semantics used by the other tree APIs.
    ///      - Tracked bridge deposits are validated in the same transaction that updates the root.
    ///
    ///      How it must be used:
    ///      - Only operator can call.
    ///      - `0 < noteCommitments.length <= batchSize`.
    ///      - Leaf ordering MUST match the prover's circuit order.
    ///      - Missing leaves are deterministically reconstructed on-chain as dummies.
    ///
    ///      Tracked-note semantics:
    ///      - If a note exists in bridge storage, it MUST be `Pending`.
    ///      - If a note is not tracked by this bridge, it is treated as external and allowed.
    ///      - For tracked notes in the batch, status is switched `Pending -> Validated` after proof succeeds.
    function recordNotesCommitmentTreeUpdate(
        bytes32 newRoot,
        bytes32[] calldata noteCommitments,
        Proof calldata treeProof,
        Proof calldata inputsProof
    ) external onlyOperator whenNotPaused {
        uint256 realLen = noteCommitments.length;
        if (realLen == 0 || realLen > batchSize) revert InvalidBatchLength(realLen, batchSize);

        bytes32 oldRoot = notesCommitmentRoot;
        bytes32[] memory fullBatch = _reconstructBatchWithDummies(
            TreeType.NotesCommitment, notesCommitmentLeafCount, noteCommitments
        );

        // Fail fast only for notes tracked by this bridge and no longer pending.
        for (uint256 i = 0; i < realLen; i++) {
            bytes32 note = noteCommitments[i];
            DepositStatus status = deposits[note].status;
            if (status != DepositStatus.None && status != DepositStatus.Pending) {
                revert InvalidDepositState(note);
            }
        }

        // Pack leaves into bytes for the commitment hash.
        bytes memory leafBytes = _packBytes32ArrayMemory(fullBatch);

        // Public input is keccak256(oldRoot || newRoot || packedLeaves), split into 8x uint32.
        bytes32 keccakCommit = keccak256(abi.encodePacked(oldRoot, newRoot, leafBytes));
        uint256[8] memory pubInputs = keccakToPublicInputs(keccakCommit);

        try aggregatedInputVerifier.verifyProof(
            inputsProof.proof, inputsProof.commitments, inputsProof.commitmentPok, pubInputs
        ) {
            // valid
        } catch {
            revert InvalidinputsProof();
        }

        try commitmentVerifier.verifyProof(treeProof.proof, treeProof.commitments, treeProof.commitmentPok, pubInputs) {
            // valid
        } catch {
            revert InvalidProof();
        }

        // Apply effects for tracked deposits only.
        for (uint256 i = 0; i < realLen; i++) {
            bytes32 note = noteCommitments[i];
            if (deposits[note].status != DepositStatus.None) {
                deposits[note].status = DepositStatus.Validated;
                emit DepositValidated(note);
            }
        }

        // Apply the verified root update (deposit-only path: both latest and confirmed advance).
        notesCommitmentRoot = newRoot;
        confirmedNotesCommitmentRoot = newRoot;
        notesCommitmentLeafCount += batchSize;
        emit ValidatedBatchFinalized(TreeType.NotesCommitment, batchSize, oldRoot, newRoot);
    }

    /// @notice Records an accounts-commitment tree update after proof verification.
    /// @param newRoot Proposed commitment tree root after appending accounts.
    /// @param accountCommitments Account commitments consumed in this batch (proof order).
    /// @param treeProof Groth16 proof of correct commitment tree update.
    /// @param inputsProof Groth16 proof for aggregated public-input validity.
    /// @dev Why needed:
    ///      - Keeps the on-chain commitment root aligned with off-chain state transitions.
    ///
    ///      How it must be used:
    ///      - Only operator can call.
    ///      - `0 < accountCommitments.length <= batchSize`.
    ///      - Leaf ordering MUST match the prover's circuit order.
    ///      - Missing leaves are deterministically reconstructed on-chain as dummies.
    ///
    ///      Step-by-step mirrors `recordNotesNullifierTreeUpdate`.
    function recordAccountsCommitmentTreeUpdate(
        bytes32 newRoot,
        bytes32[] calldata accountCommitments,
        Proof calldata treeProof,
        Proof calldata inputsProof
    ) external onlyOperator whenNotPaused {
        uint256 realLen = accountCommitments.length;
        if (realLen == 0 || realLen > batchSize) revert InvalidBatchLength(realLen, batchSize);

        bytes32 oldRoot = accountsCommitmentRoot;
        bytes32[] memory fullBatch = _reconstructBatchWithDummies(
            TreeType.AccountsCommitment, accountsCommitmentLeafCount, accountCommitments
        );

        // Pack leaves into bytes for the commitment hash.
        bytes memory leafBytes = _packBytes32ArrayMemory(fullBatch);

        // Public input is keccak256(oldRoot || newRoot || packedLeaves), split into 8x uint32.
        bytes32 keccakCommit = keccak256(abi.encodePacked(oldRoot, newRoot, leafBytes));
        uint256[8] memory pubInputs = keccakToPublicInputs(keccakCommit);

        try aggregatedInputVerifier.verifyProof(
            inputsProof.proof, inputsProof.commitments, inputsProof.commitmentPok, pubInputs
        ) {
            // valid
        } catch {
            revert InvalidinputsProof();
        }

        try commitmentVerifier.verifyProof(treeProof.proof, treeProof.commitments, treeProof.commitmentPok, pubInputs) {
            // valid
        } catch {
            revert InvalidProof();
        }

        // Apply the verified root update (deposit-only path: both latest and confirmed advance).
        accountsCommitmentRoot = newRoot;
        confirmedAccountsCommitmentRoot = newRoot;
        accountsCommitmentLeafCount += batchSize;
        emit ValidatedBatchFinalized(TreeType.AccountsCommitment, batchSize, oldRoot, newRoot);
    }

    /// @notice Records an accounts-nullifier tree update after proof verification.
    /// @param newRoot Proposed nullifier tree root after consuming accounts.
    /// @param accountCommitments Account commitments consumed in this batch (proof order).
    /// @param treeProof Groth16 proof of correct nullifier tree update.
    /// @param inputsProof Groth16 proof for aggregated public-input validity.
    /// @dev Why needed:
    ///      - Prevents double-use of account-related leaves by advancing the nullifier root under proof.
    ///
    ///      How it must be used:
    ///      - Only operator can call.
    ///      - `0 < accountCommitments.length <= batchSize`.
    ///      - Missing leaves are deterministically reconstructed on-chain as dummies.
    ///
    ///      Step-by-step mirrors `recordNotesNullifierTreeUpdate`.
    function recordAccountsNullifierTreeUpdate(
        bytes32 newRoot,
        bytes32[] calldata accountCommitments,
        Proof calldata treeProof,
        Proof calldata inputsProof
    ) external onlyOperator whenNotPaused {
        uint256 realLen = accountCommitments.length;
        if (realLen == 0 || realLen > batchSize) revert InvalidBatchLength(realLen, batchSize);

        bytes32 oldRoot = accountsNullifierRoot;
        bytes32[] memory fullBatch = _reconstructBatchWithDummies(
            TreeType.AccountsNullifier, accountsNullifierLeafCount, accountCommitments
        );

        // Pack leaves into bytes for the commitment hash.
        bytes memory leafBytes = _packBytes32ArrayMemory(fullBatch);

        // Public input is keccak256(oldRoot || newRoot || packedLeaves), split into 8x uint32.
        bytes32 keccakCommit = keccak256(abi.encodePacked(oldRoot, newRoot, leafBytes));
        uint256[8] memory pubInputs = keccakToPublicInputs(keccakCommit);

        try aggregatedInputVerifier.verifyProof(
            inputsProof.proof, inputsProof.commitments, inputsProof.commitmentPok, pubInputs
        ) {
            // valid
        } catch {
            revert InvalidinputsProof();
        }

        try nullifierVerifier.verifyProof(treeProof.proof, treeProof.commitments, treeProof.commitmentPok, pubInputs) {
            // valid
        } catch {
            revert InvalidProof();
        }

        // Apply the verified root update (deposit-only path: both latest and confirmed advance).
        accountsNullifierRoot = newRoot;
        confirmedAccountsNullifierRoot = newRoot;
        accountsNullifierLeafCount += batchSize;
        emit ValidatedBatchFinalized(TreeType.AccountsNullifier, batchSize, oldRoot, newRoot);
    }

    // -------------------------------------------------------------------------
    // Two-phase transaction-batch entry points
    // -------------------------------------------------------------------------

    /// @notice Optimistically registers a private-transaction batch for all four trees at once.
    /// @dev This is the first phase (register) of the two-phase model. All four latest roots are
    ///      updated atomically. Proofs for each tree are submitted separately via confirmTreeUpdate.
    ///
    ///      Why optimistic / non-final:
    ///      - Decouples state-application from proof generation, removing prover latency from
    ///        the hot path. Eventual ZK finality is preserved via confirmTreeUpdate.
    ///
    ///      Gas model:
    ///      - All storage slots in pendingBatches[] were pre-warmed in the constructor (20k → 2.9k).
    ///      - The slot at `batchId % MAX_PENDING_BATCHES` is written in one register call.
    ///
    ///      Deposit safety note (Phase 2):
    ///      - Tracked notes are currently advanced to `Validated` at register time.
    ///      - A future slice will introduce a `Staged` status so withdrawal is blocked only
    ///        until confirmation.
    ///
    /// @param newNotesCommitmentRoot  New notes-commitment tree root after appending noteCommitmentsOut.
    /// @param noteCommitmentsOut      Note commitments added to the commitment tree (proof order).
    /// @param newNotesNullifierRoot   New notes-nullifier tree root after consuming noteNullifiersIn.
    /// @param noteNullifiersIn        Note nullifiers consumed in this batch.
    /// @param newAccountsCommitmentRoot New accounts-commitment tree root.
    /// @param accountCommitmentsOut   Account commitments added to the commitment tree.
    /// @param newAccountsNullifierRoot  New accounts-nullifier tree root.
    /// @param accountNullifiersIn     Account nullifiers consumed in this batch.
    /// @param piCommitments           Pre-computed keccak256 PI digest per tree (index = TREE_* constant).
    ///                                Each is used as-is by confirmTreeUpdate for Groth16 verification.
    /// @return batchId  Unique 1-based ID assigned to this batch.
    function registerTransactionBatchUpdate(
        bytes32 newNotesCommitmentRoot,
        bytes32[] calldata noteCommitmentsOut,
        bytes32 newNotesNullifierRoot,
        bytes32[] calldata noteNullifiersIn,
        bytes32 newAccountsCommitmentRoot,
        bytes32[] calldata accountCommitmentsOut,
        bytes32 newAccountsNullifierRoot,
        bytes32[] calldata accountNullifiersIn,
        bytes32[4] calldata piCommitments
    ) external onlyOperator whenNotPaused returns (uint256 batchId) {
        if (_pendingCount == MAX_PENDING_BATCHES) revert PendingQueueFull();

        // Batch-length checks for all four arrays.
        {
            uint256 bs = batchSize;
            uint256 lenNC = noteCommitmentsOut.length;
            uint256 lenNN = noteNullifiersIn.length;
            uint256 lenAC = accountCommitmentsOut.length;
            uint256 lenAN = accountNullifiersIn.length;
            if (lenNC == 0 || lenNC > bs) revert InvalidBatchLength(lenNC, bs);
            if (lenNN == 0 || lenNN > bs) revert InvalidBatchLength(lenNN, bs);
            if (lenAC == 0 || lenAC > bs) revert InvalidBatchLength(lenAC, bs);
            if (lenAN == 0 || lenAN > bs) revert InvalidBatchLength(lenAN, bs);
        }

        // Notes-commitment: check deposit state for tracked notes, then validate them.
        {
            uint256 realLen = noteCommitmentsOut.length;
            for (uint256 i = 0; i < realLen; i++) {
                bytes32 note = noteCommitmentsOut[i];
                DepositStatus status = deposits[note].status;
                if (status != DepositStatus.None && status != DepositStatus.Pending) {
                    revert InvalidDepositState(note);
                }
            }
            for (uint256 i = 0; i < realLen; i++) {
                bytes32 note = noteCommitmentsOut[i];
                if (deposits[note].status != DepositStatus.None) {
                    deposits[note].status = DepositStatus.Validated;
                    emit DepositValidated(note);
                }
            }
        }

        // Assign batch ID and compute slot.
        batchId = _nextBatchId++;
        uint256 slotIndex = batchId % MAX_PENDING_BATCHES;

        // Defensive: slot should always be free if _pendingCount < MAX_PENDING_BATCHES.
        if (pendingBatches[slotIndex].batchId != 0) revert SlotConflict(slotIndex);

        // Write pending record into the pre-warmed slot.
        PendingBatch storage slot = pendingBatches[slotIndex];
        slot.batchId                   = batchId;
        slot.newNotesCommitmentRoot    = newNotesCommitmentRoot;
        slot.newNotesNullifierRoot     = newNotesNullifierRoot;
        slot.newAccountsCommitmentRoot = newAccountsCommitmentRoot;
        slot.newAccountsNullifierRoot  = newAccountsNullifierRoot;
        slot.piCommitments[TREE_NOTES_COMMITMENT]    = piCommitments[TREE_NOTES_COMMITMENT];
        slot.piCommitments[TREE_NOTES_NULLIFIER]     = piCommitments[TREE_NOTES_NULLIFIER];
        slot.piCommitments[TREE_ACCOUNTS_COMMITMENT] = piCommitments[TREE_ACCOUNTS_COMMITMENT];
        slot.piCommitments[TREE_ACCOUNTS_NULLIFIER]  = piCommitments[TREE_ACCOUNTS_NULLIFIER];
        slot.confirmedMask = 0;

        // Advance latest roots and leaf counts for all four trees.
        notesCommitmentRoot    = newNotesCommitmentRoot;
        notesNullifierRoot     = newNotesNullifierRoot;
        accountsCommitmentRoot = newAccountsCommitmentRoot;
        accountsNullifierRoot  = newAccountsNullifierRoot;
        notesCommitmentLeafCount    += batchSize;
        notesNullifierLeafCount     += batchSize;
        accountsCommitmentLeafCount += batchSize;
        accountsNullifierLeafCount  += batchSize;

        _pendingCount++;

        emit TransactionBatchRegistered(
            batchId,
            newNotesCommitmentRoot,
            newNotesNullifierRoot,
            newAccountsCommitmentRoot,
            newAccountsNullifierRoot,
            piCommitments
        );
    }

    /// @notice Confirms a single tree's proof for a previously registered transaction batch.
    /// @dev Second phase of the two-phase model. Each tree is confirmed independently; the batch
    ///      is fully finalized only when all four trees are confirmed (confirmedMask == 0xF).
    ///
    ///      Proof binding: `piCommitments[treeIndex]` stored at register time is used directly as
    ///      the 8x uint32 Groth16 public inputs. No leaf data re-submission required.
    ///
    ///      Retry safety: if the transaction lands after a crash the caller can read
    ///      `pendingBatches[batchId % MAX_PENDING_BATCHES].confirmedMask` to check which trees
    ///      are already confirmed and skip them (avoiding AlreadyConfirmed revert).
    ///
    /// @param batchId    Batch ID returned by registerTransactionBatchUpdate.
    /// @param treeIndex  TREE_* constant (0-3) identifying which tree to confirm.
    /// @param treeProof  Groth16 proof for the tree circuit.
    /// @param inputsProof Groth16 proof for aggregated public-input validity.
    function confirmTreeUpdate(
        uint256 batchId,
        uint8   treeIndex,
        Proof calldata treeProof,
        Proof calldata inputsProof
    ) external onlyOperator whenNotPaused {
        if (treeIndex > 3) revert InvalidTreeIndex(treeIndex);

        uint256 slotIndex = batchId % MAX_PENDING_BATCHES;
        PendingBatch storage slot = pendingBatches[slotIndex];

        if (slot.batchId != batchId) revert UnknownBatch(batchId);

        uint8 bit = uint8(1 << treeIndex);
        if (slot.confirmedMask & bit != 0) revert AlreadyConfirmed(batchId, treeIndex);

        // Derive public inputs from the stored PI commitment for this tree.
        uint256[8] memory pubInputs = keccakToPublicInputs(slot.piCommitments[treeIndex]);

        // Verify aggregated inputs proof.
        try aggregatedInputVerifier.verifyProof(
            inputsProof.proof, inputsProof.commitments, inputsProof.commitmentPok, pubInputs
        ) {
            // valid
        } catch {
            revert InvalidinputsProof();
        }

        // Verify tree proof using the appropriate verifier circuit.
        IGroth16Verifier verifier = (treeIndex == TREE_NOTES_COMMITMENT || treeIndex == TREE_ACCOUNTS_COMMITMENT)
            ? commitmentVerifier
            : nullifierVerifier;
        try verifier.verifyProof(treeProof.proof, treeProof.commitments, treeProof.commitmentPok, pubInputs) {
            // valid
        } catch {
            revert InvalidProof();
        }

        // Mark tree as confirmed and advance the per-tree confirmed root.
        slot.confirmedMask |= bit;
        if (treeIndex == TREE_NOTES_COMMITMENT) {
            confirmedNotesCommitmentRoot = slot.newNotesCommitmentRoot;
        } else if (treeIndex == TREE_NOTES_NULLIFIER) {
            confirmedNotesNullifierRoot = slot.newNotesNullifierRoot;
        } else if (treeIndex == TREE_ACCOUNTS_COMMITMENT) {
            confirmedAccountsCommitmentRoot = slot.newAccountsCommitmentRoot;
        } else {
            confirmedAccountsNullifierRoot = slot.newAccountsNullifierRoot;
        }
        emit TreeUpdateConfirmed(batchId, treeIndex);

        // Fully confirmed: free the slot.
        if (slot.confirmedMask == 0xF) {
            emit TransactionBatchConfirmed(batchId);
            slot.batchId       = 0;
            slot.confirmedMask = 0;
            _pendingCount--;
        }
    }

    /// @dev Packs a `bytes32[]` into a contiguous byte array (32 bytes per element, in order).
    ///      Why this exists:
    ///      - The Groth16 public-input commitment uses keccak256 over packed bytes.
    ///      - Any change to packing/order will invalidate proofs.
    function _packBytes32Array(bytes32[] calldata arr) internal pure returns (bytes memory out) {
        out = new bytes(arr.length * 32);
        for (uint256 i = 0; i < arr.length; i++) {
            bytes32 v = arr[i];
            assembly {
                mstore(add(add(out, 32), mul(i, 32)), v)
            }
        }
    }

    function _packBytes32ArrayMemory(bytes32[] memory arr) internal pure returns (bytes memory out) {
        out = new bytes(arr.length * 32);
        for (uint256 i = 0; i < arr.length; i++) {
            bytes32 v = arr[i];
            assembly {
                mstore(add(add(out, 32), mul(i, 32)), v)
            }
        }
    }

    function _reconstructBatchWithDummies(
        TreeType treeType,
        uint256 batchStartIndex,
        bytes32[] calldata realLeaves
    ) internal view returns (bytes32[] memory out) {
        uint256 realLen = realLeaves.length;
        out = new bytes32[](batchSize);
        for (uint256 i = 0; i < realLen; i++) {
            out[i] = realLeaves[i];
        }
        if (realLen == batchSize) {
            return out;
        }

        bytes32 packedHash = keccak256(
            abi.encodePacked(uint8(treeType), batchStartIndex, _packBytes32Array(realLeaves))
        );
        for (uint256 i = realLen; i < batchSize; i++) {
            uint256 leafIndex = batchStartIndex + i;
            bytes32 raw = keccak256(abi.encodePacked(leafIndex, packedHash));
            out[i] = _fieldSafeDigest(raw);
        }
    }

    function _fieldSafeDigest(bytes32 digest) internal pure returns (bytes32) {
        uint256 h = uint256(digest);
        uint256 mask = ~(uint256(1) << 255 | uint256(1) << 191 | uint256(1) << 127 | uint256(1) << 63);
        return bytes32(h & mask);
    }

    /// @notice Computes the legacy deposit commitment used by some off-chain tooling.
    /// @dev Why this exists:
    ///      - Some circuits/tools require a "leaf commitment" for deposit metadata.
    ///
    ///      How it must be used:
    ///      - This helper does not interact with on-chain storage; it is pure.
    ///      - The returned commitment clears the MSB of each 64-bit limb to fit in the Goldilocks field.
    function computeDepositCommitment(bytes32 noteCommitment, uint256 value, address recipient) public pure returns (bytes32) {
        bytes32 digest = sha256(abi.encodePacked(DOMAIN_SEP, noteCommitment, value, recipient));

        uint256 mask = ~(uint256(1) << 255 | uint256(1) << 191 | uint256(1) << 127 | uint256(1) << 63);
        return bytes32(uint256(digest) & mask);
    }

    /// @notice Converts a bytes32 keccak256 digest into 8 public inputs (uint32 words) expected by the gnark verifier.
    /// @dev Why needed:
    ///      - The generated verifier takes an array of 8 uint32-like values as public inputs.
    ///      - Splits the 256-bit digest into 8 big-endian uint32 words, matching the
    ///        Rust circuit's Keccak-256 commitment output (8 u32 words, big-endian).
    ///
    ///      How it must be used:
    ///      - The conversion here must match the circuit/verifier encoding exactly.
    ///      - Do not mix with `sha256ToPublicInputs`; only one hash is in use at a time.
    function keccakToPublicInputs(bytes32 hash) public pure returns (uint256[8] memory inputs) {
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

    /// @notice Converts a bytes32 SHA256 digest into 8 public inputs (uint32 words).
    /// @dev Kept for reference and tooling compatibility; not used by tree-update proof paths
    ///      after the Keccak-256 migration.  Use `keccakToPublicInputs` for all new proofs.
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
    /// @dev Why needed: convenience accessor with existence check; avoids silent "all zero" mapping reads.
    function getDeposit(bytes32 noteCommitment) external view returns (Deposit memory) {
        Deposit memory dep = deposits[noteCommitment];
        if (dep.status == DepositStatus.None) revert NoteNotFound(noteCommitment);
        return dep;
    }

    /// @notice Reads deposit status for `noteCommitment`.
    /// @dev Returns `DepositStatus.None` when the note is not tracked by this bridge.
    ///      Used by off-chain sequencer preflight checks to distinguish tracked vs external leaves.
    function getDepositStatus(bytes32 noteCommitment) external view returns (DepositStatus) {
        return deposits[noteCommitment].status;
    }
}
