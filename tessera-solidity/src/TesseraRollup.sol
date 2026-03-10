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
///        tree-specific verifier (`notesCommitmentVerifier`, `notesNullifierVerifier`,
///        `accountsCommitmentVerifier`, or `accountsNullifierVerifier`).
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

    /// @notice Groth16 verifier for the single super-aggregator proof covering all 5 sub-circuits.
    IGroth16Verifier public immutable superAggregatorVerifier;

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
    /// @notice Fixed batch size for note-tree circuits (notesCommitment and notesNullifier).
    /// @dev Must be a power of two and exactly 8× `accountBatchSize`.
    uint256 public immutable noteBatchSize;
    /// @notice Fixed batch size for account-tree circuits (accountsCommitment and accountsNullifier).
    /// @dev Must be a power of two and exactly 1/8 of `noteBatchSize`.
    uint256 public immutable accountBatchSize;
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

    /// @notice Maximum number of simultaneously in-flight transaction batches.
    /// @dev Sized to pre-allocate a fixed-size storage buffer so every register/confirm
    ///      writes into an already-warm slot (2,900 gas) rather than cold (20,000 gas).
    uint256 public constant MAX_PENDING_BATCHES = 128;

    /// @notice On-chain record for a pending transaction batch (registered but not yet confirmed).
    struct PendingBatch {
        /// @notice 0 = free slot; set on register, cleared on confirmation.
        uint256 batchId;
        bytes32 newNotesCommitmentRoot;
        bytes32 newNotesNullifierRoot;
        bytes32 newAccountsCommitmentRoot;
        bytes32 newAccountsNullifierRoot;
        /// @notice keccak256 of the four tree circuits' raw public inputs, concatenated.
        ///         TX PIs are excluded (enforced in-circuit by the SuperAggregator).
        ///         Used as the single Groth16 public input for confirmBatch verification.
        bytes32 superPiCommitment;
        /// @notice Set to true once confirmBatch has verified the super-aggregator proof.
        bool confirmed;
    }

    /// @notice Pre-warmed pending-batch buffer. Indexed by batchId % MAX_PENDING_BATCHES.
    mapping(uint256 => PendingBatch) public pendingBatches;

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
        uint256 effectiveBatchSize,
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
        bytes32 superPiCommitment
    );
    /// @dev Emitted when the super-aggregator proof for a batch is confirmed and all roots advance.
    event BatchConfirmed(uint256 indexed batchId);
    /// @dev Debug: per-tree Keccak sub-hashes of the superPiCommitment preimage.
    ///      Compare ncHash/nnHash/acHash/anHash against the Rust prover INFO log
    ///      "native Keccak preimage sub-hashes" to pinpoint which tree's data diverges.
    event SuperPiDebug(bytes32 ncHash, bytes32 nnHash, bytes32 acHash, bytes32 anHash, bytes32 fullHash);

    error NotOperator();
    error PausedErr();
    error InvalidProof();
    /// @dev Emitted (instead of InvalidProof) when the Groth16 verifier rejects a proof.
    ///      Includes the on-chain commitment and the 8 public inputs derived from it so the
    ///      caller can compare against the prover's `super_pi_commitment` log output.
    error ProofVerificationFailed(bytes32 superPiCommitment, uint256[8] pubInputs);
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
    error PendingQueueFull();
    error SlotConflict(uint256 slotIndex);
    error UnknownBatch(uint256 batchId);
    error BatchAlreadyConfirmed(uint256 batchId);
    error NotSorted(uint256 index);

    /// @notice Deploy bridge with verifier address, initial roots, and access-control parameters.
    /// @dev Why these parameters exist:
    ///      - The super-aggregator verifier is immutable: the deployed circuit/vk is part of
    ///        the security boundary. It covers all 5 sub-circuits in a single Groth16 proof.
    ///      - Roots are initialized to the agreed genesis values shared with the off-chain prover.
    ///      - `operator` is the only entity allowed to verify proofs on-chain (load/record functions).
    ///
    ///      Usage constraints:
    ///      - `_noteBatchSize` must be a power of two and exactly `_accountBatchSize * 8`.
    ///      - `_superAggregatorVerifier` must match the deployed super-aggregator circuit artifacts.
    ///      - `_monitoredToken` must be the ERC20 whose balance this bridge escrows.
    constructor(
        address _superAggregatorVerifier,
        address _operator,
        bytes32 _notesNullifierRoot,
        bytes32 _notesCommitmentRoot,
        bytes32 _accountsNullifierRoot,
        bytes32 _accountsCommitmentRoot,
        uint256 _noteBatchSize,
        uint256 _accountBatchSize,
        address _monitoredToken
    ) {
        if (_operator == address(0)) revert ZeroAddress();
        if (_noteBatchSize == 0 || _noteBatchSize & (_noteBatchSize - 1) != 0) revert InvalidBatchSize();
        if (_accountBatchSize == 0 || _accountBatchSize & (_accountBatchSize - 1) != 0) revert InvalidBatchSize();
        if (_noteBatchSize != _accountBatchSize * 8) revert InvalidBatchSize();
        if (_monitoredToken == address(0)) revert InvalidMonitoredToken();

        // Store immutable verifier address. Defines the single circuit that confirms all roots.
        superAggregatorVerifier = IGroth16Verifier(_superAggregatorVerifier);

        // Initialize roles.
        operator = _operator;
        // Initialize roots to the agreed genesis state.
        notesNullifierRoot = _notesNullifierRoot;
        notesCommitmentRoot = _notesCommitmentRoot;
        accountsNullifierRoot = _accountsNullifierRoot;
        accountsCommitmentRoot = _accountsCommitmentRoot;

        // Batch sizes are circuit-defined and must match the prover configuration.
        noteBatchSize    = _noteBatchSize;
        accountBatchSize = _accountBatchSize;
        // Commitment trees start empty; nullifier trees are pre-padded to batch_size
        // alignment (1 sentinel + batch_size-1 deterministic padding leaves) so the
        // first real batch starts at index batch_size.  Must match the Rust sequencer's
        // NullifierTree::new_with_padding(depth, batch_size).num_leaves().
        notesCommitmentLeafCount = 0;
        notesNullifierLeafCount = _noteBatchSize;
        accountsCommitmentLeafCount = 0;
        accountsNullifierLeafCount = _accountBatchSize;

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
        // Write then immediately clear `confirmed` on each slot: cold write (20k gas) done
        // once here so confirmBatch only pays 2,900 gas for warm rewrites.
        for (uint256 i = 0; i < MAX_PENDING_BATCHES; i++) {
            pendingBatches[i].confirmed = true;
            pendingBatches[i].confirmed = false;
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
    /// @param noteNullifiersIn        Full sorted note-nullifier batch (exactly noteBatchSize elements,
    ///        pre-sorted ascending by uint256 value, including deterministic dummies).
    ///        The sequencer computes dummies and sorts; the contract only verifies sort order.
    /// @param newAccountsCommitmentRoot New accounts-commitment tree root.
    /// @param accountCommitmentsOut   Account commitments added to the commitment tree.
    /// @param newAccountsNullifierRoot  New accounts-nullifier tree root.
    /// @param accountNullifiersIn     Full sorted account-nullifier batch (exactly accountBatchSize
    ///        elements, pre-sorted ascending, including deterministic dummies).
    /// @return batchId  Unique 1-based ID assigned to this batch.
    function registerTransactionBatchUpdate(
        bytes32 newNotesCommitmentRoot,
        bytes32[] calldata noteCommitmentsOut,
        bytes32 newNotesNullifierRoot,
        bytes32[] calldata noteNullifiersIn,
        bytes32 newAccountsCommitmentRoot,
        bytes32[] calldata accountCommitmentsOut,
        bytes32 newAccountsNullifierRoot,
        bytes32[] calldata accountNullifiersIn
    ) external onlyOperator whenNotPaused returns (uint256 batchId) {
        if (_pendingCount == MAX_PENDING_BATCHES) revert PendingQueueFull();

        // Batch-length checks: all 4 arrays must be exactly batch_size (full sorted batches).
        {
            uint256 nbs = noteBatchSize;
            uint256 abs_ = accountBatchSize;
            if (noteCommitmentsOut.length  != nbs)  revert InvalidBatchLength(noteCommitmentsOut.length,  nbs);
            if (noteNullifiersIn.length    != nbs)  revert InvalidBatchLength(noteNullifiersIn.length,    nbs);
            if (accountCommitmentsOut.length != abs_) revert InvalidBatchLength(accountCommitmentsOut.length, abs_);
            if (accountNullifiersIn.length   != abs_) revert InvalidBatchLength(accountNullifiersIn.length,   abs_);
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

        // Nullifier batches: verify ascending order (NN and AN).
        _requireSorted(noteNullifiersIn);
        _requireSorted(accountNullifiersIn);

        // Pack each tree's PI: old_root || new_root || leaves (matches circuit Keccak preimage).
        // All 4 arrays are full sorted batches passed directly from calldata.
        bytes memory ncPacked = _packBytes32Array(noteCommitmentsOut);
        bytes memory nnPacked = _packBytes32Array(noteNullifiersIn);
        bytes memory acPacked = _packBytes32Array(accountCommitmentsOut);
        bytes memory anPacked = _packBytes32Array(accountNullifiersIn);

        // Compute superPiCommitment: keccak256(nc_pis || nn_pis || ac_pis || an_pis).
        bytes32 superPiCommitment = keccak256(abi.encodePacked(
            notesCommitmentRoot, newNotesCommitmentRoot, ncPacked,
            notesNullifierRoot, newNotesNullifierRoot, nnPacked,
            accountsCommitmentRoot, newAccountsCommitmentRoot, acPacked,
            accountsNullifierRoot, newAccountsNullifierRoot, anPacked
        ));

        // Debug: per-tree sub-hashes for mismatch diagnosis.
        emit SuperPiDebug(
            keccak256(abi.encodePacked(notesCommitmentRoot, newNotesCommitmentRoot, ncPacked)),
            keccak256(abi.encodePacked(notesNullifierRoot, newNotesNullifierRoot, nnPacked)),
            keccak256(abi.encodePacked(accountsCommitmentRoot, newAccountsCommitmentRoot, acPacked)),
            keccak256(abi.encodePacked(accountsNullifierRoot, newAccountsNullifierRoot, anPacked)),
            superPiCommitment
        );

        // Write pending record into the pre-warmed slot.
        PendingBatch storage slot = pendingBatches[slotIndex];
        slot.batchId                   = batchId;
        slot.newNotesCommitmentRoot    = newNotesCommitmentRoot;
        slot.newNotesNullifierRoot     = newNotesNullifierRoot;
        slot.newAccountsCommitmentRoot = newAccountsCommitmentRoot;
        slot.newAccountsNullifierRoot  = newAccountsNullifierRoot;
        slot.superPiCommitment         = superPiCommitment;
        slot.confirmed                 = false;

        // Advance latest roots and leaf counts; note trees use noteBatchSize, account trees use accountBatchSize.
        notesCommitmentRoot    = newNotesCommitmentRoot;
        notesNullifierRoot     = newNotesNullifierRoot;
        accountsCommitmentRoot = newAccountsCommitmentRoot;
        accountsNullifierRoot  = newAccountsNullifierRoot;
        notesCommitmentLeafCount    += noteBatchSize;
        notesNullifierLeafCount     += noteBatchSize;
        accountsCommitmentLeafCount += accountBatchSize;
        accountsNullifierLeafCount  += accountBatchSize;

        _pendingCount++;

        emit TransactionBatchRegistered(
            batchId,
            newNotesCommitmentRoot,
            newNotesNullifierRoot,
            newAccountsCommitmentRoot,
            newAccountsNullifierRoot,
            superPiCommitment
        );
    }

    /// @notice Confirms a registered transaction batch by verifying the single super-aggregator proof.
    /// @dev Second phase of the two-phase model. One call per batch replaces the previous five
    ///      separate confirmation calls (4 tree proofs + 1 inputs proof). The super-aggregator
    ///      proof covers all 5 inner circuits and commits to all raw public inputs via a single
    ///      keccak256 digest (`superPiCommitment`) computed at registerTransactionBatchUpdate time.
    ///
    ///      Retry safety: if `slot.batchId != batchId` the slot was already freed (already confirmed
    ///      or never registered) — call reverts with `UnknownBatch`.
    ///
    /// @param batchId  Batch ID returned by registerTransactionBatchUpdate.
    /// @param proof    Groth16 super-aggregator proof.
    function confirmBatch(
        uint256 batchId,
        Proof calldata proof
    ) external onlyOperator whenNotPaused {
        uint256 slotIndex = batchId % MAX_PENDING_BATCHES;
        PendingBatch storage slot = pendingBatches[slotIndex];

        if (slot.batchId != batchId) revert UnknownBatch(batchId);
        if (slot.confirmed) revert BatchAlreadyConfirmed(batchId);

        uint256[8] memory pubInputs = keccakToPublicInputs(slot.superPiCommitment);

        try superAggregatorVerifier.verifyProof(
            proof.proof, proof.commitments, proof.commitmentPok, pubInputs
        ) {
            // valid
        } catch {
            revert ProofVerificationFailed(slot.superPiCommitment, pubInputs);
        }

        slot.confirmed = true;
        _tryFinalizeBatch(slot, batchId);
    }

    /// @dev Advances all confirmed roots and frees the batch slot once the super-aggregator proof
    ///      has been verified. Called by confirmBatch; roots advance atomically.
    function _tryFinalizeBatch(PendingBatch storage slot, uint256 batchId) internal {
        if (!slot.confirmed) return;
        confirmedNotesCommitmentRoot    = slot.newNotesCommitmentRoot;
        confirmedNotesNullifierRoot     = slot.newNotesNullifierRoot;
        confirmedAccountsCommitmentRoot = slot.newAccountsCommitmentRoot;
        confirmedAccountsNullifierRoot  = slot.newAccountsNullifierRoot;
        emit BatchConfirmed(batchId);
        slot.batchId    = 0;
        slot.confirmed  = false;
        _pendingCount--;
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


    /// @dev Verifies that a calldata bytes32[] is sorted in ascending uint256 order.
    ///      Reverts with `NotSorted(i)` at the first out-of-order pair.
    ///      O(n) — one comparison per element.
    function _requireSorted(bytes32[] calldata arr) internal pure {
        uint256 n = arr.length;
        for (uint256 i = 1; i < n; i++) {
            if (uint256(arr[i]) < uint256(arr[i - 1])) revert NotSorted(i);
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

    // -------------------------------------------------------------------------
    // Debug helpers (not part of the production security surface)
    // -------------------------------------------------------------------------

    /// @notice Returns the stored superPiCommitment and the 8 Groth16 public inputs that
    ///         `confirmBatch` will derive from it for the given batch.
    /// @dev Compare the returned `superPiCommitment` against the Rust prover log line
    ///      "super_pi_commitment = 0x..." to determine whether there is a preimage mismatch
    ///      (commitments differ) or a verifying-key mismatch (commitments match but proof fails).
    function getBatchDebugInfo(uint256 batchId)
        external view
        returns (bytes32 superPiCommitment, uint256[8] memory pubInputs)
    {
        uint256 slotIndex = batchId % MAX_PENDING_BATCHES;
        PendingBatch storage slot = pendingBatches[slotIndex];
        if (slot.batchId != batchId) revert UnknownBatch(batchId);
        superPiCommitment = slot.superPiCommitment;
        pubInputs = keccakToPublicInputs(superPiCommitment);
    }

    /// @notice Dry-runs the Groth16 verifier with an explicit superPiCommitment.
    /// @dev Allows decoupling the commitment-derivation step from the verifier step.
    ///      - Call with the on-chain stored commitment (from getBatchDebugInfo or the
    ///        TransactionBatchRegistered event) to test the verifier with the correct inputs.
    ///      - Call with the Rust prover's super_pi_commitment to test if the VK accepts
    ///        the proof when given the prover's own commitment.
    ///      Returns true if the verifier accepts, false if it reverts.
    function verifyProofDry(bytes32 superPiCommitment, Proof calldata proof)
        external view
        returns (bool)
    {
        uint256[8] memory inputs = keccakToPublicInputs(superPiCommitment);
        try superAggregatorVerifier.verifyProof(
            proof.proof, proof.commitments, proof.commitmentPok, inputs
        ) {
            return true;
        } catch {
            return false;
        }
    }
}
