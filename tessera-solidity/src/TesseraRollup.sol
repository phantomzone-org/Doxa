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
/// @notice ERC20 deposit escrow + ZK-proven batch validation for note commitments.
/// @dev High-level model:
///      - Users (or a `trustedSource` adapter) create deposits keyed by `noteCommitment`.
///      - While still `Pending`, the recipient can withdraw the escrowed tokens.
///      - The operator proves batched validation and advances `notesCommitmentRoot`.
///
///      Two-phase validation (recommended path):
///      1) Operator calls `loadValidateDepositBatch(newRoot, notes, proof)` to verify the proof and store the batch.
///      2) Anyone calls `executeValidateDepositBatch(newRoot, notes)` to apply it (permissionless finalization).
///
///      Why two phases?
///      - It decouples expensive proof verification (operator-only) from applying the already-proven transition.
///      - It improves liveness: if the operator goes down after loading, any relayer can still execute.
///      - It enables safe retries (idempotency) keyed by an `actionHash`.
///
///      Proof binding:
///      - For batch validation and tree updates, the verifier input is derived from
///        `SHA256(oldRoot || newRoot || packedLeaves)` converted to 8x uint32 public inputs.
///
///      Important safety note:
///      - `executeValidateDepositBatch` re-checks that every note is still `Pending`, because a user
///        might withdraw after the operator loads a batch but before anyone executes it.
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

    /// @notice Placeholder proof payload for aggregated public-input validity checks.
    /// @dev Phase A: this is not verified cryptographically yet; the contract only checks
    ///      that it is present and non-empty. Future phases can replace this with a strict
    ///      verifier-backed structure without changing call shape.
    struct AggregatedInputProof {
        bytes proofData;
    }

    /// @notice Domain separator used for off-chain commitments and action hashing.
    /// @dev Chosen to be stable across deployments of this contract family.
    bytes32 public constant DOMAIN_SEP = sha256("tessera.rollup.v1");

    /// @notice Groth16 verifier for commitment-style circuits (append / commitment tree updates).
    IGroth16Verifier public immutable commitmentVerifier;
    /// @notice Groth16 verifier for nullifier-style circuits (chained/consuming updates).
    IGroth16Verifier public immutable nullifierVerifier;

    /// @notice Governance/operator address for configuration and proof-verification entry points.
    address public operator;
    /// @notice Trusted source for delegated user deposits (and any other privileged adapter flows).
    /// @dev In local/dev this is typically a helper like `ToyUser` that atomically checks allowance and calls the bridge.
    address public trustedSource;

    /// @notice Notes nullifier tree root (proven by `nullifierVerifier`).
    bytes32 public notesNullifierRoot;
    /// @notice Notes commitment tree root (proven by `commitmentVerifier`).
    bytes32 public notesCommitmentRoot;
    /// @notice Accounts nullifier tree root (proven by `nullifierVerifier`).
    bytes32 public accountsNullifierRoot;
    /// @notice Accounts commitment tree root (proven by `commitmentVerifier`).
    bytes32 public accountsCommitmentRoot;
    /// @notice Fixed batch size required by the circuits/verifiers.
    /// @dev All batch entry points require exactly `batchSize` leaves.
    uint256 public immutable batchSize;

    /// @notice ERC20 token escrowed by this bridge for pending deposits.
    address public immutable monitoredToken;
    /// @notice Internal accounting tracker for total pending/validated escrow observed by bridge flows.
    /// @dev Updated on deposit creation and pending withdrawals.
    uint256 public lastMonitoredBalance;

    /// @notice Global pause flag for mutating entry points.
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
    event DepositValidationBatchLoaded(
        bytes32 indexed actionHash,
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot,
        bytes32 notesHash,
        uint256 batchSize
    );
    event DepositValidationBatchCanceled(
        bytes32 indexed actionHash,
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot,
        bytes32 notesHash,
        uint256 batchSize
    );
    event DepositValidationBatchExecuted(
        bytes32 indexed actionHash,
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot,
        bytes32 notesHash,
        uint256 batchSize
    );

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
    error LoadedBatchNotFound(bytes32 actionHash);
    error InvalidAggregatedInputProof();

    /// @notice Minimal stored metadata for a loaded validation batch.
    /// @dev We intentionally do not store the full note list to keep storage bounded; instead we store `notesHash`.
    ///      The execution call must provide the exact ordered notes used during load.
    struct LoadedValidationBatch {
        bytes32 oldRoot;
        bytes32 newRoot;
        bytes32 notesHash;
    }

    /// @dev actionHash => loaded candidates.
    ///      Multiple candidates can exist for the same `actionHash` because:
    ///      - `actionHash` intentionally does not include `oldRoot` (it is derived from `newRoot` + `notesHash`)
    ///      - the operator may load the same logical batch against different old roots due to reorgs or retries
    ///      Execution selects the candidate whose `oldRoot` matches the current on-chain `notesCommitmentRoot`.
    mapping(bytes32 => LoadedValidationBatch[]) internal _loadedValidationBatches;

    /// @notice Deploy bridge with verifier addresses, initial roots, and access-control parameters.
    /// @dev Why these parameters exist:
    ///      - Verifiers are immutable: the deployed circuit/vk is part of the security boundary.
    ///      - Roots are initialized to the agreed genesis values shared with the off-chain prover.
    ///      - `operator` is the only entity allowed to verify proofs on-chain (load/record functions).
    ///      - `trustedSource` is the only entity allowed to record deposits on behalf of users.
    ///
    ///      Usage constraints:
    ///      - `_batchSize` must match the circuit's expected batch size (immutable once deployed).
    ///      - `_monitoredToken` must be the ERC20 whose balance this bridge escrows.
    constructor(
        address _commitmentVerifier,
        address _nullifierVerifier,
        address _operator,
        address _trustedSource,
        bytes32 _notesNullifierRoot,
        bytes32 _notesCommitmentRoot,
        bytes32 _accountsNullifierRoot,
        bytes32 _accountsCommitmentRoot,
        uint256 _batchSize,
        address _monitoredToken
    ) {
        if (_operator == address(0) || _trustedSource == address(0)) revert ZeroAddress();
        if (_batchSize == 0) revert InvalidBatchSize();
        if (_monitoredToken == address(0)) revert InvalidMonitoredToken();

        // Store immutable verifier addresses. These define the circuits that can update roots.
        commitmentVerifier = IGroth16Verifier(_commitmentVerifier);
        nullifierVerifier = IGroth16Verifier(_nullifierVerifier);

        // Initialize roles.
        operator = _operator;
        trustedSource = _trustedSource;

        // Initialize roots to the agreed genesis state.
        notesNullifierRoot = _notesNullifierRoot;
        notesCommitmentRoot = _notesCommitmentRoot;
        accountsNullifierRoot = _accountsNullifierRoot;
        accountsCommitmentRoot = _accountsCommitmentRoot;

        // Batch size is circuit-defined and must match the prover configuration.
        batchSize = _batchSize;

        // Token escrow configuration and initial balance snapshot.
        monitoredToken = _monitoredToken;
        lastMonitoredBalance = IERC20MonitoredToken(_monitoredToken).balanceOf(address(this));
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

    /// @dev Restricts caller to `trustedSource`.
    ///      Why: delegated deposit creation should only be callable by a known adapter contract.
    modifier onlyTrustedSource() {
        _onlyTrustedSource();
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

    /// @dev Internal check for `trustedSource` gated calls.
    function _onlyTrustedSource() internal view {
        if (msg.sender != trustedSource) revert NotTrustedSource();
    }

    /// @notice Updates the operator address.
    /// @dev Why needed: operator key rotation and operational handoffs.
    ///      How to use: only current operator can call; new operator must be non-zero.
    function setOperator(address newOperator) external onlyOperator {
        if (newOperator == address(0)) revert ZeroAddress();
        emit OperatorChanged(operator, newOperator);
        operator = newOperator;
    }

    /// @notice Updates the trusted source address.
    /// @dev Why needed: trusted adapter upgrades (e.g., replace `ToyUser` with a production adapter).
    ///      How to use: only operator can call; new trusted source must be non-zero.
    function setTrustedSource(address newTrustedSource) external onlyOperator {
        if (newTrustedSource == address(0)) revert ZeroAddress();
        emit TrustedSourceChanged(trustedSource, newTrustedSource);
        trustedSource = newTrustedSource;
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

    /// @notice Trusted-source variant that pulls from a user and records their `Pending` deposit.
    /// @param noteCommitment Unique note commitment key for this deposit.
    /// @param payer User address that granted token allowance.
    /// @param maxAmount Amount attempted via `transferFrom`.
    /// @return The created note commitment.
    /// @dev Why needed:
    ///      - Enables adapter contracts to provide better UX (e.g., `permit` flows, custom batching, meta-txs).
    ///
    ///      How it must be used:
    ///      - Only `trustedSource` can call.
    ///      - `payer` MUST have approved the bridge to spend tokens.
    ///      - The recipient is set to `payer` (the withdraw right follows the payer).
    function depositAndRegisterFor(
        bytes32 noteCommitment,
        address payer,
        uint256 maxAmount
    ) external onlyTrustedSource whenNotPaused returns (bytes32) {
        return _depositAndRegister(noteCommitment, payer, payer, maxAmount);
    }

    /// @dev Shared deposit implementation for direct and trusted-source flows.
    ///      Step-by-step:
    ///      1) Enforce uniqueness and input sanity.
    ///      2) Snapshot token balance, execute `transferFrom`, re-snapshot balance.
    ///      3) Derive `value = newBalance - oldBalance` and store deposit.
    ///      4) Update internal tracked balance and emit event.
    function _depositAndRegister(
        bytes32 noteCommitment,
        address payer,
        address recipient,
        uint256 maxAmount
    ) internal returns (bytes32) {
        if (noteExists[noteCommitment]) revert DuplicateNoteCommitment(noteCommitment);
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
        noteExists[noteCommitment] = true;
        // Keep tracker aligned with bridge-managed escrow flow (used to sanity-check withdrawals).
        lastMonitoredBalance += value;

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
    ///      2) Update state and accounting.
    ///      3) Transfer tokens out.
    ///
    ///      Effects are applied before external token transfer to follow checks-effects-interactions.
    function withdrawPendingDeposit(bytes32 noteCommitment) external whenNotPaused {
        if (!noteExists[noteCommitment]) revert NoteNotFound(noteCommitment);

        Deposit storage dep = deposits[noteCommitment];
        if (dep.status != DepositStatus.Pending) revert InvalidDepositState(noteCommitment);
        if (msg.sender != dep.recipient) revert NotDepositRecipient();

        uint256 value = dep.value;
        uint256 trackedBalance = lastMonitoredBalance;
        if (trackedBalance < value) revert InsufficientTrackedBalance(trackedBalance, value);

        // Effects: mark withdrawn and decrement tracked escrow.
        dep.status = DepositStatus.Withdrawn;
        lastMonitoredBalance = trackedBalance - value;

        // Interaction: move escrowed tokens back to the recipient.
        bool ok = IERC20MonitoredToken(monitoredToken).transfer(dep.recipient, value);
        if (!ok) revert TokenTransferFailed();

        emit DepositWithdrawn(noteCommitment, value, dep.recipient);
    }

    /// @notice Records a notes-nullifier tree update after proof verification.
    /// @param newRoot Proposed nullifier tree root after consuming notes.
    /// @param noteCommitments Note commitments consumed in this batch (proof order).
    /// @param proof Groth16 proof of correct nullifier tree update.
    /// @dev Why needed:
    ///      - This is the canonical on-chain state transition for the notes nullifier tree.
    ///      - The bridge must not accept arbitrary roots; it must enforce ZK correctness.
    ///
    ///      How it must be used:
    ///      - Only operator can call.
    ///      - `noteCommitments.length` MUST equal `batchSize`.
    ///      - `noteCommitments` order MUST match the prover's circuit order.
    ///
    ///      Step-by-step:
    ///      1) Snapshot `oldRoot`.
    ///      2) Pack leaves and hash `(oldRoot, newRoot, packedLeaves)` with SHA256.
    ///      3) Convert SHA256 digest to the verifier's 8x uint32 public inputs.
    ///      4) Verify Groth16 proof and, if valid, update the stored root.
    function recordNotesNullifierTreeUpdate(bytes32 newRoot, bytes32[] calldata noteCommitments, Proof calldata proof) external onlyOperator whenNotPaused {
        uint256 batchLen = noteCommitments.length;
        if (batchLen != batchSize) revert InvalidBatchLength(batchLen, batchSize);

        bytes32 oldRoot = notesNullifierRoot;

        // Pack leaves into bytes for the commitment hash.
        bytes memory noteBytes = new bytes(noteCommitments.length * 32);
        for (uint256 i = 0; i < noteCommitments.length; i++) {
            bytes32 note = noteCommitments[i];
            assembly {
                mstore(add(add(noteBytes, 32), mul(i, 32)), note)
            }
        }

        // Public input is SHA256(oldRoot || newRoot || packedLeaves), split into 8x uint32.
        bytes32 sha256Commit = sha256(abi.encodePacked(oldRoot, newRoot, noteBytes));
        uint256[8] memory pubInputs = sha256ToPublicInputs(sha256Commit);

        try nullifierVerifier.verifyProof(proof.proof, proof.commitments, proof.commitmentPok, pubInputs) {
            // valid
        } catch {
            revert InvalidProof();
        }

        // Apply the verified root update.
        notesNullifierRoot = newRoot;
        // Note: this event name is reused across multiple "root update" paths in this contract.
        emit ValidatedBatchFinalized(batchLen, oldRoot, newRoot);
    }

    /// @notice Records an accounts-commitment tree update after proof verification.
    /// @param newRoot Proposed commitment tree root after appending accounts.
    /// @param accountCommitments Account commitments consumed in this batch (proof order).
    /// @param proof Groth16 proof of correct commitment tree update.
    /// @dev Why needed:
    ///      - Keeps the on-chain commitment root aligned with off-chain state transitions.
    ///
    ///      How it must be used:
    ///      - Only operator can call.
    ///      - `accountCommitments.length` MUST equal `batchSize`.
    ///      - Leaf ordering MUST match the prover's circuit order.
    ///
    ///      Step-by-step mirrors `recordNotesNullifierTreeUpdate`.
    function recordAccountsCommitmentTreeUpdate(
        bytes32 newRoot,
        bytes32[] calldata accountCommitments,
        Proof calldata proof
    ) external onlyOperator whenNotPaused {
        uint256 batchLen = accountCommitments.length;
        if (batchLen != batchSize) revert InvalidBatchLength(batchLen, batchSize);

        bytes32 oldRoot = accountsCommitmentRoot;

        // Pack leaves into bytes for the commitment hash.
        bytes memory leafBytes = new bytes(batchLen * 32);
        for (uint256 i = 0; i < batchLen; i++) {
            bytes32 leaf = accountCommitments[i];
            assembly {
                mstore(add(add(leafBytes, 32), mul(i, 32)), leaf)
            }
        }

        // Public input is SHA256(oldRoot || newRoot || packedLeaves), split into 8x uint32.
        bytes32 sha256Commit = sha256(abi.encodePacked(oldRoot, newRoot, leafBytes));
        uint256[8] memory pubInputs = sha256ToPublicInputs(sha256Commit);

        try commitmentVerifier.verifyProof(proof.proof, proof.commitments, proof.commitmentPok, pubInputs) {
            // valid
        } catch {
            revert InvalidProof();
        }

        // Apply the verified root update.
        accountsCommitmentRoot = newRoot;
        // Note: this event name is reused across multiple "root update" paths in this contract.
        emit ValidatedBatchFinalized(batchLen, oldRoot, newRoot);
    }

    /// @notice Records an accounts-nullifier tree update after proof verification.
    /// @param newRoot Proposed nullifier tree root after consuming accounts.
    /// @param accountCommitments Account commitments consumed in this batch (proof order).
    /// @param proof Groth16 proof of correct nullifier tree update.
    /// @dev Why needed:
    ///      - Prevents double-use of account-related leaves by advancing the nullifier root under proof.
    ///
    ///      How it must be used:
    ///      - Only operator can call.
    ///      - `accountCommitments.length` MUST equal `batchSize`.
    ///
    ///      Step-by-step mirrors `recordNotesNullifierTreeUpdate`.
    function recordAccountsNullifierTreeUpdate(
        bytes32 newRoot,
        bytes32[] calldata accountCommitments,
        Proof calldata proof
    ) external onlyOperator whenNotPaused {
        uint256 batchLen = accountCommitments.length;
        if (batchLen != batchSize) revert InvalidBatchLength(batchLen, batchSize);

        bytes32 oldRoot = accountsNullifierRoot;

        // Pack leaves into bytes for the commitment hash.
        bytes memory leafBytes = new bytes(batchLen * 32);
        for (uint256 i = 0; i < batchLen; i++) {
            bytes32 leaf = accountCommitments[i];
            assembly {
                mstore(add(add(leafBytes, 32), mul(i, 32)), leaf)
            }
        }

        // Public input is SHA256(oldRoot || newRoot || packedLeaves), split into 8x uint32.
        bytes32 sha256Commit = sha256(abi.encodePacked(oldRoot, newRoot, leafBytes));
        uint256[8] memory pubInputs = sha256ToPublicInputs(sha256Commit);

        try nullifierVerifier.verifyProof(proof.proof, proof.commitments, proof.commitmentPok, pubInputs) {
            // valid
        } catch {
            revert InvalidProof();
        }

        // Apply the verified root update.
        accountsNullifierRoot = newRoot;
        // Note: this event name is reused across multiple "root update" paths in this contract.
        emit ValidatedBatchFinalized(batchLen, oldRoot, newRoot);
    }

    /// @dev Computes the actionHash key for two-phase deposit validation.
    ///      Why this exists:
    ///      - The contract needs a stable identifier to store and later execute a proven batch.
    ///      - The key must not collide with other actions, hence domain separation.
    ///
    ///      How it must be used:
    ///      - `notesHash` MUST be keccak256(packedNoteBytes) where packedNoteBytes is the 32-byte concatenation
    ///        of the batch in prover order.
    ///      - `newNotesCommitmentRoot` MUST match the root proved by the circuit.
    function _actionHashForDepositValidation(bytes32 newNotesCommitmentRoot, bytes32 notesHash) internal pure returns (bytes32) {
        // Domain-separated action hash used as key for loading/executing proven batches.
        // This is not part of the Groth16 public inputs; it is for on-chain idempotency only.
        return keccak256(abi.encodePacked(DOMAIN_SEP, bytes1(0xD1), newNotesCommitmentRoot, notesHash));
    }

    /// @dev Packs a `bytes32[]` into a contiguous byte array (32 bytes per element, in order).
    ///      Why this exists:
    ///      - The Groth16 public-input commitment uses SHA256 over packed bytes.
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

    /// @notice Loads (verifies + stores) a deposit-validation batch for later execution.
    /// @param aggregatedInputProof Phase-A placeholder proof for aggregated public-input validity.
    ///        Must be non-empty in this phase; full verifier checks are planned for later phases.
    /// @dev Why needed:
    ///      - Proving is expensive and must be operator-controlled; execution can then be permissionless.
    ///      - Loading can be retried safely; it writes only the minimal metadata required for later execution.
    ///
    ///      How it must be used:
    ///      - Only operator can call.
    ///      - Caller MUST pass the exact `noteCommitments` used in the proof, in the same order.
    ///      - `newNotesCommitmentRoot` MUST be the root proved by the circuit.
    ///
    ///      Step-by-step:
    ///      1) Snapshot `oldNotesCommitmentRoot` (this binds the proof to current on-chain state).
    ///      2) Pre-check that all notes exist and are still `Pending` (fail fast).
    ///      3) Pack notes into bytes and compute the proof commitment.
    ///      4) Verify Groth16 proof.
    ///      5) Store a loaded candidate keyed by actionHash and emit `DepositValidationBatchLoaded`.
    ///
    ///      Important:
    ///      - Loading does NOT update `notesCommitmentRoot` and does NOT mark deposits as validated.
    ///        Those effects happen in `executeValidateDepositBatch`.
    function loadValidateDepositBatch(
        bytes32 newNotesCommitmentRoot,
        bytes32[] calldata noteCommitments,
        Proof calldata proof,
        AggregatedInputProof calldata aggregatedInputProof
    ) external onlyOperator whenNotPaused returns (bytes32 actionHash) {
        uint256 batchLen = noteCommitments.length;
        if (batchLen != batchSize) revert InvalidBatchLength(batchLen, batchSize);

        // Snapshot current on-chain root; the proof must be for (oldRoot -> newRoot).
        bytes32 oldNotesCommitmentRoot = notesCommitmentRoot;

        // Fail fast only for notes tracked by this bridge and no longer pending.
        // Notes absent from bridge storage are allowed as external/network-native leaves.
        for (uint256 i = 0; i < batchLen; i++) {
            bytes32 note = noteCommitments[i];
            if (noteExists[note] && deposits[note].status != DepositStatus.Pending) {
                revert InvalidDepositState(note);
            }
        }

        // Compute packed bytes for proof commitment, and a compact hash for storage keying.
        bytes memory noteBytes = _packBytes32Array(noteCommitments);
        bytes32 notesHash = keccak256(noteBytes);

        // Verify proof against SHA256(oldRoot || newRoot || packedNotes).
        bytes32 sha256Commit = sha256(abi.encodePacked(oldNotesCommitmentRoot, newNotesCommitmentRoot, noteBytes));
        uint256[8] memory pubInputs = sha256ToPublicInputs(sha256Commit);

        try commitmentVerifier.verifyProof(proof.proof, proof.commitments, proof.commitmentPok, pubInputs) {
            // valid
        } catch {
            revert InvalidProof();
        }
        if (aggregatedInputProof.proofData.length == 0) revert InvalidAggregatedInputProof();

        // Store as a loadable candidate. Execution will select the candidate matching current oldRoot.
        actionHash = _actionHashForDepositValidation(newNotesCommitmentRoot, notesHash);
        _loadedValidationBatches[actionHash].push(
            LoadedValidationBatch({
                oldRoot: oldNotesCommitmentRoot,
                newRoot: newNotesCommitmentRoot,
                notesHash: notesHash
            })
        );

        emit DepositValidationBatchLoaded(actionHash, oldNotesCommitmentRoot, newNotesCommitmentRoot, notesHash, batchLen);
    }

    /// @notice Cancels a previously loaded validation batch (operator-only).
    /// @dev Why needed:
    ///      - A loaded batch may become un-executable if any note is withdrawn before execution.
    ///      - Cancellation avoids leaving unusable loaded entries in storage.
    ///
    ///      How it must be used:
    ///      - Only operator can call.
    ///      - Caller MUST supply the exact `oldNotesCommitmentRoot`, `newNotesCommitmentRoot` and ordered `noteCommitments`
    ///        originally used for the load.
    ///      - If multiple candidates exist for the same actionHash, cancellation removes the matching `(oldRoot,newRoot,notesHash)` entry.
    function cancelLoadedValidateDepositBatch(
        bytes32 oldNotesCommitmentRoot,
        bytes32 newNotesCommitmentRoot,
        bytes32[] calldata noteCommitments
    ) external onlyOperator whenNotPaused returns (bytes32 actionHash) {
        uint256 batchLen = noteCommitments.length;
        if (batchLen != batchSize) revert InvalidBatchLength(batchLen, batchSize);

        bytes32 notesHash = keccak256(_packBytes32Array(noteCommitments));
        actionHash = _actionHashForDepositValidation(newNotesCommitmentRoot, notesHash);

        LoadedValidationBatch[] storage batches = _loadedValidationBatches[actionHash];
        // Scan from the end (recent entries likely to match) and remove by swap+pop.
        for (uint256 i = batches.length; i > 0; i--) {
            LoadedValidationBatch storage b = batches[i - 1];
            if (b.oldRoot == oldNotesCommitmentRoot && b.newRoot == newNotesCommitmentRoot && b.notesHash == notesHash) {
                uint256 lastIndex = batches.length - 1;
                if (i - 1 != lastIndex) {
                    batches[i - 1] = batches[lastIndex];
                }
                batches.pop();
                emit DepositValidationBatchCanceled(actionHash, oldNotesCommitmentRoot, newNotesCommitmentRoot, notesHash, batchLen);
                return actionHash;
            }
        }

        revert LoadedBatchNotFound(actionHash);
    }

    /// @notice Executes a previously loaded deposit-validation batch (permissionless).
    /// @dev Why needed:
    ///      - Enables permissionless finalization of already-proven batches.
    ///
    ///      How it must be used:
    ///      - Caller MUST pass the same `newNotesCommitmentRoot` and ordered `noteCommitments` that were used during load.
    ///      - The batch MUST have been loaded for the current `notesCommitmentRoot` (oldRoot match).
    ///
    ///      Step-by-step:
    ///      1) Snapshot `oldNotesCommitmentRoot` (must match a loaded candidate).
    ///      2) Compute actionHash and locate a candidate whose `(oldRoot,newRoot,notesHash)` matches.
    ///      3) Re-check all notes are still `Pending` (withdrawals may have occurred after load).
    ///      4) Mark deposits `Validated` and advance `notesCommitmentRoot`.
    ///      5) Delete the loaded candidate entry and emit events.
    function executeValidateDepositBatch(
        bytes32 newNotesCommitmentRoot,
        bytes32[] calldata noteCommitments
    ) external whenNotPaused returns (bytes32 actionHash) {
        uint256 batchLen = noteCommitments.length;
        if (batchLen != batchSize) revert InvalidBatchLength(batchLen, batchSize);

        bytes32 oldNotesCommitmentRoot = notesCommitmentRoot;

        bytes memory noteBytes = _packBytes32Array(noteCommitments);
        bytes32 notesHash = keccak256(noteBytes);
        actionHash = _actionHashForDepositValidation(newNotesCommitmentRoot, notesHash);

        LoadedValidationBatch[] storage batches = _loadedValidationBatches[actionHash];
        bool found = false;
        for (uint256 i = batches.length; i > 0; i--) {
            LoadedValidationBatch storage b = batches[i - 1];
            if (b.oldRoot == oldNotesCommitmentRoot && b.newRoot == newNotesCommitmentRoot && b.notesHash == notesHash) {
                // Remove candidate via swap+pop. If we revert later, the EVM will roll back this deletion.
                uint256 lastIndex = batches.length - 1;
                if (i - 1 != lastIndex) {
                    batches[i - 1] = batches[lastIndex];
                }
                batches.pop();
                found = true;
                break;
            }
        }
        if (!found) revert LoadedBatchNotFound(actionHash);

        // Re-check tracked-note availability at execution time (notes may have been withdrawn since load).
        // External notes (not tracked by this bridge) are intentionally ignored here.
        for (uint256 i = 0; i < batchLen; i++) {
            bytes32 note = noteCommitments[i];
            if (noteExists[note] && deposits[note].status != DepositStatus.Pending) {
                revert InvalidDepositState(note);
            }
        }

        // Apply effects: mark only bridge-tracked deposits as validated.
        // External notes do not have deposit records and are not written to storage.
        for (uint256 i = 0; i < batchLen; i++) {
            bytes32 note = noteCommitments[i];
            if (noteExists[note]) {
                deposits[note].status = DepositStatus.Validated;
                emit DepositValidated(note);
            }
        }

        // Advance the commitment root to the proved value.
        notesCommitmentRoot = newNotesCommitmentRoot;
        emit DepositValidationBatchExecuted(actionHash, oldNotesCommitmentRoot, newNotesCommitmentRoot, notesHash, batchLen);
        // Backwards-compatible event retained for existing off-chain listeners.
        emit ValidatedBatchFinalized(batchLen, oldNotesCommitmentRoot, newNotesCommitmentRoot);
    }

    /// @notice Finalizes a deposit-validation batch after append-proof verification.
    /// @param newNotesCommitmentRoot Proposed commitment tree root after appending notes.
    /// @param noteCommitments Notes validated in this batch (proof order).
    /// @param proof Groth16 proof for the append transition.
    /// @param aggregatedInputProof Phase-A placeholder proof for aggregated public-input validity.
    ///        Must be non-empty in this phase; full verifier checks are planned for later phases.
    /// @dev Why this exists:
    ///      - Legacy single-phase entry point (verify+apply in one call).
    ///
    ///      How it should be used:
    ///      - Prefer the two-phase flow (`loadValidateDepositBatch` + `executeValidateDepositBatch`) for better liveness.
    ///      - This method is still safe, but finalization is operator-dependent (not permissionless).
    function validateDepositBatch(
        bytes32 newNotesCommitmentRoot,
        bytes32[] calldata noteCommitments,
        Proof calldata proof,
        AggregatedInputProof calldata aggregatedInputProof
    ) external onlyOperator whenNotPaused {
        uint256 batchLen = noteCommitments.length;
        if (batchLen != batchSize) revert InvalidBatchLength(batchLen, batchSize);

        bytes32 oldNotesCommitmentRoot = notesCommitmentRoot;

        // Fail fast only for notes tracked by this bridge and no longer pending.
        // Notes absent from bridge storage are allowed as external/network-native leaves.
        for (uint256 i = 0; i < batchLen; i++) {
            bytes32 note = noteCommitments[i];
            if (noteExists[note] && deposits[note].status != DepositStatus.Pending) {
                revert InvalidDepositState(note);
            }
        }

        bytes memory noteBytes = _packBytes32Array(noteCommitments);

        // Verify proof against SHA256(oldRoot || newRoot || packedNotes).
        bytes32 sha256Commit = sha256(abi.encodePacked(oldNotesCommitmentRoot, newNotesCommitmentRoot, noteBytes));
        uint256[8] memory pubInputs = sha256ToPublicInputs(sha256Commit);

        try commitmentVerifier.verifyProof(proof.proof, proof.commitments, proof.commitmentPok, pubInputs) {
            // valid
        } catch {
            revert InvalidProof();
        }
        if (aggregatedInputProof.proofData.length == 0) revert InvalidAggregatedInputProof();

        // Apply effects for tracked deposits only.
        for (uint256 i = 0; i < batchLen; i++) {
            bytes32 note = noteCommitments[i];
            if (noteExists[note]) {
                deposits[note].status = DepositStatus.Validated;
                emit DepositValidated(note);
            }
        }

        notesCommitmentRoot = newNotesCommitmentRoot;
        emit ValidatedBatchFinalized(batchLen, oldNotesCommitmentRoot, newNotesCommitmentRoot);
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

    /// @notice Converts a bytes32 SHA256 digest into 8 public inputs (uint32 words) expected by the gnark verifier.
    /// @dev Why needed:
    ///      - The generated verifier takes an array of 8 uint32-like values as public inputs.
    ///
    ///      How it must be used:
    ///      - The conversion here must match the circuit/verifier encoding exactly.
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
        if (!noteExists[noteCommitment]) revert NoteNotFound(noteCommitment);
        return deposits[noteCommitment];
    }

    /// @notice Reads deposit status for `noteCommitment`.
    /// @dev Why needed: status-only accessor used by off-chain sequencer preflight checks.
    function getDepositStatus(bytes32 noteCommitment) external view returns (DepositStatus) {
        if (!noteExists[noteCommitment]) revert NoteNotFound(noteCommitment);
        return deposits[noteCommitment].status;
    }
}
