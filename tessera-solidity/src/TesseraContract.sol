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

/// @notice Poseidon hash over Goldilocks field — compress two packed HashOut values.
interface IPoseidonGoldilocks {
    /// @notice Compress two packed Goldilocks HashOut values into one.
    /// @param left  4 Goldilocks elements packed LE: el0|(el1<<64)|(el2<<128)|(el3<<192)
    /// @param right Same packing.
    function compress(uint256 left, uint256 right) external pure returns (uint256);
}

/// @title TesseraContract
/// @notice On-chain Poseidon Merkle tree + ERC20 deposit escrow + two-phase ZK batch proving.
///
/// Three batch types are supported, each following the same two-phase model:
///   Phase 1 – `submit*`  (operator only): validate roots, compute piCommitment, store batch.
///   Phase 2 – `prove*`   (permissionless): verify Groth16, insert nullifiers, update tree.
///
/// Keccak preimage encoding (all three types):
///   Each Goldilocks field element f is encoded as [lo_u32_BE(4 B), hi_u32_BE(4 B)]
///   where lo = uint32(f), hi = uint32(f >> 32).
///   A packed LE HashOut (uint256 = el0|(el1<<64)|(el2<<128)|(el3<<192)) produces 32 B via
///   `_glHashToBytes`. A scalar GL field (uint64) produces 8 B via `_glFieldToBytes`.
///
/// Preimage layout (must match `BatchHelper::pi_commitment` in tessera-server):
///   1. batchPoseidonRoot (32 B)
///   2. act_root          (32 B)  ← common to all slots
///   3. mainPoolConfigRoot(32 B)  ← common to all slots
///   4. Per slot: unique PIs in circuit registration order (type-specific, see below)
contract TesseraContract {
    // -------------------------------------------------------------------------
    // Enums & Structs
    // -------------------------------------------------------------------------

    /// @notice Current lifecycle state of a deposit note.
    enum DepositStatus { None, Pending, Validated, Withdrawn }

    /// @notice Canonical deposit metadata stored by note commitment.
    struct Deposit {
        uint256      value;
        address      recipient;
        DepositStatus status;
    }

    /// @notice Groth16 proof container passed to both verifier calls.
    struct Proof {
        uint256[8] proof;
        uint256[2] commitments;
        uint256[2] commitmentPok;
    }


    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    uint256 public constant MAX_TREE_DEPTH = 32;

    /// @dev Number of private-TX slots per batch (arity=8, depth=2 aggregator).
    uint256 public constant PRIV_TX_BATCH_SIZE = 64;

    /// @dev Number of withdraw slots (= deposit slots) per bridge-TX batch.
    ///      Total bridge batch size = 2 × BRIDGE_TX_HALF_SIZE = 512.
    uint256 public constant BRIDGE_TX_HALF_SIZE = 256;

    /// @dev Note slots per private-TX slot (input note nullifiers / output note commitments).
    uint256 public constant NOTE_BATCH = 7;

    /// @dev Depth of the per-batch Poseidon subtree.
    ///      Both TX and bridge-TX batches commit 512 leaves → depth = log2(512) = 9.
    uint256 public constant BATCH_SUBTREE_DEPTH = 9;

    // ── TX batch preimage layout ─────────────────────────────────────────────
    //
    // All GL hash fields (bytes32 in the preimage) are GL-preimage encoded:
    //   bytes32 = [lo0_BE(4B), hi0_BE(4B), lo1_BE(4B), hi1_BE(4B), ...]
    // GL fields stored as uint64 are encoded as [lo_u32_BE(4B), hi_u32_BE(4B)] (8 bytes).
    //
    // Header (96 B):  batchPoseidonRoot[32] | root[32] | mainPoolConfigRoot[32]
    // Per slot (520 B): notFakeTx[8] | accinNull[32] | accoutComm[32]
    //                   | noteInNull[7×32=224] | noteOutComm[7×32=224]
    uint256 private constant TX_HEADER_SIZE    = 96;
    uint256 private constant TX_SLOT_SIZE      = 8 + 32 + 32 + NOTE_BATCH * 32 + NOTE_BATCH * 32; // 520
    uint256 private constant TX_ACCIN_NULL_OFF = 8;
    uint256 private constant TX_NOTE_IN_OFF    = 8 + 32 + 32; // 72

    // ── Bridge TX batch preimage layout ─────────────────────────────────────
    //
    // Header (96 B): batchPoseidonRoot[32] | root[32] | mainPoolConfigRoot[32]
    // Withdraw section (BRIDGE_TX_HALF_SIZE × 616 B):
    //   Per w-slot (616 B): notFakeTx[8] | wAccinNull[32] | wAccoutComm[32]
    //                        | wAssetIds[7×8=56] | wWithdrawalAmounts[7×8×8=448] | wAccAddr[5×8=40]
    // Deposit section (BRIDGE_TX_HALF_SIZE × 216 B):
    //   Per d-slot (216 B): notFakeTx[8] | dAccinNull[32] | dAccoutComm[32] | dNoteComm[32]
    //                        | dEthAddress[5×8=40] | dAmount[8×8=64] | dAssetId[8]
    uint256 private constant W_SLOT_SIZE    = 8 + 32 + 32 + NOTE_BATCH * 8 + NOTE_BATCH * 64 + 40; // 616
    uint256 private constant D_SLOT_SIZE    = 8 + 32 + 32 + 32 + 40 + 64 + 8;                      // 216
    uint256 private constant D_SECTION_OFF  = 96 + BRIDGE_TX_HALF_SIZE * W_SLOT_SIZE;              // 157792
    uint256 private constant W_ACCIN_NULL_OFF = 8;
    uint256 private constant D_ACCIN_NULL_OFF = 8;
    uint256 private constant D_NOTE_COMM_OFF  = 72;

    // -------------------------------------------------------------------------
    // State variables
    // -------------------------------------------------------------------------

    // --- access control ---
    address public operator;
    bool    public paused;

    // --- verifiers ---
    IGroth16Verifier public immutable txVerifier;
    IGroth16Verifier public immutable bridgeTxVerifier;

    // --- token ---
    address public immutable monitoredToken;

    // --- pool config ---
    uint256 public poolConfigRoot;

    // --- on-chain Poseidon incremental Merkle tree ---
    IPoseidonGoldilocks public immutable poseidon;
    uint256 public immutable treeDepth;
    uint256 public leafCount;
    uint256 public currentRoot;
    mapping(uint256 => uint256) public filledSubtrees; // level => current left-sibling hash
    mapping(uint256 => uint256) public zeros;           // level => zero-hash at that level

    // --- root history (all previously confirmed tree roots) ---
    mapping(uint256 => bool) public confirmedRoots;

    // --- nullifier set ---
    mapping(uint256 => bool) public nullifiers;

    // --- leaf store (leafIndex => LE-packed GL batchPoseidonRoot) ---
    mapping(uint256 => uint256) public leaves;

    // --- validated batch roots (batchPoseidonRoot => true once its batch is proven) ---
    // Allows anyone to verify that a given batchPoseidonRoot was part of a proven batch,
    // and therefore that any leaf in its Poseidon subtree is a committed value.
    mapping(uint256 => bool) public validatedBatchRoots;

    // --- deposits ---
    mapping(bytes32 => Deposit) public deposits;

    // --- pending / confirmed batches (keyed by piCommitment = keccak256(batchPreimage)) ---
    mapping(bytes32 => bool) public pendingTxBatches;
    mapping(bytes32 => bool) public confirmedTxBatches;
    mapping(bytes32 => bool) public pendingBridgeTxBatches;
    mapping(bytes32 => bool) public confirmedBridgeTxBatches;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    event TransactionBatchSubmitted(bytes32 indexed piCommitment, bytes32 batchPoseidonRoot);
    event TransactionBatchProven(bytes32 indexed piCommitment, uint256 newTreeRoot, uint256 leafIndex);
    event BridgeTxBatchSubmitted(bytes32 indexed piCommitment, bytes32 batchPoseidonRoot);
    event BridgeTxBatchProven(bytes32 indexed piCommitment, uint256 newTreeRoot, uint256 leafIndex);
    event DepositAvailable(bytes32 indexed noteCommitment, uint256 value, address recipient);
    event DepositWithdrawn(bytes32 indexed noteCommitment, uint256 value, address recipient);
    event DepositValidated(bytes32 indexed noteCommitment);
    event OperatorChanged(address indexed oldOp, address indexed newOp);
    event PoolConfigRootUpdated(uint256 indexed oldRoot, uint256 indexed newRoot);
    event PausedChanged(bool isPaused);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    error NotOperator();
    error PausedErr();
    error ZeroAddress();
    error InvalidTreeDepth();
    error RootNotConfirmed(bytes32 root);
    error PoolConfigMismatch();
    error BatchAlreadySubmitted(bytes32 piCommitment);
    error BatchNotFound(bytes32 piCommitment);
    error BatchAlreadyConfirmed(bytes32 piCommitment);
    error ProofVerificationFailed(bytes32 piCommitment, uint256[8] pubInputs);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error NoteNotFound(bytes32 noteCommitment);
    error InvalidDepositState(bytes32 noteCommitment);
    error DuplicateNoteCommitment(bytes32 noteCommitment);
    error InvalidAmount();
    error NoTokenReceived();
    error NotDepositRecipient();
    error TokenTransferFailed();
    error TreeFull();

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /// @param _txVerifier        Groth16 verifier for private-transaction batches.
    /// @param _bridgeTxVerifier  Groth16 verifier for bridge-transaction batches.
    /// @param _poseidon          Deployed PoseidonGoldilocks contract address.
    /// @param _operator          Initial operator address.
    /// @param _monitoredToken    ERC20 token escrowed by this bridge.
    /// @param _poolConfigRoot    Initial pool configuration root (LE-packed GL HashOut).
    /// @param _treeDepth         Depth of the on-chain Poseidon Merkle tree (e.g. 20).
    constructor(
        address _txVerifier,
        address _bridgeTxVerifier,
        address _poseidon,
        address _operator,
        address _monitoredToken,
        uint256 _poolConfigRoot,
        uint256 _treeDepth
    ) {
        if (_txVerifier == address(0))       revert ZeroAddress();
        if (_bridgeTxVerifier == address(0)) revert ZeroAddress();
        if (_poseidon == address(0))         revert ZeroAddress();
        if (_operator == address(0))         revert ZeroAddress();
        if (_monitoredToken == address(0))   revert ZeroAddress();
        if (_treeDepth == 0 || _treeDepth > MAX_TREE_DEPTH) revert InvalidTreeDepth();

        txVerifier       = IGroth16Verifier(_txVerifier);
        bridgeTxVerifier = IGroth16Verifier(_bridgeTxVerifier);
        poseidon         = IPoseidonGoldilocks(_poseidon);
        operator         = _operator;
        monitoredToken   = _monitoredToken;
        poolConfigRoot   = _poolConfigRoot;
        treeDepth        = _treeDepth;

        // Build zeros chain: zeros[0] = 0, zeros[i] = compress(zeros[i-1], zeros[i-1])
        // TODO: HARDCODE
        zeros[0] = 0;
        for (uint256 i = 1; i <= _treeDepth; i++) {
            zeros[i] = IPoseidonGoldilocks(_poseidon).compress(zeros[i - 1], zeros[i - 1]);
        }

        // Initialise filledSubtrees to the zero-hash at each level.
        for (uint256 i = 0; i < _treeDepth; i++) {
            filledSubtrees[i] = zeros[i];
        }

        // Genesis root = root of an all-zero tree of the given depth.
        currentRoot = zeros[_treeDepth];
        confirmedRoots[currentRoot] = true;
    }

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    modifier onlyOperator() {
        _onlyOperator();
        _;
    }

    modifier whenNotPaused() {
        _whenNotPaused();
        _;
    }

    function _onlyOperator() internal view {
        if (msg.sender != operator) revert NotOperator();
    }

    function _whenNotPaused() internal view {
        if (paused) revert PausedErr();
    }

    // -------------------------------------------------------------------------
    // Access control & configuration
    // -------------------------------------------------------------------------

    /// @notice Transfers the operator role to `newOperator`.
    function setOperator(address newOperator) external onlyOperator {
        if (newOperator == address(0)) revert ZeroAddress();
        emit OperatorChanged(operator, newOperator);
        operator = newOperator;
    }

    /// @notice Pauses or unpauses all mutating entry points.
    function setPaused(bool _paused) external onlyOperator {
        paused = _paused;
        emit PausedChanged(_paused);
    }

    /// @notice Updates the accepted pool configuration root.
    ///         New batches must reference the current value.
    function setPoolConfigRoot(uint256 newRoot) external onlyOperator {
        emit PoolConfigRootUpdated(poolConfigRoot, newRoot);
        poolConfigRoot = newRoot;
    }

    // -------------------------------------------------------------------------
    // Deposit lifecycle
    // -------------------------------------------------------------------------

    /// @notice Pulls ERC20 from caller and creates a `Pending` deposit.
    function depositAndRegister(bytes32 noteCommitment, uint256 maxAmount)
        external
        whenNotPaused
        returns (bytes32)
    {
        return _depositAndRegister(noteCommitment, msg.sender, msg.sender, maxAmount);
    }

    /// @notice Delegated variant: pulls from `payer`, records their `Pending` deposit.
    function depositAndRegisterFor(bytes32 noteCommitment, address payer, uint256 maxAmount)
        external
        whenNotPaused
        returns (bytes32)
    {
        return _depositAndRegister(noteCommitment, payer, payer, maxAmount);
    }

    /// @notice Transfers `amount` of monitoredToken from caller to this contract,
    ///         then creates a `Pending` deposit for `noteCommitment`.
    function transferDepositAndRegister(bytes32 noteCommitment, uint256 amount)
        external
        whenNotPaused
        returns (bytes32)
    {
        bool ok = IERC20MonitoredToken(monitoredToken).transferFrom(msg.sender, address(this), amount);
        if (!ok) revert TokenTransferFailed();
        return _depositAndRegister(noteCommitment, msg.sender, msg.sender, amount);
    }

    function _depositAndRegister(
        bytes32 noteCommitment,
        address payer,
        address recipient,
        uint256 maxAmount
    ) internal returns (bytes32) {
        if (deposits[noteCommitment].status != DepositStatus.None) revert DuplicateNoteCommitment(noteCommitment);
        if (payer == address(0) || recipient == address(0)) revert ZeroAddress();
        if (maxAmount == 0) revert InvalidAmount();

        // Measure received amount via in-call balance delta (handles fee-on-transfer tokens).
        uint256 before = IERC20MonitoredToken(monitoredToken).balanceOf(address(this));
        bool ok = IERC20MonitoredToken(monitoredToken).transferFrom(payer, address(this), maxAmount);
        if (!ok) revert TokenTransferFailed();
        uint256 after_ = IERC20MonitoredToken(monitoredToken).balanceOf(address(this));
        if (after_ <= before) revert NoTokenReceived();

        uint256 value = after_ - before;
        deposits[noteCommitment] = Deposit({value: value, recipient: recipient, status: DepositStatus.Pending});

        emit DepositAvailable(noteCommitment, value, recipient);
        return noteCommitment;
    }

    /// @notice Withdraws a `Pending` deposit back to its recipient.
    function withdrawPendingDeposit(bytes32 noteCommitment) external whenNotPaused {
        Deposit storage dep = deposits[noteCommitment];
        if (dep.status == DepositStatus.None)   revert NoteNotFound(noteCommitment);
        if (dep.status != DepositStatus.Pending) revert InvalidDepositState(noteCommitment);
        if (msg.sender != dep.recipient)          revert NotDepositRecipient();

        uint256 value = dep.value;
        dep.status = DepositStatus.Withdrawn; // effects before interaction

        bool ok = IERC20MonitoredToken(monitoredToken).transfer(dep.recipient, value);
        if (!ok) revert TokenTransferFailed();

        emit DepositWithdrawn(noteCommitment, value, dep.recipient);
    }

    // -------------------------------------------------------------------------
    // Transaction batch — submit phase (operator only)
    // -------------------------------------------------------------------------

    /// @notice Registers a private-transaction batch for later proof verification.
    ///
    /// @param batchPreimage  Raw Keccak-256 preimage of the piCommitment.
    ///
    /// Preimage layout (must match `BatchHelper::pi_commitment` in tessera-server):
    ///   Header (96 B): batchPoseidonRoot[32] | root[32] | mainPoolConfigRoot[32]
    ///   Per slot s in [0, PRIV_TX_BATCH_SIZE):
    ///     notFakeTx[8] | accinNull[32] | accoutComm[32]
    ///     | noteInNull[7×32] | noteOutComm[7×32]
    ///
    /// All hash fields are GL-preimage encoded bytes32.
    /// Scalar GL fields (bools) are encoded as [lo_u32_BE(4B), hi_u32_BE(4B)].
    ///
    /// @dev Phase 1. piCommitment = keccak256(batchPreimage). Storing only the
    ///      piCommitment (1 bool) instead of the full struct saves ~3–12 M gas.
    function submitTransactionBatch(bytes calldata batchPreimage)
        external
        onlyOperator
        whenNotPaused
    {
        bytes32 root              = _cdB32(batchPreimage, 32);
        bytes32 mainPoolConfigRoot = _cdB32(batchPreimage, 64);

        if (!confirmedRoots[_glHashToU256(root)]) revert RootNotConfirmed(root);
        if (_glHashToU256(mainPoolConfigRoot) != poolConfigRoot) revert PoolConfigMismatch();

        bytes32 piCommitment = keccak256(batchPreimage);
        if (confirmedTxBatches[piCommitment])  revert BatchAlreadyConfirmed(piCommitment);
        if (pendingTxBatches[piCommitment])    revert BatchAlreadySubmitted(piCommitment);

        pendingTxBatches[piCommitment] = true;

        emit TransactionBatchSubmitted(piCommitment, _cdB32(batchPreimage, 0));
    }

    // -------------------------------------------------------------------------
    // Transaction batch — prove phase (permissionless)
    // -------------------------------------------------------------------------

    /// @notice Verifies the Groth16 proof for a submitted transaction batch and finalises it.
    ///
    /// @param batchPreimage  The same raw bytes passed to `submitTransactionBatch`.
    ///
    /// @dev Phase 2. piCommitment is re-derived as keccak256(batchPreimage) — no
    ///      re-encoding needed; all nullifiers are read from `batchPreimage` at
    ///      fixed offsets.  On success: nullifiers inserted, batchPoseidonRoot
    ///      appended to the on-chain Merkle tree.
    function proveTransactionBatch(bytes calldata batchPreimage, Proof calldata proof)
        external
        whenNotPaused
    {
        bytes32 piCommitment = keccak256(batchPreimage);

        if (!pendingTxBatches[piCommitment]) {
            if (confirmedTxBatches[piCommitment]) revert BatchAlreadyConfirmed(piCommitment);
            revert BatchNotFound(piCommitment);
        }

        uint256[8] memory pubInputs = keccakToPublicInputs(piCommitment);
        try txVerifier.verifyProof(proof.proof, proof.commitments, proof.commitmentPok, pubInputs) {
            // success — fall through
        } catch {
            revert ProofVerificationFailed(piCommitment, pubInputs);
        }

        // Pre-check all nullifiers before mutating state (read at fixed preimage offsets).
        for (uint256 s = 0; s < PRIV_TX_BATCH_SIZE; s++) {
            uint256 slotOff = TX_HEADER_SIZE + s * TX_SLOT_SIZE;
            if (!_cdBool(batchPreimage, slotOff)) continue;
            bytes32 accNull = _cdB32(batchPreimage, slotOff + TX_ACCIN_NULL_OFF);
            if (nullifiers[_glHashToU256(accNull)]) revert NullifierAlreadyUsed(accNull);
            for (uint256 j = 0; j < NOTE_BATCH; j++) {
                bytes32 nn = _cdB32(batchPreimage, slotOff + TX_NOTE_IN_OFF + j * 32);
                if (nullifiers[_glHashToU256(nn)]) revert NullifierAlreadyUsed(nn);
            }
        }

        delete pendingTxBatches[piCommitment];
        confirmedTxBatches[piCommitment] = true;

        // Insert nullifiers for real slots only.
        for (uint256 s = 0; s < PRIV_TX_BATCH_SIZE; s++) {
            uint256 slotOff = TX_HEADER_SIZE + s * TX_SLOT_SIZE;
            if (!_cdBool(batchPreimage, slotOff)) continue;
            nullifiers[_glHashToU256(_cdB32(batchPreimage, slotOff + TX_ACCIN_NULL_OFF))] = true;
            for (uint256 j = 0; j < NOTE_BATCH; j++) {
                nullifiers[_glHashToU256(_cdB32(batchPreimage, slotOff + TX_NOTE_IN_OFF + j * 32))] = true;
            }
        }

        uint256 leafIndex = leafCount;
        _appendLeaf(_glHashToU256(_cdB32(batchPreimage, 0)));

        emit TransactionBatchProven(piCommitment, currentRoot, leafIndex);
    }

    // -------------------------------------------------------------------------
    // Bridge-transaction batch — submit phase (operator only)
    // -------------------------------------------------------------------------

    /// @notice Registers a bridge-transaction batch (256 withdrawals + 256 deposits).
    ///
    /// @param batchPreimage  Raw Keccak-256 preimage of the piCommitment.
    ///
    /// Preimage layout:
    ///   Header (96 B): batchPoseidonRoot[32] | root[32] | mainPoolConfigRoot[32]
    ///   Withdraw section (BRIDGE_TX_HALF_SIZE × 616 B)
    ///   Deposit section  (BRIDGE_TX_HALF_SIZE × 216 B)
    ///
    /// @dev Phase 1.  All referenced deposit notes must be `Pending`.
    function submitBridgeTxBatch(bytes calldata batchPreimage)
        external
        onlyOperator
        whenNotPaused
    {
        bytes32 root               = _cdB32(batchPreimage, 32);
        bytes32 mainPoolConfigRoot = _cdB32(batchPreimage, 64);

        if (!confirmedRoots[_glHashToU256(root)]) revert RootNotConfirmed(root);
        if (_glHashToU256(mainPoolConfigRoot) != poolConfigRoot) revert PoolConfigMismatch();

        // Validate all real deposit notes exist and are Pending.
        for (uint256 s = 0; s < BRIDGE_TX_HALF_SIZE; s++) {
            uint256 slotOff = D_SECTION_OFF + s * D_SLOT_SIZE;
            if (!_cdBool(batchPreimage, slotOff)) continue;
            bytes32 noteKey = _cdB32(batchPreimage, slotOff + D_NOTE_COMM_OFF);
            DepositStatus st = deposits[noteKey].status;
            if (st == DepositStatus.None)    revert NoteNotFound(noteKey);
            if (st != DepositStatus.Pending) revert InvalidDepositState(noteKey);
        }

        bytes32 piCommitment = keccak256(batchPreimage);
        if (confirmedBridgeTxBatches[piCommitment]) revert BatchAlreadyConfirmed(piCommitment);
        if (pendingBridgeTxBatches[piCommitment])   revert BatchAlreadySubmitted(piCommitment);

        pendingBridgeTxBatches[piCommitment] = true;

        emit BridgeTxBatchSubmitted(piCommitment, _cdB32(batchPreimage, 0));
    }

    // -------------------------------------------------------------------------
    // Bridge-transaction batch — prove phase (permissionless)
    // -------------------------------------------------------------------------

    /// @notice Verifies the Groth16 proof for a submitted bridge-tx batch and finalises it.
    ///
    /// @param batchPreimage  The same raw bytes passed to `submitBridgeTxBatch`.
    ///
    /// @dev Phase 2. On success:
    ///      - Account nullifiers inserted for real withdraw and deposit slots.
    ///      - Deposit notes advanced to `Validated` for real deposit slots.
    ///      - batchPoseidonRoot appended to the on-chain tree.
    ///      - TODO: release ERC20 tokens for real withdrawal slots (requires multi-asset registry).
    function proveBridgeTxBatch(bytes calldata batchPreimage, Proof calldata proof)
        external
        whenNotPaused
    {
        bytes32 piCommitment = keccak256(batchPreimage);

        if (!pendingBridgeTxBatches[piCommitment]) {
            if (confirmedBridgeTxBatches[piCommitment]) revert BatchAlreadyConfirmed(piCommitment);
            revert BatchNotFound(piCommitment);
        }

        uint256[8] memory pubInputs = keccakToPublicInputs(piCommitment);
        try bridgeTxVerifier.verifyProof(proof.proof, proof.commitments, proof.commitmentPok, pubInputs) {
            // success — fall through
        } catch {
            revert ProofVerificationFailed(piCommitment, pubInputs);
        }

        // Pre-check all account nullifiers before mutating state.
        for (uint256 s = 0; s < BRIDGE_TX_HALF_SIZE; s++) {
            uint256 wOff = 96 + s * W_SLOT_SIZE;
            if (_cdBool(batchPreimage, wOff) && nullifiers[_glHashToU256(_cdB32(batchPreimage, wOff + W_ACCIN_NULL_OFF))])
                revert NullifierAlreadyUsed(_cdB32(batchPreimage, wOff + W_ACCIN_NULL_OFF));
            uint256 dOff = D_SECTION_OFF + s * D_SLOT_SIZE;
            if (_cdBool(batchPreimage, dOff) && nullifiers[_glHashToU256(_cdB32(batchPreimage, dOff + D_ACCIN_NULL_OFF))])
                revert NullifierAlreadyUsed(_cdB32(batchPreimage, dOff + D_ACCIN_NULL_OFF));
        }

        delete pendingBridgeTxBatches[piCommitment];
        confirmedBridgeTxBatches[piCommitment] = true;

        // Insert withdraw account nullifiers (token release: TODO — requires multi-asset registry).
        for (uint256 s = 0; s < BRIDGE_TX_HALF_SIZE; s++) {
            uint256 wOff = 96 + s * W_SLOT_SIZE;
            if (!_cdBool(batchPreimage, wOff)) continue;
            nullifiers[_glHashToU256(_cdB32(batchPreimage, wOff + W_ACCIN_NULL_OFF))] = true;
        }

        // Insert deposit account nullifiers and advance deposit note lifecycle.
        for (uint256 s = 0; s < BRIDGE_TX_HALF_SIZE; s++) {
            uint256 dOff = D_SECTION_OFF + s * D_SLOT_SIZE;
            if (!_cdBool(batchPreimage, dOff)) continue;
            nullifiers[_glHashToU256(_cdB32(batchPreimage, dOff + D_ACCIN_NULL_OFF))] = true;
            bytes32 noteKey = _cdB32(batchPreimage, dOff + D_NOTE_COMM_OFF);
            deposits[noteKey].status = DepositStatus.Validated;
            emit DepositValidated(noteKey);
        }

        uint256 leafIndex = leafCount;
        _appendLeaf(_glHashToU256(_cdB32(batchPreimage, 0)));

        emit BridgeTxBatchProven(piCommitment, currentRoot, leafIndex);
    }

    // -------------------------------------------------------------------------
    // Incremental Merkle tree (internal)
    // -------------------------------------------------------------------------

    /// @dev Standard IMT append. O(treeDepth) Poseidon calls.
    ///      Stores the new root in confirmedRoots so it can be referenced by future batches.
    ///      Also persists the raw leaf value so clients can reconstruct Merkle paths.
    function _appendLeaf(uint256 leaf) internal {
        if (leafCount >= (uint256(1) << treeDepth)) revert TreeFull();

        leaves[leafCount] = leaf;
        validatedBatchRoots[leaf] = true;

        uint256 node = leaf;
        for (uint256 i = 0; i < treeDepth; i++) {
            if ((leafCount >> i) & 1 == 0) {
                // Current node is a left child: cache it and pair with the zero sibling.
                filledSubtrees[i] = node;
                node = poseidon.compress(node, zeros[i]);
            } else {
                // Current node is a right child: pair with the cached left sibling.
                node = poseidon.compress(filledSubtrees[i], node);
            }
        }
        leafCount++;
        currentRoot = node;
        confirmedRoots[node] = true;
    }

    // -------------------------------------------------------------------------
    // Calldata read helpers
    // -------------------------------------------------------------------------

    /// @dev Read 32 bytes from `data` at byte offset `off` as a bytes32.
    function _cdB32(bytes calldata data, uint256 off) private pure returns (bytes32 v) {
        assembly ("memory-safe") {
            v := calldataload(add(data.offset, off))
        }
    }

    /// @dev Read 8 bytes (one GL field) from `data` at byte offset `off` and
    ///      return true iff the value is non-zero.
    ///      GL-field encoding: [lo_u32_BE(4B), hi_u32_BE(4B)].
    function _cdBool(bytes calldata data, uint256 off) private pure returns (bool v) {
        assembly ("memory-safe") {
            v := iszero(iszero(shr(192, calldataload(add(data.offset, off)))))
        }
    }

    // -------------------------------------------------------------------------
    // Goldilocks encoding helpers
    // -------------------------------------------------------------------------

    /// @dev Convert a GL-preimage-encoded bytes32 back to a LE-packed uint256.
    ///      Preimage layout: [lo0_BE4][hi0_BE4][lo1_BE4][hi1_BE4]...
    ///      LE-packed layout: e0|(e1<<64)|(e2<<128)|(e3<<192)
    ///      Used for confirmedRoots/nullifiers lookups and _appendLeaf calls.
    function _glHashToU256(bytes32 b) private pure returns (uint256) {
        uint256 w = uint256(b);
        return  (w >> 224) |
               (((w >> 192) & 0xFFFFFFFF) << 32)  |
               (((w >> 160) & 0xFFFFFFFF) << 64)  |
               (((w >> 128) & 0xFFFFFFFF) << 96)  |
               (((w >>  96) & 0xFFFFFFFF) << 128) |
               (((w >>  64) & 0xFFFFFFFF) << 160) |
               (((w >>  32) & 0xFFFFFFFF) << 192) |
               ( (w          & 0xFFFFFFFF) << 224);
    }

    // -------------------------------------------------------------------------
    // View helpers
    // -------------------------------------------------------------------------

    /// @notice Returns the deposit record for `noteCommitment`; reverts if absent.
    function getDeposit(bytes32 noteCommitment) external view returns (Deposit memory) {
        Deposit memory dep = deposits[noteCommitment];
        if (dep.status == DepositStatus.None) revert NoteNotFound(noteCommitment);
        return dep;
    }

    /// @notice Returns whether `root` is in the confirmed root history.
    function isConfirmedRoot(uint256 root) external view returns (bool) {
        return confirmedRoots[root];
    }

    /// @notice Returns whether `nullifier` has been consumed.
    function isNullifierUsed(uint256 nullifier_) external view returns (bool) {
        return nullifiers[nullifier_];
    }

    /// @notice Verifies that `leaf` is at position `leafIndex` in the Poseidon subtree
    ///         committed by `batchRoot`, AND that `batchRoot` belongs to a validated batch.
    ///
    /// @param batchRoot  LE-packed GL uint256 batchPoseidonRoot to check (must be in
    ///                   `validatedBatchRoots`).
    /// @param leaf       LE-packed GL uint256 leaf value (account or note commitment).
    /// @param leafIndex  0-based index of `leaf` within the 512-leaf batch subtree.
    /// @param siblings   Poseidon Merkle path of exactly `BATCH_SUBTREE_DEPTH` (= 9) siblings.
    ///                   siblings[0] is paired with the leaf; siblings[8] is paired just below
    ///                   the root.
    /// @return           True iff (1) batchRoot is validated and (2) the path hashes to batchRoot.
    ///
    /// @dev The per-level zero hashes for the 512-leaf subtree are identical to `zeros[0..8]`
    ///      already stored in the contract (same Poseidon hasher, same starting zero).
    function verifyBatchLeaf(
        uint256 batchRoot,
        uint256 leaf,
        uint256 leafIndex,
        uint256[] calldata siblings
    ) external view returns (bool) {
        if (!validatedBatchRoots[batchRoot]) return false;
        if (siblings.length != BATCH_SUBTREE_DEPTH) return false;
        uint256 node = leaf;
        for (uint256 i = 0; i < BATCH_SUBTREE_DEPTH; i++) {
            if ((leafIndex >> i) & 1 == 0) {
                node = poseidon.compress(node, siblings[i]);
            } else {
                node = poseidon.compress(siblings[i], node);
            }
        }
        return node == batchRoot;
    }

    /// @notice Converts a bytes32 Keccak-256 digest to the 8 uint32 public inputs
    ///         expected by the gnark Groth16 verifier (big-endian 32-bit words).
    function keccakToPublicInputs(bytes32 hash) public pure returns (uint256[8] memory inputs) {
        uint256 h = uint256(hash);
        inputs[0] = (h >> 224) & 0xFFFFFFFF;
        inputs[1] = (h >> 192) & 0xFFFFFFFF;
        inputs[2] = (h >> 160) & 0xFFFFFFFF;
        inputs[3] = (h >> 128) & 0xFFFFFFFF;
        inputs[4] = (h >> 96)  & 0xFFFFFFFF;
        inputs[5] = (h >> 64)  & 0xFFFFFFFF;
        inputs[6] = (h >> 32)  & 0xFFFFFFFF;
        inputs[7] =  h         & 0xFFFFFFFF;
    }
}
