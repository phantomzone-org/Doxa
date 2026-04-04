// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20MonitoredToken {
    /// @notice Returns token balance for `account`.
    function balanceOf(address account) external view returns (uint256);

    /// @notice Moves `value` tokens from `from` to `to` using allowance.
    function transferFrom(
        address from,
        address to,
        uint256 value
    ) external returns (bool);

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
    function compress(
        uint256 left,
        uint256 right
    ) external pure returns (uint256);
}

/// @title TesseraContract
/// @notice On-chain Poseidon Merkle tree + ERC20 deposit escrow + two-phase ZK batch proving.
/// @dev V2 moves the commitment tree onto the contract. The contract is the canonical
///      source of truth for all confirmed tree roots. Nullifiers are stored in a flat
///      mapping; the ZK circuit proves double-spend absence and the contract enforces
///      replay protection post-proof.
contract TesseraContract {
    // -------------------------------------------------------------------------
    // Enums & Structs
    // -------------------------------------------------------------------------

    /// @notice Current lifecycle state of a deposit note.
    enum DepositStatus {
        None,
        Pending,
        Validated,
        Withdrawn
    }

    /// @notice Canonical deposit metadata stored by note commitment.
    struct Deposit {
        uint256 value;
        address recipient;
        DepositStatus status;
    }

    /// @notice Groth16 proof container passed to both verifier calls.
    struct Proof {
        uint256[8] proof;
        uint256[2] commitments;
        uint256[2] commitmentPok;
    }

    /// @notice On-chain record for a pending private-transaction batch.
    struct TransactionBatch {
        uint256 root; // single IMT root — must be in confirmedRoots
        bytes32 mainPoolConfigRoot;
        uint256[] noteCommitments; // 7 per slot (row-major, NC only — no AC)
        uint256[] noteNullifiers; // 7 per slot (row-major, NN only — no AN)
        uint256[] accountCommitments; // 1 per slot (64 total)
        uint256[] accountNullifiers; // 1 per slot (64 total)
        uint256 batchPoseidonRoot; // Poseidon root of subtree leaves; inserted as leaf on prove
        bool confirmed;
    }

    /// @notice On-chain record for a pending deposit batch.
    struct DepositBatch {
        uint256 root; // single IMT root — must be in confirmedRoots
        bytes32 mainPoolConfigRoot;
        bytes32[] depositNoteCommitments; // note commitments consumed from pending deposits
        //TODO: add []accinnulls, []accoutcomms
        uint256 batchPoseidonRoot;
        bool confirmed;
    }

    /// @notice On-chain record for a pending withdrawal batch.
    struct WithdrawalBatch {
        bytes32 act_root;
        bytes32 mainPoolConfigRoot;
        bytes32[] account_comms;
        bytes32[] accin_nulls;
        uint256[] amounts;
        address[] addresses;
        uint256 batchPoseidonRoot;
        bool confirmed;
    }

    /// @notice A single pending withdrawal entry queued for flushing.
    struct UnclaimedWithdrawal {
        address recipient;
        uint256 amount;
    }

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    uint256 public constant MAX_TREE_DEPTH = 32;

    bytes32 private constant DEPOSIT_TYPEHASH =
        keccak256("Deposit(bytes32 depositNoteCommitment,uint256 amount)");

    /// @dev Must match `DEPOSIT_BATCH_SIZE` in the Rust deposit artifact generator
    ///      (tessera-e2e/src/bin/deposit_artifacts.rs).  The circuit hashes all
    ///      `DEPOSIT_BATCH_SIZE` eth-address slots; dummy slots carry address(0).
    uint256 public constant DEPOSIT_BATCH_SIZE = 512;

    // -------------------------------------------------------------------------
    // State variables
    // -------------------------------------------------------------------------

    // --- EIP-712 ---
    bytes32 private immutable DOMAIN_SEPARATOR;

    // --- access control ---
    address public operator;
    bool public paused;

    // --- verifiers ---
    IGroth16Verifier public immutable txVerifier;
    IGroth16Verifier public immutable depositVerifier;
    IGroth16Verifier public immutable withdrawalVerifier;

    // --- token ---
    address public immutable monitoredToken;

    // --- pool config ---
    bytes32 public poolConfigRoot;

    // --- on-chain Poseidon incremental Merkle tree ---
    IPoseidonGoldilocks public immutable poseidon;
    uint256 public immutable treeDepth;
    uint256 public leafCount;
    uint256 public currentRoot;
    mapping(uint256 => uint256) public filledSubtrees; // level => current left-sibling hash
    mapping(uint256 => uint256) public zeros; // level => zero-hash at that level

    // --- root history (all previously confirmed tree roots) ---
    mapping(uint256 => bool) public confirmedRoots;

    // --- nullifier set ---
    mapping(uint256 => bool) public nullifiers;

    // --- deposits ---
    mapping(bytes32 => Deposit) public deposits;

    // --- pending batches ---
    mapping(bytes32 => TransactionBatch) public pendingTxBatches;
    mapping(bytes32 => DepositBatch) public pendingDepositBatches;
    mapping(bytes32 => WithdrawalBatch) public pendingWithdrawalBatches;

    // --- unclaimed withdrawals (flushed permissionlessly) ---
    UnclaimedWithdrawal[] public unclaimedWithdrawals;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    event TransactionBatchSubmitted(
        bytes32 indexed piCommitment,
        uint256 batchPoseidonRoot
    );
    event TransactionBatchProven(
        bytes32 indexed piCommitment,
        uint256 newTreeRoot,
        uint256 leafIndex
    );
    event DepositBatchSubmitted(
        bytes32 indexed piCommitment,
        uint256 batchPoseidonRoot
    );
    event DepositBatchProven(
        bytes32 indexed piCommitment,
        uint256 newTreeRoot,
        uint256 leafIndex
    );
    event DepositAvailable(
        bytes32 indexed noteCommitment,
        uint256 value,
        address recipient
    );
    event DepositWithdrawn(
        bytes32 indexed noteCommitment,
        uint256 value,
        address recipient
    );
    event DepositValidated(bytes32 indexed noteCommitment);
    event WithdrawalBatchSubmitted(bytes32 indexed commitment);
    event WithdrawalBatchProven(bytes32 indexed commitment);
    event WithdrawalFlushed(address indexed recipient, uint256 amount);
    event OperatorChanged(address indexed oldOp, address indexed newOp);
    event PoolConfigRootUpdated(
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot
    );
    event PausedChanged(bool isPaused);
    event DebugDepositPreimage(bytes preimage, bytes32 result);
    event DebugTxPreimage(bytes preimage, bytes32 result);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    error NotOperator();
    error PausedErr();
    error ZeroAddress();
    error InvalidTreeDepth();
    error RootNotConfirmed(uint256 root);
    error PoolConfigMismatch();
    error BatchAlreadySubmitted(bytes32 piCommitment);
    error BatchNotFound(bytes32 piCommitment);
    error BatchAlreadyConfirmed(bytes32 piCommitment);
    error ProofVerificationFailed(bytes32 piCommitment, uint256[8] pubInputs);
    error NullifierAlreadyUsed(uint256 nullifier);
    error NoteNotFound(bytes32 noteCommitment);
    error InvalidDepositState(bytes32 noteCommitment);
    error DuplicateNoteCommitment(bytes32 noteCommitment);
    error InvalidAmount();
    error NoTokenReceived();
    error NotDepositRecipient();
    error TokenTransferFailed();
    error TreeFull();
    error WithdrawalBatchAlreadySubmitted(bytes32 commitment);
    error WithdrawalBatchAlreadyConfirmed(bytes32 commitment);

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /// @param _txVerifier         Groth16 verifier for transaction batches.
    /// @param _depositVerifier    Groth16 verifier for deposit batches.
    /// @param _withdrawalVerifier Groth16 verifier for withdrawal batches.
    /// @param _poseidon           Deployed PoseidonGoldilocks contract address.
    /// @param _operator           Initial operator address.
    /// @param _monitoredToken     ERC20 token escrowed by this bridge.
    /// @param _poolConfigRoot     Initial pool configuration root.
    /// @param _treeDepth          Depth of the on-chain Poseidon Merkle tree (e.g. 20).
    constructor(
        address _txVerifier,
        address _depositVerifier,
        address _withdrawalVerifier,
        address _poseidon,
        address _operator,
        address _monitoredToken,
        bytes32 _poolConfigRoot,
        uint256 _treeDepth
    ) {
        if (_txVerifier == address(0)) revert ZeroAddress();
        if (_depositVerifier == address(0)) revert ZeroAddress();
        if (_withdrawalVerifier == address(0)) revert ZeroAddress();
        if (_poseidon == address(0)) revert ZeroAddress();
        if (_operator == address(0)) revert ZeroAddress();
        if (_monitoredToken == address(0)) revert ZeroAddress();
        if (_treeDepth == 0 || _treeDepth > MAX_TREE_DEPTH)
            revert InvalidTreeDepth();

        txVerifier = IGroth16Verifier(_txVerifier);
        depositVerifier = IGroth16Verifier(_depositVerifier);
        withdrawalVerifier = IGroth16Verifier(_withdrawalVerifier);
        poseidon = IPoseidonGoldilocks(_poseidon);
        operator = _operator;
        monitoredToken = _monitoredToken;
        poolConfigRoot = _poolConfigRoot;
        treeDepth = _treeDepth;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("TesseraDeposit"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );

        // Build zeros chain: zeros[0] = 0, zeros[i] = compress(zeros[i-1], zeros[i-1])
        // TODO: HARDODE
        zeros[0] = 0;
        for (uint256 i = 1; i <= _treeDepth; i++) {
            zeros[i] = IPoseidonGoldilocks(_poseidon).compress(
                zeros[i - 1],
                zeros[i - 1]
            );
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
    function setPoolConfigRoot(bytes32 newRoot) external onlyOperator {
        emit PoolConfigRootUpdated(poolConfigRoot, newRoot);
        poolConfigRoot = newRoot;
    }

    // -------------------------------------------------------------------------
    // Deposit lifecycle
    // -------------------------------------------------------------------------

    /// @notice Pulls ERC20 from caller and creates a `Pending` deposit.
    function depositAndRegister(
        bytes32 noteCommitment,
        uint256 maxAmount
    ) external whenNotPaused returns (bytes32) {
        return
            _depositAndRegister(
                noteCommitment,
                msg.sender,
                msg.sender,
                maxAmount
            );
    }

    /// @notice Delegated variant: pulls from `payer`, records their `Pending` deposit.
    function depositAndRegisterFor(
        bytes32 noteCommitment,
        address payer,
        uint256 maxAmount
    ) external whenNotPaused returns (bytes32) {
        return _depositAndRegister(noteCommitment, payer, payer, maxAmount);
    }

    /// @notice Operator-pays-gas variant: depositor signs an EIP-712 typed-data message
    ///         off-chain; the operator submits this call on their behalf.
    ///         The signature covers {depositNoteCommitment, amount} and must be 65 bytes (r,s,v).
    function signedDepositAndRegister(
        bytes memory signature,
        bytes32 depositNoteCommitment,
        uint256 amount
    ) external whenNotPaused {
        require(signature.length == 65, "bad sig length");

        bytes32 structHash = keccak256(
            abi.encode(DEPOSIT_TYPEHASH, depositNoteCommitment, amount)
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        if (v < 27) v += 27;

        address depositor = ecrecover(digest, v, r, s);
        require(depositor != address(0), "invalid signature");

        _depositAndRegister(
            depositNoteCommitment,
            depositor,
            depositor,
            amount
        );
    }

    function _depositAndRegister(
        bytes32 noteCommitment,
        address payer,
        address recipient,
        uint256 maxAmount
    ) internal returns (bytes32) {
        if (deposits[noteCommitment].status != DepositStatus.None)
            revert DuplicateNoteCommitment(noteCommitment);
        if (payer == address(0) || recipient == address(0))
            revert ZeroAddress();
        if (maxAmount == 0) revert InvalidAmount();

        // Measure received amount via in-call balance delta (handles fee-on-transfer tokens).
        uint256 before = IERC20MonitoredToken(monitoredToken).balanceOf(
            address(this)
        );
        bool ok = IERC20MonitoredToken(monitoredToken).transferFrom(
            payer,
            address(this),
            maxAmount
        );
        if (!ok) revert TokenTransferFailed();
        uint256 after_ = IERC20MonitoredToken(monitoredToken).balanceOf(
            address(this)
        );
        if (after_ <= before) revert NoTokenReceived();

        uint256 value = after_ - before;
        deposits[noteCommitment] = Deposit({
            value: value,
            recipient: recipient,
            status: DepositStatus.Pending
        });

        emit DepositAvailable(noteCommitment, value, recipient);
        return noteCommitment;
    }

    /// @notice Withdraws a `Pending` deposit back to its recipient.
    function withdrawPendingDeposit(
        bytes32 noteCommitment
    ) external whenNotPaused {
        Deposit storage dep = deposits[noteCommitment];
        if (dep.status == DepositStatus.None)
            revert NoteNotFound(noteCommitment);
        if (dep.status != DepositStatus.Pending)
            revert InvalidDepositState(noteCommitment);
        if (msg.sender != dep.recipient) revert NotDepositRecipient();

        uint256 value = dep.value;
        dep.status = DepositStatus.Withdrawn; // effects before interaction

        bool ok = IERC20MonitoredToken(monitoredToken).transfer(
            dep.recipient,
            value
        );
        if (!ok) revert TokenTransferFailed();

        emit DepositWithdrawn(noteCommitment, value, dep.recipient);
    }

    // -------------------------------------------------------------------------
    // Transaction batch — submit phase (operator only)
    // -------------------------------------------------------------------------

    /// @notice Registers a private-transaction batch for later proof verification.
    /// @dev Phase 1 of the two-phase model. Validates roots and pre-checks nullifiers,
    ///      then stores the batch keyed by its piCommitment.
    function submitTransactionBatch(
        TransactionBatch calldata batch
    ) external onlyOperator whenNotPaused {
        if (!confirmedRoots[batch.root]) revert RootNotConfirmed(batch.root);
        if (batch.mainPoolConfigRoot != poolConfigRoot)
            revert PoolConfigMismatch();

        bytes32 piCommitment = _computeTxPiCommitment(batch);
        if (pendingTxBatches[piCommitment].batchPoseidonRoot != 0)
            revert BatchAlreadySubmitted(piCommitment);

        // Deep-copy calldata to storage; always set confirmed = false.
        pendingTxBatches[piCommitment] = batch;
        pendingTxBatches[piCommitment].confirmed = false;

        emit TransactionBatchSubmitted(piCommitment, batch.batchPoseidonRoot);
    }

    // -------------------------------------------------------------------------
    // Transaction batch — prove phase (permissionless)
    // -------------------------------------------------------------------------

    /// @notice Verifies the Groth16 proof for a submitted transaction batch and finalises it.
    /// @dev Phase 2 of the two-phase model. Anyone may call.
    ///      On success: nullifiers inserted, batchPoseidonRoot appended to the on-chain tree.
    function proveTransactionBatch(
        bytes32 piCommitment,
        Proof calldata proof
    ) external whenNotPaused {
        TransactionBatch storage batch = pendingTxBatches[piCommitment];
        if (batch.batchPoseidonRoot == 0) revert BatchNotFound(piCommitment);
        if (batch.confirmed) revert BatchAlreadyConfirmed(piCommitment);

        uint256[8] memory pubInputs = keccakToPublicInputs(piCommitment);
        try
            txVerifier.verifyProof(
                proof.proof,
                proof.commitments,
                proof.commitmentPok,
                pubInputs
            )
        {
            // success — fall through
        } catch {
            revert ProofVerificationFailed(piCommitment, pubInputs);
        }

        uint256 nnLen = batch.noteNullifiers.length;
        for (uint256 i = 0; i < nnLen; i++) {
            if (nullifiers[batch.noteNullifiers[i]])
                revert NullifierAlreadyUsed(batch.noteNullifiers[i]);
        }
        uint256 anLen = batch.accountNullifiers.length;
        for (uint256 i = 0; i < anLen; i++) {
            if (nullifiers[batch.accountNullifiers[i]])
                revert NullifierAlreadyUsed(batch.accountNullifiers[i]);
        }

        batch.confirmed = true;

        // Insert nullifiers into the flat set.
        for (uint256 i = 0; i < nnLen; i++) {
            nullifiers[batch.noteNullifiers[i]] = true;
        }
        for (uint256 i = 0; i < anLen; i++) {
            nullifiers[batch.accountNullifiers[i]] = true;
        }

        uint256 leafIndex = leafCount;
        _appendLeaf(batch.batchPoseidonRoot);

        emit TransactionBatchProven(piCommitment, currentRoot, leafIndex);
    }

    // -------------------------------------------------------------------------
    // Deposit batch — submit phase (operator only)
    // -------------------------------------------------------------------------

    /// @notice Registers a deposit batch for later proof verification.
    ///         All referenced deposit notes must be `Pending`.
    function submitDepositBatch(
        DepositBatch calldata batch
    ) external onlyOperator whenNotPaused {
        if (!confirmedRoots[batch.root]) revert RootNotConfirmed(batch.root);
        if (batch.mainPoolConfigRoot != poolConfigRoot)
            revert PoolConfigMismatch();

        // Validate each deposit note exists and is Pending.
        //
        // TODO(fix): One can withdraw between the submitDepositBatch and proveDepositBatch.
        uint256 len = batch.depositNoteCommitments.length;
        for (uint256 i = 0; i < len; i++) {
            bytes32 nc = batch.depositNoteCommitments[i];
            DepositStatus s = deposits[nc].status;
            if (s == DepositStatus.None) revert NoteNotFound(nc);
            if (s != DepositStatus.Pending) revert InvalidDepositState(nc);
        }

        bytes32 piCommitment = _computeDepositPiCommitment(batch);
        if (pendingDepositBatches[piCommitment].batchPoseidonRoot != 0)
            revert BatchAlreadySubmitted(piCommitment);

        pendingDepositBatches[piCommitment] = batch;
        pendingDepositBatches[piCommitment].confirmed = false;

        emit DepositBatchSubmitted(piCommitment, batch.batchPoseidonRoot);
    }

    // -------------------------------------------------------------------------
    // Deposit batch — prove phase (permissionless)
    // -------------------------------------------------------------------------

    /// @notice Verifies the Groth16 proof for a submitted deposit batch and finalises it.
    ///         On success: deposit notes advanced to `Validated`, batchPoseidonRoot appended.
    function proveDepositBatch(
        bytes32 piCommitment,
        Proof calldata proof
    ) external whenNotPaused {
        DepositBatch storage batch = pendingDepositBatches[piCommitment];
        if (batch.batchPoseidonRoot == 0) revert BatchNotFound(piCommitment);
        if (batch.confirmed) revert BatchAlreadyConfirmed(piCommitment);

        uint256[8] memory pubInputs = keccakToPublicInputs(piCommitment);
        try
            depositVerifier.verifyProof(
                proof.proof,
                proof.commitments,
                proof.commitmentPok,
                pubInputs
            )
        {
            // success — fall through
        } catch {
            revert ProofVerificationFailed(piCommitment, pubInputs);
        }

        batch.confirmed = true;

        // Mark deposit notes as Validated.
        uint256 len = batch.depositNoteCommitments.length;
        for (uint256 i = 0; i < len; i++) {
            bytes32 nc = batch.depositNoteCommitments[i];
            deposits[nc].status = DepositStatus.Validated;
            emit DepositValidated(nc);
        }

        uint256 leafIndex = leafCount;
        _appendLeaf(batch.batchPoseidonRoot);

        emit DepositBatchProven(piCommitment, currentRoot, leafIndex);
    }

    // -------------------------------------------------------------------------
    // Withdrawal batch — submit phase (operator only)
    // -------------------------------------------------------------------------

    /// @notice Registers a withdrawal batch for later proof verification.
    function submitWithdrawalBatch(
        WithdrawalBatch calldata batch
    ) external onlyOperator whenNotPaused {
        bytes32 commitment = _computeWithdrawalCommitment(batch);
        if (pendingWithdrawalBatches[commitment].batchPoseidonRoot != 0)
            revert WithdrawalBatchAlreadySubmitted(commitment);

        pendingWithdrawalBatches[commitment] = batch;
        pendingWithdrawalBatches[commitment].confirmed = false;

        emit WithdrawalBatchSubmitted(commitment);
    }

    // -------------------------------------------------------------------------
    // Withdrawal batch — prove phase (permissionless)
    // -------------------------------------------------------------------------

    /// @notice Verifies the Groth16 proof for a submitted withdrawal batch and finalises it.
    ///         On success: all (address, amount) pairs are appended to unclaimedWithdrawals.
    ///         Returns silently if the batch is not found, already confirmed, or the commitment
    ///         does not match. Reverts if proof verification fails.
    function proveWithdrawalBatch(
        bytes32 withdrawalBatchCommitment,
        Proof calldata proof
    ) external whenNotPaused {
        WithdrawalBatch storage batch = pendingWithdrawalBatches[
            withdrawalBatchCommitment
        ];
        if (batch.batchPoseidonRoot == 0) return;
        if (batch.confirmed) return;

        uint256[8] memory pubInputs = keccakToPublicInputs(
            withdrawalBatchCommitment
        );
        try
            withdrawalVerifier.verifyProof(
                proof.proof,
                proof.commitments,
                proof.commitmentPok,
                pubInputs
            )
        {
            // success — fall through
        } catch {
            revert ProofVerificationFailed(
                withdrawalBatchCommitment,
                pubInputs
            );
        }

        batch.confirmed = true;

        uint256 len = batch.addresses.length;
        for (uint256 i = 0; i < len; i++) {
            unclaimedWithdrawals.push(
                UnclaimedWithdrawal({
                    recipient: batch.addresses[i],
                    amount: batch.amounts[i]
                })
            );
        }

        _appendLeaf(batch.batchPoseidonRoot);

        emit WithdrawalBatchProven(withdrawalBatchCommitment);
    }

    // -------------------------------------------------------------------------
    // Flush unclaimed withdrawals (permissionless)
    // -------------------------------------------------------------------------

    /// @notice Transfers all accumulated unclaimed withdrawals from the contract to recipients.
    ///         Anyone may call this; the full list is flushed in one transaction.
    function flushUnclaimedWithdrawals() external whenNotPaused {
        uint256 len = unclaimedWithdrawals.length;
        for (uint256 i = 0; i < len; i++) {
            UnclaimedWithdrawal memory w = unclaimedWithdrawals[i];
            bool ok = IERC20MonitoredToken(monitoredToken).transfer(
                w.recipient,
                w.amount
            );
            if (!ok) revert TokenTransferFailed();
            emit WithdrawalFlushed(w.recipient, w.amount);
        }
        delete unclaimedWithdrawals;
    }

    // -------------------------------------------------------------------------
    // Incremental Merkle tree (internal)
    // -------------------------------------------------------------------------

    /// @dev Standard IMT append. O(treeDepth) Poseidon calls.
    ///      Stores the new root in confirmedRoots so it can be referenced by future batches.
    function _appendLeaf(uint256 leaf) internal {
        if (leafCount >= (uint256(1) << treeDepth)) revert TreeFull();

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
    // piCommitment helpers (internal pure)
    // -------------------------------------------------------------------------

    /// @dev Computes the Keccak-256 commitment over all transaction batch public inputs.
    ///      Field order must match the Rust sequencer and SuperAggregator circuit exactly.
    ///      Preimage (packed, no length prefixes):
    ///        root | mainPoolConfigRoot | batchPoseidonRoot |
    ///        accountCommitments[0..S] | accountNullifiers[0..S] |
    ///        noteCommitments[0..7*S] | noteNullifiers[0..7*S]
    function _computeTxPiCommitment(
        TransactionBatch calldata batch
    ) internal returns (bytes32) {
        bytes memory preimage = abi.encodePacked(
            batch.root,
            batch.mainPoolConfigRoot,
            batch.batchPoseidonRoot,
            batch.accountCommitments,
            batch.accountNullifiers,
            batch.noteCommitments,
            batch.noteNullifiers
        );
        bytes32 result = keccak256(preimage);
        emit DebugTxPreimage(preimage, result);
        return result;
    }

    /// @dev Computes the Keccak-256 commitment over deposit batch public inputs.
    ///      Preimage (packed):
    ///        root | mainPoolConfigRoot | batchPoseidonRoot | ethAddresses[0..DEPOSIT_BATCH_SIZE]
    ///      Real deposit slots carry the depositor address; dummy slots carry address(0).
    ///      Each address is serialised as 5 × 4-byte little-endian u32 limbs, matching
    ///      the `map_h160_to_f` encoding used by the deposit-TX circuit.
    function _computeDepositPiCommitment(
        DepositBatch calldata batch
    ) internal returns (bytes32) {
        bytes memory preimage = abi.encodePacked(
            batch.root,
            batch.mainPoolConfigRoot,
            batch.batchPoseidonRoot
        );
        uint256 realLen = batch.depositNoteCommitments.length;
        for (uint256 i = 0; i < realLen; i++) {
            address depositor = deposits[batch.depositNoteCommitments[i]]
                .recipient;
            preimage = bytes.concat(preimage, _addressToLE20(depositor));
        }
        // Pad remaining slots with address(0) to match the circuit's fixed DEPOSIT_BATCH_SIZE.
        bytes memory zeroPadded = _addressToLE20(address(0));
        for (uint256 i = realLen; i < DEPOSIT_BATCH_SIZE; i++) {
            preimage = bytes.concat(preimage, zeroPadded);
        }
        bytes32 result = keccak256(preimage);
        emit DebugDepositPreimage(preimage, result);
        return result;
    }

    /// @dev Computes the Keccak-256 commitment over all withdrawal batch public inputs.
    ///      Preimage (packed, no length prefixes):
    ///        act_root | mainPoolConfigRoot | batchPoseidonRoot |
    ///        account_comms[0..N] | accin_nulls[0..N] | amounts[0..N] | addresses[0..N]
    function _computeWithdrawalCommitment(
        WithdrawalBatch memory batch
    ) internal pure returns (bytes32) {
        bytes memory preimage = abi.encodePacked(
            batch.act_root,
            batch.mainPoolConfigRoot,
            batch.batchPoseidonRoot
        );
        //TODO: append zeros uptill BATCH size
        for (uint256 i = 0; i < batch.account_comms.length; i++) {
            preimage = bytes.concat(
                preimage,
                abi.encodePacked(batch.account_comms[i])
            );
        }
        for (uint256 i = 0; i < batch.accin_nulls.length; i++) {
            preimage = bytes.concat(
                preimage,
                abi.encodePacked(batch.accin_nulls[i])
            );
        }
        for (uint256 i = 0; i < batch.amounts.length; i++) {
            preimage = bytes.concat(
                preimage,
                abi.encodePacked(batch.amounts[i])
            );
        }
        for (uint256 i = 0; i < batch.addresses.length; i++) {
            preimage = bytes.concat(
                preimage,
                abi.encodePacked(batch.addresses[i])
            );
        }
        return keccak256(preimage);
    }

    /// @dev Serialises an Ethereum address as 5 × 4-byte little-endian u32 limbs.
    ///
    /// The EVM stores `address` as 20 bytes in big-endian order. The deposit-TX
    /// circuit encodes addresses via `map_h160_to_f`, which splits the 20 bytes
    /// into 5 × u32 limbs using `u32::from_le_bytes` — i.e. each 4-byte chunk is
    /// interpreted in little-endian (byte 0 is the LSB of that limb). The Keccak
    /// gadget then emits each u32 as 4 big-endian bytes, effectively byte-reversing
    /// each chunk. This helper reproduces that transformation on-chain.
    function _addressToLE20(
        address a
    ) internal pure returns (bytes memory out) {
        bytes20 be = bytes20(a); // big-endian: be[0] is the most-significant byte
        out = new bytes(20);
        for (uint256 i = 0; i < 5; i++) {
            out[4 * i] = be[4 * i + 3];
            out[4 * i + 1] = be[4 * i + 2];
            out[4 * i + 2] = be[4 * i + 1];
            out[4 * i + 3] = be[4 * i];
        }
    }

    // -------------------------------------------------------------------------
    // View helpers
    // -------------------------------------------------------------------------

    /// @notice Returns the deposit record for `noteCommitment`; reverts if absent.
    function getDeposit(
        bytes32 noteCommitment
    ) external view returns (Deposit memory) {
        Deposit memory dep = deposits[noteCommitment];
        if (dep.status == DepositStatus.None)
            revert NoteNotFound(noteCommitment);
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

    /// @notice Converts a bytes32 Keccak-256 digest to the 8 uint32 public inputs
    ///         expected by the gnark Groth16 verifier (big-endian 32-bit words).
    function keccakToPublicInputs(
        bytes32 hash
    ) public pure returns (uint256[8] memory inputs) {
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
}
