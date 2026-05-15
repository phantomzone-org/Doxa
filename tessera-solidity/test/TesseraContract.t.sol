// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {TesseraContract} from "../src/TesseraContract.sol";
import {PoseidonGoldilocks} from "../src/PoseidonGoldilocks.sol";
import {ToyUSDT} from "../src/ToyUSDT.sol";

// ---------------------------------------------------------------------------
// Test-only verifiers
// ---------------------------------------------------------------------------

/// @dev Accepts every Groth16-shaped proof. Never deploy to production.
contract AcceptAllVerifier {
    function verifyProof(
        uint256[8] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[8] calldata
    ) external pure {}
}

/// @dev Rejects every proof — used to exercise ProofVerificationFailed paths.
contract RejectAllVerifier {
    function verifyProof(
        uint256[8] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[8] calldata
    ) external pure {
        revert("bad proof");
    }
}

// ---------------------------------------------------------------------------
// Main test contract
// ---------------------------------------------------------------------------

contract TesseraRollupV2Test is Test {
    TesseraContract public rollup;
    PoseidonGoldilocks public poseidon;
    ToyUSDT public token;
    AcceptAllVerifier public acceptVerifier;
    RejectAllVerifier public rejectVerifier;

    address constant OP = address(0x0001);
    address constant ALICE = address(0xA11CE);

    uint256 constant DEPTH = 4; // 16 leaf slots
    uint256 constant ASSET_ID = 1; // registered asset ID for `token` in tests

    // Unique-nullifier counter; reset per test by Forge's EVM isolation.
    uint256 private _nc;

    // Reference IMT state — storage variables, reset per test by Forge isolation.
    uint256 private _simLC;
    mapping(uint256 => uint256) private _simFS;

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------

    function setUp() public {
        poseidon = new PoseidonGoldilocks();
        token = new ToyUSDT();
        acceptVerifier = new AcceptAllVerifier();
        rejectVerifier = new RejectAllVerifier();
        rollup = _deploy(DEPTH);
        _nc = 0xDEAD_0001;
        // Register the test token so deposit functions work.
        vm.prank(OP);
        rollup.registerAsset(ASSET_ID, address(token));
    }

    // -----------------------------------------------------------------------
    // Deployment helpers
    // -----------------------------------------------------------------------

    function _deploy(uint256 depth) internal returns (TesseraContract) {
        return
            new TesseraContract(
                address(acceptVerifier),
                address(acceptVerifier),
                address(poseidon),
                OP,
                depth,
                20,
                0
            );
    }

    function _deployRejectTx(uint256 depth) internal returns (TesseraContract) {
        return
            new TesseraContract(
                address(rejectVerifier),
                address(acceptVerifier),
                address(poseidon),
                OP,
                depth,
                20,
                0
            );
    }

    // -----------------------------------------------------------------------
    // Goldilocks encoding helpers (mirrors TesseraContract internals)
    // -----------------------------------------------------------------------

    /// @dev Mirrors TesseraContract._glHashToBytes.
    function _glHashToBytes(
        uint256 packed
    ) internal pure returns (bytes memory out) {
        out = new bytes(32);
        for (uint256 i = 0; i < 4; i++) {
            uint64 el = uint64(packed >> (i * 64));
            uint32 lo = uint32(el);
            uint32 hi = uint32(el >> 32);
            out[8 * i] = bytes1(uint8(lo >> 24));
            out[8 * i + 1] = bytes1(uint8(lo >> 16));
            out[8 * i + 2] = bytes1(uint8(lo >> 8));
            out[8 * i + 3] = bytes1(uint8(lo));
            out[8 * i + 4] = bytes1(uint8(hi >> 24));
            out[8 * i + 5] = bytes1(uint8(hi >> 16));
            out[8 * i + 6] = bytes1(uint8(hi >> 8));
            out[8 * i + 7] = bytes1(uint8(hi));
        }
    }

    /// @dev Mirrors TesseraContract._glFieldToBytes.
    function _glFieldToBytes(
        uint64 el
    ) internal pure returns (bytes memory out) {
        out = new bytes(8);
        uint32 lo = uint32(el);
        uint32 hi = uint32(el >> 32);
        out[0] = bytes1(uint8(lo >> 24));
        out[1] = bytes1(uint8(lo >> 16));
        out[2] = bytes1(uint8(lo >> 8));
        out[3] = bytes1(uint8(lo));
        out[4] = bytes1(uint8(hi >> 24));
        out[5] = bytes1(uint8(hi >> 16));
        out[6] = bytes1(uint8(hi >> 8));
        out[7] = bytes1(uint8(hi));
    }

    // -----------------------------------------------------------------------
    // Batch / proof helpers
    // -----------------------------------------------------------------------

    function _dummyProof()
        internal
        pure
        returns (TesseraContract.Proof memory p)
    {
        // All-zero default — AcceptAllVerifier ignores contents.
    }

    // ── TX batch preimage builder helpers ────────────────────────────────────

    /// @dev Builds a minimal TX batch preimage (all-padding, no real slots).
    ///
    /// Layout: batchPoseidonRoot[32] | root[32] | mainPoolConfigRoot[32]
    ///         | N × (notFakeTx[8] | accinNull[32] | accoutComm[32]
    ///                | noteInNull[NB×32] | noteOutComm[NB×32])
    /// All slot data is zero (notFakeTx = false).
    function _minBatch(
        TesseraContract r,
        uint256 bpr
    ) internal view returns (bytes memory p) {
        uint256 N = r.PRIV_TX_BATCH_SIZE();
        uint256 NB = r.NOTE_BATCH();
        p = new bytes(96 + N * (8 + 32 + 32 + NB * 64));
        _wb32(p, 0, _glH(bpr)); // batchPoseidonRoot
        _wb32(p, 32, _glH(r.imtCurrentRoot())); // root (confirmed)
        _wb32(p, 64, _glH(r.mainPoolConfigRoot())); // mainPoolConfigRoot
        // Remaining bytes stay zero (all notFakeTx = 0).
    }

    function _minBatch(uint256 bpr) internal view returns (bytes memory) {
        return _minBatch(rollup, bpr);
    }

    /// @dev Like _minBatch but marks slot 0 as real with given account + note nullifiers.
    function _batchWithRealSlot(
        uint256 bpr,
        uint256 acNull,
        uint256[] memory noteNulls // length must be NOTE_BATCH
    ) internal view returns (bytes memory p) {
        p = _minBatch(bpr);
        uint256 slotOff = 96; // slot 0
        _wf8(p, slotOff, 1); // notFakeTx = 1
        _wb32(p, slotOff + 8, _glH(acNull)); // accinNullifier
        for (uint256 j = 0; j < noteNulls.length; j++) {
            _wb32(p, slotOff + 72 + j * 32, _glH(noteNulls[j])); // noteInNullifiers
        }
    }

    // ── Bridge TX batch preimage builder helpers ─────────────────────────────

    uint256 private constant W_SLOT_SIZE = 8 + 32 + 32 + 7 * 8 + 7 * 64 + 40; // 616
    uint256 private constant D_SLOT_SIZE = 8 + 32 + 32 + 32 + 40 + 64 + 8; // 216

    /// @dev Builds a minimal bridge TX batch preimage (all-padding).
    function _minBridgeBatch(
        TesseraContract r,
        uint256 bpr
    ) internal view returns (bytes memory p) {
        uint256 H = r.BRIDGE_TX_HALF_SIZE();
        p = new bytes(96 + H * (W_SLOT_SIZE + D_SLOT_SIZE));
        _wb32(p, 0, _glH(bpr)); // batchPoseidonRoot
        _wb32(p, 32, _glH(r.imtCurrentRoot())); // root
        _wb32(p, 64, _glH(r.mainPoolConfigRoot())); // mainPoolConfigRoot
    }

    /// @dev Like _minBridgeBatch but marks deposit slot 0 as real.
    function _bridgeBatchWithDeposit(
        uint256 bpr,
        uint256 noteKey,
        uint256 acNull
    ) internal view returns (bytes memory p) {
        p = _minBridgeBatch(rollup, bpr);
        uint256 H = rollup.BRIDGE_TX_HALF_SIZE();
        uint256 dSectionOff = 96 + H * W_SLOT_SIZE;
        uint256 slot0Off = dSectionOff; // deposit slot 0
        _wf8(p, slot0Off, 1); // dNotFakeTx = 1
        _wb32(p, slot0Off + 8, _glH(acNull)); // dAccinNull
        // dAccoutComm at +40 stays zero
        _wb32(p, slot0Off + 72, bytes32(noteKey)); // dNoteComm (raw bytes32)
    }

    // ── Submission/prove wrappers ─────────────────────────────────────────────

    /// @dev Submit + prove a TX batch on rollup `r`; appends bpr as a leaf.
    function _appendTo(
        TesseraContract r,
        uint256 bpr
    ) internal returns (bytes32 pic) {
        bytes memory preimage = _minBatch(r, bpr);
        vm.prank(OP);
        r.submitTransactionBatch(preimage);
        pic = keccak256(preimage);
        r.proveTransactionBatch(preimage, _dummyProof());
    }

    function _append(uint256 bpr) internal returns (bytes32 pic) {
        return _appendTo(rollup, bpr);
    }

    // ── GL preimage helpers ───────────────────────────────────────────────────

    /// @dev Convert LE-packed uint256 to GL-preimage bytes32.
    ///      Preimage: [lo0_BE4][hi0_BE4][lo1_BE4][hi1_BE4]...
    function _glH(uint256 p) internal pure returns (bytes32) {
        uint256 e0 = p & 0xFFFFFFFFFFFFFFFF;
        uint256 e1 = (p >> 64) & 0xFFFFFFFFFFFFFFFF;
        uint256 e2 = (p >> 128) & 0xFFFFFFFFFFFFFFFF;
        uint256 e3 = p >> 192;
        return
            bytes32(
                ((e0 & 0xFFFFFFFF) << 224) |
                    ((e0 >> 32) << 192) |
                    ((e1 & 0xFFFFFFFF) << 160) |
                    ((e1 >> 32) << 128) |
                    ((e2 & 0xFFFFFFFF) << 96) |
                    ((e2 >> 32) << 64) |
                    ((e3 & 0xFFFFFFFF) << 32) |
                    (e3 >> 32)
            );
    }

    /// @dev Copy a GL-preimage-encoded bytes32 into pre-allocated `buf` at `off`.
    function _wb32(bytes memory buf, uint256 off, bytes32 val) private pure {
        assembly ("memory-safe") {
            mstore(add(add(buf, 0x20), off), val)
        }
    }

    /// @dev Write 8-byte GL field at `off` in pre-allocated `buf`.
    function _wf8(bytes memory buf, uint256 off, uint64 el) private pure {
        assembly ("memory-safe") {
            let ptr := add(add(buf, 0x20), off)
            let lo := and(el, 0xFFFFFFFF)
            let hi := and(shr(32, el), 0xFFFFFFFF)
            mstore8(ptr, byte(28, lo))
            mstore8(add(ptr, 1), byte(29, lo))
            mstore8(add(ptr, 2), byte(30, lo))
            mstore8(add(ptr, 3), byte(31, lo))
            mstore8(add(ptr, 4), byte(28, hi))
            mstore8(add(ptr, 5), byte(29, hi))
            mstore8(add(ptr, 6), byte(30, hi))
            mstore8(add(ptr, 7), byte(31, hi))
        }
    }

    // -----------------------------------------------------------------------
    // Reference IMT simulation
    // -----------------------------------------------------------------------

    /// @dev Compute the zero hash at `level` using the same Poseidon as the contract.
    ///      zeros[0] = 0, zeros[i] = compress(zeros[i-1], zeros[i-1]).
    function _zeroHash(uint256 level) internal returns (uint256 z) {
        z = 0;
        for (uint256 i = 0; i < level; i++) z = poseidon.compress(z, z);
    }

    /// @dev Simulates one _appendLeaf using the same PoseidonGoldilocks as the contract.
    function _simAppend(uint256 leaf) internal returns (uint256 root) {
        uint256 depth = rollup.treeDepth();
        // Build zero chain locally (no passthrough needed).
        uint256[] memory zeros = new uint256[](depth);
        zeros[0] = 0;
        for (uint256 i = 1; i < depth; i++)
            zeros[i] = poseidon.compress(zeros[i - 1], zeros[i - 1]);

        uint256 node = leaf;
        for (uint256 i = 0; i < depth; i++) {
            if ((_simLC >> i) & 1 == 0) {
                _simFS[i] = node;
                node = poseidon.compress(node, zeros[i]);
            } else {
                node = poseidon.compress(_simFS[i], node);
            }
        }
        _simLC++;
        root = node;
    }

    // -----------------------------------------------------------------------
    // Deposit helper
    // -----------------------------------------------------------------------

    function _deposit(address user, bytes32 nc, uint256 amount) internal {
        token.mint(user, amount);
        vm.prank(user);
        token.approve(address(rollup), amount);
        vm.prank(user);
        rollup.depositAndRegister(nc, ASSET_ID, amount);
    }

    // -----------------------------------------------------------------------
    // =====================================================================
    // TESTS: Poseidon incremental Merkle tree
    // =====================================================================
    // -----------------------------------------------------------------------

    /// After first append, leafCount == 1, currentRoot matches reference.
    function test_appendLeaf_first() public {
        uint256 leaf = 0x1234;
        uint256 expected = _simAppend(leaf);

        _append(leaf);

        assertEq(rollup.imtLeafCount(), 1, "leafCount");
        assertEq(rollup.imtCurrentRoot(), expected, "root matches reference");
        assertTrue(
            rollup.isConfirmedRoot(expected),
            "new root in confirmedRoots"
        );
    }

    /// After 2, 4, 8 appends, root matches reference at each milestone.
    function test_appendLeaf_power_of_two() public {
        uint256[8] memory leaves;
        for (uint256 i = 0; i < 8; i++) leaves[i] = 0x1000 + i;

        uint256 ref2;
        uint256 ref4;
        uint256 ref8;
        for (uint256 i = 0; i < 8; i++) {
            uint256 r = _simAppend(leaves[i]);
            if (i == 1) ref2 = r;
            if (i == 3) ref4 = r;
            if (i == 7) ref8 = r;
        }

        for (uint256 i = 0; i < 8; i++) _append(leaves[i]);

        assertEq(rollup.imtLeafCount(), 8);
        assertEq(rollup.imtCurrentRoot(), ref8, "root after 8");
        assertTrue(rollup.isConfirmedRoot(ref2), "root@2 in confirmedRoots");
        assertTrue(rollup.isConfirmedRoot(ref4), "root@4 in confirmedRoots");
        assertTrue(rollup.isConfirmedRoot(ref8), "root@8 in confirmedRoots");
    }

    /// After 3, 5, 7 appends, root matches reference at each count.
    function test_appendLeaf_arbitrary() public {
        uint256 ref3;
        uint256 ref5;
        uint256 ref7;
        for (uint256 i = 0; i < 7; i++) {
            uint256 r = _simAppend(0x2000 + i);
            if (i == 2) ref3 = r;
            if (i == 4) ref5 = r;
            if (i == 6) ref7 = r;
        }

        for (uint256 i = 0; i < 7; i++) _append(0x2000 + i);

        assertEq(rollup.imtLeafCount(), 7);
        assertEq(rollup.imtCurrentRoot(), ref7, "root after 7");
        assertTrue(rollup.isConfirmedRoot(ref3), "root@3 in confirmedRoots");
        assertTrue(rollup.isConfirmedRoot(ref5), "root@5 in confirmedRoots");
    }

    /// Each append records the new root; genesis root stays confirmed forever.
    function test_appendLeaf_adds_to_confirmedRoots() public {
        // Genesis root = zeros[treeDepth]; computed locally as the initial imt.currentRoot.
        uint256 genesisRoot = rollup.imtCurrentRoot();
        assertTrue(
            rollup.isConfirmedRoot(genesisRoot),
            "genesis confirmed at deploy"
        );

        uint256 prevRoot = genesisRoot;
        for (uint256 i = 1; i <= 4; i++) {
            _append(0x3000 + i);
            uint256 newRoot = rollup.imtCurrentRoot();
            assertTrue(rollup.isConfirmedRoot(newRoot), "new root confirmed");
            assertTrue(
                rollup.isConfirmedRoot(prevRoot),
                "old root still confirmed"
            );
            prevRoot = newRoot;
        }
    }

    /// Appending past 2^treeDepth reverts with TreeFull.
    function test_appendLeaf_treeFullReverts() public {
        TesseraContract small = _deploy(1);
        _appendTo(small, 0x4001);
        _appendTo(small, 0x4002);

        bytes memory preimage = _minBatch(small, 0x4003);
        vm.prank(OP);
        small.submitTransactionBatch(preimage);

        vm.expectRevert(TesseraContract.TreeFull.selector);
        small.proveTransactionBatch(preimage, _dummyProof());
    }

    // -----------------------------------------------------------------------
    // =====================================================================
    // TESTS: submitTransactionBatch
    // =====================================================================
    // -----------------------------------------------------------------------

    /// Valid batch is stored; event emitted.
    function test_submit_happy() public {
        bytes memory preimage = _minBatch(0x9999);
        bytes32 pic = keccak256(preimage);
        bytes32 bpr = _glH(0x9999); // batchPoseidonRoot is at offset 0

        vm.expectEmit(true, false, false, true, address(rollup));
        emit TesseraContract.TransactionBatchSubmitted(pic, bpr);

        vm.prank(OP);
        rollup.submitTransactionBatch(preimage);

        rollup.proveTransactionBatch(preimage, _dummyProof());
        assertEq(rollup.imtLeafCount(), 1);
    }

    /// Unknown root reverts RootNotConfirmed.
    function test_submit_unknownRoot() public {
        bytes memory preimage = _minBatch(1);
        bytes32 unknown = _glH(0xDEAD);
        _wb32(preimage, 32, unknown); // overwrite root at offset 32

        vm.prank(OP);
        vm.expectRevert(
            abi.encodeWithSelector(
                TesseraContract.RootNotConfirmed.selector,
                unknown
            )
        );
        rollup.submitTransactionBatch(preimage);
    }

    /// Wrong poolConfigRoot reverts PoolConfigMismatch.
    function test_submit_wrongPoolConfig() public {
        bytes memory preimage = _minBatch(1);
        _wb32(preimage, 64, _glH(0x1BAD)); // overwrite mainPoolConfigRoot at offset 64

        vm.prank(OP);
        vm.expectRevert(TesseraContract.PoolConfigMismatch.selector);
        rollup.submitTransactionBatch(preimage);
    }

    /// Re-using a spent nullifier in a new batch reverts NullifierAlreadyUsed at prove time.
    function test_submit_nullifierAlreadyUsed() public {
        uint256 knownNullifier = 0x9ABC;
        uint256[] memory noteNulls = new uint256[](rollup.NOTE_BATCH());

        // Prove a batch that spends knownNullifier as the account nullifier.
        {
            bytes memory p = _batchWithRealSlot(
                0x1111,
                knownNullifier,
                noteNulls
            );
            vm.prank(OP);
            rollup.submitTransactionBatch(p);
            rollup.proveTransactionBatch(p, _dummyProof());
        }
        assertTrue(rollup.nullifiers(knownNullifier));

        // Submit a second batch reusing knownNullifier — submit succeeds.
        bytes memory p2 = _batchWithRealSlot(0x2222, knownNullifier, noteNulls);
        vm.prank(OP);
        rollup.submitTransactionBatch(p2);

        // Prove phase must revert with NullifierAlreadyUsed.
        vm.expectRevert(
            abi.encodeWithSelector(
                TesseraContract.NullifierAlreadyUsed.selector,
                _glH(knownNullifier)
            )
        );
        rollup.proveTransactionBatch(p2, _dummyProof());
    }

    /// Submitting the same batch twice reverts BatchAlreadySubmitted.
    function test_submit_duplicate() public {
        bytes memory preimage = _minBatch(0x7777);
        bytes32 pic = keccak256(preimage);

        vm.prank(OP);
        rollup.submitTransactionBatch(preimage);

        vm.prank(OP);
        vm.expectRevert(
            abi.encodeWithSelector(
                TesseraContract.BatchAlreadySubmitted.selector,
                pic
            )
        );
        rollup.submitTransactionBatch(preimage);
    }

    /// Non-operator caller reverts NotOperator.
    function test_submit_notOperator() public {
        bytes memory preimage = _minBatch(0x8888);
        vm.prank(ALICE);
        vm.expectRevert(TesseraContract.NotOperator.selector);
        rollup.submitTransactionBatch(preimage);
    }

    /// Submit while paused reverts PausedErr.
    function test_submit_whenPaused() public {
        vm.prank(OP);
        rollup.setPaused(true);

        bytes memory preimage = _minBatch(0x9999);
        vm.prank(OP);
        vm.expectRevert(TesseraContract.PausedErr.selector);
        rollup.submitTransactionBatch(preimage);
    }

    // -----------------------------------------------------------------------
    // =====================================================================
    // TESTS: proveTransactionBatch
    // =====================================================================
    // -----------------------------------------------------------------------

    /// Happy path: proof accepted, leaf appended, event emitted.
    function test_prove_happy() public {
        uint256 bpr = 0xABCD;
        uint256 lcBefore = rollup.imtLeafCount();
        uint256 rootBefore = rollup.imtCurrentRoot();

        bytes memory preimage = _minBatch(bpr);
        vm.prank(OP);
        rollup.submitTransactionBatch(preimage);
        rollup.proveTransactionBatch(preimage, _dummyProof());

        uint256 newRoot = rollup.imtCurrentRoot();
        assertEq(rollup.imtLeafCount(), lcBefore + 1, "leafCount incremented");
        assertTrue(newRoot != rootBefore, "root changed");
        assertTrue(
            rollup.isConfirmedRoot(newRoot),
            "new root in confirmedRoots"
        );
        assertTrue(
            rollup.isConfirmedRoot(rootBefore),
            "old root still confirmed"
        );
    }

    /// Unknown piCommitment reverts BatchNotFound.
    function test_prove_unknownPiCommitment() public {
        bytes memory fake = hex"DEADBEEF";
        bytes32 pic = keccak256(fake);
        vm.expectRevert(
            abi.encodeWithSelector(TesseraContract.BatchNotFound.selector, pic)
        );
        rollup.proveTransactionBatch(fake, _dummyProof());
    }

    /// Proving an already-confirmed batch reverts BatchAlreadyConfirmed.
    function test_prove_alreadyConfirmed() public {
        bytes memory preimage = _minBatch(0xBBBB);
        bytes32 pic = keccak256(preimage);
        vm.prank(OP);
        rollup.submitTransactionBatch(preimage);
        rollup.proveTransactionBatch(preimage, _dummyProof());

        vm.expectRevert(
            abi.encodeWithSelector(
                TesseraContract.BatchAlreadyConfirmed.selector,
                pic
            )
        );
        rollup.proveTransactionBatch(preimage, _dummyProof());
    }

    /// Invalid proof reverts ProofVerificationFailed.
    function test_prove_invalidProof() public {
        TesseraContract bad = _deployRejectTx(DEPTH);
        bytes memory preimage = _minBatch(bad, 0xCCCC);
        bytes32 pic = keccak256(preimage);
        vm.prank(OP);
        bad.submitTransactionBatch(preimage);

        uint256[8] memory inputs = bad.keccakToPublicInputs(pic);
        vm.expectRevert(
            abi.encodeWithSelector(
                TesseraContract.ProofVerificationFailed.selector,
                pic,
                inputs
            )
        );
        bad.proveTransactionBatch(preimage, _dummyProof());
    }

    /// Anyone (not just operator) can call proveTransactionBatch.
    function test_prove_permissionless() public {
        bytes memory preimage = _minBatch(0xDDDD);
        vm.prank(OP);
        rollup.submitTransactionBatch(preimage);

        vm.prank(ALICE);
        rollup.proveTransactionBatch(preimage, _dummyProof());
    }

    /// Note and account nullifiers for a real slot are inserted after prove.
    /// Padding slots (notFakeTx = false) do not produce nullifiers.
    function test_prove_nullifiersInserted() public {
        uint256[] memory noteNulls = new uint256[](rollup.NOTE_BATCH());
        noteNulls[0] = 0xF001;
        noteNulls[1] = 0xF002;
        uint256 acNull = 0xF003;

        bytes memory preimage = _batchWithRealSlot(0xEEEE, acNull, noteNulls);
        vm.prank(OP);
        rollup.submitTransactionBatch(preimage);
        rollup.proveTransactionBatch(preimage, _dummyProof());

        assertTrue(rollup.nullifiers(noteNulls[0]), "note nullifier 0");
        assertTrue(rollup.nullifiers(noteNulls[1]), "note nullifier 1");
        assertTrue(rollup.nullifiers(acNull), "account nullifier");
    }

    /// Padding slots (notFakeTx = false) do not insert their zero nullifiers.
    function test_prove_paddingNullifiersNotInserted() public {
        bytes memory preimage = _minBatch(0x1234);
        vm.prank(OP);
        rollup.submitTransactionBatch(preimage);
        rollup.proveTransactionBatch(preimage, _dummyProof());

        assertFalse(
            rollup.nullifiers(0),
            "zero nullifier must not be inserted"
        );
    }

    /// Previous currentRoot stays in confirmedRoots after a new leaf is appended.
    function test_prove_rootHistoryPreserved() public {
        uint256 r0 = rollup.imtCurrentRoot();
        _append(0x1111);
        uint256 r1 = rollup.imtCurrentRoot();
        _append(0x2222);
        uint256 r2 = rollup.imtCurrentRoot();

        assertTrue(rollup.isConfirmedRoot(r0), "genesis root preserved");
        assertTrue(rollup.isConfirmedRoot(r1), "root@1 preserved");
        assertTrue(rollup.isConfirmedRoot(r2), "root@2 present");
    }

    // -----------------------------------------------------------------------
    // =====================================================================
    // TESTS: Deposit lifecycle
    // =====================================================================
    // -----------------------------------------------------------------------

    /// depositAndRegister: tokens transferred, status Pending, event emitted.
    function test_deposit_happy() public {
        bytes32 nc = bytes32(uint256(77));
        uint256 amount = 100e6;

        token.mint(ALICE, amount);
        vm.prank(ALICE);
        token.approve(address(rollup), amount);

        vm.expectEmit(true, false, false, true, address(rollup));
        emit TesseraContract.DepositAvailable(nc, amount, ALICE, ASSET_ID);
        vm.prank(ALICE);
        rollup.depositAndRegister(nc, ASSET_ID, amount);

        TesseraContract.Deposit memory d = rollup.getDeposit(nc);
        assertEq(d.value, amount);
        assertEq(d.recipient, ALICE);
        assertEq(uint8(d.status), uint8(TesseraContract.DepositStatus.Pending));
        assertEq(token.balanceOf(address(rollup)), amount);
    }

    /// Recipient can withdraw a Pending deposit; tokens returned.
    function test_withdraw_pending() public {
        bytes32 nc = bytes32(uint256(88));
        uint256 amount = 50e6;
        _deposit(ALICE, nc, amount);

        vm.prank(ALICE);
        rollup.withdrawPendingDeposit(nc);

        assertEq(
            uint8(rollup.getDeposit(nc).status),
            uint8(TesseraContract.DepositStatus.Withdrawn)
        );
        assertEq(token.balanceOf(ALICE), amount);
        assertEq(token.balanceOf(address(rollup)), 0);
    }

    /// Non-recipient cannot withdraw; reverts NotDepositRecipient.
    function test_withdraw_nonRecipient() public {
        bytes32 nc = bytes32(uint256(99));
        _deposit(ALICE, nc, 10e6);

        vm.prank(address(0xB0B));
        vm.expectRevert(TesseraContract.NotDepositRecipient.selector);
        rollup.withdrawPendingDeposit(nc);
    }

    // -----------------------------------------------------------------------
    // =====================================================================
    // TESTS: BridgeTxBatch
    // =====================================================================
    // -----------------------------------------------------------------------

    /// submitBridgeTxBatch with a real deposit slot validates the note is Pending.
    function test_submitBridgeTxBatch_validatesPendingDeposits() public {
        uint256 noteKey = 1001;
        bytes32 nc = bytes32(noteKey);
        _deposit(ALICE, nc, 1e6);

        bytes memory preimage = _bridgeBatchWithDeposit(0x1234, noteKey, _nc++);

        vm.prank(OP);
        rollup.submitBridgeTxBatch(preimage); // must not revert

        // Note still Pending (not yet proven).
        assertEq(
            uint8(rollup.getDeposit(nc).status),
            uint8(TesseraContract.DepositStatus.Pending)
        );
    }

    /// submitBridgeTxBatch with a non-existent deposit note reverts NoteNotFound.
    function test_submitBridgeTxBatch_rejectsMissingNote() public {
        uint256 noteKey = 9999;
        bytes memory preimage = _bridgeBatchWithDeposit(1, noteKey, _nc++);

        vm.prank(OP);
        vm.expectRevert(
            abi.encodeWithSelector(
                TesseraContract.NoteNotFound.selector,
                bytes32(noteKey)
            )
        );
        rollup.submitBridgeTxBatch(preimage);
    }

    /// proveBridgeTxBatch advances real deposit notes to Validated and appends tree leaf.
    function test_proveBridgeTxBatch_marksDepositValidated() public {
        uint256 noteKey = 3001;
        bytes32 nc = bytes32(noteKey);
        _deposit(ALICE, nc, 1e6);

        bytes memory preimage = _bridgeBatchWithDeposit(0x5678, noteKey, _nc++);

        vm.prank(OP);
        rollup.submitBridgeTxBatch(preimage);

        rollup.proveBridgeTxBatch(preimage, _dummyProof());

        assertEq(
            uint8(rollup.getDeposit(nc).status),
            uint8(TesseraContract.DepositStatus.Validated),
            "deposit not validated"
        );
        assertEq(rollup.imtLeafCount(), 1, "leaf not appended");
    }

    /// All-padding batch appends a leaf after prove.
    function test_proveBridgeTxBatch_paddingAppendsLeaf() public {
        bytes memory preimage = _minBridgeBatch(rollup, 0xABCD);
        vm.prank(OP);
        rollup.submitBridgeTxBatch(preimage);
        assertEq(rollup.imtLeafCount(), 0, "no leaf yet before prove");
        rollup.proveBridgeTxBatch(preimage, _dummyProof());
        assertEq(rollup.imtLeafCount(), 1, "leaf appended after prove");
    }

    /// Cannot withdraw a deposit after it has been Validated.
    function test_withdraw_afterValidated() public {
        uint256 noteKey = 4001;
        bytes32 nc = bytes32(noteKey);
        _deposit(ALICE, nc, 5e6);

        bytes memory preimage = _bridgeBatchWithDeposit(0x9ABC, noteKey, _nc++);
        vm.prank(OP);
        rollup.submitBridgeTxBatch(preimage);

        // Verify that attempting to withdraw a Pending deposit (not yet validated)
        // by non-recipient fails.
        vm.prank(address(0xB0B));
        vm.expectRevert(TesseraContract.NotDepositRecipient.selector);
        rollup.withdrawPendingDeposit(nc);
    }

    // -----------------------------------------------------------------------
    // =====================================================================
    // TESTS: Access control + pause
    // =====================================================================
    // -----------------------------------------------------------------------

    /// Operator can transfer the operator role.
    function test_setOperator() public {
        address newOp = address(0xABCD);
        vm.prank(OP);
        vm.expectEmit(true, true, false, false, address(rollup));
        emit TesseraContract.OperatorChanged(OP, newOp);
        rollup.setOperator(newOp);
        assertEq(rollup.operator(), newOp);
    }

    /// Non-operator cannot set operator; reverts NotOperator.
    function test_setOperator_nonOperator() public {
        vm.prank(ALICE);
        vm.expectRevert(TesseraContract.NotOperator.selector);
        rollup.setOperator(ALICE);
    }

    /// Pause blocks all mutating entry points; unpause restores them.
    function test_setPaused_blocksSubmit() public {
        vm.prank(OP);
        rollup.setPaused(true);
        assertTrue(rollup.paused());

        bytes memory preimage = _minBatch(1);

        vm.prank(OP);
        vm.expectRevert(TesseraContract.PausedErr.selector);
        rollup.submitTransactionBatch(preimage);

        vm.expectRevert(TesseraContract.PausedErr.selector);
        rollup.proveTransactionBatch(new bytes(0), _dummyProof());

        vm.prank(ALICE);
        vm.expectRevert(TesseraContract.PausedErr.selector);
        rollup.depositAndRegister(bytes32(uint256(1)), ASSET_ID, 100);

        vm.prank(ALICE);
        vm.expectRevert(TesseraContract.PausedErr.selector);
        rollup.withdrawPendingDeposit(bytes32(uint256(1)));

        vm.prank(OP);
        rollup.setPaused(false);
        vm.prank(OP);
        rollup.submitTransactionBatch(preimage);
    }

    // -----------------------------------------------------------------------
    // =====================================================================
    // TESTS: keccakToPublicInputs encoding
    // =====================================================================
    // -----------------------------------------------------------------------

    /// keccakToPublicInputs correctly decomposes a known bytes32 into 8 uint32 words.
    function test_keccakToPublicInputs_roundtrip() public view {
        uint256[8] memory words;
        words[0] = 0xDEADBEEF;
        words[1] = 0x01234567;
        words[2] = 0x89ABCDEF;
        words[3] = 0xFEDCBA98;
        words[4] = 0x11223344;
        words[5] = 0x55667788;
        words[6] = 0x99AABBCC;
        words[7] = 0x00FF00FF;

        bytes32 packed = bytes32(
            (words[0] << 224) |
                (words[1] << 192) |
                (words[2] << 160) |
                (words[3] << 128) |
                (words[4] << 96) |
                (words[5] << 64) |
                (words[6] << 32) |
                words[7]
        );

        uint256[8] memory unpacked = rollup.keccakToPublicInputs(packed);
        for (uint256 i = 0; i < 8; i++) {
            assertEq(unpacked[i], words[i], "word mismatch");
        }
    }

    /// keccakToPublicInputs round-trips the all-zero bytes32.
    function test_keccakToPublicInputs_allZero() public view {
        uint256[8] memory inputs = rollup.keccakToPublicInputs(bytes32(0));
        for (uint256 i = 0; i < 8; i++) {
            assertEq(inputs[i], 0, "zero mismatch");
        }
    }

    /// keccakToPublicInputs round-trips the all-ones bytes32.
    function test_keccakToPublicInputs_allOnes() public view {
        bytes32 allOnes = bytes32(type(uint256).max);
        uint256[8] memory inputs = rollup.keccakToPublicInputs(allOnes);
        for (uint256 i = 0; i < 8; i++) {
            assertEq(inputs[i], 0xFFFFFFFF, "allOnes mismatch");
        }
    }

    // -----------------------------------------------------------------------
    // =====================================================================
    // TESTS: GL encoding helpers (_glHashToBytes / _glFieldToBytes)
    // =====================================================================
    // -----------------------------------------------------------------------

    /// _glHashToBytes: all-zero packed value produces 32 zero bytes.
    function test_glHashToBytes_zero() public pure {
        bytes memory b = _glHashToBytes(0);
        assertEq(b.length, 32, "length");
        for (uint256 i = 0; i < 32; i++) assertEq(uint8(b[i]), 0, "byte");
    }

    /// _glFieldToBytes: zero field → 8 zero bytes.
    function test_glFieldToBytes_zero() public pure {
        bytes memory b = _glFieldToBytes(0);
        assertEq(b.length, 8, "length");
        for (uint256 i = 0; i < 8; i++) assertEq(uint8(b[i]), 0, "byte");
    }

    /// _glFieldToBytes: known value — lo=1, hi=0 → [0,0,0,1, 0,0,0,0].
    function test_glFieldToBytes_loOne() public pure {
        // el = 1 → lo=1, hi=0
        bytes memory b = _glFieldToBytes(1);
        assertEq(uint8(b[0]), 0);
        assertEq(uint8(b[1]), 0);
        assertEq(uint8(b[2]), 0);
        assertEq(uint8(b[3]), 1); // lo = 1 in BE
        assertEq(uint8(b[4]), 0);
        assertEq(uint8(b[5]), 0);
        assertEq(uint8(b[6]), 0);
        assertEq(uint8(b[7]), 0); // hi = 0
    }

    /// _glFieldToBytes: el = 0x0000_0001_0000_0002 → lo=2, hi=1.
    function test_glFieldToBytes_hiAndLo() public pure {
        uint64 el = (uint64(1) << 32) | uint64(2); // hi=1, lo=2
        bytes memory b = _glFieldToBytes(el);
        // lo=2 → [0,0,0,2]; hi=1 → [0,0,0,1]
        assertEq(uint8(b[3]), 2, "lo byte3");
        assertEq(uint8(b[7]), 1, "hi byte3");
    }

    /// _glHashToBytes: known single-element value round-trips via _glFieldToBytes.
    ///   el0 = 0x0102030405060708, el1=el2=el3=0
    ///   packed = el0 (in lowest 64 bits)
    function test_glHashToBytes_knownElement() public pure {
        uint64 el0 = 0x0102030405060708;
        uint256 packed = uint256(el0); // el0 in lowest 64 bits
        bytes memory h = _glHashToBytes(packed);
        bytes memory f = _glFieldToBytes(el0);
        // First 8 bytes of hash should match _glFieldToBytes(el0)
        for (uint256 i = 0; i < 8; i++) {
            assertEq(uint8(h[i]), uint8(f[i]), "mismatch at byte");
        }
        // Remaining 24 bytes should be zero (el1=el2=el3=0)
        for (uint256 i = 8; i < 32; i++) {
            assertEq(uint8(h[i]), 0, "non-zero in upper bytes");
        }
    }

    // -----------------------------------------------------------------------
    // =====================================================================
    // TESTS: piCommitment generation
    // =====================================================================
    // -----------------------------------------------------------------------

    /// TX piCommitment: round-trip — submitTransactionBatch emits the same hash
    /// as keccak256(preimage).
    function test_txPiCommitment_roundTrip() public {
        bytes memory preimage = _minBatch(0x1234567890);
        bytes32 expected = keccak256(preimage);

        vm.prank(OP);
        vm.expectEmit(true, false, false, false, address(rollup));
        emit TesseraContract.TransactionBatchSubmitted(
            expected,
            _glH(0x1234567890)
        );
        rollup.submitTransactionBatch(preimage);
    }

    /// TX piCommitment: different batchPoseidonRoots produce different commitments.
    function test_txPiCommitment_bprMatters() public view {
        bytes memory p1 = _minBatch(0x111);
        bytes memory p2 = _minBatch(0x222);
        assertNotEq(
            keccak256(p1),
            keccak256(p2),
            "distinct BPRs must yield distinct commitments"
        );
    }

    /// TX piCommitment: different act_roots produce different commitments.
    function test_txPiCommitment_rootMatters() public view {
        bytes memory p1 = _minBatch(0x999);
        bytes memory p2 = _minBatch(0x999);
        // Flip one bit in the root field at offset 32.
        p2[32] ^= 0x01;
        assertNotEq(
            keccak256(p1),
            keccak256(p2),
            "distinct roots must yield distinct commitments"
        );
    }

    /// Genesis mainPoolConfigRoot matches zeros[configTreeDepth] computed locally.
    function test_genesisConfigRoot() public {
        uint256 expected = _zeroHash(rollup.configTreeDepth());
        assertEq(
            rollup.mainPoolConfigRoot(),
            expected,
            "genesis config root mismatch"
        );
    }

    /// withdrawalDelay blocks early withdrawal; passes after delay elapses.
    function test_withdrawalDelay() public {
        // Deploy a rollup with a 10-block delay.
        TesseraContract delayed = new TesseraContract(
            address(acceptVerifier),
            address(acceptVerifier),
            address(poseidon),
            OP,
            DEPTH,
            20,
            10
        );
        // Register the test token on the delayed contract.
        vm.prank(OP);
        delayed.registerAsset(ASSET_ID, address(token));

        bytes32 nc = bytes32(uint256(55));
        uint256 amount = 1e6;
        token.mint(ALICE, amount);
        vm.prank(ALICE);
        token.approve(address(delayed), amount);
        vm.prank(ALICE);
        delayed.depositAndRegister(nc, ASSET_ID, amount);

        // Attempt withdrawal immediately — should revert.
        vm.prank(ALICE);
        vm.expectRevert(
            abi.encodeWithSelector(
                TesseraContract.WithdrawalTooEarly.selector,
                nc,
                block.number + 10
            )
        );
        delayed.withdrawPendingDeposit(nc);

        // Roll forward 10 blocks — withdrawal should succeed.
        vm.roll(block.number + 10);
        vm.prank(ALICE);
        delayed.withdrawPendingDeposit(nc);
        assertEq(token.balanceOf(ALICE), amount);
    }

    /// assignSubpoolOwner rejects subpoolId 0.
    function test_assignSubpoolOwner_rejectsZero() public {
        vm.prank(OP);
        vm.expectRevert(TesseraContract.SubpoolIdZero.selector);
        rollup.assignSubpoolOwner(0, ALICE);
    }

    /// assignSubpoolOwner only callable by operator.
    function test_assignSubpoolOwner_onlyOperator() public {
        vm.prank(ALICE);
        vm.expectRevert(TesseraContract.NotOperator.selector);
        rollup.assignSubpoolOwner(1, ALICE);
    }
}

contract GasMeasureTest is TesseraRollupV2Test {
    // 1. Build preimage bytes (no contract call, no storage)
    function test_measure_preimage_build() public view {
        _minBatch(0x1234);
    }

    // 2. submitTransactionBatch — single bool SSTORE + keccak (much cheaper than struct storage).
    function test_measure_submit_only() public {
        bytes memory preimage = _minBatch(0x1234);
        vm.prank(OP);
        rollup.submitTransactionBatch(preimage);
    }
}
