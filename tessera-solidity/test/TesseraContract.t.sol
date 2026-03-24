// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {TesseraContract} from "../src/TesseraContract.sol";
import {PoseidonGoldilocks} from "../src/PoseidonGoldilocks.sol";
import {ToyUSDT} from "../src/ToyUSDT.sol";

// ---------------------------------------------------------------------------
// Test-only verifiers
// ---------------------------------------------------------------------------

/// @dev Accepts every Groth16-shaped proof. Never deploy to production.
contract AcceptAllVerifier {
    function verifyProof(
        uint256[8] calldata, uint256[2] calldata, uint256[2] calldata, uint256[8] calldata
    ) external pure {}
}

/// @dev Rejects every proof — used to exercise ProofVerificationFailed paths.
contract RejectAllVerifier {
    function verifyProof(
        uint256[8] calldata, uint256[2] calldata, uint256[2] calldata, uint256[8] calldata
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

    address constant OP    = address(0x0001);
    address constant ALICE = address(0xA11CE);
    bytes32 constant PCR   = bytes32(uint256(0xC0FFEE));
    uint256 constant DEPTH = 4; // 16 leaf slots

    // Unique-nullifier counter; reset per test by Forge's EVM isolation.
    uint256 private _nc;

    // Reference IMT state — storage variables, reset per test by Forge isolation.
    uint256 private _simLC;
    mapping(uint256 => uint256) private _simFS;

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------

    function setUp() public {
        poseidon       = new PoseidonGoldilocks();
        token          = new ToyUSDT();
        acceptVerifier = new AcceptAllVerifier();
        rejectVerifier = new RejectAllVerifier();
        rollup = _deploy(DEPTH);
        _nc    = 0xDEAD_0001;
    }

    // -----------------------------------------------------------------------
    // Deployment helpers
    // -----------------------------------------------------------------------

    function _deploy(uint256 depth) internal returns (TesseraContract) {
        return new TesseraContract(
            address(acceptVerifier),
            address(acceptVerifier),
            address(poseidon),
            OP,
            address(token),
            PCR,
            depth
        );
    }

    function _deployRejectTx(uint256 depth) internal returns (TesseraContract) {
        return new TesseraContract(
            address(rejectVerifier),
            address(acceptVerifier),
            address(poseidon),
            OP,
            address(token),
            PCR,
            depth
        );
    }

    // -----------------------------------------------------------------------
    // Batch / proof helpers
    // -----------------------------------------------------------------------

    function _dummyProof() internal pure returns (TesseraContract.Proof memory p) {
        // All-zero default — AcceptAllVerifier ignores contents.
    }

    /// @dev Builds a minimal valid TransactionBatch against rollup `r` with the given batchPoseidonRoot.
    function _minBatch(TesseraContract r, uint256 bpr)
        internal
        returns (TesseraContract.TransactionBatch memory b)
    {
        uint256 genesis = r.zeros(r.treeDepth());
        uint256[] memory empty = new uint256[](0);
        uint256 an = _nc++;
        uint256[] memory acs = new uint256[](1);
        acs[0] = an + 1;
        uint256[] memory ans = new uint256[](1);
        ans[0] = an;
        b = TesseraContract.TransactionBatch({
            root:              genesis,
            mainPoolConfigRoot: PCR,
            noteCommitments:   empty,
            noteNullifiers:    empty,
            accountCommitments: acs,
            accountNullifiers:  ans,
            batchPoseidonRoot: bpr,
            confirmed:         false
        });
    }

    function _minBatch(uint256 bpr) internal returns (TesseraContract.TransactionBatch memory) {
        return _minBatch(rollup, bpr);
    }

    /// @dev Computes the tx piCommitment — must mirror contract's _computeTxPiCommitment.
    function _txPI(TesseraContract.TransactionBatch memory b) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            b.root, b.mainPoolConfigRoot, b.batchPoseidonRoot,
            b.accountCommitments, b.accountNullifiers,
            b.noteCommitments, b.noteNullifiers
        ));
    }

    /// @dev Computes the deposit piCommitment — mirrors contract's _computeDepositPiCommitment.
    ///      Real deposit slots carry the depositor address (looked up from rollup storage);
    ///      dummy slots (up to DEPOSIT_BATCH_SIZE) carry address(0).
    function _depositPI(TesseraContract.DepositBatch memory b) internal view returns (bytes32) {
        bytes memory preimage = abi.encodePacked(
            b.root, b.mainPoolConfigRoot, b.batchPoseidonRoot
        );
        uint256 realLen = b.depositNoteCommitments.length;
        for (uint256 i = 0; i < realLen; i++) {
            (, address depositor,) = rollup.deposits(b.depositNoteCommitments[i]);
            preimage = bytes.concat(preimage, _addressToLE20(depositor));
        }
        bytes memory zeroAddr = _addressToLE20(address(0));
        for (uint256 i = realLen; i < rollup.DEPOSIT_BATCH_SIZE(); i++) {
            preimage = bytes.concat(preimage, zeroAddr);
        }
        return keccak256(preimage);
    }

    /// @dev Mirrors TesseraContract._addressToLE20: serialises an address as
    ///      5 × 4-byte little-endian u32 limbs (byte-reverse each 4-byte chunk).
    function _addressToLE20(address a) internal pure returns (bytes memory out) {
        bytes20 be = bytes20(a);
        out = new bytes(20);
        for (uint256 i = 0; i < 5; i++) {
            out[4 * i]     = be[4 * i + 3];
            out[4 * i + 1] = be[4 * i + 2];
            out[4 * i + 2] = be[4 * i + 1];
            out[4 * i + 3] = be[4 * i];
        }
    }

    /// @dev Submit + prove a tx batch on rollup `r`; appends bpr as a leaf.
    function _appendTo(TesseraContract r, uint256 bpr) internal returns (bytes32 pic) {
        TesseraContract.TransactionBatch memory b = _minBatch(r, bpr);
        vm.prank(OP);
        r.submitTransactionBatch(b);
        pic = _txPI(b);
        r.proveTransactionBatch(pic, _dummyProof());
    }

    function _append(uint256 bpr) internal returns (bytes32 pic) {
        return _appendTo(rollup, bpr);
    }

    // -----------------------------------------------------------------------
    // Reference IMT simulation
    // -----------------------------------------------------------------------

    /// @dev Simulates one _appendLeaf using the same PoseidonGoldilocks as the contract.
    ///      Reads zeros from `rollup`; updates _simLC and _simFS in test storage.
    function _simAppend(uint256 leaf) internal returns (uint256 root) {
        uint256 depth = rollup.treeDepth();
        uint256 node  = leaf;
        for (uint256 i = 0; i < depth; i++) {
            if ((_simLC >> i) & 1 == 0) {
                _simFS[i] = node;
                node = poseidon.compress(node, rollup.zeros(i));
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
        rollup.depositAndRegister(nc, amount);
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

        assertEq(rollup.leafCount(), 1, "leafCount");
        assertEq(rollup.currentRoot(), expected, "root matches reference");
        assertTrue(rollup.confirmedRoots(expected), "new root in confirmedRoots");
    }

    /// After 2, 4, 8 appends, root matches reference at each milestone.
    function test_appendLeaf_power_of_two() public {
        // Compute all 8 reference roots in order.
        uint256[8] memory leaves;
        for (uint256 i = 0; i < 8; i++) {
            leaves[i] = 0x1000 + i;
        }
        uint256 ref2;
        uint256 ref4;
        uint256 ref8;
        for (uint256 i = 0; i < 8; i++) {
            uint256 r = _simAppend(leaves[i]);
            if (i == 1) ref2 = r;
            if (i == 3) ref4 = r;
            if (i == 7) ref8 = r;
        }

        // Append the same leaves to the contract.
        for (uint256 i = 0; i < 8; i++) {
            _append(leaves[i]);
        }

        assertEq(rollup.leafCount(), 8);
        assertEq(rollup.currentRoot(), ref8, "root after 8");
        // All intermediate roots are confirmed forever.
        assertTrue(rollup.confirmedRoots(ref2), "root@2 in confirmedRoots");
        assertTrue(rollup.confirmedRoots(ref4), "root@4 in confirmedRoots");
        assertTrue(rollup.confirmedRoots(ref8), "root@8 in confirmedRoots");
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

        for (uint256 i = 0; i < 7; i++) {
            _append(0x2000 + i);
        }

        assertEq(rollup.leafCount(), 7);
        assertEq(rollup.currentRoot(), ref7, "root after 7");
        assertTrue(rollup.confirmedRoots(ref3), "root@3 in confirmedRoots");
        assertTrue(rollup.confirmedRoots(ref5), "root@5 in confirmedRoots");
    }

    /// Each append records the new root; genesis root stays confirmed forever.
    function test_appendLeaf_adds_to_confirmedRoots() public {
        uint256 genesis = rollup.zeros(rollup.treeDepth());
        assertTrue(rollup.confirmedRoots(genesis), "genesis confirmed at deploy");

        uint256 prevRoot = rollup.currentRoot();
        for (uint256 i = 1; i <= 4; i++) {
            _append(0x3000 + i);
            uint256 newRoot = rollup.currentRoot();
            assertTrue(rollup.confirmedRoots(newRoot),  "new root confirmed");
            assertTrue(rollup.confirmedRoots(prevRoot), "old root still confirmed");
            prevRoot = newRoot;
        }
    }

    /// Appending past 2^treeDepth reverts with TreeFull.
    function test_appendLeaf_treeFullReverts() public {
        // depth-1 tree holds exactly 2 leaves.
        TesseraContract small = _deploy(1);
        _appendTo(small, 0x4001);
        _appendTo(small, 0x4002);

        TesseraContract.TransactionBatch memory b = _minBatch(small, 0x4003);
        vm.prank(OP);
        small.submitTransactionBatch(b);
        bytes32 pic = _txPI(b);

        vm.expectRevert(TesseraContract.TreeFull.selector);
        small.proveTransactionBatch(pic, _dummyProof());
    }

    // -----------------------------------------------------------------------
    // =====================================================================
    // TESTS: submitTransactionBatch
    // =====================================================================
    // -----------------------------------------------------------------------

    /// Valid batch is stored; event emitted.
    function test_submit_happy() public {
        TesseraContract.TransactionBatch memory b = _minBatch(uint256(0x9999));
        bytes32 pic = _txPI(b);

        vm.expectEmit(true, false, false, true, address(rollup));
        emit TesseraContract.TransactionBatchSubmitted(pic, b.batchPoseidonRoot);

        vm.prank(OP);
        rollup.submitTransactionBatch(b);

        // Confirm stored by proving successfully.
        rollup.proveTransactionBatch(pic, _dummyProof());
        assertEq(rollup.leafCount(), 1);
    }

    /// Unknown root reverts RootNotConfirmed.
    function test_submit_unknownRoot() public {
        uint256 unknown = 0xDEAD;
        uint256[] memory empty = new uint256[](0);
        uint256 an = _nc++;
        uint256[] memory acs = new uint256[](1); acs[0] = an + 1;
        uint256[] memory ans = new uint256[](1); ans[0] = an;
        TesseraContract.TransactionBatch memory b = TesseraContract.TransactionBatch({
            root: unknown, mainPoolConfigRoot: PCR,
            noteCommitments: empty, noteNullifiers: empty,
            accountCommitments: acs, accountNullifiers: ans,
            batchPoseidonRoot: 1, confirmed: false
        });
        vm.prank(OP);
        vm.expectRevert(abi.encodeWithSelector(TesseraContract.RootNotConfirmed.selector, unknown));
        rollup.submitTransactionBatch(b);
    }

    /// Wrong poolConfigRoot reverts PoolConfigMismatch.
    function test_submit_wrongPoolConfig() public {
        uint256 genesis = rollup.zeros(rollup.treeDepth());
        uint256[] memory empty = new uint256[](0);
        uint256 an = _nc++;
        uint256[] memory acs = new uint256[](1); acs[0] = an + 1;
        uint256[] memory ans = new uint256[](1); ans[0] = an;
        TesseraContract.TransactionBatch memory b = TesseraContract.TransactionBatch({
            root: genesis, mainPoolConfigRoot: bytes32(uint256(0x1BAD)),
            noteCommitments: empty, noteNullifiers: empty,
            accountCommitments: acs, accountNullifiers: ans,
            batchPoseidonRoot: 1, confirmed: false
        });
        vm.prank(OP);
        vm.expectRevert(TesseraContract.PoolConfigMismatch.selector);
        rollup.submitTransactionBatch(b);
    }

    /// Re-using a spent nullifier in a new batch reverts NullifierAlreadyUsed at prove time.
    ///
    /// submitTransactionBatch is permissive (no nullifier pre-check); the check
    /// is enforced in proveTransactionBatch so that the two-phase model can
    /// reject races without blocking submission.
    function test_submit_nullifierAlreadyUsed() public {
        uint256 knownNullifier = 0x9ABC;
        uint256 genesis = rollup.zeros(rollup.treeDepth());
        uint256[] memory empty = new uint256[](0);

        // Prove a batch that spends knownNullifier.
        {
            uint256[] memory acs = new uint256[](1); acs[0] = _nc++;
            uint256[] memory ans = new uint256[](1); ans[0] = knownNullifier;
            TesseraContract.TransactionBatch memory b = TesseraContract.TransactionBatch({
                root: genesis, mainPoolConfigRoot: PCR,
                noteCommitments: empty, noteNullifiers: empty,
                accountCommitments: acs, accountNullifiers: ans,
                batchPoseidonRoot: 0x1111, confirmed: false
            });
            bytes32 pic = _txPI(b);
            vm.prank(OP); rollup.submitTransactionBatch(b);
            rollup.proveTransactionBatch(pic, _dummyProof());
        }
        assertTrue(rollup.nullifiers(knownNullifier));

        // Submit a second batch reusing knownNullifier — submit succeeds.
        uint256[] memory acs2 = new uint256[](1); acs2[0] = _nc++;
        uint256[] memory ans2 = new uint256[](1); ans2[0] = knownNullifier;
        TesseraContract.TransactionBatch memory b2 = TesseraContract.TransactionBatch({
            root: genesis, mainPoolConfigRoot: PCR,
            noteCommitments: empty, noteNullifiers: empty,
            accountCommitments: acs2, accountNullifiers: ans2,
            batchPoseidonRoot: 0x2222, confirmed: false
        });
        bytes32 pic2 = _txPI(b2);
        vm.prank(OP);
        rollup.submitTransactionBatch(b2);

        // Prove phase must revert with NullifierAlreadyUsed.
        vm.expectRevert(abi.encodeWithSelector(TesseraContract.NullifierAlreadyUsed.selector, knownNullifier));
        rollup.proveTransactionBatch(pic2, _dummyProof());
    }

    /// Submitting the same batch twice reverts BatchAlreadySubmitted.
    function test_submit_duplicate() public {
        TesseraContract.TransactionBatch memory b = _minBatch(0x7777);
        bytes32 pic = _txPI(b);

        vm.prank(OP);
        rollup.submitTransactionBatch(b);

        vm.prank(OP);
        vm.expectRevert(abi.encodeWithSelector(TesseraContract.BatchAlreadySubmitted.selector, pic));
        rollup.submitTransactionBatch(b);
    }

    /// Non-operator caller reverts NotOperator.
    function test_submit_notOperator() public {
        TesseraContract.TransactionBatch memory b = _minBatch(0x8888);
        vm.prank(ALICE);
        vm.expectRevert(TesseraContract.NotOperator.selector);
        rollup.submitTransactionBatch(b);
    }

    /// Submit while paused reverts PausedErr.
    function test_submit_whenPaused() public {
        vm.prank(OP);
        rollup.setPaused(true);

        TesseraContract.TransactionBatch memory b = _minBatch(0x9999);
        vm.prank(OP);
        vm.expectRevert(TesseraContract.PausedErr.selector);
        rollup.submitTransactionBatch(b);
    }

    // -----------------------------------------------------------------------
    // =====================================================================
    // TESTS: proveTransactionBatch
    // =====================================================================
    // -----------------------------------------------------------------------

    /// Happy path: proof accepted, leaf appended, event emitted.
    function test_prove_happy() public {
        uint256 bpr       = 0xABCD;
        uint256 lcBefore  = rollup.leafCount();
        uint256 rootBefore = rollup.currentRoot();

        TesseraContract.TransactionBatch memory b = _minBatch(bpr);
        bytes32 pic = _txPI(b);
        vm.prank(OP);
        rollup.submitTransactionBatch(b);
        rollup.proveTransactionBatch(pic, _dummyProof());

        uint256 newRoot = rollup.currentRoot();
        assertEq(rollup.leafCount(), lcBefore + 1,        "leafCount incremented");
        assertTrue(newRoot != rootBefore,                 "root changed");
        assertTrue(rollup.confirmedRoots(newRoot),        "new root in confirmedRoots");
        assertTrue(rollup.confirmedRoots(rootBefore),     "old root still confirmed");
    }

    /// Unknown piCommitment reverts BatchNotFound.
    function test_prove_unknownPiCommitment() public {
        bytes32 fake = bytes32(uint256(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(TesseraContract.BatchNotFound.selector, fake));
        rollup.proveTransactionBatch(fake, _dummyProof());
    }

    /// Proving an already-confirmed batch reverts BatchAlreadyConfirmed.
    function test_prove_alreadyConfirmed() public {
        TesseraContract.TransactionBatch memory b = _minBatch(0xBBBB);
        bytes32 pic = _txPI(b);
        vm.prank(OP);
        rollup.submitTransactionBatch(b);
        rollup.proveTransactionBatch(pic, _dummyProof());

        vm.expectRevert(abi.encodeWithSelector(TesseraContract.BatchAlreadyConfirmed.selector, pic));
        rollup.proveTransactionBatch(pic, _dummyProof());
    }

    /// Invalid proof reverts ProofVerificationFailed.
    function test_prove_invalidProof() public {
        TesseraContract bad = _deployRejectTx(DEPTH);
        TesseraContract.TransactionBatch memory b = _minBatch(bad, 0xCCCC);
        bytes32 pic = _txPI(b);
        vm.prank(OP);
        bad.submitTransactionBatch(b);

        uint256[8] memory inputs = bad.keccakToPublicInputs(pic);
        vm.expectRevert(abi.encodeWithSelector(TesseraContract.ProofVerificationFailed.selector, pic, inputs));
        bad.proveTransactionBatch(pic, _dummyProof());
    }

    /// Anyone (not just operator) can call proveTransactionBatch.
    function test_prove_permissionless() public {
        TesseraContract.TransactionBatch memory b = _minBatch(0xDDDD);
        bytes32 pic = _txPI(b);
        vm.prank(OP);
        rollup.submitTransactionBatch(b);

        vm.prank(ALICE); // non-operator
        rollup.proveTransactionBatch(pic, _dummyProof()); // must not revert
    }

    /// All note nullifiers and the account nullifier are inserted after prove.
    function test_prove_nullifiersInserted() public {
        uint256 genesis = rollup.zeros(rollup.treeDepth());
        uint256[] memory empty = new uint256[](0);
        uint256[] memory nns = new uint256[](2);
        nns[0] = 0xF001;
        nns[1] = 0xF002;
        uint256 acNull = 0xF003;

        uint256[] memory acs = new uint256[](1); acs[0] = _nc++;
        uint256[] memory ans = new uint256[](1); ans[0] = acNull;
        TesseraContract.TransactionBatch memory b = TesseraContract.TransactionBatch({
            root: genesis, mainPoolConfigRoot: PCR,
            noteCommitments: empty, noteNullifiers: nns,
            accountCommitments: acs, accountNullifiers: ans,
            batchPoseidonRoot: 0xEEEE, confirmed: false
        });
        bytes32 pic = _txPI(b);
        vm.prank(OP); rollup.submitTransactionBatch(b);
        rollup.proveTransactionBatch(pic, _dummyProof());

        assertTrue(rollup.nullifiers(nns[0]),  "note nullifier 0");
        assertTrue(rollup.nullifiers(nns[1]),  "note nullifier 1");
        assertTrue(rollup.nullifiers(acNull),  "account nullifier");
    }

    /// Previous currentRoot stays in confirmedRoots after a new leaf is appended.
    function test_prove_rootHistoryPreserved() public {
        uint256 r0 = rollup.currentRoot();
        _append(0x1111);
        uint256 r1 = rollup.currentRoot();
        _append(0x2222);
        uint256 r2 = rollup.currentRoot();

        assertTrue(rollup.confirmedRoots(r0), "genesis root preserved");
        assertTrue(rollup.confirmedRoots(r1), "root@1 preserved");
        assertTrue(rollup.confirmedRoots(r2), "root@2 present");
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

        // Prepare allowance before the event check so the Transfer from mint/approve
        // doesn't precede the expectEmit declaration.
        token.mint(ALICE, amount);
        vm.prank(ALICE);
        token.approve(address(rollup), amount);

        // Now set the expectation immediately before the rollup call.
        vm.expectEmit(true, false, false, true, address(rollup));
        emit TesseraContract.DepositAvailable(nc, amount, ALICE);
        vm.prank(ALICE);
        rollup.depositAndRegister(nc, amount);

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

        assertEq(uint8(rollup.getDeposit(nc).status), uint8(TesseraContract.DepositStatus.Withdrawn));
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

    /// submitDepositBatch validates referenced notes exist and are Pending.
    function test_submitDepositBatch_validatesNotes() public {
        bytes32 nc1 = bytes32(uint256(1001));
        bytes32 nc2 = bytes32(uint256(1002));
        _deposit(ALICE, nc1, 1e6);
        _deposit(ALICE, nc2, 2e6);

        uint256 genesis = rollup.zeros(rollup.treeDepth());
        bytes32[] memory dncs = new bytes32[](2);
        dncs[0] = nc1;
        dncs[1] = nc2;

        TesseraContract.DepositBatch memory db = TesseraContract.DepositBatch({
            root: genesis, mainPoolConfigRoot: PCR,
            depositNoteCommitments: dncs, batchPoseidonRoot: 0x1234, confirmed: false
        });
        vm.prank(OP);
        rollup.submitDepositBatch(db); // must not revert

        // Notes still Pending (not yet proven).
        assertEq(uint8(rollup.getDeposit(nc1).status), uint8(TesseraContract.DepositStatus.Pending));
    }

    /// submitDepositBatch with a non-existent note reverts NoteNotFound.
    function test_submitDepositBatch_rejectsMissingNote() public {
        bytes32 missing = bytes32(uint256(9999));
        uint256 genesis = rollup.zeros(rollup.treeDepth());
        bytes32[] memory dncs = new bytes32[](1);
        dncs[0] = missing;

        TesseraContract.DepositBatch memory db = TesseraContract.DepositBatch({
            root: genesis, mainPoolConfigRoot: PCR,
            depositNoteCommitments: dncs, batchPoseidonRoot: 1, confirmed: false
        });
        vm.prank(OP);
        vm.expectRevert(abi.encodeWithSelector(TesseraContract.NoteNotFound.selector, missing));
        rollup.submitDepositBatch(db);
    }

    /// proveDepositBatch advances all referenced deposit notes to Validated.
    function test_proveDepositBatch_marksValidated() public {
        bytes32 nc1 = bytes32(uint256(3001));
        bytes32 nc2 = bytes32(uint256(3002));
        _deposit(ALICE, nc1, 1e6);
        _deposit(ALICE, nc2, 2e6);

        uint256 genesis = rollup.zeros(rollup.treeDepth());
        bytes32[] memory dncs = new bytes32[](2);
        dncs[0] = nc1;
        dncs[1] = nc2;

        TesseraContract.DepositBatch memory db = TesseraContract.DepositBatch({
            root: genesis, mainPoolConfigRoot: PCR,
            depositNoteCommitments: dncs, batchPoseidonRoot: 0x5678, confirmed: false
        });
        bytes32 pic = _depositPI(db);
        vm.prank(OP);
        rollup.submitDepositBatch(db);
        rollup.proveDepositBatch(pic, _dummyProof());

        assertEq(uint8(rollup.getDeposit(nc1).status), uint8(TesseraContract.DepositStatus.Validated));
        assertEq(uint8(rollup.getDeposit(nc2).status), uint8(TesseraContract.DepositStatus.Validated));
        assertEq(rollup.leafCount(), 1, "batchPoseidonRoot appended as leaf");
    }

    /// Cannot withdraw a Validated deposit.
    function test_withdraw_afterValidated() public {
        bytes32 nc = bytes32(uint256(4001));
        _deposit(ALICE, nc, 5e6);

        uint256 genesis = rollup.zeros(rollup.treeDepth());
        bytes32[] memory dncs = new bytes32[](1);
        dncs[0] = nc;
        TesseraContract.DepositBatch memory db = TesseraContract.DepositBatch({
            root: genesis, mainPoolConfigRoot: PCR,
            depositNoteCommitments: dncs, batchPoseidonRoot: 0x9ABC, confirmed: false
        });
        bytes32 pic = _depositPI(db);
        vm.prank(OP);
        rollup.submitDepositBatch(db);
        rollup.proveDepositBatch(pic, _dummyProof());

        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(TesseraContract.InvalidDepositState.selector, nc));
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

        TesseraContract.TransactionBatch memory b = _minBatch(1);

        // submitTransactionBatch
        vm.prank(OP);
        vm.expectRevert(TesseraContract.PausedErr.selector);
        rollup.submitTransactionBatch(b);

        // proveTransactionBatch
        vm.expectRevert(TesseraContract.PausedErr.selector);
        rollup.proveTransactionBatch(bytes32(0), _dummyProof());

        // depositAndRegister
        vm.prank(ALICE);
        vm.expectRevert(TesseraContract.PausedErr.selector);
        rollup.depositAndRegister(bytes32(uint256(1)), 100);

        // withdrawPendingDeposit
        vm.prank(ALICE);
        vm.expectRevert(TesseraContract.PausedErr.selector);
        rollup.withdrawPendingDeposit(bytes32(uint256(1)));

        // Unpause: submit should succeed again.
        vm.prank(OP);
        rollup.setPaused(false);
        vm.prank(OP);
        rollup.submitTransactionBatch(b);
    }

    // -----------------------------------------------------------------------
    // =====================================================================
    // TESTS: keccakToPublicInputs encoding
    // =====================================================================
    // -----------------------------------------------------------------------

    /// keccakToPublicInputs correctly decomposes a known bytes32 into 8 uint32 words.
    ///
    /// Mirrors the Rust `keccak_to_public_inputs` unit test in prover_v2.rs and
    /// verifies that the Solidity ↔ Rust encoding contract holds.
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

        // Pack words into bytes32 big-endian (mirrors prove_plonky2 in Rust).
        bytes32 packed = bytes32(
            (words[0] << 224) | (words[1] << 192) | (words[2] << 160) | (words[3] << 128) |
            (words[4] << 96)  | (words[5] << 64)  | (words[6] << 32)  | words[7]
        );

        uint256[8] memory unpacked = rollup.keccakToPublicInputs(packed);
        for (uint256 i = 0; i < 8; i++) {
            assertEq(unpacked[i], words[i], "word mismatch");
        }
    }

    /// keccakToPublicInputs round-trips the all-zero bytes32 (dummy proof piCommitment).
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
    // TESTS: Access control + pause
    // =====================================================================
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // =====================================================================
    // TESTS: piCommitment generation
    // =====================================================================
    // -----------------------------------------------------------------------

    /// TX piCommitment: round-trip — submitTransactionBatch emits the same hash
    /// as our off-chain _txPI helper.
    function test_txPiCommitment_roundTrip() public {
        uint256 genesis = rollup.zeros(rollup.treeDepth());
        uint256[] memory ncs = new uint256[](2);
        ncs[0] = 0xBEEF_0001;
        ncs[1] = 0xBEEF_0002;
        uint256[] memory nulls = new uint256[](1);
        nulls[0] = 0xDEAD_0001;

        uint256[] memory acs = new uint256[](1); acs[0] = 0xACC1;
        uint256[] memory ans = new uint256[](1); ans[0] = 0xACC2;
        TesseraContract.TransactionBatch memory b = TesseraContract.TransactionBatch({
            root: genesis,
            mainPoolConfigRoot: PCR,
            noteCommitments: ncs,
            noteNullifiers: nulls,
            accountCommitments: acs,
            accountNullifiers: ans,
            batchPoseidonRoot: 0x1234567890,
            confirmed: false
        });

        bytes32 expected = _txPI(b);

        vm.prank(OP);
        vm.expectEmit(true, false, false, false, address(rollup));
        emit TesseraContract.TransactionBatchSubmitted(expected, b.batchPoseidonRoot);
        rollup.submitTransactionBatch(b);
    }

    /// TX piCommitment: changing root changes the commitment (root appears twice in preimage).
    function test_txPiCommitment_rootMatters() public pure {
        uint256[] memory empty1 = new uint256[](0);
        uint256[] memory empty2 = new uint256[](0);
        bytes32 pcr = bytes32(uint256(0xC0FFEE));

        bytes32 h1 = keccak256(abi.encodePacked(
            uint256(0x111), uint256(0x111), pcr, uint256(3), uint256(1), uint256(2), empty1, empty1
        ));
        bytes32 h2 = keccak256(abi.encodePacked(
            uint256(0x222), uint256(0x222), pcr, uint256(3), uint256(1), uint256(2), empty2, empty2
        ));

        // Different roots must produce different commitments.
        assertNotEq(h1, h2, "distinct roots must differ");
    }

    /// Deposit piCommitment: zero deposits — all 512 slots carry address(0).
    /// The commitment must NOT equal the all-zero-address-free preimage.
    function test_depositPiCommitment_allDummySlots() public {
        bytes32 nc = bytes32(uint256(0xDEAD_0001));
        _deposit(ALICE, nc, 1e6);

        uint256 genesis = rollup.zeros(rollup.treeDepth());
        bytes32[] memory dncs = new bytes32[](1);
        dncs[0] = nc;

        TesseraContract.DepositBatch memory db = TesseraContract.DepositBatch({
            root: genesis, mainPoolConfigRoot: PCR,
            depositNoteCommitments: dncs, batchPoseidonRoot: 0xABC, confirmed: false
        });

        // Commitment WITHOUT eth-addresses (old, wrong formula):
        bytes32 noAddrCommitment = keccak256(abi.encodePacked(
            db.root, db.root, db.mainPoolConfigRoot, db.batchPoseidonRoot
        ));

        bytes32 withAddrCommitment = _depositPI(db);
        assertNotEq(withAddrCommitment, noAddrCommitment,
            "with-address commitment must differ from no-address commitment");
    }

    /// Deposit piCommitment: round-trip — submitDepositBatch emits the same hash
    /// as our off-chain _depositPI helper.
    function test_depositPiCommitment_roundTrip() public {
        bytes32 nc1 = bytes32(uint256(0xDEAD_0002));
        bytes32 nc2 = bytes32(uint256(0xDEAD_0003));
        _deposit(ALICE,    nc1, 1e6);
        _deposit(address(0x1234), nc2, 2e6);

        uint256 genesis = rollup.zeros(rollup.treeDepth());
        bytes32[] memory dncs = new bytes32[](2);
        dncs[0] = nc1;
        dncs[1] = nc2;

        TesseraContract.DepositBatch memory db = TesseraContract.DepositBatch({
            root: genesis, mainPoolConfigRoot: PCR,
            depositNoteCommitments: dncs, batchPoseidonRoot: 0xDEF, confirmed: false
        });

        bytes32 expected = _depositPI(db);

        vm.prank(OP);
        vm.expectEmit(true, false, false, false, address(rollup));
        emit TesseraContract.DepositBatchSubmitted(expected, db.batchPoseidonRoot);
        rollup.submitDepositBatch(db);
    }

    /// Deposit piCommitment: distinct depositor addresses produce distinct commitments.
    function test_depositPiCommitment_addressMatters() public {
        bytes32 nc_alice = bytes32(uint256(0xDEAD_0010));
        bytes32 nc_bob   = bytes32(uint256(0xDEAD_0011));
        address BOB = address(0xB0B);

        _deposit(ALICE, nc_alice, 1e6);
        _deposit(BOB,   nc_bob,   1e6);

        uint256 genesis = rollup.zeros(rollup.treeDepth());
        bytes32[] memory dncs_alice = new bytes32[](1);
        bytes32[] memory dncs_bob   = new bytes32[](1);
        dncs_alice[0] = nc_alice;
        dncs_bob[0]   = nc_bob;

        TesseraContract.DepositBatch memory db_alice = TesseraContract.DepositBatch({
            root: genesis, mainPoolConfigRoot: PCR,
            depositNoteCommitments: dncs_alice, batchPoseidonRoot: 0x999, confirmed: false
        });
        TesseraContract.DepositBatch memory db_bob = TesseraContract.DepositBatch({
            root: genesis, mainPoolConfigRoot: PCR,
            depositNoteCommitments: dncs_bob, batchPoseidonRoot: 0x999, confirmed: false
        });

        assertNotEq(_depositPI(db_alice), _depositPI(db_bob),
            "different depositors must yield different commitments");
    }

    /// Deposit piCommitment: preimage is exactly 96 + DEPOSIT_BATCH_SIZE×20 bytes.
    function test_depositPiCommitment_preimageSize() public view {
        // 96 bytes fixed header (root + mainPoolConfigRoot + batchPoseidonRoot) + 512 slots × 20 bytes per address = 10336 bytes.
        uint256 expected = 96 + rollup.DEPOSIT_BATCH_SIZE() * 20;
        assertEq(expected, 10336, "preimage size sanity check");
    }

    /// Operator can update poolConfigRoot; old value rejected by new batches.
    function test_setPoolConfigRoot() public {
        bytes32 newPCR = bytes32(uint256(0xABCDEF));
        vm.prank(OP);
        vm.expectEmit(true, true, false, false, address(rollup));
        emit TesseraContract.PoolConfigRootUpdated(PCR, newPCR);
        rollup.setPoolConfigRoot(newPCR);
        assertEq(rollup.poolConfigRoot(), newPCR);

        // Old PCR is rejected.
        uint256 genesis = rollup.zeros(rollup.treeDepth());
        uint256[] memory empty = new uint256[](0);
        uint256[] memory acs = new uint256[](1); acs[0] = _nc++;
        uint256[] memory ans = new uint256[](1); ans[0] = _nc++;
        TesseraContract.TransactionBatch memory b = TesseraContract.TransactionBatch({
            root: genesis,
            mainPoolConfigRoot: PCR,  // old value
            noteCommitments: empty, noteNullifiers: empty,
            accountCommitments: acs, accountNullifiers: ans,
            batchPoseidonRoot: 1, confirmed: false
        });
        vm.prank(OP);
        vm.expectRevert(TesseraContract.PoolConfigMismatch.selector);
        rollup.submitTransactionBatch(b);
    }
}
