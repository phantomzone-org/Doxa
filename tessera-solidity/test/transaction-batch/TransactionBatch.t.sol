// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {DepositsRollupBridge, IGroth16Verifier} from "../../src/TesseraRollup.sol";
import {ToyUSDT} from "../../src/ToyUSDT.sol";

// Always-pass mock verifier (same pattern as existing tests).
contract MockVerifierOk is IGroth16Verifier {
    function verifyProof(uint256[8] calldata, uint256[2] calldata, uint256[2] calldata, uint256[8] calldata)
        external
        pure
    {}
}

// Always-revert mock verifier — used to exercise proof-failure paths.
contract MockVerifierRevert is IGroth16Verifier {
    function verifyProof(uint256[8] calldata, uint256[2] calldata, uint256[2] calldata, uint256[8] calldata)
        external
        pure
    {
        revert("bad proof");
    }
}

contract TransactionBatchTest is Test {
    DepositsRollupBridge public bridge;
    ToyUSDT public token;

    address public operator = address(this);

    bytes32 public constant GENESIS_NULLIFIER_ROOT   = bytes32(uint256(0x1111));
    bytes32 public constant GENESIS_COMMITMENT_ROOT  = bytes32(uint256(0x2222));
    bytes32 public constant GENESIS_ACC_NULL_ROOT    = bytes32(uint256(0x3333));
    bytes32 public constant GENESIS_ACC_COMMIT_ROOT  = bytes32(uint256(0x4444));
    uint256 public constant BATCH_SIZE = 2;

    // Convenient root progression values.
    bytes32 constant ROOT_NC_1 = bytes32(uint256(0xA1));
    bytes32 constant ROOT_NN_1 = bytes32(uint256(0xB1));
    bytes32 constant ROOT_AC_1 = bytes32(uint256(0xC1));
    bytes32 constant ROOT_AN_1 = bytes32(uint256(0xD1));

    bytes32 constant ROOT_NC_2 = bytes32(uint256(0xA2));
    bytes32 constant ROOT_NN_2 = bytes32(uint256(0xB2));
    bytes32 constant ROOT_AC_2 = bytes32(uint256(0xC2));
    bytes32 constant ROOT_AN_2 = bytes32(uint256(0xD2));

    // Dummy PI commitments (any non-zero bytes32).
    bytes32[4] public PI_1;
    bytes32[4] public PI_2;

    // Dummy leaf arrays (length 1 to satisfy 0 < len <= batchSize with BATCH_SIZE=2).
    bytes32[] public LEAVES_1;
    bytes32[] public LEAVES_2;

    function setUp() public {
        MockVerifierOk verifierOk = new MockVerifierOk();
        token = new ToyUSDT();

        bridge = new DepositsRollupBridge(
            address(verifierOk),
            address(verifierOk),
            address(verifierOk),
            operator,
            GENESIS_NULLIFIER_ROOT,
            GENESIS_COMMITMENT_ROOT,
            GENESIS_ACC_NULL_ROOT,
            GENESIS_ACC_COMMIT_ROOT,
            BATCH_SIZE,
            address(token)
        );

        PI_1[0] = bytes32(uint256(0x11));
        PI_1[1] = bytes32(uint256(0x12));
        PI_1[2] = bytes32(uint256(0x13));
        PI_1[3] = bytes32(uint256(0x14));

        PI_2[0] = bytes32(uint256(0x21));
        PI_2[1] = bytes32(uint256(0x22));
        PI_2[2] = bytes32(uint256(0x23));
        PI_2[3] = bytes32(uint256(0x24));

        LEAVES_1.push(bytes32(uint256(0xF1)));
        LEAVES_2.push(bytes32(uint256(0xF2)));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    function _dummyProof() internal pure returns (DepositsRollupBridge.Proof memory) {
        return DepositsRollupBridge.Proof({
            proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0],
            commitments: [uint256(0), 0],
            commitmentPok: [uint256(0), 0]
        });
    }

    /// Register one batch and return its batchId.
    function _registerBatch(
        bytes32 ncRoot,
        bytes32 nnRoot,
        bytes32 acRoot,
        bytes32 anRoot,
        bytes32[4] memory pi
    ) internal returns (uint256) {
        return bridge.registerTransactionBatchUpdate(
            ncRoot, LEAVES_1,
            nnRoot, LEAVES_1,
            acRoot, LEAVES_1,
            anRoot, LEAVES_1,
            pi
        );
    }

    /// Confirm all 4 trees for a batch.
    function _confirmAll(uint256 batchId) internal {
        DepositsRollupBridge.Proof memory p = _dummyProof();
        bridge.confirmTreeUpdate(batchId, bridge.TREE_NOTES_COMMITMENT(),    p, p);
        bridge.confirmTreeUpdate(batchId, bridge.TREE_NOTES_NULLIFIER(),     p, p);
        bridge.confirmTreeUpdate(batchId, bridge.TREE_ACCOUNTS_COMMITMENT(), p, p);
        bridge.confirmTreeUpdate(batchId, bridge.TREE_ACCOUNTS_NULLIFIER(),  p, p);
    }

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    function testConstruction_ConfirmedRootsMatchGenesis() public view {
        assertEq(bridge.confirmedNotesCommitmentRoot(),    GENESIS_COMMITMENT_ROOT);
        assertEq(bridge.confirmedNotesNullifierRoot(),     GENESIS_NULLIFIER_ROOT);
        assertEq(bridge.confirmedAccountsCommitmentRoot(), GENESIS_ACC_COMMIT_ROOT);
        assertEq(bridge.confirmedAccountsNullifierRoot(),  GENESIS_ACC_NULL_ROOT);
    }

    function testConstruction_NextBatchIdStartsAtOne() public {
        // First register should return batchId = 1.
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);
        assertEq(id, 1);
    }

    // -------------------------------------------------------------------------
    // registerTransactionBatchUpdate — happy path
    // -------------------------------------------------------------------------

    function testRegister_ReturnsIncrementingBatchIds() public {
        uint256 id1 = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);
        _confirmAll(id1);
        uint256 id2 = _registerBatch(ROOT_NC_2, ROOT_NN_2, ROOT_AC_2, ROOT_AN_2, PI_2);
        assertEq(id1, 1);
        assertEq(id2, 2);
    }

    function testRegister_AdvancesLatestRoots() public {
        _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);

        assertEq(bridge.notesCommitmentRoot(),    ROOT_NC_1);
        assertEq(bridge.notesNullifierRoot(),     ROOT_NN_1);
        assertEq(bridge.accountsCommitmentRoot(), ROOT_AC_1);
        assertEq(bridge.accountsNullifierRoot(),  ROOT_AN_1);
    }

    function testRegister_DoesNotAdvanceConfirmedRoots() public {
        _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);

        // Confirmed roots unchanged until confirmTreeUpdate.
        assertEq(bridge.confirmedNotesCommitmentRoot(),    GENESIS_COMMITMENT_ROOT);
        assertEq(bridge.confirmedNotesNullifierRoot(),     GENESIS_NULLIFIER_ROOT);
        assertEq(bridge.confirmedAccountsCommitmentRoot(), GENESIS_ACC_COMMIT_ROOT);
        assertEq(bridge.confirmedAccountsNullifierRoot(),  GENESIS_ACC_NULL_ROOT);
    }

    function testRegister_SlotPopulatedCorrectly() public {
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);
        uint256 slotIdx = id % bridge.MAX_PENDING_BATCHES();

        (
            uint256 storedId,
            bytes32 ncRoot,
            bytes32 nnRoot,
            bytes32 acRoot,
            bytes32 anRoot,
            uint8 mask
        ) = bridge.pendingBatches(slotIdx);

        assertEq(storedId, id);
        assertEq(ncRoot, ROOT_NC_1);
        assertEq(nnRoot, ROOT_NN_1);
        assertEq(acRoot, ROOT_AC_1);
        assertEq(anRoot, ROOT_AN_1);
        assertEq(mask, 0);
    }

    function testRegister_EmitsEvent() public {
        vm.expectEmit(true, false, false, true);
        emit DepositsRollupBridge.TransactionBatchRegistered(
            1, ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1
        );
        _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);
    }

    function testRegister_MarksTrackedDepositsValidated() public {
        address user = address(0xCAFE);
        uint256 amount = 1e6;
        bytes32 note = bytes32(uint256(99));

        token.mint(user, amount);
        vm.prank(user);
        token.approve(address(bridge), amount);
        vm.prank(user);
        bridge.depositAndRegister(note, amount);

        // Use the tracked note as a noteCommitmentsOut leaf.
        bytes32[] memory notesOut = new bytes32[](1);
        notesOut[0] = note;

        bridge.registerTransactionBatchUpdate(
            ROOT_NC_1, notesOut,
            ROOT_NN_1, LEAVES_1,
            ROOT_AC_1, LEAVES_1,
            ROOT_AN_1, LEAVES_1,
            PI_1
        );

        assertEq(
            uint256(bridge.getDeposit(note).status),
            uint256(DepositsRollupBridge.DepositStatus.Validated)
        );
    }

    // -------------------------------------------------------------------------
    // registerTransactionBatchUpdate — validation errors
    // -------------------------------------------------------------------------

    function testRegister_RevertsOnZeroLengthArray() public {
        bytes32[] memory empty = new bytes32[](0);
        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.InvalidBatchLength.selector, 0, BATCH_SIZE));
        bridge.registerTransactionBatchUpdate(
            ROOT_NC_1, empty,
            ROOT_NN_1, LEAVES_1,
            ROOT_AC_1, LEAVES_1,
            ROOT_AN_1, LEAVES_1,
            PI_1
        );
    }

    function testRegister_RevertsOnOversizedArray() public {
        bytes32[] memory big = new bytes32[](BATCH_SIZE + 1);
        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.InvalidBatchLength.selector, BATCH_SIZE + 1, BATCH_SIZE));
        bridge.registerTransactionBatchUpdate(
            ROOT_NC_1, big,
            ROOT_NN_1, LEAVES_1,
            ROOT_AC_1, LEAVES_1,
            ROOT_AN_1, LEAVES_1,
            PI_1
        );
    }

    function testRegister_RevertsOnInvalidDepositState() public {
        address user = address(0xCAFE);
        uint256 amount = 1e6;
        bytes32 note = bytes32(uint256(99));

        token.mint(user, amount);
        vm.prank(user);
        token.approve(address(bridge), amount);
        vm.prank(user);
        bridge.depositAndRegister(note, amount);
        vm.prank(user);
        bridge.withdrawPendingDeposit(note); // status → Withdrawn

        bytes32[] memory notesOut = new bytes32[](1);
        notesOut[0] = note;

        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.InvalidDepositState.selector, note));
        bridge.registerTransactionBatchUpdate(
            ROOT_NC_1, notesOut,
            ROOT_NN_1, LEAVES_1,
            ROOT_AC_1, LEAVES_1,
            ROOT_AN_1, LEAVES_1,
            PI_1
        );
    }

    function testRegister_RevertsOnNonOperator() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(DepositsRollupBridge.NotOperator.selector);
        _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);
    }

    // -------------------------------------------------------------------------
    // Pending queue full
    // -------------------------------------------------------------------------

    function testRegister_RevertsWhenQueueFull() public {
        uint256 max = bridge.MAX_PENDING_BATCHES();
        // Fill the queue.
        for (uint256 i = 0; i < max; i++) {
            bytes32 r = bytes32(i + 1);
            _registerBatch(r, r, r, r, PI_1);
        }
        vm.expectRevert(DepositsRollupBridge.PendingQueueFull.selector);
        _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);
    }

    // -------------------------------------------------------------------------
    // confirmTreeUpdate — happy path
    // -------------------------------------------------------------------------

    function testConfirm_AdvancesConfirmedRootPerTree() public {
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);
        DepositsRollupBridge.Proof memory p = _dummyProof();

        bridge.confirmTreeUpdate(id, bridge.TREE_NOTES_COMMITMENT(), p, p);
        assertEq(bridge.confirmedNotesCommitmentRoot(), ROOT_NC_1);
        assertEq(bridge.confirmedNotesNullifierRoot(), GENESIS_NULLIFIER_ROOT); // unchanged

        bridge.confirmTreeUpdate(id, bridge.TREE_NOTES_NULLIFIER(), p, p);
        assertEq(bridge.confirmedNotesNullifierRoot(), ROOT_NN_1);

        bridge.confirmTreeUpdate(id, bridge.TREE_ACCOUNTS_COMMITMENT(), p, p);
        assertEq(bridge.confirmedAccountsCommitmentRoot(), ROOT_AC_1);

        bridge.confirmTreeUpdate(id, bridge.TREE_ACCOUNTS_NULLIFIER(), p, p);
        assertEq(bridge.confirmedAccountsNullifierRoot(), ROOT_AN_1);
    }

    function testConfirm_EmitsTreeUpdateConfirmedEvents() public {
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);
        DepositsRollupBridge.Proof memory p = _dummyProof();

        vm.expectEmit(true, false, false, true);
        emit DepositsRollupBridge.TreeUpdateConfirmed(id, bridge.TREE_NOTES_COMMITMENT());
        bridge.confirmTreeUpdate(id, bridge.TREE_NOTES_COMMITMENT(), p, p);
    }

    function testConfirm_EmitsTransactionBatchConfirmedOnLastTree() public {
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);
        DepositsRollupBridge.Proof memory p = _dummyProof();

        bridge.confirmTreeUpdate(id, bridge.TREE_NOTES_COMMITMENT(),    p, p);
        bridge.confirmTreeUpdate(id, bridge.TREE_NOTES_NULLIFIER(),     p, p);
        bridge.confirmTreeUpdate(id, bridge.TREE_ACCOUNTS_COMMITMENT(), p, p);

        vm.expectEmit(true, false, false, false);
        emit DepositsRollupBridge.TransactionBatchConfirmed(id);
        bridge.confirmTreeUpdate(id, bridge.TREE_ACCOUNTS_NULLIFIER(), p, p);
    }

    function testConfirm_FreesSlotAfterAllFourTrees() public {
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);
        _confirmAll(id);

        uint256 slotIdx = id % bridge.MAX_PENDING_BATCHES();
        (uint256 storedId,,,,, uint8 mask) = bridge.pendingBatches(slotIdx);
        assertEq(storedId, 0);
        assertEq(mask, 0);
    }

    function testConfirm_DecrementsCountOnlyAfterAllFourTrees() public {
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);
        DepositsRollupBridge.Proof memory p = _dummyProof();

        // After 3 confirms the slot is still occupied.
        bridge.confirmTreeUpdate(id, bridge.TREE_NOTES_COMMITMENT(),    p, p);
        bridge.confirmTreeUpdate(id, bridge.TREE_NOTES_NULLIFIER(),     p, p);
        bridge.confirmTreeUpdate(id, bridge.TREE_ACCOUNTS_COMMITMENT(), p, p);

        // Register another batch — if count hadn't decremented yet this is fine (count = 2).
        _registerBatch(ROOT_NC_2, ROOT_NN_2, ROOT_AC_2, ROOT_AN_2, PI_2);

        // Complete batch 1.
        bridge.confirmTreeUpdate(id, bridge.TREE_ACCOUNTS_NULLIFIER(), p, p);
        // Slot freed — batchId 1 slot is now available for recycling.
        uint256 slotIdx = id % bridge.MAX_PENDING_BATCHES();
        (uint256 storedId,,,,,) = bridge.pendingBatches(slotIdx);
        assertEq(storedId, 0);
    }

    // -------------------------------------------------------------------------
    // confirmTreeUpdate — out-of-order
    // -------------------------------------------------------------------------

    function testConfirm_OutOfOrder_TreesCompleteInAnyOrder() public {
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);
        DepositsRollupBridge.Proof memory p = _dummyProof();

        // Confirm in reverse order: 3, 2, 1, 0.
        bridge.confirmTreeUpdate(id, bridge.TREE_ACCOUNTS_NULLIFIER(),  p, p);
        bridge.confirmTreeUpdate(id, bridge.TREE_ACCOUNTS_COMMITMENT(), p, p);
        bridge.confirmTreeUpdate(id, bridge.TREE_NOTES_NULLIFIER(),     p, p);
        bridge.confirmTreeUpdate(id, bridge.TREE_NOTES_COMMITMENT(),    p, p);

        uint256 slotIdx = id % bridge.MAX_PENDING_BATCHES();
        (uint256 storedId,,,,,) = bridge.pendingBatches(slotIdx);
        assertEq(storedId, 0);
    }

    // -------------------------------------------------------------------------
    // confirmTreeUpdate — error cases
    // -------------------------------------------------------------------------

    function testConfirm_RevertsOnInvalidTreeIndex() public {
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);
        DepositsRollupBridge.Proof memory p = _dummyProof();
        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.InvalidTreeIndex.selector, 4));
        bridge.confirmTreeUpdate(id, 4, p, p);
    }

    function testConfirm_RevertsOnUnknownBatch() public {
        DepositsRollupBridge.Proof memory p = _dummyProof();
        // batchId 999 was never registered.
        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.UnknownBatch.selector, 999));
        bridge.confirmTreeUpdate(999, 0, p, p);
    }

    function testConfirm_RevertsOnAlreadyConfirmed() public {
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);
        DepositsRollupBridge.Proof memory p = _dummyProof();

        uint8 treeIdx = bridge.TREE_NOTES_COMMITMENT(); // cache before expectRevert trap is set
        bridge.confirmTreeUpdate(id, treeIdx, p, p);

        vm.expectRevert(
            abi.encodeWithSelector(DepositsRollupBridge.AlreadyConfirmed.selector, id, treeIdx)
        );
        bridge.confirmTreeUpdate(id, treeIdx, p, p);
    }

    function testConfirm_RevertsOnNonOperator() public {
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);
        DepositsRollupBridge.Proof memory p = _dummyProof();
        vm.prank(address(0xDEAD));
        vm.expectRevert(DepositsRollupBridge.NotOperator.selector);
        bridge.confirmTreeUpdate(id, 0, p, p);
    }

    // -------------------------------------------------------------------------
    // Slot recycling after full confirmation
    // -------------------------------------------------------------------------

    function testSlotRecycling_ReusedAfterFullConfirmation() public {
        uint256 id1 = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, PI_1);
        _confirmAll(id1);

        // MAX_PENDING_BATCHES = 128; batchId 129 maps to slot 129 % 128 = 1 (same as batchId 1).
        // Fill slots 2..128 so the counter wraps properly.
        uint256 max = bridge.MAX_PENDING_BATCHES();
        for (uint256 i = 1; i < max; i++) {
            bytes32 r = bytes32(i + 100);
            _registerBatch(r, r, r, r, PI_1);
        }
        // All 128 slots (slots 2..128 + 1 recycled slot 1) now occupied — except slot 1 was freed.
        // Actually slots 2..128 are occupied (127 batches), slot 1 is free.
        // batchId is now 129; slotIndex = 129 % 128 = 1 — the freed slot.
        uint256 id129 = _registerBatch(ROOT_NC_2, ROOT_NN_2, ROOT_AC_2, ROOT_AN_2, PI_2);
        assertEq(id129, max + 1); // batchId = 128 + 1
        assertEq(id129 % max, 1); // same slot as batch 1
        (uint256 storedId,,,,,) = bridge.pendingBatches(1);
        assertEq(storedId, id129);
    }

    // -------------------------------------------------------------------------
    // Proof failure via MockVerifierRevert (requires deploying a new bridge)
    // -------------------------------------------------------------------------

    function testConfirm_RevertsOnBadInputsProof() public {
        // Deploy bridge where aggregatedInputVerifier always reverts.
        MockVerifierOk verifierOk = new MockVerifierOk();
        MockVerifierRevert verifierBad = new MockVerifierRevert();

        DepositsRollupBridge badBridge = new DepositsRollupBridge(
            address(verifierOk),
            address(verifierOk),
            address(verifierBad), // aggregatedInputVerifier always reverts
            operator,
            GENESIS_NULLIFIER_ROOT,
            GENESIS_COMMITMENT_ROOT,
            GENESIS_ACC_NULL_ROOT,
            GENESIS_ACC_COMMIT_ROOT,
            BATCH_SIZE,
            address(token)
        );

        uint256 id = badBridge.registerTransactionBatchUpdate(
            ROOT_NC_1, LEAVES_1,
            ROOT_NN_1, LEAVES_1,
            ROOT_AC_1, LEAVES_1,
            ROOT_AN_1, LEAVES_1,
            PI_1
        );

        DepositsRollupBridge.Proof memory p = _dummyProof();
        vm.expectRevert(DepositsRollupBridge.InvalidinputsProof.selector);
        badBridge.confirmTreeUpdate(id, 0, p, p);
    }

    function testConfirm_RevertsOnBadTreeProof() public {
        MockVerifierOk verifierOk = new MockVerifierOk();
        MockVerifierRevert verifierBad = new MockVerifierRevert();

        // Commitment verifier reverts; nullifier OK.
        DepositsRollupBridge badBridge = new DepositsRollupBridge(
            address(verifierBad), // commitmentVerifier always reverts
            address(verifierOk),
            address(verifierOk),
            operator,
            GENESIS_NULLIFIER_ROOT,
            GENESIS_COMMITMENT_ROOT,
            GENESIS_ACC_NULL_ROOT,
            GENESIS_ACC_COMMIT_ROOT,
            BATCH_SIZE,
            address(token)
        );

        uint256 id = badBridge.registerTransactionBatchUpdate(
            ROOT_NC_1, LEAVES_1,
            ROOT_NN_1, LEAVES_1,
            ROOT_AC_1, LEAVES_1,
            ROOT_AN_1, LEAVES_1,
            PI_1
        );

        DepositsRollupBridge.Proof memory p = _dummyProof();
        // Confirming a commitment tree (index 0) should fail on tree proof.
        vm.expectRevert(DepositsRollupBridge.InvalidProof.selector);
        badBridge.confirmTreeUpdate(id, 0, p, p);
    }

    // -------------------------------------------------------------------------
    // withdrawPendingDeposit blocked after register (deposit already Validated)
    // -------------------------------------------------------------------------

    function testWithdraw_RevertsForNoteAlreadyStagedInRegisteredBatch() public {
        address user = address(0xCAFE);
        uint256 amount = 1e6;
        bytes32 note = bytes32(uint256(99));

        token.mint(user, amount);
        vm.prank(user);
        token.approve(address(bridge), amount);
        vm.prank(user);
        bridge.depositAndRegister(note, amount);

        // Register batch with this note in noteCommitmentsOut.
        bytes32[] memory notesOut = new bytes32[](1);
        notesOut[0] = note;
        bridge.registerTransactionBatchUpdate(
            ROOT_NC_1, notesOut,
            ROOT_NN_1, LEAVES_1,
            ROOT_AC_1, LEAVES_1,
            ROOT_AN_1, LEAVES_1,
            PI_1
        );

        // Deposit is now Validated; withdrawal should revert.
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.InvalidDepositState.selector, note));
        bridge.withdrawPendingDeposit(note);
    }
}
