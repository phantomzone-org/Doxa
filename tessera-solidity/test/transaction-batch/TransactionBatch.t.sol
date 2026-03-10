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

    // noteBatchSize = 8, accountBatchSize = 1 (enforces 8:1 ratio).
    uint256 public constant NOTE_BATCH_SIZE    = 8;
    uint256 public constant ACCOUNT_BATCH_SIZE = 1;

    // Convenient root progression values.
    bytes32 constant ROOT_NC_1 = bytes32(uint256(0xA1));
    bytes32 constant ROOT_NN_1 = bytes32(uint256(0xB1));
    bytes32 constant ROOT_AC_1 = bytes32(uint256(0xC1));
    bytes32 constant ROOT_AN_1 = bytes32(uint256(0xD1));

    bytes32 constant ROOT_NC_2 = bytes32(uint256(0xA2));
    bytes32 constant ROOT_NN_2 = bytes32(uint256(0xB2));
    bytes32 constant ROOT_AC_2 = bytes32(uint256(0xC2));
    bytes32 constant ROOT_AN_2 = bytes32(uint256(0xD2));

    // Full sorted leaf arrays for all 4 trees (exactly batchSize elements each).
    bytes32[] public NOTE_LEAVES_1;
    bytes32[] public NOTE_LEAVES_2;
    bytes32[] public ACCT_LEAVES_1;
    bytes32[] public ACCT_LEAVES_2;
    bytes32[] public NN_LEAVES_1;
    bytes32[] public NN_LEAVES_2;
    bytes32[] public AN_LEAVES_1;
    bytes32[] public AN_LEAVES_2;

    function setUp() public {
        MockVerifierOk verifierOk = new MockVerifierOk();
        token = new ToyUSDT();

        bridge = new DepositsRollupBridge(
            address(verifierOk),  // superAggregatorVerifier
            operator,
            GENESIS_NULLIFIER_ROOT,
            GENESIS_COMMITMENT_ROOT,
            GENESIS_ACC_NULL_ROOT,
            GENESIS_ACC_COMMIT_ROOT,
            NOTE_BATCH_SIZE,
            ACCOUNT_BATCH_SIZE,
            address(token)
        );

        // Full sorted note commitment batches (NOTE_BATCH_SIZE = 8 elements, ascending).
        for (uint256 i = 0; i < NOTE_BATCH_SIZE; i++) {
            NOTE_LEAVES_1.push(bytes32(uint256(0xF100 + i)));
            NOTE_LEAVES_2.push(bytes32(uint256(0xF200 + i)));
        }
        // Full sorted account commitment batches (ACCOUNT_BATCH_SIZE = 1).
        ACCT_LEAVES_1.push(bytes32(uint256(0xE1)));
        ACCT_LEAVES_2.push(bytes32(uint256(0xE2)));

        // Full sorted nullifier batches (NOTE_BATCH_SIZE = 8 elements, ascending).
        for (uint256 i = 0; i < NOTE_BATCH_SIZE; i++) {
            NN_LEAVES_1.push(bytes32(uint256(0x1000 + i)));
            NN_LEAVES_2.push(bytes32(uint256(0x2000 + i)));
        }
        // Account nullifier batches (ACCOUNT_BATCH_SIZE = 1).
        AN_LEAVES_1.push(bytes32(uint256(0x3001)));
        AN_LEAVES_2.push(bytes32(uint256(0x3002)));
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
        bytes32 anRoot
    ) internal returns (uint256) {
        return bridge.registerTransactionBatchUpdate(
            ncRoot, NOTE_LEAVES_1,
            nnRoot, NN_LEAVES_1,
            acRoot, ACCT_LEAVES_1,
            anRoot, AN_LEAVES_1
        );
    }

    /// Confirm a batch (single confirmBatch replaces the previous five confirmation calls).
    function _confirmAll(uint256 batchId) internal {
        bridge.confirmBatch(batchId, _dummyProof());
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
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1);
        assertEq(id, 1);
    }

    function testConstruction_BatchSizes() public view {
        assertEq(bridge.noteBatchSize(),    NOTE_BATCH_SIZE);
        assertEq(bridge.accountBatchSize(), ACCOUNT_BATCH_SIZE);
    }

    // -------------------------------------------------------------------------
    // registerTransactionBatchUpdate — happy path
    // -------------------------------------------------------------------------

    function testRegister_ReturnsIncrementingBatchIds() public {
        uint256 id1 = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1);
        _confirmAll(id1);
        uint256 id2 = _registerBatch(ROOT_NC_2, ROOT_NN_2, ROOT_AC_2, ROOT_AN_2);
        assertEq(id1, 1);
        assertEq(id2, 2);
    }

    function testRegister_AdvancesLatestRoots() public {
        _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1);

        assertEq(bridge.notesCommitmentRoot(),    ROOT_NC_1);
        assertEq(bridge.notesNullifierRoot(),     ROOT_NN_1);
        assertEq(bridge.accountsCommitmentRoot(), ROOT_AC_1);
        assertEq(bridge.accountsNullifierRoot(),  ROOT_AN_1);
    }

    function testRegister_AdvancesLeafCountsByTreeWidth() public {
        uint256 nc0 = bridge.notesCommitmentLeafCount();
        uint256 nn0 = bridge.notesNullifierLeafCount();
        uint256 ac0 = bridge.accountsCommitmentLeafCount();
        uint256 an0 = bridge.accountsNullifierLeafCount();

        _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1);

        assertEq(bridge.notesCommitmentLeafCount(),    nc0 + NOTE_BATCH_SIZE);
        assertEq(bridge.notesNullifierLeafCount(),     nn0 + NOTE_BATCH_SIZE);
        assertEq(bridge.accountsCommitmentLeafCount(), ac0 + ACCOUNT_BATCH_SIZE);
        assertEq(bridge.accountsNullifierLeafCount(),  an0 + ACCOUNT_BATCH_SIZE);
    }

    function testRegister_DoesNotAdvanceConfirmedRoots() public {
        _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1);

        // Confirmed roots unchanged until confirmBatch is called.
        assertEq(bridge.confirmedNotesCommitmentRoot(),    GENESIS_COMMITMENT_ROOT);
        assertEq(bridge.confirmedNotesNullifierRoot(),     GENESIS_NULLIFIER_ROOT);
        assertEq(bridge.confirmedAccountsCommitmentRoot(), GENESIS_ACC_COMMIT_ROOT);
        assertEq(bridge.confirmedAccountsNullifierRoot(),  GENESIS_ACC_NULL_ROOT);
    }

    function testRegister_SlotPopulatedCorrectly() public {
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1);
        uint256 slotIdx = id % bridge.MAX_PENDING_BATCHES();

        (
            uint256 storedId,
            bytes32 ncRoot,
            bytes32 nnRoot,
            bytes32 acRoot,
            bytes32 anRoot,
            ,
            bool confirmed
        ) = bridge.pendingBatches(slotIdx);

        assertEq(storedId, id);
        assertEq(ncRoot, ROOT_NC_1);
        assertEq(nnRoot, ROOT_NN_1);
        assertEq(acRoot, ROOT_AC_1);
        assertEq(anRoot, ROOT_AN_1);
        assertFalse(confirmed);
    }

    function testRegister_EmitsEvent() public {
        // Only check the indexed batchId; superPiCommitment is computed inside the contract.
        vm.expectEmit(true, false, false, false);
        emit DepositsRollupBridge.TransactionBatchRegistered(
            1, ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1, bytes32(0)
        );
        _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1);
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

        // Full sorted NC batch with the tracked note as one leaf (rest are dummies).
        bytes32[] memory notesOut = new bytes32[](NOTE_BATCH_SIZE);
        notesOut[0] = note;
        for (uint256 i = 1; i < NOTE_BATCH_SIZE; i++) {
            notesOut[i] = bytes32(uint256(0xFF00 + i));
        }

        bridge.registerTransactionBatchUpdate(
            ROOT_NC_1, notesOut,
            ROOT_NN_1, NN_LEAVES_1,
            ROOT_AC_1, ACCT_LEAVES_1,
            ROOT_AN_1, AN_LEAVES_1
        );

        assertEq(
            uint256(bridge.getDeposit(note).status),
            uint256(DepositsRollupBridge.DepositStatus.Validated)
        );
    }

    // -------------------------------------------------------------------------
    // registerTransactionBatchUpdate — validation errors (mixed-width)
    // -------------------------------------------------------------------------

    function testRegister_RevertsOnWrongSizeNoteArray() public {
        bytes32[] memory wrong = new bytes32[](NOTE_BATCH_SIZE + 1);
        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.InvalidBatchLength.selector, NOTE_BATCH_SIZE + 1, NOTE_BATCH_SIZE));
        bridge.registerTransactionBatchUpdate(
            ROOT_NC_1, wrong,
            ROOT_NN_1, NN_LEAVES_1,
            ROOT_AC_1, ACCT_LEAVES_1,
            ROOT_AN_1, AN_LEAVES_1
        );
    }

    function testRegister_RevertsOnWrongSizeAccountArray() public {
        bytes32[] memory wrong = new bytes32[](ACCOUNT_BATCH_SIZE + 1);
        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.InvalidBatchLength.selector, ACCOUNT_BATCH_SIZE + 1, ACCOUNT_BATCH_SIZE));
        bridge.registerTransactionBatchUpdate(
            ROOT_NC_1, NOTE_LEAVES_1,
            ROOT_NN_1, NN_LEAVES_1,
            ROOT_AC_1, wrong,
            ROOT_AN_1, AN_LEAVES_1
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

        bytes32[] memory notesOut = new bytes32[](NOTE_BATCH_SIZE);
        notesOut[0] = note;
        for (uint256 i = 1; i < NOTE_BATCH_SIZE; i++) {
            notesOut[i] = bytes32(uint256(0xFF00 + i));
        }

        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.InvalidDepositState.selector, note));
        bridge.registerTransactionBatchUpdate(
            ROOT_NC_1, notesOut,
            ROOT_NN_1, NN_LEAVES_1,
            ROOT_AC_1, ACCT_LEAVES_1,
            ROOT_AN_1, AN_LEAVES_1
        );
    }

    function testRegister_RevertsOnNonOperator() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(DepositsRollupBridge.NotOperator.selector);
        _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1);
    }

    // -------------------------------------------------------------------------
    // Pending queue full
    // -------------------------------------------------------------------------

    function testRegister_RevertsWhenQueueFull() public {
        uint256 max = bridge.MAX_PENDING_BATCHES();
        // Fill the queue.
        for (uint256 i = 0; i < max; i++) {
            bytes32 r = bytes32(i + 1);
            _registerBatch(r, r, r, r);
        }
        vm.expectRevert(DepositsRollupBridge.PendingQueueFull.selector);
        _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1);
    }

    // -------------------------------------------------------------------------
    // confirmBatch — happy path
    // -------------------------------------------------------------------------

    function testConfirm_ConfirmedRootsAdvanceAtomicallyAfterBatch() public {
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1);
        DepositsRollupBridge.Proof memory p = _dummyProof();

        // Confirmed roots must NOT advance after register alone.
        assertEq(bridge.confirmedNotesCommitmentRoot(),    GENESIS_COMMITMENT_ROOT);
        assertEq(bridge.confirmedNotesNullifierRoot(),     GENESIS_NULLIFIER_ROOT);
        assertEq(bridge.confirmedAccountsCommitmentRoot(), GENESIS_ACC_COMMIT_ROOT);
        assertEq(bridge.confirmedAccountsNullifierRoot(),  GENESIS_ACC_NULL_ROOT);

        // All 4 confirmed roots advance atomically after confirmBatch.
        bridge.confirmBatch(id, p);
        assertEq(bridge.confirmedNotesCommitmentRoot(),    ROOT_NC_1);
        assertEq(bridge.confirmedNotesNullifierRoot(),     ROOT_NN_1);
        assertEq(bridge.confirmedAccountsCommitmentRoot(), ROOT_AC_1);
        assertEq(bridge.confirmedAccountsNullifierRoot(),  ROOT_AN_1);
    }

    function testConfirm_EmitsBatchConfirmedEvent() public {
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1);

        vm.expectEmit(true, false, false, false);
        emit DepositsRollupBridge.BatchConfirmed(id);
        bridge.confirmBatch(id, _dummyProof());
    }

    function testConfirm_FreesSlotAfterConfirm() public {
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1);
        _confirmAll(id);

        uint256 slotIdx = id % bridge.MAX_PENDING_BATCHES();
        (uint256 storedId,,,,,, bool confirmed) = bridge.pendingBatches(slotIdx);
        assertEq(storedId, 0);
        assertFalse(confirmed);
    }

    function testConfirm_FreesSlotAllowsNextBatch() public {
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1);
        uint256 slotIdx = id % bridge.MAX_PENDING_BATCHES();

        // Slot occupied after register.
        (uint256 storedIdBefore,,,,,,) = bridge.pendingBatches(slotIdx);
        assertEq(storedIdBefore, id);

        // Register another batch — count is 2, queue not full.
        _registerBatch(ROOT_NC_2, ROOT_NN_2, ROOT_AC_2, ROOT_AN_2);

        // Confirm batch 1 — slot freed.
        bridge.confirmBatch(id, _dummyProof());

        // Slot freed.
        (uint256 storedId,,,,,,) = bridge.pendingBatches(slotIdx);
        assertEq(storedId, 0);
    }

    // -------------------------------------------------------------------------
    // confirmBatch — error cases
    // -------------------------------------------------------------------------

    function testConfirm_RevertsOnUnknownBatch() public {
        DepositsRollupBridge.Proof memory p = _dummyProof();
        // batchId 999 was never registered.
        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.UnknownBatch.selector, 999));
        bridge.confirmBatch(999, p);
    }

    function testConfirm_RevertsOnAlreadyConfirmed() public {
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1);
        DepositsRollupBridge.Proof memory p = _dummyProof();

        bridge.confirmBatch(id, p);

        // After finalization the slot is freed (batchId reset to 0), so a second call
        // cannot find the batch and reverts with UnknownBatch.
        vm.expectRevert(
            abi.encodeWithSelector(DepositsRollupBridge.UnknownBatch.selector, id)
        );
        bridge.confirmBatch(id, p);
    }

    function testConfirm_RevertsOnNonOperator() public {
        uint256 id = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1);
        DepositsRollupBridge.Proof memory p = _dummyProof();
        vm.prank(address(0xDEAD));
        vm.expectRevert(DepositsRollupBridge.NotOperator.selector);
        bridge.confirmBatch(id, p);
    }

    // -------------------------------------------------------------------------
    // Slot recycling after full confirmation
    // -------------------------------------------------------------------------

    function testSlotRecycling_ReusedAfterFullConfirmation() public {
        uint256 id1 = _registerBatch(ROOT_NC_1, ROOT_NN_1, ROOT_AC_1, ROOT_AN_1);
        _confirmAll(id1);

        // MAX_PENDING_BATCHES = 128; batchId 129 maps to slot 129 % 128 = 1 (same as batchId 1).
        // Fill slots 2..128 so the counter wraps properly.
        uint256 max = bridge.MAX_PENDING_BATCHES();
        for (uint256 i = 1; i < max; i++) {
            bytes32 r = bytes32(i + 100);
            _registerBatch(r, r, r, r);
        }
        // batchId is now 129; slotIndex = 129 % 128 = 1 — the freed slot.
        uint256 id129 = _registerBatch(ROOT_NC_2, ROOT_NN_2, ROOT_AC_2, ROOT_AN_2);
        assertEq(id129, max + 1);
        assertEq(id129 % max, 1);
        (uint256 storedId,,,,,,) = bridge.pendingBatches(1);
        assertEq(storedId, id129);
    }

    // -------------------------------------------------------------------------
    // Proof failure via MockVerifierRevert
    // -------------------------------------------------------------------------

    function testConfirm_RevertsOnBadProof() public {
        MockVerifierRevert verifierBad = new MockVerifierRevert();

        DepositsRollupBridge badBridge = new DepositsRollupBridge(
            address(verifierBad), // superAggregatorVerifier always reverts
            operator,
            GENESIS_NULLIFIER_ROOT,
            GENESIS_COMMITMENT_ROOT,
            GENESIS_ACC_NULL_ROOT,
            GENESIS_ACC_COMMIT_ROOT,
            NOTE_BATCH_SIZE,
            ACCOUNT_BATCH_SIZE,
            address(token)
        );

        // Build full sorted batches for the bad-verifier bridge.
        bytes32[] memory ncFull = new bytes32[](NOTE_BATCH_SIZE);
        bytes32[] memory nnFull = new bytes32[](NOTE_BATCH_SIZE);
        bytes32[] memory acFull = new bytes32[](ACCOUNT_BATCH_SIZE);
        bytes32[] memory anFull = new bytes32[](ACCOUNT_BATCH_SIZE);
        for (uint256 i = 0; i < NOTE_BATCH_SIZE; i++) {
            ncFull[i] = bytes32(uint256(0xF100 + i));
            nnFull[i] = bytes32(uint256(0x1000 + i));
        }
        acFull[0] = bytes32(uint256(0xE1));
        anFull[0] = bytes32(uint256(0x3001));

        uint256 id = badBridge.registerTransactionBatchUpdate(
            ROOT_NC_1, ncFull,
            ROOT_NN_1, nnFull,
            ROOT_AC_1, acFull,
            ROOT_AN_1, anFull
        );

        // Read the exact commitment stored for this batch so the expected revert data matches.
        (bytes32 commitment, uint256[8] memory pubInputs) = badBridge.getBatchDebugInfo(id);

        DepositsRollupBridge.Proof memory p = _dummyProof();
        vm.expectRevert(abi.encodeWithSelector(
            DepositsRollupBridge.ProofVerificationFailed.selector,
            commitment,
            pubInputs
        ));
        badBridge.confirmBatch(id, p);
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

        // Register batch with this note in noteCommitmentsOut (full sorted batch).
        bytes32[] memory notesOut = new bytes32[](NOTE_BATCH_SIZE);
        notesOut[0] = note;
        for (uint256 i = 1; i < NOTE_BATCH_SIZE; i++) {
            notesOut[i] = bytes32(uint256(0xFF00 + i));
        }
        bridge.registerTransactionBatchUpdate(
            ROOT_NC_1, notesOut,
            ROOT_NN_1, NN_LEAVES_1,
            ROOT_AC_1, ACCT_LEAVES_1,
            ROOT_AN_1, AN_LEAVES_1
        );

        // Deposit is now Validated; withdrawal should revert.
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.InvalidDepositState.selector, note));
        bridge.withdrawPendingDeposit(note);
    }
}
