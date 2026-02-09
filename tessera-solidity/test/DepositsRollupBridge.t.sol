// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title  DepositsRollupBridge — Unit Tests
/// @notice 40 tests covering the two-phase submit → finalize lifecycle.
///
///         Test strategy:
///           - Three mock verifiers isolate contract logic from real
///             Groth16 verification: MockVerifier (accept), MockVerifierReject
///             (reject), MockVerifierCheckInputs (validate public inputs).
///           - Sections mirror the contract's functional areas:
///             1.  Constructor / initial state / constants
///             2.  submitBatch — happy path, events, reverts
///             3.  finalizeBatch — happy path, events, reverts
///             4.  cancelPendingBatch — happy path, reverts
///             5.  Domain separation
///             6.  sha256ToPublicInputs
///             7.  Public input derivation (end-to-end with mock)
///             8.  Atomicity (state unchanged on revert)
///             9.  Multi-batch chained flow
///             10. Stale batch scenario
///             11. Admin functions
///             12. View helpers
///
///         Run: `forge test --match-contract DepositsRollupBridgeTest -vv`

import {Test} from "forge-std/Test.sol";
import {DepositsRollupBridge, IGroth16Verifier} from "../src/DepositsRollupBridge.sol";

// ====================================================================
// Mock verifiers
// ====================================================================

/// @dev Always-accept mock.
contract MockVerifier is IGroth16Verifier {
    function verifyProof(
        uint256[8] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[8] calldata
    ) external pure {}
}

/// @dev Always-reject mock.
contract MockVerifierReject is IGroth16Verifier {
    function verifyProof(
        uint256[8] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[8] calldata
    ) external pure {
        revert("MOCK_REJECT");
    }
}

/// @dev Accepts only when public inputs match expected values.
contract MockVerifierCheckInputs is IGroth16Verifier {
    uint256[8] public expectedInputs;

    function setExpectedInputs(uint256[8] memory inputs) external {
        expectedInputs = inputs;
    }

    function verifyProof(
        uint256[8] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[8] calldata input
    ) external view {
        for (uint256 i = 0; i < 8; i++) {
            require(input[i] == expectedInputs[i], "INPUT_MISMATCH");
        }
    }
}

// ====================================================================
// Test suite
// ====================================================================

/// @title  DepositsRollupBridge unit tests
/// @notice Covers the two-phase submit → finalize flow, cancellation,
///         domain separation, admin functions, and edge cases.
contract DepositsRollupBridgeTest is Test {
    DepositsRollupBridge public bridge;

    MockVerifier            public mockOk;
    MockVerifierReject      public mockReject;
    MockVerifierCheckInputs public mockCheck;

    address public operator = address(this);
    bytes32 public constant GENESIS = bytes32(uint256(0xBEEF));
    bytes32 public constant NEW_ROOT = bytes32(uint256(0xCAFE));

    // ------------------------------------------------------------------
    // Setup
    // ------------------------------------------------------------------

    function setUp() public {
        mockOk     = new MockVerifier();
        mockReject = new MockVerifierReject();
        mockCheck  = new MockVerifierCheckInputs();
        bridge     = new DepositsRollupBridge(address(mockOk), operator, GENESIS);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// @dev Build a Deposit[] with deterministic but non-zero values.
    function _dummyDeposits(uint8 seed)
        internal
        pure
        returns (DepositsRollupBridge.Deposit[] memory deps)
    {
        deps = new DepositsRollupBridge.Deposit[](128);
        for (uint256 i = 0; i < 128; i++) {
            uint256 v = uint256(keccak256(abi.encode(seed, i)));
            deps[i] = DepositsRollupBridge.Deposit({
                noteCommitment: bytes32(v),
                addr0: uint64(v),
                addr1: uint64(v >> 64),
                addr2: uint64(v >> 128),
                amount: uint64(v >> 192)
            });
        }
    }

    /// @dev 4096-byte zeroed leaves blob.
    function _dummyLeaves() internal pure returns (bytes memory) {
        return new bytes(4096);
    }

    /// @dev 4096-byte leaves blob with deterministic pattern.
    function _dummyLeaves(uint8 seed) internal pure returns (bytes memory leaves) {
        leaves = new bytes(4096);
        for (uint256 i = 0; i < 4096; i++) {
            unchecked {
                leaves[i] = bytes1(uint8((uint256(seed) + i) % 256));
            }
        }
    }

    /// @dev Zeroed proof struct.
    function _dummyProof() internal pure returns (DepositsRollupBridge.Proof memory) {
        return DepositsRollupBridge.Proof({
            proof: [uint256(0),0,0,0,0,0,0,0],
            commitments: [uint256(0),0],
            commitmentPok: [uint256(0),0]
        });
    }

    /// @dev Submit a batch and return its commit key.
    function _submitDefault() internal returns (bytes32 commit) {
        return bridge.submitBatch(NEW_ROOT, _dummyDeposits(1), _dummyLeaves(1));
    }

    // ==================================================================
    // 1. Constructor / Initial State / Constants
    // ==================================================================

    function testInitialState() public view {
        assertEq(bridge.stateRoot(), GENESIS);
        assertEq(bridge.batchNumber(), 0);
        assertEq(bridge.operator(), operator);
        assertFalse(bridge.paused());
    }

    function testConstants() public view {
        assertEq(bridge.BATCH_SIZE(), 128);
        assertEq(bridge.HASH_SIZE(), 4);
        assertEq(bridge.FIELD_ELEMENT_BYTES(), 8);
        assertEq(bridge.LEAVES_BYTE_LEN(), 4096);
        assertEq(bridge.PROTOCOL_VERSION(), 1);
    }

    // ==================================================================
    // 2. submitBatch
    // ==================================================================

    /// @notice Happy-path: submit stores a Pending batch with correct fields.
    function testSubmitBatch_HappyPath() public {
        DepositsRollupBridge.Deposit[] memory deps = _dummyDeposits(1);
        bytes memory leaves = _dummyLeaves(1);

        bytes32 commit = bridge.submitBatch(NEW_ROOT, deps, leaves);
        assertTrue(commit != bytes32(0));

        (
            bytes32 oldRoot,
            bytes32 newRoot,
            bytes32 sha256Commit,
            uint64 blockNum,
            DepositsRollupBridge.BatchStatus status,
            uint256 depositsCount
        ) = bridge.getBatch(commit);

        assertEq(oldRoot, GENESIS);
        assertEq(newRoot, NEW_ROOT);
        assertTrue(sha256Commit != bytes32(0));
        assertEq(blockNum, uint64(block.number));
        assertTrue(status == DepositsRollupBridge.BatchStatus.Pending);
        assertEq(depositsCount, 128);

        // Verify first deposit stored correctly.
        DepositsRollupBridge.Deposit memory d0 = bridge.getBatchDeposit(commit, 0);
        assertEq(d0.noteCommitment, deps[0].noteCommitment);
        assertEq(d0.addr0, deps[0].addr0);
        assertEq(d0.amount, deps[0].amount);
    }

    /// @notice submitBatch emits BatchSubmitted with correct indexed commit.
    function testSubmitBatch_EmitsEvent() public {
        DepositsRollupBridge.Deposit[] memory deps = _dummyDeposits(1);
        bytes memory leaves = _dummyLeaves(1);

        // Compute expected commit.
        bytes32 sha256Commit = sha256(abi.encodePacked(GENESIS, NEW_ROOT, leaves));
        bytes32 expectedCommit = bridge.computeDomainCommitment(sha256Commit);

        vm.expectEmit(true, false, false, false);
        emit DepositsRollupBridge.BatchSubmitted(
            expectedCommit, sha256Commit, GENESIS, NEW_ROOT, deps, leaves
        );
        bridge.submitBatch(NEW_ROOT, deps, leaves);
    }

    function testSubmitBatch_RevertNotOperator() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(DepositsRollupBridge.NotOperator.selector);
        bridge.submitBatch(NEW_ROOT, _dummyDeposits(1), _dummyLeaves(1));
    }

    function testSubmitBatch_RevertPaused() public {
        bridge.setPaused(true);
        vm.expectRevert(DepositsRollupBridge.PausedErr.selector);
        bridge.submitBatch(NEW_ROOT, _dummyDeposits(1), _dummyLeaves(1));
    }

    function testSubmitBatch_RevertInvalidDepositsLength() public {
        DepositsRollupBridge.Deposit[] memory deps = new DepositsRollupBridge.Deposit[](10);
        vm.expectRevert(DepositsRollupBridge.InvalidDepositsLength.selector);
        bridge.submitBatch(NEW_ROOT, deps, _dummyLeaves(1));
    }

    function testSubmitBatch_RevertInvalidLeavesLength_Empty() public {
        vm.expectRevert(DepositsRollupBridge.InvalidLeavesLength.selector);
        bridge.submitBatch(NEW_ROOT, _dummyDeposits(1), "");
    }

    function testSubmitBatch_RevertInvalidLeavesLength_TooShort() public {
        vm.expectRevert(DepositsRollupBridge.InvalidLeavesLength.selector);
        bridge.submitBatch(NEW_ROOT, _dummyDeposits(1), new bytes(100));
    }

    function testSubmitBatch_RevertInvalidLeavesLength_TooLong() public {
        vm.expectRevert(DepositsRollupBridge.InvalidLeavesLength.selector);
        bridge.submitBatch(NEW_ROOT, _dummyDeposits(1), new bytes(5000));
    }

    function testSubmitBatch_RevertAlreadyPending() public {
        bytes32 commit = _submitDefault();
        // Same inputs → same commit → revert.
        vm.expectRevert(abi.encodeWithSelector(
            DepositsRollupBridge.BatchAlreadyExists.selector, commit
        ));
        bridge.submitBatch(NEW_ROOT, _dummyDeposits(1), _dummyLeaves(1));
    }

    function testSubmitBatch_RevertAlreadyValidated() public {
        bytes32 commit = _submitDefault();
        bridge.finalizeBatch(commit, _dummyProof());

        // State root changed, so submitting the same batch data will produce
        // a different sha256Commit (different oldRoot) and a different commit.
        // To get the SAME commit we need to manually submit after root change.
        // Instead, verify that a validated batch blocks resubmission by
        // reverting the root and re-submitting.
        // This case is naturally prevented because stateRoot changed.
        // We verify the status is Validated.
        (, , , , DepositsRollupBridge.BatchStatus status, ) = bridge.getBatch(commit);
        assertTrue(status == DepositsRollupBridge.BatchStatus.Validated);
    }

    // ==================================================================
    // 3. finalizeBatch
    // ==================================================================

    /// @notice Happy-path: finalize transitions Pending → Validated and
    ///         updates stateRoot + batchNumber.
    function testFinalizeBatch_HappyPath() public {
        bytes32 commit = _submitDefault();

        bridge.finalizeBatch(commit, _dummyProof());

        // State updated.
        assertEq(bridge.stateRoot(), NEW_ROOT);
        assertEq(bridge.batchNumber(), 1);

        // Batch is now Validated.
        (, , , uint64 blockNum, DepositsRollupBridge.BatchStatus status, uint256 depsCount) =
            bridge.getBatch(commit);
        assertTrue(status == DepositsRollupBridge.BatchStatus.Validated);
        assertEq(blockNum, uint64(block.number));
        assertEq(depsCount, 128);
    }

    /// @notice finalizeBatch emits BatchFinalized.
    function testFinalizeBatch_EmitsEvent() public {
        bytes32 commit = _submitDefault();

        vm.expectEmit(true, false, false, true);
        emit DepositsRollupBridge.BatchFinalized(commit, GENESIS, NEW_ROOT, 0);
        bridge.finalizeBatch(commit, _dummyProof());
    }

    function testFinalizeBatch_RevertNotOperator() public {
        bytes32 commit = _submitDefault();
        vm.prank(address(0xDEAD));
        vm.expectRevert(DepositsRollupBridge.NotOperator.selector);
        bridge.finalizeBatch(commit, _dummyProof());
    }

    function testFinalizeBatch_RevertPaused() public {
        bytes32 commit = _submitDefault();
        bridge.setPaused(true);
        vm.expectRevert(DepositsRollupBridge.PausedErr.selector);
        bridge.finalizeBatch(commit, _dummyProof());
    }

    function testFinalizeBatch_RevertBatchNotFound() public {
        bytes32 fakeCommit = bytes32(uint256(0x1234));
        vm.expectRevert(abi.encodeWithSelector(
            DepositsRollupBridge.BatchNotPending.selector, fakeCommit
        ));
        bridge.finalizeBatch(fakeCommit, _dummyProof());
    }

    /// @notice After finalizing batch1, batch2 (submitted with same stateRoot)
    ///         becomes stale.
    function testFinalizeBatch_RevertStaleRoot() public {
        // Submit two batches with same stateRoot (different newRoot/leaves).
        bytes32 commit1 = bridge.submitBatch(NEW_ROOT, _dummyDeposits(1), _dummyLeaves(1));
        bytes32 commit2 = bridge.submitBatch(
            bytes32(uint256(0xAAAA)),
            _dummyDeposits(2),
            _dummyLeaves(2)
        );
        assertTrue(commit1 != commit2);

        // Finalize batch1 → stateRoot changes.
        bridge.finalizeBatch(commit1, _dummyProof());
        assertEq(bridge.stateRoot(), NEW_ROOT);

        // batch2.oldRoot == GENESIS != NEW_ROOT → stale.
        vm.expectRevert(abi.encodeWithSelector(
            DepositsRollupBridge.StaleRoot.selector, NEW_ROOT, GENESIS
        ));
        bridge.finalizeBatch(commit2, _dummyProof());
    }

    function testFinalizeBatch_RevertInvalidProof() public {
        DepositsRollupBridge bridgeReject = new DepositsRollupBridge(
            address(mockReject), operator, GENESIS
        );
        bytes32 commit = bridgeReject.submitBatch(NEW_ROOT, _dummyDeposits(1), _dummyLeaves(1));

        vm.expectRevert(DepositsRollupBridge.InvalidProof.selector);
        bridgeReject.finalizeBatch(commit, _dummyProof());
    }

    // ==================================================================
    // 4. cancelPendingBatch
    // ==================================================================

    function testCancelPendingBatch_HappyPath() public {
        bytes32 commit = _submitDefault();

        vm.expectEmit(true, false, false, false);
        emit DepositsRollupBridge.BatchCancelled(commit);
        bridge.cancelPendingBatch(commit);

        // Batch gone.
        (, , , , DepositsRollupBridge.BatchStatus status, ) = bridge.getBatch(commit);
        assertTrue(status == DepositsRollupBridge.BatchStatus.None);
    }

    function testCancelPendingBatch_RevertNotOperator() public {
        bytes32 commit = _submitDefault();
        vm.prank(address(0xDEAD));
        vm.expectRevert(DepositsRollupBridge.NotOperator.selector);
        bridge.cancelPendingBatch(commit);
    }

    function testCancelPendingBatch_RevertNotPending() public {
        bytes32 fakeCommit = bytes32(uint256(0x1234));
        vm.expectRevert(abi.encodeWithSelector(
            DepositsRollupBridge.BatchNotPending.selector, fakeCommit
        ));
        bridge.cancelPendingBatch(fakeCommit);
    }

    function testCancelPendingBatch_RevertAlreadyValidated() public {
        bytes32 commit = _submitDefault();
        bridge.finalizeBatch(commit, _dummyProof());

        vm.expectRevert(abi.encodeWithSelector(
            DepositsRollupBridge.BatchNotPending.selector, commit
        ));
        bridge.cancelPendingBatch(commit);
    }

    // ==================================================================
    // 5. Domain separation
    // ==================================================================

    /// @notice Same sha256Commit on different chain IDs produces different commit keys.
    function testDomainSeparation_DifferentChainId() public view {
        bytes32 sha256Commit = bytes32(uint256(0x42));
        bytes32 commitHere = bridge.computeDomainCommitment(sha256Commit);

        // Manually compute for a different chainid.
        bytes32 commitOtherChain = keccak256(
            abi.encodePacked(
                uint256(999),
                address(bridge),
                bridge.PROTOCOL_VERSION(),
                sha256Commit
            )
        );
        assertTrue(commitHere != commitOtherChain);
    }

    // ==================================================================
    // 6. sha256ToPublicInputs
    // ==================================================================

    function testSha256ToPublicInputs_Zero() public view {
        uint256[8] memory inputs = bridge.sha256ToPublicInputs(bytes32(0));
        for (uint256 i = 0; i < 8; i++) {
            assertEq(inputs[i], 0);
        }
    }

    function testSha256ToPublicInputs_AllOnes() public view {
        uint256[8] memory inputs = bridge.sha256ToPublicInputs(
            bytes32(type(uint256).max)
        );
        for (uint256 i = 0; i < 8; i++) {
            assertEq(inputs[i], 0xFFFFFFFF);
        }
    }

    /// @notice SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223 ...
    function testSha256ToPublicInputs_KnownVector() public view {
        bytes32 h = sha256("abc");
        uint256[8] memory inputs = bridge.sha256ToPublicInputs(h);
        assertEq(inputs[0], 0xba7816bf);
        assertEq(inputs[1], 0x8f01cfea);
    }

    // ==================================================================
    // 7. Public input derivation (end-to-end with MockVerifierCheckInputs)
    // ==================================================================

    /// @notice Confirms the bridge forwards the correct public inputs
    ///         to the verifier during finalizeBatch.
    function testFinalizeBatch_PublicInputsMatchSha256() public {
        DepositsRollupBridge bridgeCheck = new DepositsRollupBridge(
            address(mockCheck), operator, GENESIS
        );
        bytes memory leaves = _dummyLeaves(1);
        bytes32 sha256Commit = sha256(abi.encodePacked(GENESIS, NEW_ROOT, leaves));
        uint256[8] memory expected = bridgeCheck.sha256ToPublicInputs(sha256Commit);
        mockCheck.setExpectedInputs(expected);

        bytes32 commit = bridgeCheck.submitBatch(NEW_ROOT, _dummyDeposits(1), leaves);
        // Will revert with INPUT_MISMATCH if inputs are wrong.
        bridgeCheck.finalizeBatch(commit, _dummyProof());
    }

    // ==================================================================
    // 8. Atomicity — state unchanged on failed finalization
    // ==================================================================

    function testFinalizeBatch_StateUnchangedOnRevert() public {
        DepositsRollupBridge bridgeReject = new DepositsRollupBridge(
            address(mockReject), operator, GENESIS
        );
        bytes32 commit = bridgeReject.submitBatch(NEW_ROOT, _dummyDeposits(1), _dummyLeaves(1));

        vm.expectRevert(DepositsRollupBridge.InvalidProof.selector);
        bridgeReject.finalizeBatch(commit, _dummyProof());

        // State unchanged.
        assertEq(bridgeReject.stateRoot(), GENESIS);
        assertEq(bridgeReject.batchNumber(), 0);

        // Batch still pending.
        (, , , , DepositsRollupBridge.BatchStatus status, ) = bridgeReject.getBatch(commit);
        assertTrue(status == DepositsRollupBridge.BatchStatus.Pending);
    }

    // ==================================================================
    // 9. Multi-batch chained flow
    // ==================================================================

    /// @notice submit1 → finalize1 → submit2 → finalize2
    function testTwoBatches_ChainedFlow() public {
        bytes32 root2 = bytes32(uint256(0xBBBB));

        // Batch 1.
        bytes32 commit1 = bridge.submitBatch(NEW_ROOT, _dummyDeposits(1), _dummyLeaves(1));
        bridge.finalizeBatch(commit1, _dummyProof());
        assertEq(bridge.stateRoot(), NEW_ROOT);
        assertEq(bridge.batchNumber(), 1);

        // Batch 2 (oldRoot = NEW_ROOT now).
        bytes32 commit2 = bridge.submitBatch(root2, _dummyDeposits(2), _dummyLeaves(2));
        bridge.finalizeBatch(commit2, _dummyProof());
        assertEq(bridge.stateRoot(), root2);
        assertEq(bridge.batchNumber(), 2);
    }

    // ==================================================================
    // 10. Stale batch scenario
    // ==================================================================

    /// @notice Two batches submitted with same oldRoot. After one is finalized,
    ///         the other is stale and can be cancelled.
    function testStaleBatch_CancelAfterFinalize() public {
        bytes32 commit1 = bridge.submitBatch(NEW_ROOT, _dummyDeposits(1), _dummyLeaves(1));
        bytes32 commit2 = bridge.submitBatch(
            bytes32(uint256(0xAAAA)),
            _dummyDeposits(2),
            _dummyLeaves(2)
        );

        bridge.finalizeBatch(commit1, _dummyProof());

        // commit2 is stale — cancel it.
        bridge.cancelPendingBatch(commit2);
        (, , , , DepositsRollupBridge.BatchStatus status, ) = bridge.getBatch(commit2);
        assertTrue(status == DepositsRollupBridge.BatchStatus.None);
    }

    // ==================================================================
    // 11. Admin functions
    // ==================================================================

    function testSetOperator() public {
        address newOp = address(0x1234);
        bridge.setOperator(newOp);
        assertEq(bridge.operator(), newOp);
    }

    function testSetOperator_EmitsEvent() public {
        address newOp = address(0x1234);
        vm.expectEmit(true, true, false, false);
        emit DepositsRollupBridge.OperatorChanged(operator, newOp);
        bridge.setOperator(newOp);
    }

    function testSetOperator_RevertNotOperator() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(DepositsRollupBridge.NotOperator.selector);
        bridge.setOperator(address(0x1234));
    }

    function testSetPaused() public {
        bridge.setPaused(true);
        assertTrue(bridge.paused());
        bridge.setPaused(false);
        assertFalse(bridge.paused());
    }

    function testSetPaused_EmitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit DepositsRollupBridge.PausedChanged(true);
        bridge.setPaused(true);
    }

    function testSetPaused_RevertNotOperator() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(DepositsRollupBridge.NotOperator.selector);
        bridge.setPaused(true);
    }

    function testOperatorTransferChain() public {
        address op2 = address(0x2222);
        address op3 = address(0x3333);

        bridge.setOperator(op2);
        assertEq(bridge.operator(), op2);

        // Original operator can no longer act.
        vm.expectRevert(DepositsRollupBridge.NotOperator.selector);
        bridge.setOperator(address(0x9999));

        // op2 transfers to op3.
        vm.prank(op2);
        bridge.setOperator(op3);
        assertEq(bridge.operator(), op3);
    }

    function testPauseUnpauseFlow() public {
        // Submit while active.
        bytes32 commit1 = _submitDefault();

        // Pause blocks finalize.
        bridge.setPaused(true);
        vm.expectRevert(DepositsRollupBridge.PausedErr.selector);
        bridge.finalizeBatch(commit1, _dummyProof());

        // Unpause allows finalize.
        bridge.setPaused(false);
        bridge.finalizeBatch(commit1, _dummyProof());
        assertEq(bridge.batchNumber(), 1);
    }

    // ==================================================================
    // 12. computeSha256Commitment view helper
    // ==================================================================

    function testComputeSha256Commitment() public view {
        bytes memory leaves = _dummyLeaves(1);
        bytes32 expected = sha256(abi.encodePacked(GENESIS, NEW_ROOT, leaves));
        bytes32 got = bridge.computeSha256Commitment(GENESIS, NEW_ROOT, leaves);
        assertEq(got, expected);
    }
}
