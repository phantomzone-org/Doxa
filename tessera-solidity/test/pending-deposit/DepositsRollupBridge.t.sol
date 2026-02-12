// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title  DepositsRollupBridge — Unit Tests
/// @notice Covers the deposit → finalize lifecycle, commitment computation,
///         admin functions, and edge cases.
///
///         Test strategy:
///           - Three mock verifiers isolate contract logic from real
///             Groth16 verification: MockVerifier (accept), MockVerifierReject
///             (reject), MockVerifierCheckInputs (validate public inputs).
///           - Deposits are created in-test via `bridge.deposit()`.
///           - Sections:
///             1.  Constructor / initial state
///             2.  deposit — happy path, events, reverts
///             3.  computeCommitment — determinism, MSB clearing
///             4.  finalizeBatch — happy path, events, reverts
///             5.  sha256ToPublicInputs
///             6.  Public input derivation (end-to-end with mock)
///             7.  Atomicity (state unchanged on revert)
///             8.  Multi-batch chained flow
///             9.  Admin functions
///             10. View helpers
///
///         Run: `forge test --match-contract DepositsRollupBridgeTest -vv`

import {Test} from "forge-std/Test.sol";
import {DepositsRollupBridge, IGroth16Verifier} from "../../src/pending-deposit/DepositsRollupBridge.sol";

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

contract DepositsRollupBridgeTest is Test {
    DepositsRollupBridge public bridge;

    MockVerifier            public mockOk;
    MockVerifierReject      public mockReject;
    MockVerifierCheckInputs public mockCheck;

    address public operator = address(this);
    bytes32 public constant GENESIS = bytes32(uint256(0xBEEF));
    bytes32 public constant NEW_ROOT = bytes32(uint256(0xCAFE));

    uint256 public constant BATCH_SIZE = 128;

    // ------------------------------------------------------------------
    // Setup
    // ------------------------------------------------------------------

    function setUp() public {
        mockOk     = new MockVerifier();
        mockReject = new MockVerifierReject();
        mockCheck  = new MockVerifierCheckInputs();
        bridge     = new DepositsRollupBridge(address(mockOk), operator, GENESIS, BATCH_SIZE);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// @dev Generate deterministic deposit parameters for index `idx`.
    function _makeDeposit(uint256 idx)
        internal
        pure
        returns (bytes32 noteCommitment, uint256 value, address recipient)
    {
        noteCommitment = bytes32(idx + 1);
        value = (idx + 1) * 1e18;
        recipient = address(uint160(idx + 1));
    }

    /// @dev Submit a full batch of 128 deposits.
    function _depositBatch() internal {
        for (uint256 i = 0; i < BATCH_SIZE; i++) {
            (bytes32 nc, uint256 val, address recip) = _makeDeposit(i);
            bridge.deposit(nc, val, recip);
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

    // ==================================================================
    // 1. Constructor / Initial State
    // ==================================================================

    function testInitialState() public view {
        assertEq(bridge.merkleRoot(), GENESIS);
        assertEq(bridge.nextDepositId(), 0);
        assertEq(bridge.batchSize(), BATCH_SIZE);
        assertEq(bridge.operator(), operator);
        assertFalse(bridge.paused());
    }

    function testDomainSep() public view {
        bytes32 expected = sha256("tessera.pending-deposit.v1");
        assertEq(bridge.DOMAIN_SEP(), expected);
    }

    // ==================================================================
    // 2. deposit
    // ==================================================================

    function testDeposit_HappyPath() public {
        (bytes32 nc, uint256 val, address recip) = _makeDeposit(0);
        uint256 id = bridge.deposit(nc, val, recip);

        assertEq(id, 0);
        assertEq(bridge.nextDepositId(), 1);

        DepositsRollupBridge.Deposit memory d = bridge.getDeposit(0);
        bytes32 expectedCommitment = bridge.computeCommitment(nc, val, recip);
        assertEq(d.commitment, expectedCommitment);
        assertEq(d.value, val);
        assertEq(d.recipient, recip);
        assertTrue(d.status == DepositsRollupBridge.DepositStatus.Pending);
    }

    function testDeposit_EmitsEvent() public {
        (bytes32 nc, uint256 val, address recip) = _makeDeposit(0);
        bytes32 expectedCommitment = bridge.computeCommitment(nc, val, recip);

        vm.expectEmit(true, false, false, true);
        emit DepositsRollupBridge.DepositPending(0, expectedCommitment, val, recip);
        bridge.deposit(nc, val, recip);
    }

    function testDeposit_MultipleDeposits() public {
        for (uint256 i = 0; i < 5; i++) {
            (bytes32 nc, uint256 val, address recip) = _makeDeposit(i);
            uint256 id = bridge.deposit(nc, val, recip);
            assertEq(id, i);
        }
        assertEq(bridge.nextDepositId(), 5);
    }

    function testDeposit_Permissionless() public {
        // Any address can deposit.
        (bytes32 nc, uint256 val, address recip) = _makeDeposit(0);
        vm.prank(address(0xDEAD));
        uint256 id = bridge.deposit(nc, val, recip);
        assertEq(id, 0);
    }

    function testDeposit_RevertPaused() public {
        bridge.setPaused(true);
        (bytes32 nc, uint256 val, address recip) = _makeDeposit(0);
        vm.expectRevert(DepositsRollupBridge.PausedErr.selector);
        bridge.deposit(nc, val, recip);
    }

    // ==================================================================
    // 3. computeCommitment
    // ==================================================================

    function testComputeCommitment_Deterministic() public view {
        (bytes32 nc, uint256 val, address recip) = _makeDeposit(42);
        bytes32 c1 = bridge.computeCommitment(nc, val, recip);
        bytes32 c2 = bridge.computeCommitment(nc, val, recip);
        assertEq(c1, c2);
        assertTrue(c1 != bytes32(0));
    }

    function testComputeCommitment_MsbCleared() public view {
        (bytes32 nc, uint256 val, address recip) = _makeDeposit(0);
        bytes32 c = bridge.computeCommitment(nc, val, recip);
        uint256 cv = uint256(c);

        // MSB of each 64-bit chunk must be zero.
        assertEq(cv & (uint256(1) << 255), 0);
        assertEq(cv & (uint256(1) << 191), 0);
        assertEq(cv & (uint256(1) << 127), 0);
        assertEq(cv & (uint256(1) << 63), 0);
    }

    function testComputeCommitment_DifferentInputsDifferentOutputs() public view {
        bytes32 c1 = bridge.computeCommitment(bytes32(uint256(1)), 100, address(1));
        bytes32 c2 = bridge.computeCommitment(bytes32(uint256(2)), 100, address(1));
        bytes32 c3 = bridge.computeCommitment(bytes32(uint256(1)), 200, address(1));
        bytes32 c4 = bridge.computeCommitment(bytes32(uint256(1)), 100, address(2));
        assertTrue(c1 != c2);
        assertTrue(c1 != c3);
        assertTrue(c1 != c4);
    }

    function testFuzz_ComputeCommitment_MsbCleared(
        bytes32 nc, uint256 val, address recip
    ) public view {
        bytes32 c = bridge.computeCommitment(nc, val, recip);
        uint256 cv = uint256(c);
        assertEq(cv & (uint256(1) << 255), 0, "bit 255 not cleared");
        assertEq(cv & (uint256(1) << 191), 0, "bit 191 not cleared");
        assertEq(cv & (uint256(1) << 127), 0, "bit 127 not cleared");
        assertEq(cv & (uint256(1) << 63),  0, "bit 63 not cleared");
    }

    // ==================================================================
    // 4. finalizeBatch
    // ==================================================================

    /// @notice Happy-path: deposit 128 → finalize → merkleRoot updated,
    ///         all deposits Validated.
    function testFinalizeBatch_HappyPath() public {
        _depositBatch();

        bridge.finalizeBatch(NEW_ROOT, 0, _dummyProof());

        // State updated.
        assertEq(bridge.merkleRoot(), NEW_ROOT);

        // All deposits validated.
        for (uint256 i = 0; i < BATCH_SIZE; i++) {
            DepositsRollupBridge.Deposit memory d = bridge.getDeposit(i);
            assertTrue(d.status == DepositsRollupBridge.DepositStatus.Validated);
        }
    }

    function testFinalizeBatch_EmitsEvent() public {
        _depositBatch();

        vm.expectEmit(true, false, false, true);
        emit DepositsRollupBridge.BatchValidated(0, NEW_ROOT);
        bridge.finalizeBatch(NEW_ROOT, 0, _dummyProof());
    }

    function testFinalizeBatch_RevertNotOperator() public {
        _depositBatch();
        vm.prank(address(0xDEAD));
        vm.expectRevert(DepositsRollupBridge.NotOperator.selector);
        bridge.finalizeBatch(NEW_ROOT, 0, _dummyProof());
    }

    function testFinalizeBatch_RevertPaused() public {
        _depositBatch();
        bridge.setPaused(true);
        vm.expectRevert(DepositsRollupBridge.PausedErr.selector);
        bridge.finalizeBatch(NEW_ROOT, 0, _dummyProof());
    }

    function testFinalizeBatch_RevertInsufficientDeposits() public {
        // Only deposit 10 (less than batch size of 128).
        for (uint256 i = 0; i < 10; i++) {
            (bytes32 nc, uint256 val, address recip) = _makeDeposit(i);
            bridge.deposit(nc, val, recip);
        }
        vm.expectRevert(DepositsRollupBridge.InsufficientDeposits.selector);
        bridge.finalizeBatch(NEW_ROOT, 0, _dummyProof());
    }

    function testFinalizeBatch_RevertDepositNotPending() public {
        _depositBatch();

        // Finalize batch 0.
        bridge.finalizeBatch(NEW_ROOT, 0, _dummyProof());

        // Try to finalize same batch again — nextBatchStartIndex is now 128, so
        // depositStartIndex=0 is rejected before the status check.
        vm.expectRevert(DepositsRollupBridge.InvalidDepositStartIndex.selector);
        bridge.finalizeBatch(bytes32(uint256(0xBBBB)), 0, _dummyProof());
    }

    function testFinalizeBatch_RevertInvalidStartIndex() public {
        _depositBatch();
        // Correct start index is 0; passing 128 should revert immediately.
        vm.expectRevert(DepositsRollupBridge.InvalidDepositStartIndex.selector);
        bridge.finalizeBatch(NEW_ROOT, BATCH_SIZE, _dummyProof());
    }

    function testFinalizeBatch_RevertInvalidProof() public {
        DepositsRollupBridge bridgeReject = new DepositsRollupBridge(
            address(mockReject), operator, GENESIS, BATCH_SIZE
        );

        for (uint256 i = 0; i < BATCH_SIZE; i++) {
            (bytes32 nc, uint256 val, address recip) = _makeDeposit(i);
            bridgeReject.deposit(nc, val, recip);
        }

        vm.expectRevert(DepositsRollupBridge.InvalidProof.selector);
        bridgeReject.finalizeBatch(NEW_ROOT, 0, _dummyProof());
    }

    // ==================================================================
    // 5. sha256ToPublicInputs
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
    // 6. Public input derivation (end-to-end with MockVerifierCheckInputs)
    // ==================================================================

    function testFinalizeBatch_PublicInputsMatchSha256() public {
        DepositsRollupBridge bridgeCheck = new DepositsRollupBridge(
            address(mockCheck), operator, GENESIS, BATCH_SIZE
        );

        // Deposit a full batch.
        for (uint256 i = 0; i < BATCH_SIZE; i++) {
            (bytes32 nc, uint256 val, address recip) = _makeDeposit(i);
            bridgeCheck.deposit(nc, val, recip);
        }

        // Compute expected SHA-256 commitment and public inputs.
        bytes memory cb = new bytes(BATCH_SIZE * 32);
        for (uint256 i = 0; i < BATCH_SIZE; i++) {
            DepositsRollupBridge.Deposit memory d = bridgeCheck.getDeposit(i);
            bytes32 c = d.commitment;
            assembly {
                mstore(add(add(cb, 32), mul(i, 32)), c)
            }
        }
        bytes32 sha256Commit = sha256(abi.encodePacked(GENESIS, NEW_ROOT, cb));
        uint256[8] memory expected = bridgeCheck.sha256ToPublicInputs(sha256Commit);
        mockCheck.setExpectedInputs(expected);

        // Will revert with INPUT_MISMATCH if inputs are wrong.
        bridgeCheck.finalizeBatch(NEW_ROOT, 0, _dummyProof());
    }

    // ==================================================================
    // 7. Atomicity — state unchanged on failed finalization
    // ==================================================================

    function testFinalizeBatch_StateUnchangedOnRevert() public {
        DepositsRollupBridge bridgeReject = new DepositsRollupBridge(
            address(mockReject), operator, GENESIS, BATCH_SIZE
        );

        for (uint256 i = 0; i < BATCH_SIZE; i++) {
            (bytes32 nc, uint256 val, address recip) = _makeDeposit(i);
            bridgeReject.deposit(nc, val, recip);
        }

        vm.expectRevert(DepositsRollupBridge.InvalidProof.selector);
        bridgeReject.finalizeBatch(NEW_ROOT, 0, _dummyProof());

        // State unchanged.
        assertEq(bridgeReject.merkleRoot(), GENESIS);

        // Deposits still pending.
        DepositsRollupBridge.Deposit memory d = bridgeReject.getDeposit(0);
        assertTrue(d.status == DepositsRollupBridge.DepositStatus.Pending);
    }

    // ==================================================================
    // 8. Multi-batch chained flow
    // ==================================================================

    /// @notice deposit 256 → finalize batch 0 → finalize batch 1
    function testTwoBatches_ChainedFlow() public {
        bytes32 root2 = bytes32(uint256(0xBBBB));

        // Deposit 256 items (two full batches).
        for (uint256 i = 0; i < BATCH_SIZE * 2; i++) {
            (bytes32 nc, uint256 val, address recip) = _makeDeposit(i);
            bridge.deposit(nc, val, recip);
        }

        // Batch 0.
        bridge.finalizeBatch(NEW_ROOT, 0, _dummyProof());
        assertEq(bridge.merkleRoot(), NEW_ROOT);

        // Batch 1 (merkleRoot = NEW_ROOT now).
        bridge.finalizeBatch(root2, BATCH_SIZE, _dummyProof());
        assertEq(bridge.merkleRoot(), root2);
    }

    /// @notice Batch IDs are sequential: 0, 1, 2, ...
    function testBatchId_Sequential() public {
        // Deposit 256 items.
        for (uint256 i = 0; i < BATCH_SIZE * 2; i++) {
            (bytes32 nc, uint256 val, address recip) = _makeDeposit(i);
            bridge.deposit(nc, val, recip);
        }

        vm.expectEmit(true, false, false, true);
        emit DepositsRollupBridge.BatchValidated(0, NEW_ROOT);
        bridge.finalizeBatch(NEW_ROOT, 0, _dummyProof());

        vm.expectEmit(true, false, false, true);
        emit DepositsRollupBridge.BatchValidated(1, bytes32(uint256(0xBBBB)));
        bridge.finalizeBatch(bytes32(uint256(0xBBBB)), BATCH_SIZE, _dummyProof());
    }

    // ==================================================================
    // 9. Admin functions
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

    function testSetOperator_RevertZeroAddress() public {
        vm.expectRevert(DepositsRollupBridge.ZeroAddress.selector);
        bridge.setOperator(address(0));
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
        _depositBatch();

        // Pause blocks finalize.
        bridge.setPaused(true);
        vm.expectRevert(DepositsRollupBridge.PausedErr.selector);
        bridge.finalizeBatch(NEW_ROOT, 0, _dummyProof());

        // Unpause allows finalize.
        bridge.setPaused(false);
        bridge.finalizeBatch(NEW_ROOT, 0, _dummyProof());
        assertEq(bridge.merkleRoot(), NEW_ROOT);
    }

    // ==================================================================
    // 10. View helpers
    // ==================================================================

    function testGetDeposit() public {
        (bytes32 nc, uint256 val, address recip) = _makeDeposit(0);
        bridge.deposit(nc, val, recip);

        DepositsRollupBridge.Deposit memory d = bridge.getDeposit(0);
        assertEq(d.value, val);
        assertEq(d.recipient, recip);
        assertTrue(d.status == DepositsRollupBridge.DepositStatus.Pending);
    }

    function testGetDeposit_AfterFinalization() public {
        _depositBatch();
        bridge.finalizeBatch(NEW_ROOT, 0, _dummyProof());

        DepositsRollupBridge.Deposit memory d = bridge.getDeposit(0);
        assertTrue(d.status == DepositsRollupBridge.DepositStatus.Validated);
    }
}
