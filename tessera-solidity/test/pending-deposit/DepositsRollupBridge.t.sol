// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {DepositsRollupBridge, IGroth16Verifier} from "../../src/pending-deposit/DepositsRollupBridge.sol";

contract MockVerifier is IGroth16Verifier {
    function verifyProof(
        uint256[8] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[8] calldata
    ) external pure {}
}

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

contract DepositsRollupBridgeTest is Test {
    DepositsRollupBridge public bridge;

    MockVerifier public mockOk;
    MockVerifierReject public mockReject;
    MockVerifierCheckInputs public mockCheck;

    address public operator = address(this);
    address public trustedSource = address(0xBEEF);
    address public depositor = address(0xABCD);
    address public recipient = address(0x1234);

    bytes32 public constant GENESIS_CONSUMED_ROOT = bytes32(uint256(0x1111));
    bytes32 public constant NEW_CONSUMED_ROOT = bytes32(uint256(0x2222));
    uint256 public constant CONSUME_BATCH_SIZE = 2;

    function setUp() public {
        mockOk = new MockVerifier();
        mockReject = new MockVerifierReject();
        mockCheck = new MockVerifierCheckInputs();

        bridge = new DepositsRollupBridge(
            address(mockOk),
            operator,
            trustedSource,
            GENESIS_CONSUMED_ROOT,
            CONSUME_BATCH_SIZE
        );
    }

    function _dummyProof() internal pure returns (DepositsRollupBridge.Proof memory) {
        return DepositsRollupBridge.Proof({
            proof: [uint256(0),0,0,0,0,0,0,0],
            commitments: [uint256(0),0],
            commitmentPok: [uint256(0),0]
        });
    }

    function _record(
        bytes32 noteCommitment,
        uint256 value
    ) internal returns (uint256 id, bytes32 commitment) {
        commitment = bridge.computeCommitment(noteCommitment, value, recipient);
        vm.prank(trustedSource);
        id = bridge.recordDeposit(noteCommitment, value, depositor, recipient);
    }

    function testInitialState() public view {
        assertEq(bridge.operator(), operator);
        assertEq(bridge.trustedSource(), trustedSource);
        assertEq(bridge.consumedRoot(), GENESIS_CONSUMED_ROOT);
        assertEq(bridge.consumeBatchSize(), CONSUME_BATCH_SIZE);
        assertEq(bridge.nextDepositId(), 0);
        assertFalse(bridge.paused());
    }

    function testRequestConsume_HappyPath() public {
        (, bytes32 commitment) = _record(bytes32(uint256(1)), 1e6);
        bridge.requestConsume(commitment);
        assertTrue(bridge.consumeRequested(commitment));
    }

    function testRequestConsume_RevertCommitmentNotFound() public {
        bytes32 missing = bytes32(uint256(0xA5));
        vm.expectRevert(
            abi.encodeWithSelector(DepositsRollupBridge.CommitmentNotFound.selector, missing)
        );
        bridge.requestConsume(missing);
    }

    function testRequestConsume_RevertAlreadyRequested() public {
        (, bytes32 commitment) = _record(bytes32(uint256(1)), 1e6);
        bridge.requestConsume(commitment);
        vm.expectRevert(
            abi.encodeWithSelector(DepositsRollupBridge.ConsumeAlreadyRequested.selector, commitment)
        );
        bridge.requestConsume(commitment);
    }

    function testWithdraw_HappyPath() public {
        (uint256 id,) = _record(bytes32(uint256(1)), 1e6);
        vm.prank(depositor);
        bridge.withdraw(id);
        assertTrue(bridge.getDeposit(id).status == DepositsRollupBridge.DepositStatus.Withdrawn);
    }

    function testRequestConsume_RevertInvalidState_WhenWithdrawn() public {
        (uint256 id, bytes32 commitment) = _record(bytes32(uint256(1)), 1e6);
        vm.prank(depositor);
        bridge.withdraw(id);

        vm.expectRevert(
            abi.encodeWithSelector(DepositsRollupBridge.InvalidDepositState.selector, id)
        );
        bridge.requestConsume(commitment);
    }

    function testFinalizeConsumeBatch_HappyPath_AnyOrder() public {
        (uint256 id0, bytes32 c0) = _record(bytes32(uint256(1)), 1e6);
        (uint256 id1, bytes32 c1) = _record(bytes32(uint256(2)), 2e6);

        bridge.requestConsume(c0);
        bridge.requestConsume(c1);

        // Reverse order to prove arbitrary ordering support.
        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = c1;
        commitments[1] = c0;

        bridge.finalizeConsumeBatch(NEW_CONSUMED_ROOT, commitments, _dummyProof());

        assertTrue(bridge.getDeposit(id0).status == DepositsRollupBridge.DepositStatus.Consumed);
        assertTrue(bridge.getDeposit(id1).status == DepositsRollupBridge.DepositStatus.Consumed);
        assertFalse(bridge.consumeRequested(c0));
        assertFalse(bridge.consumeRequested(c1));
        assertEq(bridge.consumedRoot(), NEW_CONSUMED_ROOT);
    }

    function testFinalizeConsumeBatch_RevertInvalidLength() public {
        (, bytes32 c0) = _record(bytes32(uint256(1)), 1e6);
        bridge.requestConsume(c0);

        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = c0;

        vm.expectRevert(
            abi.encodeWithSelector(
                DepositsRollupBridge.InvalidConsumeBatchLength.selector,
                1,
                CONSUME_BATCH_SIZE
            )
        );
        bridge.finalizeConsumeBatch(NEW_CONSUMED_ROOT, commitments, _dummyProof());
    }

    function testFinalizeConsumeBatch_RevertNotOperator() public {
        (, bytes32 c0) = _record(bytes32(uint256(1)), 1e6);
        (, bytes32 c1) = _record(bytes32(uint256(2)), 2e6);
        bridge.requestConsume(c0);
        bridge.requestConsume(c1);

        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = c0;
        commitments[1] = c1;

        vm.prank(address(0xD00D));
        vm.expectRevert(DepositsRollupBridge.NotOperator.selector);
        bridge.finalizeConsumeBatch(NEW_CONSUMED_ROOT, commitments, _dummyProof());
    }

    function testFinalizeConsumeBatch_RevertCommitmentNotRequested() public {
        (, bytes32 c0) = _record(bytes32(uint256(1)), 1e6);
        (, bytes32 c1) = _record(bytes32(uint256(2)), 2e6);
        bridge.requestConsume(c0);

        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = c0;
        commitments[1] = c1;

        vm.expectRevert(
            abi.encodeWithSelector(DepositsRollupBridge.CommitmentNotRequested.selector, c1)
        );
        bridge.finalizeConsumeBatch(NEW_CONSUMED_ROOT, commitments, _dummyProof());
    }

    function testFinalizeConsumeBatch_RevertInvalidProof() public {
        DepositsRollupBridge bridgeReject = new DepositsRollupBridge(
            address(mockReject),
            operator,
            trustedSource,
            GENESIS_CONSUMED_ROOT,
            CONSUME_BATCH_SIZE
        );

        bytes32 c0 = bridgeReject.computeCommitment(bytes32(uint256(1)), 1e6, recipient);
        bytes32 c1 = bridgeReject.computeCommitment(bytes32(uint256(2)), 2e6, recipient);
        vm.prank(trustedSource);
        bridgeReject.recordDeposit(bytes32(uint256(1)), 1e6, depositor, recipient);
        vm.prank(trustedSource);
        bridgeReject.recordDeposit(bytes32(uint256(2)), 2e6, depositor, recipient);

        bridgeReject.requestConsume(c0);
        bridgeReject.requestConsume(c1);

        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = c0;
        commitments[1] = c1;

        vm.expectRevert(DepositsRollupBridge.InvalidProof.selector);
        bridgeReject.finalizeConsumeBatch(NEW_CONSUMED_ROOT, commitments, _dummyProof());
    }

    function testFinalizeConsumeBatch_PublicInputsMatchSha256() public {
        DepositsRollupBridge bridgeCheck = new DepositsRollupBridge(
            address(mockCheck),
            operator,
            trustedSource,
            GENESIS_CONSUMED_ROOT,
            CONSUME_BATCH_SIZE
        );

        bytes32 c0 = bridgeCheck.computeCommitment(bytes32(uint256(1)), 1e6, recipient);
        bytes32 c1 = bridgeCheck.computeCommitment(bytes32(uint256(2)), 2e6, recipient);

        vm.prank(trustedSource);
        bridgeCheck.recordDeposit(bytes32(uint256(1)), 1e6, depositor, recipient);
        vm.prank(trustedSource);
        bridgeCheck.recordDeposit(bytes32(uint256(2)), 2e6, depositor, recipient);

        bridgeCheck.requestConsume(c0);
        bridgeCheck.requestConsume(c1);

        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = c1;
        commitments[1] = c0;

        bytes memory commitmentBytes = new bytes(64);
        assembly {
            mstore(add(commitmentBytes, 32), c1)
            mstore(add(commitmentBytes, 64), c0)
        }
        bytes32 sha256Commit = sha256(abi.encodePacked(GENESIS_CONSUMED_ROOT, NEW_CONSUMED_ROOT, commitmentBytes));
        uint256[8] memory expected = bridgeCheck.sha256ToPublicInputs(sha256Commit);
        mockCheck.setExpectedInputs(expected);

        bridgeCheck.finalizeConsumeBatch(NEW_CONSUMED_ROOT, commitments, _dummyProof());
    }
}
