// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {DepositsRollupBridge, IGroth16Verifier} from "../../src/pending-deposit/DepositsRollupBridge.sol";
import {ToyUSDT} from "../../src/pending-deposit/ToyUSDT.sol";

contract MockVerifier is IGroth16Verifier {
    function verifyProof(uint256[8] calldata, uint256[2] calldata, uint256[2] calldata, uint256[8] calldata)
        external
        pure {}
}

contract MockVerifierReject is IGroth16Verifier {
    function verifyProof(uint256[8] calldata, uint256[2] calldata, uint256[2] calldata, uint256[8] calldata)
        external
        pure
    {
        revert("MOCK_REJECT");
    }
}

contract MockVerifierCheckInputs is IGroth16Verifier {
    uint256[8] public expectedInputs;

    function setExpectedInputs(uint256[8] memory inputs) external {
        expectedInputs = inputs;
    }

    function verifyProof(uint256[8] calldata, uint256[2] calldata, uint256[2] calldata, uint256[8] calldata input)
        external
        view
    {
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
    ToyUSDT public token;

    address public operator = address(this);
    address public trustedSource = address(0xBEEF);

    bytes32 public constant GENESIS_CONSUMED_ROOT = bytes32(uint256(0x1111));
    bytes32 public constant NEW_CONSUMED_ROOT = bytes32(uint256(0x2222));
    uint256 public constant CONSUME_BATCH_SIZE = 2;

    function setUp() public {
        mockOk = new MockVerifier();
        mockReject = new MockVerifierReject();
        mockCheck = new MockVerifierCheckInputs();
        token = new ToyUSDT();

        bridge = new DepositsRollupBridge(
            address(mockOk), operator, trustedSource, GENESIS_CONSUMED_ROOT, CONSUME_BATCH_SIZE, address(token)
        );
    }

    function _dummyProof() internal pure returns (DepositsRollupBridge.Proof memory) {
        return DepositsRollupBridge.Proof({
            proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0], commitments: [uint256(0), 0], commitmentPok: [uint256(0), 0]
        });
    }

    function _record(bytes32 noteCommitment, uint256 value) internal returns (bytes32 note) {
        token.mint(address(bridge), value);
        vm.prank(trustedSource);
        note = bridge.recordDeposit(noteCommitment);
    }

    function testInitialState() public view {
        assertEq(bridge.operator(), operator);
        assertEq(bridge.trustedSource(), trustedSource);
        assertEq(bridge.consumedRoot(), GENESIS_CONSUMED_ROOT);
        assertEq(bridge.consumeBatchSize(), CONSUME_BATCH_SIZE);
        assertFalse(bridge.paused());
    }

    function testRecordDeposit_RevertNoTokenIncrease() public {
        vm.prank(trustedSource);
        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.NoTokenIncrease.selector, 0, 0));
        bridge.recordDeposit(bytes32(uint256(1)));
    }

    function testGetDeposit_RevertNoteNotFound() public {
        bytes32 missing = bytes32(uint256(0xA5));
        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.NoteNotFound.selector, missing));
        bridge.getDeposit(missing);
    }

    function testFinalizeConsumeBatch_HappyPath_AnyOrder() public {
        bytes32 n0 = _record(bytes32(uint256(1)), 1e6);
        bytes32 n1 = _record(bytes32(uint256(2)), 2e6);

        // Reverse order to prove arbitrary ordering support.
        bytes32[] memory notes = new bytes32[](2);
        notes[0] = n1;
        notes[1] = n0;

        bridge.finalizeConsumeBatch(NEW_CONSUMED_ROOT, notes, _dummyProof());

        assertTrue(bridge.getDeposit(n0).status == DepositsRollupBridge.DepositStatus.Consumed);
        assertTrue(bridge.getDeposit(n1).status == DepositsRollupBridge.DepositStatus.Consumed);
        assertEq(bridge.consumedRoot(), NEW_CONSUMED_ROOT);
    }

    function testFinalizeConsumeBatch_RevertInvalidLength() public {
        bytes32 n0 = _record(bytes32(uint256(1)), 1e6);

        bytes32[] memory notes = new bytes32[](1);
        notes[0] = n0;

        vm.expectRevert(
            abi.encodeWithSelector(DepositsRollupBridge.InvalidConsumeBatchLength.selector, 1, CONSUME_BATCH_SIZE)
        );
        bridge.finalizeConsumeBatch(NEW_CONSUMED_ROOT, notes, _dummyProof());
    }

    function testFinalizeConsumeBatch_RevertNotOperator() public {
        bytes32 n0 = _record(bytes32(uint256(1)), 1e6);
        bytes32 n1 = _record(bytes32(uint256(2)), 2e6);

        bytes32[] memory notes = new bytes32[](2);
        notes[0] = n0;
        notes[1] = n1;

        vm.prank(address(0xD00D));
        vm.expectRevert(DepositsRollupBridge.NotOperator.selector);
        bridge.finalizeConsumeBatch(NEW_CONSUMED_ROOT, notes, _dummyProof());
    }

    function testFinalizeConsumeBatch_RevertNoteNotFound() public {
        bytes32 n0 = _record(bytes32(uint256(1)), 1e6);
        bytes32 missing = bytes32(uint256(0xBEEF));

        bytes32[] memory notes = new bytes32[](2);
        notes[0] = n0;
        notes[1] = missing;

        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.NoteNotFound.selector, missing));
        bridge.finalizeConsumeBatch(NEW_CONSUMED_ROOT, notes, _dummyProof());
    }

    function testFinalizeConsumeBatch_RevertInvalidState_WhenAlreadyConsumed() public {
        bytes32 n0 = _record(bytes32(uint256(1)), 1e6);
        bytes32 n1 = _record(bytes32(uint256(2)), 2e6);

        bytes32[] memory notes = new bytes32[](2);
        notes[0] = n0;
        notes[1] = n1;
        bridge.finalizeConsumeBatch(NEW_CONSUMED_ROOT, notes, _dummyProof());

        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.InvalidDepositState.selector, n0));
        bridge.finalizeConsumeBatch(bytes32(uint256(0x3333)), notes, _dummyProof());
    }

    function testFinalizeConsumeBatch_RevertInvalidProof() public {
        DepositsRollupBridge bridgeReject = new DepositsRollupBridge(
            address(mockReject), operator, trustedSource, GENESIS_CONSUMED_ROOT, CONSUME_BATCH_SIZE, address(token)
        );

        bytes32 n0 = bytes32(uint256(1));
        bytes32 n1 = bytes32(uint256(2));
        token.mint(address(bridgeReject), 1e6);
        vm.prank(trustedSource);
        bridgeReject.recordDeposit(n0);
        token.mint(address(bridgeReject), 2e6);
        vm.prank(trustedSource);
        bridgeReject.recordDeposit(n1);

        bytes32[] memory notes = new bytes32[](2);
        notes[0] = n0;
        notes[1] = n1;

        vm.expectRevert(DepositsRollupBridge.InvalidProof.selector);
        bridgeReject.finalizeConsumeBatch(NEW_CONSUMED_ROOT, notes, _dummyProof());
    }

    function testFinalizeConsumeBatch_PublicInputsMatchSha256() public {
        DepositsRollupBridge bridgeCheck = new DepositsRollupBridge(
            address(mockCheck), operator, trustedSource, GENESIS_CONSUMED_ROOT, CONSUME_BATCH_SIZE, address(token)
        );

        bytes32 n0 = bytes32(uint256(1));
        bytes32 n1 = bytes32(uint256(2));

        token.mint(address(bridgeCheck), 1e6);
        vm.prank(trustedSource);
        bridgeCheck.recordDeposit(n0);
        token.mint(address(bridgeCheck), 2e6);
        vm.prank(trustedSource);
        bridgeCheck.recordDeposit(n1);

        bytes32[] memory notes = new bytes32[](2);
        notes[0] = n1;
        notes[1] = n0;

        bytes memory noteBytes = new bytes(64);
        assembly {
            mstore(add(noteBytes, 32), n1)
            mstore(add(noteBytes, 64), n0)
        }
        bytes32 sha256Commit = sha256(abi.encodePacked(GENESIS_CONSUMED_ROOT, NEW_CONSUMED_ROOT, noteBytes));
        uint256[8] memory expected = bridgeCheck.sha256ToPublicInputs(sha256Commit);
        mockCheck.setExpectedInputs(expected);

        bridgeCheck.finalizeConsumeBatch(NEW_CONSUMED_ROOT, notes, _dummyProof());
    }
}
