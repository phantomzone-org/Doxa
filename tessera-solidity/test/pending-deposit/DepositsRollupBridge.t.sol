// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {DepositsRollupBridge, IGroth16Verifier} from "../../src/TesseraRollup.sol";
import {ToyUSDT} from "../../src/ToyUSDT.sol";

contract MockVerifierOk is IGroth16Verifier {
    function verifyProof(uint256[8] calldata, uint256[2] calldata, uint256[2] calldata, uint256[8] calldata)
        external
        pure
    {}
}

contract DepositsRollupBridgeTest is Test {
    DepositsRollupBridge public bridge;
    ToyUSDT public token;

    address public operator = address(this);
    address public trustedSource = address(0xBEEF);

    bytes32 public constant GENESIS_NULLIFIER_ROOT = bytes32(uint256(0x1111));
    bytes32 public constant GENESIS_COMMITMENT_ROOT = bytes32(uint256(0x2222));
    uint256 public constant BATCH_SIZE = 2;

    function setUp() public {
        MockVerifierOk commitmentVerifier = new MockVerifierOk();
        MockVerifierOk nullifierVerifier = new MockVerifierOk();
        token = new ToyUSDT();

        bridge = new DepositsRollupBridge(
            address(commitmentVerifier),
            address(nullifierVerifier),
            operator,
            trustedSource,
            GENESIS_NULLIFIER_ROOT,
            GENESIS_COMMITMENT_ROOT,
            bytes32(uint256(0x3333)),
            bytes32(uint256(0x4444)),
            BATCH_SIZE,
            address(token)
        );
    }

    function _dummyProof() internal pure returns (DepositsRollupBridge.Proof memory) {
        return DepositsRollupBridge.Proof({
            proof: [uint256(0), 0, 0, 0, 0, 0, 0, 0],
            commitments: [uint256(0), 0],
            commitmentPok: [uint256(0), 0]
        });
    }

    function _dummyAggregatedInputProof() internal pure returns (DepositsRollupBridge.AggregatedInputProof memory) {
        return DepositsRollupBridge.AggregatedInputProof({proofData: hex"01"});
    }

    function testDepositAndRegister_Direct() public {
        address user = address(0xCAFE);
        uint256 amount = 25e6;
        bytes32 note = bytes32(uint256(77));

        token.mint(user, amount);
        vm.prank(user);
        token.approve(address(bridge), amount);

        vm.prank(user);
        bytes32 stored = bridge.depositAndRegister(note, amount);

        DepositsRollupBridge.Deposit memory d = bridge.getDeposit(stored);
        assertEq(d.value, amount);
        assertEq(d.recipient, user);
        assertEq(uint256(d.status), uint256(DepositsRollupBridge.DepositStatus.Pending));
        assertEq(token.balanceOf(address(bridge)), amount);
    }

    function testWithdrawPendingDeposit_HappyPath() public {
        address user = address(0xCAFE);
        uint256 amount = 25e6;
        bytes32 note = bytes32(uint256(77));

        token.mint(user, amount);
        vm.prank(user);
        token.approve(address(bridge), amount);

        vm.prank(user);
        bridge.depositAndRegister(note, amount);

        vm.prank(user);
        bridge.withdrawPendingDeposit(note);

        DepositsRollupBridge.Deposit memory d = bridge.getDeposit(note);
        assertEq(uint256(d.status), uint256(DepositsRollupBridge.DepositStatus.Withdrawn));
        assertEq(token.balanceOf(user), amount);
        assertEq(token.balanceOf(address(bridge)), 0);
    }

    function testValidateDepositBatch_MovesPendingToValidated() public {
        address user = address(0xCAFE);
        uint256 amount0 = 1e6;
        uint256 amount1 = 2e6;
        bytes32 n0 = bytes32(uint256(1));
        bytes32 n1 = bytes32(uint256(2));

        token.mint(user, amount0 + amount1);
        vm.prank(user);
        token.approve(address(bridge), amount0 + amount1);
        vm.startPrank(user);
        bridge.depositAndRegister(n0, amount0);
        bridge.depositAndRegister(n1, amount1);
        vm.stopPrank();

        bytes32[] memory notes = new bytes32[](2);
        notes[0] = n0;
        notes[1] = n1;

        bridge.validateDepositBatch(bytes32(uint256(0x9999)), notes, _dummyProof(), _dummyAggregatedInputProof());

        assertEq(uint256(bridge.getDepositStatus(n0)), uint256(DepositsRollupBridge.DepositStatus.Validated));
        assertEq(uint256(bridge.getDepositStatus(n1)), uint256(DepositsRollupBridge.DepositStatus.Validated));
    }

    function testLoadAndExecuteValidateDepositBatch_MovesPendingToValidated() public {
        address user = address(0xCAFE);
        uint256 amount0 = 1e6;
        uint256 amount1 = 2e6;
        bytes32 n0 = bytes32(uint256(1));
        bytes32 n1 = bytes32(uint256(2));

        token.mint(user, amount0 + amount1);
        vm.prank(user);
        token.approve(address(bridge), amount0 + amount1);
        vm.startPrank(user);
        bridge.depositAndRegister(n0, amount0);
        bridge.depositAndRegister(n1, amount1);
        vm.stopPrank();

        bytes32[] memory notes = new bytes32[](2);
        notes[0] = n0;
        notes[1] = n1;

        // Load does not change state.
        bridge.loadValidateDepositBatch(bytes32(uint256(0x9999)), notes, _dummyProof(), _dummyAggregatedInputProof());
        assertEq(uint256(bridge.getDepositStatus(n0)), uint256(DepositsRollupBridge.DepositStatus.Pending));
        assertEq(uint256(bridge.getDepositStatus(n1)), uint256(DepositsRollupBridge.DepositStatus.Pending));

        // Execute is permissionless (call from arbitrary address).
        vm.prank(address(0x1234));
        bridge.executeValidateDepositBatch(bytes32(uint256(0x9999)), notes);

        assertEq(uint256(bridge.getDepositStatus(n0)), uint256(DepositsRollupBridge.DepositStatus.Validated));
        assertEq(uint256(bridge.getDepositStatus(n1)), uint256(DepositsRollupBridge.DepositStatus.Validated));
    }

    function testValidateDepositBatch_AllowsExternalNotes() public {
        address user = address(0xCAFE);
        uint256 amount = 1e6;
        bytes32 tracked = bytes32(uint256(1));
        bytes32 externalNote = bytes32(uint256(999));

        token.mint(user, amount);
        vm.prank(user);
        token.approve(address(bridge), amount);
        vm.prank(user);
        bridge.depositAndRegister(tracked, amount);

        bytes32[] memory notes = new bytes32[](2);
        notes[0] = tracked;
        notes[1] = externalNote;

        bridge.validateDepositBatch(bytes32(uint256(0x9999)), notes, _dummyProof(), _dummyAggregatedInputProof());

        assertEq(uint256(bridge.getDepositStatus(tracked)), uint256(DepositsRollupBridge.DepositStatus.Validated));
        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.NoteNotFound.selector, externalNote));
        bridge.getDepositStatus(externalNote);
    }

    function testLoadAndExecuteValidateDepositBatch_AllowsExternalNotes() public {
        address user = address(0xCAFE);
        uint256 amount = 1e6;
        bytes32 tracked = bytes32(uint256(1));
        bytes32 externalNote = bytes32(uint256(999));

        token.mint(user, amount);
        vm.prank(user);
        token.approve(address(bridge), amount);
        vm.prank(user);
        bridge.depositAndRegister(tracked, amount);

        bytes32[] memory notes = new bytes32[](2);
        notes[0] = tracked;
        notes[1] = externalNote;

        bridge.loadValidateDepositBatch(bytes32(uint256(0x9999)), notes, _dummyProof(), _dummyAggregatedInputProof());

        vm.prank(address(0x1234));
        bridge.executeValidateDepositBatch(bytes32(uint256(0x9999)), notes);

        assertEq(uint256(bridge.getDepositStatus(tracked)), uint256(DepositsRollupBridge.DepositStatus.Validated));
        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.NoteNotFound.selector, externalNote));
        bridge.getDepositStatus(externalNote);
    }

    function testExecuteValidateDepositBatch_WithoutLoadReverts() public {
        bytes32[] memory notes = new bytes32[](2);
        notes[0] = bytes32(uint256(1));
        notes[1] = bytes32(uint256(2));

        bytes32 domainSep = bridge.DOMAIN_SEP();
        bytes32 notesHash = keccak256(abi.encodePacked(notes));
        bytes32 actionHash = keccak256(abi.encodePacked(domainSep, bytes1(0xD1), bytes32(uint256(0x9999)), notesHash));

        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.LoadedBatchNotFound.selector, actionHash));
        bridge.executeValidateDepositBatch(bytes32(uint256(0x9999)), notes);
    }

    function testExecuteValidateDepositBatch_AfterWithdrawalRevertsAndCanCancel() public {
        address user = address(0xCAFE);
        uint256 amount0 = 1e6;
        uint256 amount1 = 2e6;
        bytes32 n0 = bytes32(uint256(1));
        bytes32 n1 = bytes32(uint256(2));

        token.mint(user, amount0 + amount1);
        vm.prank(user);
        token.approve(address(bridge), amount0 + amount1);
        vm.startPrank(user);
        bridge.depositAndRegister(n0, amount0);
        bridge.depositAndRegister(n1, amount1);
        vm.stopPrank();

        bytes32[] memory notes = new bytes32[](2);
        notes[0] = n0;
        notes[1] = n1;

        bytes32 oldRoot = bridge.notesCommitmentRoot();
        bridge.loadValidateDepositBatch(bytes32(uint256(0x9999)), notes, _dummyProof(), _dummyAggregatedInputProof());

        // User withdraws one note after load, making execution invalid.
        vm.prank(user);
        bridge.withdrawPendingDeposit(n0);

        vm.expectRevert(abi.encodeWithSelector(DepositsRollupBridge.InvalidDepositState.selector, n0));
        bridge.executeValidateDepositBatch(bytes32(uint256(0x9999)), notes);

        // Operator can cancel the loaded batch.
        bridge.cancelLoadedValidateDepositBatch(oldRoot, bytes32(uint256(0x9999)), notes);
    }
}
