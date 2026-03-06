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

    bytes32 public constant GENESIS_NULLIFIER_ROOT = bytes32(uint256(0x1111));
    bytes32 public constant GENESIS_COMMITMENT_ROOT = bytes32(uint256(0x2222));
    uint256 public constant NOTE_BATCH_SIZE    = 8;
    uint256 public constant ACCOUNT_BATCH_SIZE = 1;

    function setUp() public {
        MockVerifierOk verifier = new MockVerifierOk();
        token = new ToyUSDT();

        bridge = new DepositsRollupBridge(
            address(verifier),  // superAggregatorVerifier
            operator,
            GENESIS_NULLIFIER_ROOT,
            GENESIS_COMMITMENT_ROOT,
            bytes32(uint256(0x3333)),
            bytes32(uint256(0x4444)),
            NOTE_BATCH_SIZE,
            ACCOUNT_BATCH_SIZE,
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

        bytes32[] memory dummy = new bytes32[](1);
        dummy[0] = bytes32(uint256(1));

        bridge.registerTransactionBatchUpdate(
            bytes32(uint256(0x9999)), notes,
            bytes32(uint256(0x8888)), dummy,
            bytes32(uint256(0x7777)), dummy,
            bytes32(uint256(0x6666)), dummy
        );

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

        bytes32[] memory dummy = new bytes32[](1);
        dummy[0] = bytes32(uint256(1));

        bridge.registerTransactionBatchUpdate(
            bytes32(uint256(0x9999)), notes,
            bytes32(uint256(0x8888)), dummy,
            bytes32(uint256(0x7777)), dummy,
            bytes32(uint256(0x6666)), dummy
        );

        assertEq(uint256(bridge.getDepositStatus(tracked)), uint256(DepositsRollupBridge.DepositStatus.Validated));
        assertEq(uint256(bridge.getDepositStatus(externalNote)), uint256(DepositsRollupBridge.DepositStatus.None));
    }

    function testValidateDepositBatch_AllowsPartialBatchAndUpdatesOnlyRealNotes() public {
        address user = address(0xCAFE);
        uint256 amount = 1e6;
        bytes32 tracked = bytes32(uint256(1));

        token.mint(user, amount);
        vm.prank(user);
        token.approve(address(bridge), amount);
        vm.prank(user);
        bridge.depositAndRegister(tracked, amount);

        bytes32[] memory notes = new bytes32[](1);
        notes[0] = tracked;

        bytes32[] memory dummy = new bytes32[](1);
        dummy[0] = bytes32(uint256(1));

        uint256 beforeLeafCount = bridge.notesCommitmentLeafCount();
        bridge.registerTransactionBatchUpdate(
            bytes32(uint256(0x9999)), notes,
            bytes32(uint256(0x8888)), dummy,
            bytes32(uint256(0x7777)), dummy,
            bytes32(uint256(0x6666)), dummy
        );

        assertEq(uint256(bridge.getDepositStatus(tracked)), uint256(DepositsRollupBridge.DepositStatus.Validated));
        assertEq(bridge.notesCommitmentLeafCount(), beforeLeafCount + NOTE_BATCH_SIZE);
    }

}
