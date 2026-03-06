// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {DepositsRollupBridge, IGroth16Verifier} from "../../src/TesseraRollup.sol";
import {ToyUSDT} from "../../src/ToyUSDT.sol";
import {ToyUser} from "../../src/ToyUser.sol";

contract IntegrationMockVerifier is IGroth16Verifier {
    function verifyProof(uint256[8] calldata, uint256[2] calldata, uint256[2] calldata, uint256[8] calldata)
        external
        pure {}
}

contract DepositsRollupBridgeIntegrationTest is Test {
    function testIntegration_AtomicTransferAndRecord() public {
        IntegrationMockVerifier superAggVerifier = new IntegrationMockVerifier();
        ToyUSDT token = new ToyUSDT();

        address user = address(0xCAFE);
        uint256 amount = 25e6;
        bytes32 note = bytes32(uint256(77));

        // Deploy bridge. noteBatchSize=8, accountBatchSize=1 (8:1 ratio).
        DepositsRollupBridge bridge = new DepositsRollupBridge(
            address(superAggVerifier),
            address(this),
            bytes32(uint256(0x1111)),
            bytes32(uint256(0x2222)),
            bytes32(uint256(0x3333)),
            bytes32(uint256(0x4444)),
            8,  // noteBatchSize
            1,  // accountBatchSize
            address(token)
        );

        ToyUser userAdapter = new ToyUser(address(bridge), address(token));

        token.mint(user, amount);
        vm.prank(user);
        // Allowance must be granted to the bridge, since the bridge executes `transferFrom`.
        token.approve(address(bridge), amount);

        vm.prank(user);
        bytes32 depositedNote = userAdapter.depositAndRecord(note, amount);

        DepositsRollupBridge.Deposit memory d = bridge.getDeposit(depositedNote);
        assertEq(d.value, amount);
        assertEq(d.recipient, user);
        assertEq(token.balanceOf(address(bridge)), amount);
    }
}
