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
        IntegrationMockVerifier commitmentVerifier = new IntegrationMockVerifier();
        IntegrationMockVerifier nullifierVerifier = new IntegrationMockVerifier();
        ToyUSDT token = new ToyUSDT();

        address user = address(0xCAFE);
        uint256 amount = 25e6;
        bytes32 note = bytes32(uint256(77));

        // Deploy bridge first with placeholder trusted source; update after adapter deployment.
        DepositsRollupBridge bridge = new DepositsRollupBridge(
            address(commitmentVerifier),
            address(nullifierVerifier),
            address(this),
            address(0xBEEF),
            bytes32(uint256(0x1111)),
            bytes32(uint256(0x2222)),
            2,
            address(token)
        );

        ToyUser userAdapter = new ToyUser(address(bridge), address(token));
        bridge.setTrustedSource(address(userAdapter));

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
