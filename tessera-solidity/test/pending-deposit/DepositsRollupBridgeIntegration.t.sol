// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {DepositsRollupBridge, IGroth16Verifier} from "../../src/pending-deposit/DepositsRollupBridge.sol";
import {ToyUSDT} from "../../src/pending-deposit/ToyUSDT.sol";
import {ToyTrustedSource} from "../../src/pending-deposit/ToyTrustedSource.sol";

contract IntegrationMockVerifier is IGroth16Verifier {
    function verifyProof(uint256[8] calldata, uint256[2] calldata, uint256[2] calldata, uint256[8] calldata)
        external
        pure {}
}

contract DepositsRollupBridgeIntegrationTest is Test {
    function testIntegration_NewFlowPlaceholder() public {
        IntegrationMockVerifier verifier = new IntegrationMockVerifier();
        ToyUSDT token = new ToyUSDT();
        DepositsRollupBridge bridge = new DepositsRollupBridge(
            address(verifier), address(this), address(0xBEEF), bytes32(uint256(0x1111)), 2, address(token)
        );

        token.mint(address(bridge), 1e6);
        vm.prank(address(0xBEEF));
        bytes32 note = bytes32(uint256(1));
        bytes32 stored = bridge.recordDeposit(note);
        assertEq(stored, note);
    }

    function testIntegration_AtomicTransferAndRecord() public {
        IntegrationMockVerifier verifier = new IntegrationMockVerifier();
        ToyUSDT token = new ToyUSDT();

        address user = address(0xCAFE);
        uint256 amount = 25e6;
        bytes32 note = bytes32(uint256(77));

        // Deploy bridge first with placeholder trusted source; update after adapter deployment.
        DepositsRollupBridge bridge = new DepositsRollupBridge(
            address(verifier), address(this), address(0xBEEF), bytes32(uint256(0x1111)), 2, address(token)
        );

        ToyTrustedSource trusted = new ToyTrustedSource(address(bridge), address(token));
        bridge.setTrustedSource(address(trusted));

        token.mint(user, amount);
        vm.prank(user);
        token.approve(address(trusted), amount);

        vm.prank(user);
        bytes32 depositedNote = trusted.depositAndRecord(note, amount);

        DepositsRollupBridge.Deposit memory d = bridge.getDeposit(depositedNote);
        assertEq(d.value, amount);
        assertEq(d.recipient, address(trusted));
        assertEq(token.balanceOf(address(bridge)), amount);
    }
}
