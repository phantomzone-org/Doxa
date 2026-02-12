// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {DepositsRollupBridge, IGroth16Verifier} from "../../src/pending-deposit/DepositsRollupBridge.sol";

contract IntegrationMockVerifier is IGroth16Verifier {
    function verifyProof(
        uint256[8] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[8] calldata
    ) external pure {}
}

contract DepositsRollupBridgeIntegrationTest is Test {
    function testIntegration_NewFlowPlaceholder() public {
        IntegrationMockVerifier verifier = new IntegrationMockVerifier();
        DepositsRollupBridge bridge = new DepositsRollupBridge(
            address(verifier),
            address(this),
            address(0xBEEF),
            bytes32(uint256(0x1111)),
            2
        );

        vm.prank(address(0xBEEF));
        uint256 id = bridge.recordDeposit(bytes32(uint256(1)), 1e6, address(0xABCD), address(0x1234));
        assertEq(id, 0);
    }
}
