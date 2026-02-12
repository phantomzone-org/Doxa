// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {DepositsRollupBridge} from "../../src/pending-deposit/DepositsRollupBridge.sol";
import {Verifier} from "../../src/pending-deposit/Verifier.sol";

/// @title  Deploy Verifier + DepositsRollupBridge
/// @notice Deploys both contracts to the target chain. The deployer
///         (`msg.sender`) is set as the initial operator.
///
/// Required environment variables:
///   TESSERA_TRUSTED_SOURCE -- address allowed to record deposits
///   TESSERA_CONSUMED_GENERIS_ROOT  -- bytes32 consumed/nullifier tree genesis root
///   TESSERA_CONSUME_BATCH_SIZE -- number of consume requests per batch
///
/// Usage (local anvil):
///   # Terminal 1: start anvil
///   anvil
///
///   # Terminal 2: set consume tree genesis root + trusted source
///   export TESSERA_CONSUMED_GENERIS_ROOT=0x1ef897f4a5c3f5c07cddaf7dec41197f2259296bb1bb56264ca73c3e1b998bf9
///   export TESSERA_TRUSTED_SOURCE=0xYourTrustedSource
///   export TESSERA_CONSUME_BATCH_SIZE=128
///
///   # Terminal 3: deploy
///   cd tessera-solidity
///   forge script script/Deploy.s.sol --rpc-url http://localhost:8545 \
///     --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
///     --broadcast
contract DeployScript is Script {
    function run() public {
        // Sanity check: ensure the deployed verifier matches the Groth16 artifacts.
        // This prevents on-chain verification failures due to mismatched verifier code.
        string memory artifactsPath = "../tessera-server/artifacts/used-deposit/groth-artifacts/Verifier.sol";
        string memory localPath = "src/pending-deposit/Verifier.sol";
        bytes memory artifactsSrc = bytes(vm.readFile(artifactsPath));
        bytes memory localSrc = bytes(vm.readFile(localPath));
        if (keccak256(artifactsSrc) != keccak256(localSrc)) {
            revert("Verifier mismatch: update src/pending-deposit/Verifier.sol from artifacts/used-deposit/groth-artifacts/Verifier.sol");
        }

        address trustedSource = vm.envAddress("TESSERA_TRUSTED_SOURCE");
        bytes32 consumedRoot = vm.envBytes32("TESSERA_CONSUMED_GENERIS_ROOT");
        uint256 consumeBatchSize = vm.envUint("TESSERA_CONSUME_BATCH_SIZE");

        vm.startBroadcast();

        Verifier verifier = new Verifier();
        DepositsRollupBridge bridge = new DepositsRollupBridge(
            address(verifier),
            msg.sender,
            trustedSource,
            consumedRoot,
            consumeBatchSize
        );

        vm.stopBroadcast();

        console.log("Verifier deployed at:", address(verifier));
        console.log("Bridge deployed at:  ", address(bridge));
        console.log("Operator:            ", msg.sender);
        console.log("Trusted source:      ", trustedSource);
        console.log("Consume batch size:  ", consumeBatchSize);
        console.logBytes32(consumedRoot);
    }
}
