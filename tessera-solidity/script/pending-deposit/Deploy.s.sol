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
///   TESSERA_GENESIS_ROOT  -- bytes32 genesis Merkle root (from `genesis_root` example)
///
/// Usage (local anvil):
///   # Terminal 1: start anvil
///   anvil
///
///   # Terminal 2: compute genesis root
///   export TESSERA_GENESIS_ROOT=$(cargo run -p tessera-server --example genesis_root --release)
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
        string memory artifactsPath = "../tessera-server/artifacts/pending-deposit/groth-artifacts/Verifier.sol";
        string memory localPath = "src/pending-deposit/Verifier.sol";
        bytes memory artifactsSrc = bytes(vm.readFile(artifactsPath));
        bytes memory localSrc = bytes(vm.readFile(localPath));
        if (keccak256(artifactsSrc) != keccak256(localSrc)) {
            revert("Verifier mismatch: update src/pending-deposit/Verifier.sol from groth-artifacts/Verifier.sol");
        }

        bytes32 genesisRoot = vm.envBytes32("TESSERA_GENESIS_ROOT");

        vm.startBroadcast();

        Verifier verifier = new Verifier();
        DepositsRollupBridge bridge = new DepositsRollupBridge(
            address(verifier),
            msg.sender,
            genesisRoot,
            128
        );

        vm.stopBroadcast();

        console.log("Verifier deployed at:", address(verifier));
        console.log("Bridge deployed at:  ", address(bridge));
        console.log("Operator:            ", msg.sender);
        console.logBytes32(genesisRoot);
    }
}
