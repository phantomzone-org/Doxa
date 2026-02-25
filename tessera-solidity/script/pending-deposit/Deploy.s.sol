// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {DepositsRollupBridge} from "../../src/TesseraRollup.sol";
import {Verifier as SuperAggregatorVerifier} from "../../src/VerifierSuperAggregator.sol";

/// @title  Deploy VerifierSuperAggregator + DepositsRollupBridge
/// @notice Deploys both contracts to the target chain. The deployer
///         (`msg.sender`) is set as the initial operator.
///
/// Required environment variables:
///   TESSERA_NOTES_NULLIFIER_ROOT  -- bytes32 nullifier tree genesis root
///   TESSERA_NOTES_COMMITMENT_ROOT -- bytes32 commitment tree genesis root
///   TESSERA_ACCOUNTS_NULLIFIER_ROOT  -- bytes32 accounts nullifier tree genesis root
///   TESSERA_ACCOUNTS_COMMITMENT_ROOT -- bytes32 accounts commitment tree genesis root
///   TESSERA_NOTE_BATCH_SIZE    -- note-tree batch size (must be power of two, = account size × 8)
///   TESSERA_ACCOUNT_BATCH_SIZE -- account-tree batch size (must be power of two, = note size / 8)
///   TESSERA_MONITORED_TOKEN -- ERC20 address escrowed by the bridge
///
/// Usage (local anvil):
///   # Terminal 1: start anvil
///   anvil
///
///   # Terminal 2: set roots
///   export TESSERA_NOTES_NULLIFIER_ROOT=0x5d85139746d173c92bf3543b4c6ce3daf11bdff30e5b44879d216bc5f06256b6
///   export TESSERA_NOTES_COMMITMENT_ROOT=0x5d85139746d173c92bf3543b4c6ce3daf11bdff30e5b44879d216bc5f06256b6
///   export TESSERA_NOTE_BATCH_SIZE=128
///   export TESSERA_ACCOUNT_BATCH_SIZE=16
///   export TESSERA_MONITORED_TOKEN=0xYourToken
///
///   # Terminal 3: deploy
///   cd tessera-solidity
///   forge script script/Deploy.s.sol --rpc-url http://localhost:8545 \
///     --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
///     --broadcast
contract DeployScript is Script {
    function run() public {
        bytes32 notesNullifierRoot = vm.envBytes32("TESSERA_NOTES_NULLIFIER_ROOT");
        bytes32 notesCommitmentRoot = vm.envBytes32("TESSERA_NOTES_COMMITMENT_ROOT");
        bytes32 accountsNullifierRoot = vm.envBytes32("TESSERA_ACCOUNTS_NULLIFIER_ROOT");
        bytes32 accountsCommitmentRoot = vm.envBytes32("TESSERA_ACCOUNTS_COMMITMENT_ROOT");
        uint256 noteBatchSize = vm.envUint("TESSERA_NOTE_BATCH_SIZE");
        uint256 accountBatchSize = vm.envUint("TESSERA_ACCOUNT_BATCH_SIZE");
        address monitoredToken = vm.envAddress("TESSERA_MONITORED_TOKEN");

        vm.startBroadcast();

        SuperAggregatorVerifier superAggregatorVerifier = new SuperAggregatorVerifier();
        DepositsRollupBridge bridge = new DepositsRollupBridge(
            address(superAggregatorVerifier),
            msg.sender,
            notesNullifierRoot,
            notesCommitmentRoot,
            accountsNullifierRoot,
            accountsCommitmentRoot,
            noteBatchSize,
            accountBatchSize,
            monitoredToken
        );

        vm.stopBroadcast();

        console.log("Super-aggregator verifier:", address(superAggregatorVerifier));
        console.log("Bridge deployed at:       ", address(bridge));
        console.log("Operator:                 ", msg.sender);
        console.log("Note batch size:          ", noteBatchSize);
        console.log("Account batch size:       ", accountBatchSize);
        console.log("Monitored token:          ", monitoredToken);
        console.logBytes32(notesNullifierRoot);
        console.logBytes32(notesCommitmentRoot);
        console.logBytes32(accountsNullifierRoot);
        console.logBytes32(accountsCommitmentRoot);
    }
}
