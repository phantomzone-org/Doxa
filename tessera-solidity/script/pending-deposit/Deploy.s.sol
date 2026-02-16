// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {DepositsRollupBridge} from "../../src/TesseraRollup.sol";
import {Verifier as CommitmentVerifier} from "../../src/VerifierCommitment.sol";
import {Verifier as NullifierVerifier} from "../../src/VerifierNullifier.sol";

/// @title  Deploy Verifier + DepositsRollupBridge
/// @notice Deploys both contracts to the target chain. The deployer
///         (`msg.sender`) is set as the initial operator.
///
/// Required environment variables:
///   TESSERA_TRUSTED_SOURCE -- address allowed to record deposits
///   TESSERA_NOTES_NULLIFIER_ROOT  -- bytes32 nullifier tree genesis root
///   TESSERA_NOTES_COMMITMENT_ROOT -- bytes32 commitment tree genesis root
///   TESSERA_ACCOUNTS_NULLIFIER_ROOT  -- bytes32 accounts nullifier tree genesis root
///   TESSERA_ACCOUNTS_COMMITMENT_ROOT -- bytes32 accounts commitment tree genesis root
///   TESSERA_BATCH_SIZE -- number of notes per batch
///   TESSERA_MONITORED_TOKEN -- ERC20 address escrowed by the bridge
///
/// Usage (local anvil):
///   # Terminal 1: start anvil
///   anvil
///
///   # Terminal 2: set roots + trusted source
///   export TESSERA_NOTES_NULLIFIER_ROOT=0x5d85139746d173c92bf3543b4c6ce3daf11bdff30e5b44879d216bc5f06256b6
///   export TESSERA_NOTES_COMMITMENT_ROOT=0x5d85139746d173c92bf3543b4c6ce3daf11bdff30e5b44879d216bc5f06256b6
///   export TESSERA_TRUSTED_SOURCE=0xYourTrustedSource
///   export TESSERA_BATCH_SIZE=128
///   export TESSERA_MONITORED_TOKEN=0xYourToken
///
///   # Terminal 3: deploy
///   cd tessera-solidity
///   forge script script/Deploy.s.sol --rpc-url http://localhost:8545 \
///     --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
///     --broadcast
contract DeployScript is Script {
    function run() public {
        address trustedSource = vm.envAddress("TESSERA_TRUSTED_SOURCE");
        bytes32 notesNullifierRoot = vm.envBytes32("TESSERA_NOTES_NULLIFIER_ROOT");
        bytes32 notesCommitmentRoot = vm.envBytes32("TESSERA_NOTES_COMMITMENT_ROOT");
        bytes32 accountsNullifierRoot = vm.envBytes32("TESSERA_ACCOUNTS_NULLIFIER_ROOT");
        bytes32 accountsCommitmentRoot = vm.envBytes32("TESSERA_ACCOUNTS_COMMITMENT_ROOT");
        uint256 batchSize = vm.envUint("TESSERA_BATCH_SIZE");
        address monitoredToken = vm.envAddress("TESSERA_MONITORED_TOKEN");

        vm.startBroadcast();

        CommitmentVerifier commitmentVerifier = new CommitmentVerifier();
        NullifierVerifier nullifierVerifier = new NullifierVerifier();
        DepositsRollupBridge bridge = new DepositsRollupBridge(
            address(commitmentVerifier),
            address(nullifierVerifier),
            msg.sender,
            trustedSource,
            notesNullifierRoot,
            notesCommitmentRoot,
            accountsNullifierRoot,
            accountsCommitmentRoot,
            batchSize,
            monitoredToken
        );

        vm.stopBroadcast();

        console.log("Commitment verifier: ", address(commitmentVerifier));
        console.log("Nullifier verifier:  ", address(nullifierVerifier));
        console.log("Bridge deployed at:  ", address(bridge));
        console.log("Operator:            ", msg.sender);
        console.log("Trusted source:      ", trustedSource);
        console.log("Batch size:          ", batchSize);
        console.log("Monitored token:     ", monitoredToken);
        console.logBytes32(notesNullifierRoot);
        console.logBytes32(notesCommitmentRoot);
        console.logBytes32(accountsNullifierRoot);
        console.logBytes32(accountsCommitmentRoot);
    }
}
