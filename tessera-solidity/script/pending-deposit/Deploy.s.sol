// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {DepositsRollupBridge} from "../../src/TesseraRollup.sol";
import {Verifier as CommitmentVerifier} from "../../src/VerifierCommitment.sol";
import {Verifier as NullifierVerifier} from "../../src/VerifierNullifier.sol";
import {DummyVerifier} from "../../src/DummyVerifier.sol";

/// @title  Deploy Verifier + DepositsRollupBridge
/// @notice Deploys both contracts to the target chain. The deployer
///         (`msg.sender`) is set as the initial operator.
///
/// Required environment variables:
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
///   # Terminal 2: set roots
///   export TESSERA_NOTES_NULLIFIER_ROOT=0x5d85139746d173c92bf3543b4c6ce3daf11bdff30e5b44879d216bc5f06256b6
///   export TESSERA_NOTES_COMMITMENT_ROOT=0x5d85139746d173c92bf3543b4c6ce3daf11bdff30e5b44879d216bc5f06256b6
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
        bytes32 notesNullifierRoot = vm.envBytes32("TESSERA_NOTES_NULLIFIER_ROOT");
        bytes32 notesCommitmentRoot = vm.envBytes32("TESSERA_NOTES_COMMITMENT_ROOT");
        bytes32 accountsNullifierRoot = vm.envBytes32("TESSERA_ACCOUNTS_NULLIFIER_ROOT");
        bytes32 accountsCommitmentRoot = vm.envBytes32("TESSERA_ACCOUNTS_COMMITMENT_ROOT");
        uint256 batchSize = vm.envUint("TESSERA_BATCH_SIZE");
        address monitoredToken = vm.envAddress("TESSERA_MONITORED_TOKEN");

        vm.startBroadcast();

        CommitmentVerifier commitmentVerifier = new CommitmentVerifier();
        NullifierVerifier nullifierVerifier = new NullifierVerifier();
        DummyVerifier aggregatedInputVerifier = new DummyVerifier();
        DepositsRollupBridge bridge = new DepositsRollupBridge(
            address(commitmentVerifier),
            address(nullifierVerifier),
            address(aggregatedInputVerifier),
            msg.sender,
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
        console.log("PI verifier (dummy): ", address(aggregatedInputVerifier));
        console.log("Bridge deployed at:  ", address(bridge));
        console.log("Operator:            ", msg.sender);
        console.log("Batch size:          ", batchSize);
        console.log("Monitored token:     ", monitoredToken);
        console.logBytes32(notesNullifierRoot);
        console.logBytes32(notesCommitmentRoot);
        console.logBytes32(accountsNullifierRoot);
        console.logBytes32(accountsCommitmentRoot);
    }
}
