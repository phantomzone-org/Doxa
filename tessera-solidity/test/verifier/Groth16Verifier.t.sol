// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";

import {Verifier as ArtifactSuperAggregatorVerifier} from "../fixtures/VerifierSuperAggregatorArtifact.sol";

/// @notice Verifies the super-aggregator Groth16 proof artifact produced by
///         `cargo run --bin super_aggregator_artifacts --release` (Step 18).
/// @dev These tests require Step 18 artifacts to be built first. Run:
///      cargo run --bin super_aggregator_artifacts --release
///      cp tessera-server/artifacts/super-aggregator/groth-artifacts/VerifierSuperAggregator.sol \
///         tessera-solidity/src/VerifierSuperAggregator.sol
///      cp tessera-server/artifacts/super-aggregator/groth-artifacts/VerifierSuperAggregator.sol \
///         tessera-solidity/test/fixtures/VerifierSuperAggregatorArtifact.sol
contract Groth16VerifierTest is Test {
    using stdJson for string;

    struct ProofFixture {
        uint256[8] proof;
        uint256[2] commitments;
        uint256[2] commitmentPok;
        uint256[8] publicInputs;
    }

    function testSuperAggregatorVerifier_AcceptsArtifactProof() public {
        ArtifactSuperAggregatorVerifier verifier = new ArtifactSuperAggregatorVerifier();
        ProofFixture memory fixture =
            _loadFixture("../tessera-server/artifacts/super-aggregator/groth-artifacts/proof_solidity.json");

        verifier.verifyProof(
            fixture.proof,
            fixture.commitments,
            fixture.commitmentPok,
            fixture.publicInputs
        );
    }

    function testSuperAggregatorVerifier_RejectsTamperedPublicInput() public {
        ArtifactSuperAggregatorVerifier verifier = new ArtifactSuperAggregatorVerifier();
        ProofFixture memory fixture =
            _loadFixture("../tessera-server/artifacts/super-aggregator/groth-artifacts/proof_solidity.json");

        fixture.publicInputs[0] = fixture.publicInputs[0] + 1;

        vm.expectRevert();
        verifier.verifyProof(
            fixture.proof,
            fixture.commitments,
            fixture.commitmentPok,
            fixture.publicInputs
        );
    }

    function _loadFixture(string memory path) internal view returns (ProofFixture memory fixture) {
        string memory json = vm.readFile(path);

        for (uint256 i = 0; i < 8; i++) {
            fixture.proof[i] = vm.parseUint(
                json.readString(string.concat(".proof[", vm.toString(i), "]"))
            );
            fixture.publicInputs[i] = vm.parseUint(
                json.readString(string.concat(".publicInputs[", vm.toString(i), "]"))
            );
        }

        for (uint256 i = 0; i < 2; i++) {
            fixture.commitments[i] = vm.parseUint(
                json.readString(string.concat(".commitments[", vm.toString(i), "]"))
            );
            fixture.commitmentPok[i] = vm.parseUint(
                json.readString(string.concat(".commitmentPok[", vm.toString(i), "]"))
            );
        }
    }
}
