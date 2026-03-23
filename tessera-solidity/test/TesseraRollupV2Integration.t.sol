// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {TesseraRollupV2} from "../src/TesseraRollupV2.sol";
import {PoseidonGoldilocks} from "../src/PoseidonGoldilocks.sol";
import {ToyUSDT} from "../src/ToyUSDT.sol";
import {VerifierSuperAggregatorV2} from "../src/VerifierSuperAggregatorV2.sol";

/// @title  Integration tests — real gnark Groth16 verifier
/// @notice These tests require the SAV2 artifact binary to have run first:
///
///           cargo run --bin super_aggregator_v2_artifacts --release
///
///         The binary writes two files consumed here:
///           tessera-solidity/src/VerifierSuperAggregatorV2.sol   (real gnark verifier)
///           tessera-solidity/test/fixtures/groth16_proof.json    (dummy SAV2 proof)
///
///         When the fixture file is absent the tests are skipped via vm.skip().
contract TesseraRollupV2IntegrationTest is Test {

    string constant FIXTURE = "test/fixtures/groth16_proof.json";

    VerifierSuperAggregatorV2 public verifier;
    PoseidonGoldilocks         public poseidon;
    ToyUSDT                    public token;
    TesseraRollupV2            public rollup;

    address constant OP  = address(0x0001);
    bytes32 constant PCR = bytes32(0);

    function setUp() public {
        verifier = new VerifierSuperAggregatorV2();
        poseidon = new PoseidonGoldilocks();
        token    = new ToyUSDT();
        rollup   = new TesseraRollupV2(
            address(verifier),
            address(verifier),
            address(poseidon),
            OP,
            address(token),
            PCR,
            4
        );
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Load and parse the gnark proof fixture JSON.
    ///
    /// JSON layout (produced by Groth16Wrapper::proof_to_solidity_json):
    ///   { "proof": ["0x...", ...×8],
    ///     "commitments":   ["0x...", "0x..."],
    ///     "commitmentPok": ["0x...", "0x..."],
    ///     "publicInputs":  ["0x...", ...×8] }
    function _loadProof()
        internal
        view
        returns (
            uint256[8] memory proof,
            uint256[2] memory commitments,
            uint256[2] memory commitmentPok,
            uint256[8] memory publicInputs
        )
    {
        string memory json = vm.readFile(FIXTURE);
        for (uint256 i = 0; i < 8; i++) {
            proof[i]        = vm.parseJsonUint(json, _idx(".proof",        i));
            publicInputs[i] = vm.parseJsonUint(json, _idx(".publicInputs", i));
        }
        for (uint256 i = 0; i < 2; i++) {
            commitments[i]   = vm.parseJsonUint(json, _idx(".commitments",   i));
            commitmentPok[i] = vm.parseJsonUint(json, _idx(".commitmentPok", i));
        }
    }

    /// Build a JSON array-index path like ".proof[2]".
    function _idx(string memory field, uint256 i) internal pure returns (string memory) {
        return string.concat(field, "[", vm.toString(i), "]");
    }

    /// Load the batch parameters written by `super_aggregator_v2_artifacts`:
    ///   root              — genesis root used as the single IMT root in the dummy proof
    ///   batchPoseidonRoot — Goldilocks Poseidon Merkle root of all NC leaves (all zero)
    ///   noteCommitmentsCount / noteNullifiersCount — array sizes (512 / 448)
    function _loadBatchParams()
        internal
        view
        returns (
            uint256 root,
            uint256 batchPoseidonRoot,
            uint256 noteCommitmentsCount,
            uint256 noteNullifiersCount
        )
    {
        string memory json = vm.readFile(FIXTURE);
        root                 = vm.parseJsonUint(json, ".root");
        batchPoseidonRoot    = vm.parseJsonUint(json, ".batchPoseidonRoot");
        noteCommitmentsCount = vm.parseJsonUint(json, ".noteCommitmentsCount");
        noteNullifiersCount  = vm.parseJsonUint(json, ".noteNullifiersCount");
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /// The gnark-generated Groth16 verifier accepts the dummy SAV2 proof.
    function test_groth16_real_proof_accepted() public {
        if (!vm.isFile(FIXTURE)) { vm.skip(true); }

        (
            uint256[8] memory proof,
            uint256[2] memory commitments,
            uint256[2] memory commitmentPok,
            uint256[8] memory publicInputs
        ) = _loadProof();

        // Must not revert.
        verifier.verifyProof(proof, commitments, commitmentPok, publicInputs);
    }

    /// publicInputs from the fixture, when re-packed to bytes32, decompose
    /// back to the same 8 words via keccakToPublicInputs.
    ///
    /// This cross-checks the Rust encoding (prove_plonky2 bytes32 packing),
    /// the gnark output (public inputs), and the Solidity decoder in one shot.
    function test_groth16_public_inputs_match_piCommitment() public {
        if (!vm.isFile(FIXTURE)) { vm.skip(true); }

        (, , , uint256[8] memory publicInputs) = _loadProof();

        // Each publicInputs[i] is a u32 word.  Reconstruct bytes32 by packing
        // them big-endian — mirrors Rust's prove_plonky2 commitment assembly.
        bytes32 piCommitment = bytes32(
            (publicInputs[0] << 224) | (publicInputs[1] << 192) |
            (publicInputs[2] << 160) | (publicInputs[3] << 128) |
            (publicInputs[4] << 96)  | (publicInputs[5] << 64)  |
            (publicInputs[6] << 32)  |  publicInputs[7]
        );

        uint256[8] memory unpacked = rollup.keccakToPublicInputs(piCommitment);
        for (uint256 i = 0; i < 8; i++) {
            assertEq(unpacked[i], publicInputs[i], "keccakToPublicInputs mismatch");
        }
    }

    /// End-to-end: submit + prove a TX batch using the real Groth16 verifier.
    ///
    /// The dummy SAV2 proof is generated with:
    ///   root               = genesis root (zeros[SOLIDITY_TREE_DEPTH])
    ///   mainPoolConfigRoot = 0
    ///   batchPoseidonRoot  = Goldilocks Poseidon Merkle root of 512 all-zero NC leaves
    ///   noteCommitments    = 512 × uint256(0)
    ///   noteNullifiers     = 448 × uint256(0)  (64 slots × 7 NNs/slot)
    ///
    /// These values are stored alongside the proof in the fixture JSON so this
    /// test can reconstruct the exact TransactionBatch.
    function test_groth16_prove_transaction_batch() public {
        if (!vm.isFile(FIXTURE)) { vm.skip(true); }

        (
            uint256[8] memory proof,
            uint256[2] memory commitments,
            uint256[2] memory commitmentPok,
            uint256[8] memory publicInputs
        ) = _loadProof();

        (
            uint256 root,
            uint256 batchPoseidonRoot,
            uint256 ncCount,
            uint256 nnCount
        ) = _loadBatchParams();

        // Reconstruct piCommitment from publicInputs.
        bytes32 piCommitment = bytes32(
            (publicInputs[0] << 224) | (publicInputs[1] << 192) |
            (publicInputs[2] << 160) | (publicInputs[3] << 128) |
            (publicInputs[4] << 96)  | (publicInputs[5] << 64)  |
            (publicInputs[6] << 32)  |  publicInputs[7]
        );

        // Build the matching TransactionBatch.
        // noteCommitments and noteNullifiers are all-zero (default uint256[] values).
        uint256[] memory noteCommitments = new uint256[](ncCount);
        uint256[] memory noteNullifiers  = new uint256[](nnCount);
        TesseraRollupV2.TransactionBatch memory batch = TesseraRollupV2.TransactionBatch({
            root:               root,
            mainPoolConfigRoot: PCR,
            noteCommitments:    noteCommitments,
            noteNullifiers:     noteNullifiers,
            accountCommitment:  0,
            accountNullifier:   0,
            batchPoseidonRoot:  batchPoseidonRoot,
            confirmed:          false
        });

        // Verify our local piCommitment matches what the contract will compute.
        bytes32 computed = keccak256(abi.encodePacked(
            batch.root, batch.root, batch.mainPoolConfigRoot, batch.batchPoseidonRoot,
            batch.accountCommitment, batch.accountNullifier,
            batch.noteCommitments, batch.noteNullifiers
        ));
        assertEq(computed, piCommitment, "piCommitment mismatch - batch fields don't match proof");

        // Submit phase (operator).
        vm.prank(OP);
        rollup.submitTransactionBatch(batch);

        // Prove phase — uses the real gnark verifier.
        TesseraRollupV2.Proof memory p = TesseraRollupV2.Proof({
            proof:         proof,
            commitments:   commitments,
            commitmentPok: commitmentPok
        });
        rollup.proveTransactionBatch(piCommitment, p);

        assertEq(rollup.leafCount(), 1, "leaf appended");
    }
}
