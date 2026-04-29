// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {TesseraContract} from "../src/TesseraContract.sol";
import {PoseidonGoldilocks} from "../src/PoseidonGoldilocks.sol";
import {ToyUSDT} from "../src/ToyUSDT.sol";
import {TesseraBatchTransactionVerifier} from "../src/TesseraBatchTransactionVerifier.sol";
import {AcceptAllVerifier} from "../src/AcceptAllVerifier.sol";

/// @title  Integration tests — real gnark Groth16 verifiers (TX + Deposit)
/// @notice These tests require the artifact binaries to have run first:
///
///           cargo run -p tessera-e2e --bin tx_artifacts --release
///           cargo run -p tessera-e2e --bin deposit_artifacts --release
///
///         Each binary writes a verifier contract and a fixture JSON.
///         When the fixture file is absent the tests are skipped via vm.skip().
contract TesseraRollupV2IntegrationTest is Test {

    string constant FIXTURE = "test/fixtures/groth16_proof.json";

    TesseraBatchTransactionVerifier public batch_tx_verifier;
    AcceptAllVerifier public accept_all_verifier;
    PoseidonGoldilocks         public poseidon;
    ToyUSDT                    public token;
    TesseraContract            public tessera_contract;

    address constant OP  = address(0x0001);
    uint256 constant PCR = 0;

    function setUp() public {
        batch_tx_verifier = new TesseraBatchTransactionVerifier();
        accept_all_verifier = new AcceptAllVerifier();
        poseidon = new PoseidonGoldilocks();
        token    = new ToyUSDT();
        tessera_contract   = new TesseraContract(
            address(batch_tx_verifier),
            address(accept_all_verifier),
            address(poseidon),
            OP,
            address(token),
            PCR,
            32,
            20
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

    /// Convert LE-packed uint256 (el0|(el1<<64)|...) to GL-preimage bytes32
    /// ([lo0_BE4][hi0_BE4][lo1_BE4][hi1_BE4]...).
    function _glH(uint256 p) internal pure returns (bytes32) {
        uint256 e0 = p & 0xFFFFFFFFFFFFFFFF;
        uint256 e1 = (p >> 64)  & 0xFFFFFFFFFFFFFFFF;
        uint256 e2 = (p >> 128) & 0xFFFFFFFFFFFFFFFF;
        uint256 e3 =  p >> 192;
        return bytes32(
            ((e0 & 0xFFFFFFFF) << 224) | ((e0 >> 32) << 192) |
            ((e1 & 0xFFFFFFFF) << 160) | ((e1 >> 32) << 128) |
            ((e2 & 0xFFFFFFFF) << 96)  | ((e2 >> 32) << 64)  |
            ((e3 & 0xFFFFFFFF) << 32)  |  (e3 >> 32)
        );
    }

    /// Build the batch preimage bytes from the fixture JSON.
    ///
    /// Layout: [batchPoseidonRoot(32B)][root(32B)][mainPoolConfigRoot(32B)]
    ///         then 64 slots × 520B:
    ///           [notFakeTx: 8B GL-field][accinNull: 32B][accoutComm: 32B]
    ///           [noteInNull×7: 7×32B][noteOutComm×7: 7×32B]
    function _loadBatch() internal returns (bytes memory preimage) {
        string memory json = vm.readFile(FIXTURE);

        preimage = abi.encodePacked(
            _glH(vm.parseJsonUint(json, ".batchPoseidonRoot")),
            _glH(vm.parseJsonUint(json, ".root")),
            _glH(PCR)
        );

        bool[] memory notFakeTx;
        try vm.parseJsonBoolArray(json, ".notFakeTx") returns (bool[] memory nft) {
            notFakeTx = nft;
        } catch {
            vm.skip(true);
        }
        uint256[] memory acNull  = vm.parseJsonUintArray(json, ".accinNullifiers");
        uint256[] memory acComm  = vm.parseJsonUintArray(json, ".accoutCommitments");
        uint256[] memory noteNull = vm.parseJsonUintArray(json, ".noteInNullifiers");
        uint256[] memory noteComm = vm.parseJsonUintArray(json, ".noteOutCommitments");

        uint256 NOTE_BATCH = 7;
        for (uint256 s = 0; s < 64; s++) {
            // 8B: notFakeTx as GL field — [lo_BE4][hi_BE4], value 0 or 1
            uint32 nftVal = notFakeTx[s] ? 1 : 0;
            preimage = abi.encodePacked(preimage, bytes4(nftVal), bytes4(uint32(0)));
            // 32B each: accin nullifier, accout commitment
            preimage = abi.encodePacked(preimage, _glH(acNull[s]), _glH(acComm[s]));
            // 7×32B: note-in nullifiers, note-out commitments
            for (uint256 n = 0; n < NOTE_BATCH; n++) {
                preimage = abi.encodePacked(preimage, _glH(noteNull[s * NOTE_BATCH + n]));
            }
            for (uint256 n = 0; n < NOTE_BATCH; n++) {
                preimage = abi.encodePacked(preimage, _glH(noteComm[s * NOTE_BATCH + n]));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /// The gnark-generated Groth16 verifier accepts the dummy Final Plonky2 Proof proof.
    function test_batch_tx_groth16_real_proof_accepted() public {
        if (!vm.isFile(FIXTURE)) { vm.skip(true); }

        (
            uint256[8] memory proof,
            uint256[2] memory commitments,
            uint256[2] memory commitmentPok,
            uint256[8] memory publicInputs
        ) = _loadProof();

        // Must not revert.
        batch_tx_verifier.verifyProof(proof, commitments, commitmentPok, publicInputs);
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

        uint256[8] memory unpacked = tessera_contract.keccakToPublicInputs(piCommitment);
        for (uint256 i = 0; i < 8; i++) {
            assertEq(unpacked[i], publicInputs[i], "keccakToPublicInputs mismatch");
        }
    }

    /// End-to-end: submit + prove a TX batch using the real Groth16 verifier.
    ///
    /// The fixture JSON (written by `tx_artifacts`) contains the exact
    /// AC/AN/NC/NN arrays that the circuit used for its keccak piCommitment.
    function test_groth16_prove_transaction_batch() public {
        if (!vm.isFile(FIXTURE)) { vm.skip(true); }

        (
            uint256[8] memory proof,
            uint256[2] memory commitments,
            uint256[2] memory commitmentPok,
            uint256[8] memory publicInputs
        ) = _loadProof();

        // Reconstruct piCommitment from publicInputs.
        bytes32 piCommitment = bytes32(
            (publicInputs[0] << 224) | (publicInputs[1] << 192) |
            (publicInputs[2] << 160) | (publicInputs[3] << 128) |
            (publicInputs[4] << 96)  | (publicInputs[5] << 64)  |
            (publicInputs[6] << 32)  |  publicInputs[7]
        );

        // Build preimage bytes from fixture and verify piCommitment matches the proof.
        bytes memory preimage = _loadBatch();
        assertEq(keccak256(preimage), piCommitment, "piCommitment mismatch - batch fields don't match proof");

        // Submit phase (operator).
        vm.prank(OP);
        tessera_contract.submitTransactionBatch(preimage);

        // Prove phase — uses the real gnark verifier.
        TesseraContract.Proof memory p = TesseraContract.Proof({
            proof:         proof,
            commitments:   commitments,
            commitmentPok: commitmentPok
        });
        tessera_contract.proveTransactionBatch(preimage, p);

        assertEq(tessera_contract.leafCount(), 1, "leaf appended");
    }
}

// =========================================================================
// Deposit Groth16 integration tests
// =========================================================================

/// @title  Deposit integration tests — real gnark Groth16 verifier
/// @notice Requires:  cargo run -p tessera-e2e --bin deposit_artifacts --release
///         Fixture:   tessera-solidity/test/fixtures/groth16_deposit_proof.json
///         Verifier:  tessera-solidity/src/VerifierDepositSuperAggregatorV2.sol
contract TesseraDepositIntegrationTest is Test {

    string constant FIXTURE = "test/fixtures/groth16_deposit_proof.json";

    TesseraBatchTransactionVerifier        public batch_tx_verifier;
    AcceptAllVerifier public accept_all_verifier;
    PoseidonGoldilocks               public poseidon;
    ToyUSDT                          public token;
    TesseraContract                  public rollup;

    address constant OP  = address(0x0001);
    uint256 constant PCR = 0;

    function setUp() public {
        batch_tx_verifier      = new TesseraBatchTransactionVerifier();
        accept_all_verifier      = new AcceptAllVerifier();
        poseidon        = new PoseidonGoldilocks();
        token           = new ToyUSDT();
        rollup          = new TesseraContract(
            address(batch_tx_verifier),
            address(accept_all_verifier),
            address(poseidon),
            OP,
            address(token),
            PCR,
            32,
            20
        );
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    function _loadProof(string memory path)
        internal
        view
        returns (
            uint256[8] memory proof,
            uint256[2] memory commitments,
            uint256[2] memory commitmentPok,
            uint256[8] memory publicInputs
        )
    {
        string memory json = vm.readFile(path);
        for (uint256 i = 0; i < 8; i++) {
            proof[i]        = vm.parseJsonUint(json, _idx(".proof",        i));
            publicInputs[i] = vm.parseJsonUint(json, _idx(".publicInputs", i));
        }
        for (uint256 i = 0; i < 2; i++) {
            commitments[i]   = vm.parseJsonUint(json, _idx(".commitments",   i));
            commitmentPok[i] = vm.parseJsonUint(json, _idx(".commitmentPok", i));
        }
    }

    function _idx(string memory field, uint256 i) internal pure returns (string memory) {
        return string.concat(field, "[", vm.toString(i), "]");
    }

    /// Pack 8 u32 public input words into bytes32.
    function _packPiCommitment(uint256[8] memory pi) internal pure returns (bytes32) {
        return bytes32(
            (pi[0] << 224) | (pi[1] << 192) |
            (pi[2] << 160) | (pi[3] << 128) |
            (pi[4] << 96)  | (pi[5] << 64)  |
            (pi[6] << 32)  |  pi[7]
        );
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /// publicInputs round-trip through keccakToPublicInputs.
    function test_groth16_deposit_public_inputs_match_piCommitment() public {
        if (!vm.isFile(FIXTURE)) { vm.skip(true); }

        (, , , uint256[8] memory publicInputs) = _loadProof(FIXTURE);

        bytes32 piCommitment = _packPiCommitment(publicInputs);
        uint256[8] memory unpacked = rollup.keccakToPublicInputs(piCommitment);
        for (uint256 i = 0; i < 8; i++) {
            assertEq(unpacked[i], publicInputs[i], "keccakToPublicInputs mismatch");
        }
    }

    /// Deposit piCommitment preimage matches the Groth16 proof.
    ///
    /// The dummy DSAV2 proof is generated with:
    ///   act_root           = [0;4]  (uint256 zero)
    ///   mainPoolConfigRoot = bytes32(0)
    ///   batchPoseidonRoot  = SR root over 512 dummy NC leaves
    ///   ethAddresses       = 512 × address(0)  (all dummy deposits)
    ///
    /// The fixture stores `batchPoseidonRoot` so we can reconstruct the
    /// exact Keccak preimage without running the full pipeline.
    function test_groth16_deposit_piCommitment_matches() public {
        if (!vm.isFile(FIXTURE)) { vm.skip(true); }

        string memory json = vm.readFile(FIXTURE);

        // Skip if fixture doesn't have batch params yet.
        // After re-running deposit_artifacts these fields will be present.
        try vm.parseJsonUint(json, ".batchPoseidonRoot") returns (uint256) {}
        catch { vm.skip(true); }

        (, , , uint256[8] memory publicInputs) = _loadProof(FIXTURE);
        bytes32 piCommitment = _packPiCommitment(publicInputs);

        uint256 batchPoseidonRoot = vm.parseJsonUint(json, ".batchPoseidonRoot");

        // Deposit preimage: root | mainPoolConfigRoot | batchPoseidonRoot | ethAddresses[512]
        // All dummy → root=0, mainPoolConfigRoot=0, all addresses=0.
        // _addressToLE20(address(0)) = 20 zero bytes.
        bytes memory preimage = abi.encodePacked(
            uint256(0),           // root
            uint256(0),           // mainPoolConfigRoot
            batchPoseidonRoot     // batchPoseidonRoot
        );
        // 512 × address(0) LE-encoded = 512 × 20 zero bytes = 10240 zero bytes.
        for (uint256 i = 0; i < 512; i++) {
            preimage = bytes.concat(preimage, new bytes(20));
        }

        bytes32 computed = keccak256(preimage);
        assertEq(computed, piCommitment, "deposit piCommitment mismatch");
    }
}
