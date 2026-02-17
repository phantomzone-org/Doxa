// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IGroth16Verifier} from "./TesseraRollup.sol";

/// @notice Dev-only verifier that accepts any Groth16-shaped proof.
/// @dev Never deploy this verifier in production.
contract DummyVerifier is IGroth16Verifier {
    function verifyProof(
        uint256[8] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[8] calldata
    ) external pure {}
}

