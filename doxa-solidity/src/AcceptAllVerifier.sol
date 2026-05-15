// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Groth16 verifier stub that accepts every proof unconditionally.
/// @dev For local testing ONLY — accepts zero proofs, so NEVER deploy to production.
contract AcceptAllVerifier {
    function verifyProof(
        uint256[8] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[8] calldata
    ) external pure {}
}
