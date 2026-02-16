#!/usr/bin/env bash
set -euo pipefail

# Copy freshly generated Groth16 verifier contracts (from tessera-server artifacts)
# into tessera-solidity, so on-chain verification keys match the prover's artifacts.
#
# Why this exists:
# - If you regenerate Groth16 trusted setup/artifacts, the verifying keys change.
# - The bridge will revert with `InvalidProof()` unless the deployed Solidity verifier
#   matches the proving/verifying keys used by the prover.
#
# Expected artifact inputs:
# - tessera-server/artifacts/commitment-tree/groth-artifacts/Verifier.sol
# - tessera-server/artifacts/nullifier-tree/groth-artifacts/Verifier.sol
#
# Outputs:
# - tessera-solidity/src/VerifierCommitment.sol
# - tessera-solidity/src/VerifierNullifier.sol

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SRC_COMMIT="$ROOT_DIR/tessera-server/artifacts/commitment-tree/groth-artifacts/Verifier.sol"
SRC_NULL="$ROOT_DIR/tessera-server/artifacts/nullifier-tree/groth-artifacts/Verifier.sol"

DST_COMMIT="$ROOT_DIR/tessera-solidity/src/VerifierCommitment.sol"
DST_NULL="$ROOT_DIR/tessera-solidity/src/VerifierNullifier.sol"

if [[ ! -f "$SRC_COMMIT" ]]; then
  echo "ERROR: missing commitment verifier artifact: $SRC_COMMIT" >&2
  exit 1
fi
if [[ ! -f "$SRC_NULL" ]]; then
  echo "ERROR: missing nullifier verifier artifact: $SRC_NULL" >&2
  exit 1
fi

cp "$SRC_COMMIT" "$DST_COMMIT"
cp "$SRC_NULL" "$DST_NULL"

echo "Synced verifier contracts:"
echo "  $DST_COMMIT <= $SRC_COMMIT"
echo "  $DST_NULL   <= $SRC_NULL"

