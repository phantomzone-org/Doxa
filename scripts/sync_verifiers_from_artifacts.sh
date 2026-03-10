#!/usr/bin/env bash
set -euo pipefail

# Copy the freshly generated Groth16 verifier contract (from tessera-server artifacts)
# into tessera-solidity, so on-chain verification keys match the prover's artifacts.
#
# Why this exists:
# - If you regenerate Groth16 trusted setup/artifacts, the verifying key changes.
# - The bridge will revert with `InvalidProof()` unless the deployed Solidity verifier
#   matches the proving/verifying keys used by the prover.
#
# Expected artifact input (single SuperAggregator verifier):
# - tessera-server/artifacts/super-aggregator/groth-artifacts/Verifier.sol
#
# Output:
# - tessera-solidity/src/VerifierSuperAggregator.sol

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SRC="$ROOT_DIR/tessera-server/artifacts/super-aggregator/groth-artifacts/Verifier.sol"
DST="$ROOT_DIR/tessera-solidity/src/VerifierSuperAggregator.sol"
FIXTURE="$ROOT_DIR/tessera-solidity/test/fixtures/VerifierSuperAggregatorArtifact.sol"

if [[ ! -f "$SRC" ]]; then
  echo "ERROR: missing super-aggregator verifier artifact: $SRC" >&2
  echo "Run: TESSERA_NOTE_BATCH_SIZE=1024 TESSERA_ACCOUNT_BATCH_SIZE=128 cargo run --bin super_aggregator_artifacts --release" >&2
  exit 1
fi

cp "$SRC" "$DST"
cp "$SRC" "$FIXTURE"

echo "Synced verifier contracts:"
echo "  $DST <= $SRC"
echo "  $FIXTURE <= $SRC"
