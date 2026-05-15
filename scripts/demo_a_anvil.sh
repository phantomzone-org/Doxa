#!/usr/bin/env bash
set -euo pipefail

# Step A: start a local Anvil chain.
# Pass-through args are forwarded to `anvil`.

echo "Starting Anvil (block gas limit = 300M)..."
anvil --gas-limit 300000000 "$@"
