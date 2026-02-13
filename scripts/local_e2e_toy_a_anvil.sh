#!/usr/bin/env bash
set -euo pipefail

# Console A: start local chain.
# Pass-through args are forwarded to `anvil`.

anvil "$@"
