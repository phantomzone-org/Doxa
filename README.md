# Doxa

Doxa is a compliant, privacy layer for institutional workflows on public blockchains. Check [doxa-spec](https://github.com/phantomzone-org/doxa-spec) or [this](https://doxalabs.xyz/litepaper) page for protocol details.

## Crates

- `doxa-client` — Client-side primitives and Plonky2 circuits for various transactions.
- `doxa-trees` — Merkle tree and state tree utilities.
- `doxa-utils` — Shared cryptographic utilities, Plonky2/STARK gadgets.
- `doxa-server` — Aggregation/batching circuits and service.
- `doxa-state-sync` — On-chain Doxa state sync service.
- `doxa-subpool-database` — subpool-specific service for user management operated by the subpool owner.
- `doxa-subpool-operator` — subpool-specific service to faciliate transactions (& proving) operated by the subpool owner.
- `doxa-e2e` — End-to-end tests for protocol flows across the workspace.
- `doxa-solidity` — Solidity contracts for Doxa protocol.
