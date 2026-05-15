# Doxa State Sync Service

A standalone HTTP service that tracks on-chain state from `DoxaContract` and provides real-time access to:
- Account and note commitment Merkle paths
- Nullifier confirmations
- Subpool configuration proofs
- Batch submission and proof statuses
- Deposit lifecycle tracking

## Quick Start

### Prerequisites

- Rust 1.70+ (see CLAUDE.md for build instructions)
- Access to a JSON-RPC endpoint (local or remote)
- A deployed `DoxaContract` instance

### Installation & Configuration

1. **Set environment variables** in a `.env` file or shell:

```bash
# Required
DOXA_RPC_URL="http://localhost:8545"
DOXA_CONTRACT_ADDRESS="0x..."

# Optional (defaults shown)
DOXA_STATE_SYNC_POLL_INTERVAL="12"  # seconds
DOXA_STATE_SYNC_BIND_ADDR="0.0.0.0:3001"
```

2. **Run the service**:

```bash
cd doxa-state-sync
cargo run --release
```

The service will:
1. Perform a complete genesis sync (replay all on-chain events from the contract's deployment)
2. Start the HTTP server on the configured bind address
3. Begin polling for new events every `POLL_INTERVAL` seconds

**Note**: Genesis sync may take several minutes depending on contract deployment height and event volume. The HTTP server does not accept requests until genesis sync completes.

## API Reference

All endpoints accept `GET` requests with query parameters and return JSON. Hash values are hex-encoded with `0x` prefix.

### `GET /commitment/merkle-path`

Get the two-layer Merkle proof for an account or note commitment.

**Parameters**:
- `commitment` (hex string, required): The commitment hash (32 bytes)

**Response** (if confirmed):
```json
{
  "status": "confirmed",
  "batch_subtree_path": {
    "leaf_index": 3,
    "siblings": ["0x...", "0x...", ...],
    "directions": [0, 1, 0, ...]
  },
  "state_tree_path": {
    "leaf_index": 7,
    "siblings": ["0x...", ...],
    "directions": [...]
  }
}
```

- `batch_subtree_path`: Merkle path within the 512-leaf batch subtree (9 siblings)
- `state_tree_path`: Merkle path within the state tree (proof of the batch in the IMT)
- `directions`: Array of 0s and 1s (0 = go left in tree, 1 = go right)

**Response** (if pending — commitment known but batch not yet proven on-chain):
```json
{
  "status": "pending",
  "pi_commitment": "0x..."
}
```

**Response** (if unknown):
```json
{
  "status": "not_found"
}
```

**Example**:
```bash
curl "http://localhost:3001/commitment/merkle-path?commitment=0xabcd1234..."
```

### `GET /nullifier/status`

Check if a nullifier has been confirmed or is still pending.

**Parameters**:
- `nullifier` (hex string, required): The nullifier hash (32 bytes)

**Response**:
- `{ "status": "confirmed" }` — nullifier is on-chain
- `{ "status": "pending", "pi_commitment": "0x..." }` — in a pending batch
- `{ "status": "not_found" }` — unknown

**Example**:
```bash
curl "http://localhost:3001/nullifier/status?nullifier=0x..."
```

### `GET /subpool/full-proof`

Get the Merkle proof for a subpool in the main pool configuration tree.

**Parameters**:
- `subpool_id` (integer, required): The subpool ID

**Response**:
```json
{
  "subpool_id": 3,
  "subpool_root": "0x...",
  "leaf_value": "0x...",
  "config_tree_root": "0x...",
  "siblings": ["0x...", ...],
  "directions": [0, 1, ...]
}
```

- `subpool_root`: The current root of the subpool's state tree (0 if never updated)
- `leaf_value`: The hash committed in the config tree for this subpool
- `config_tree_root`: The root of the main pool config tree
- `siblings`: Merkle proof (depth 20)
- `directions`: Path directions

**Status codes**:
- `200 OK` — subpool found and assigned an owner
- `404 Not Found` — subpool ID is 0 (reserved) or never assigned an owner

**Example**:
```bash
curl "http://localhost:3001/subpool/full-proof?subpool_id=1"
```

### `GET /batch/status`

Check if a batch submission has been proven on-chain.

**Parameters**:
- `pi_commitment` (hex string, required): The batch identifier (keccak256 of preimage)
- `kind` (string, required): Either `"tx"` or `"bridge"` (case-sensitive)

**Response**:
- `{ "status": "pending" }` — batch submitted but not yet proven
- `{ "status": "confirmed" }` — batch proven on-chain
- `{ "status": "not_found" }` — batch never seen

**Example**:
```bash
curl "http://localhost:3001/batch/status?pi_commitment=0x...&kind=tx"
curl "http://localhost:3001/batch/status?pi_commitment=0x...&kind=bridge"
```

### `GET /deposits`

Retrieve all deposits (notes) first seen at or after a given block.

**Parameters**:
- `from_block` (integer, optional): Block number cutoff (default: 0, returns all deposits)

**Response**:
```json
[
  {
    "note_commitment": "0x...",
    "value": "1000000",
    "recipient": "0x...",
    "asset_id": "1",
    "status": "Pending",
    "deposit_block": 12345
  },
  ...
]
```

- `status`: One of `"Pending"` (submitted but not validated), `"Validated"` (confirmed on-chain), or `"Withdrawn"` (withdrawn from the system)
- `value`, `asset_id`: Returned as strings to preserve precision

**Example**:
```bash
curl "http://localhost:3001/deposits"
curl "http://localhost:3001/deposits?from_block=10000"
```

## Health & Monitoring

### Logs

Logging is controlled via `RUST_LOG` environment variable:

```bash
# Info level (default)
RUST_LOG=doxa_state_sync=info cargo run --release

# Debug level (more detail)
RUST_LOG=doxa_state_sync=debug cargo run --release

# Trace level (very verbose)
RUST_LOG=doxa_state_sync=trace cargo run --release
```

Key log messages indicate:
- Genesis sync progress (block ranges, event counts)
- Poll sync start/completion and errors
- Root divergence warnings (if local and on-chain roots disagree)
- API request handling (via tracing instrumentation)

### Startup Behavior

On startup, the service logs:
1. Environment configuration loaded
2. Genesis sync starting
3. Genesis sync completing (total events synced)
4. HTTP server binding to address
5. Polling loop starting

If genesis sync fails, the service exits with an error and does not start the HTTP server.

## Typical Workflows

### 1. Client Submits a Private Transaction

From the client's perspective:
1. Create a transaction, generate a Plonky2 proof locally
2. Submit the batch preimage to the sequencer
3. Poll `/batch/status?pi_commitment=...&kind=tx` until `"confirmed"`
4. Once confirmed, fetch the commitment Merkle paths via `/commitment/merkle-path` for use in future transactions

### 2. Operator Validates Deposits

1. Monitor `/deposits` (optionally filtering by `from_block`)
2. Check deposit status transitions: `Pending` → `Validated` (on-chain validation) → `Withdrawn` (user withdrawal)
3. Use `/nullifier/status` to confirm account nullifiers have been spent

### 3. Subpool Owner Updates Configuration

1. After calling `updateSubpoolRoot()` on-chain, poll `/subpool/full-proof?subpool_id=...` to fetch the updated proof
2. Use the proof in client wallet operations or governance transactions

## Deployment

### Local Development

See `scripts/local_e2e_toy_a_anvil.sh` and related scripts in the repo root for a complete local demo setup.

### Production

For production deployment:

1. **Use a reliable RPC endpoint** — run your own node or use a service with SLA guarantees
2. **Set appropriate log levels** — use `info` or `warn` to reduce noise
3. **Monitor polls** — track the `last_synced_block` via logs to ensure the service stays in sync
4. **Restart strategy** — if the service crashes, restart it (genesis sync will replay missed events)
5. **Redundancy** (optional) — run multiple instances behind a load balancer; all instances will maintain independent in-memory state

### Example systemd Service

```ini
[Unit]
Description=Doxa State Sync Service
After=network.target

[Service]
Type=simple
User=doxa
WorkingDirectory=/opt/doxa
ExecStart=/opt/doxa/doxa-state-sync
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal

Environment="DOXA_RPC_URL=http://localhost:8545"
Environment="DOXA_CONTRACT_ADDRESS=0x..."
Environment="DOXA_STATE_SYNC_POLL_INTERVAL=12"
Environment="DOXA_STATE_SYNC_BIND_ADDR=0.0.0.0:3001"
Environment="RUST_LOG=doxa_state_sync=info"

[Install]
WantedBy=multi-user.target
```

## Troubleshooting

### "genesis sync failed" on startup

**Cause**: The service cannot sync from genesis. Common reasons:
- Invalid `DOXA_RPC_URL` (network timeout, malformed URL)
- Invalid `DOXA_CONTRACT_ADDRESS` (wrong address, not deployed)
- RPC endpoint rate-limited or down

**Fix**:
1. Verify RPC URL is reachable: `curl $DOXA_RPC_URL`
2. Verify contract address is correct and deployed: check on-chain via explorer
3. Use a stable RPC endpoint (avoid public rate-limited endpoints for large syncs)
4. Increase RPC timeout (internal; contact maintainers if needed)

### "HTTP server failed"

**Cause**: Port is in use or permission denied.

**Fix**:
1. Change `DOXA_STATE_SYNC_BIND_ADDR` to a different port
2. Check if another instance is running: `lsof -i :3001`

### API returns `"status": "not_found"` unexpectedly

**Cause**: The commitment, nullifier, or batch has not been synced yet, or the service is behind the chain.

**Fix**:
1. Check logs for sync status: `RUST_LOG=doxa_state_sync=debug`
2. Verify the transaction was actually submitted on-chain (check transaction hash on explorer)
3. Wait a moment for the polling loop to catch up (default 12-second interval)

### "root divergence" warning in logs

**Cause**: The local state tree root does not match the on-chain root after a batch confirmation.

**Impact**: This is a critical divergence indicating a potential contract bug or sync bug. The service continues to operate but logs a warning.

**Action**: Immediately investigate:
1. Check on-chain root via `DoxaContract.root()` call
2. Review recent batch submissions in logs
3. Consider restarting the service (genesis sync will replay all events and rebuild state)
4. Report to maintainers with logs attached

## Architecture & State

The service maintains seven synchronized indexes:

1. **StateTree Mirror**: On-chain IMT (Merkle tree of batch roots)
2. **Batch Subtrees**: 512-leaf subtree for each batch (account + note commitments)
3. **Commitment Index**: Maps each commitment to its batch and subtree position
4. **Batch Status**: Pending vs. confirmed for both TX and bridge-TX batches
5. **Nullifier Index**: Confirmed vs. pending nullifiers
6. **Subpool Config Tree**: Mirror of the on-chain configuration tree
7. **Deposit Index**: Full lifecycle tracking with status transitions

All state is held in memory and lost on restart (see Future Work in AGENTS.md for persistence options).

## See Also

- **AGENTS.md** — Technical notes for developers and agents working on this crate
- **CLAUDE.md** (repo root) — Build commands, architecture overview, environment setup
- **doxa-solidity/contracts/DoxaContract.sol** — Smart contract source (event definitions, state)
- **doxa-client/src/lib.rs** — Client-side types and circuit definitions
