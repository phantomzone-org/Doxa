# Tessera Local Services

Run the full Tessera stack locally: 1 sequencer, 3 subpool database APIs,
3 subpool operators, and PostgreSQL — all as background daemons from a single
command.

## Prerequisites

- [Rust toolchain](https://rustup.rs/) (stable)
- [Docker](https://docs.docker.com/get-docker/) (for PostgreSQL)
- `psql` (PostgreSQL client, for schema init)
- `curl`
- Anvil running with contracts already deployed (see `tessera-demo/README.md`)

## Setup

### Step 1 — Configure services.env

Edit `tessera-demo/scripts/services.env` and set the deployed contract addresses:

| Variable | Description |
|----------|------------|
| `RPC_URL` | Ethereum JSON-RPC endpoint (default `http://localhost:8545`) |
| `BRIDGE_ADDRESS` | Deployed TesseraContract address (`0x`-prefixed) |
| `TOKEN_ADDRESS` | Deployed ToyUSDT / ERC-20 token address (`0x`-prefixed) |

All other values have sensible defaults for local development.

### Step 2 — Start PostgreSQL

```bash
./tessera-demo/scripts/services_db.sh
```

Starts a PostgreSQL 16 Docker container and initializes the `subpool_1`,
`subpool_2`, `subpool_3` schemas. Idempotent — reuses the container if already
running.

You can also run this independently to set up the database without starting
the Rust services.

### Step 3 — Start all services

```bash
./tessera-demo/scripts/services_start.sh
```

This will:

1. Start PostgreSQL if not already running (calls `services_db.sh`)
2. Build all Rust binaries (`cargo build --release`)
3. Start the demo sequencer on `127.0.0.1:3000`
4. Start 3 subpool database APIs on ports `8081`, `8082`, `8083`
5. Wait for each DB API to be ready (migrations run automatically on startup)
6. Start 3 subpool operators (polling the sequencer and their respective databases)

All PIDs are tracked in `tessera-demo/logs/services.pid`.

### Step 4 — Verify

```bash
# Check all services are running
./tessera-demo/scripts/services_status.sh

# Sequencer health
curl http://127.0.0.1:3000/status

# Subpool DB APIs
curl http://localhost:8081/health
curl http://localhost:8082/health
curl http://localhost:8083/health
```

## Stopping services

```bash
# Stop everything (including PostgreSQL container)
./tessera-demo/scripts/services_stop.sh

# Stop Rust processes but keep PostgreSQL running
./tessera-demo/scripts/services_stop.sh --keep-db
```

## Logs

Each process writes to its own log file in `tessera-demo/logs/`:

| Log file | Service |
|----------|---------|
| `sequencer.log` | Demo sequencer |
| `db-1.log` | Subpool DB API 1 (port 8081) |
| `db-2.log` | Subpool DB API 2 (port 8082) |
| `db-3.log` | Subpool DB API 3 (port 8083) |
| `operator-1.log` | Subpool operator 1 |
| `operator-2.log` | Subpool operator 2 |
| `operator-3.log` | Subpool operator 3 |

Tail a log in real time:

```bash
tail -f tessera-demo/logs/sequencer.log
```

## Architecture

```
                     ┌──────────────┐
                     │    Anvil     │
                     │  (local EVM) │
                     └──────┬───────┘
                            │
          ┌─────────────────┼──────────────────┐
          │                 │                  │
┌─────────┴───────┐  ┌──────┴───────┐  ┌───────┴─────────┐
│ TesseraContract │  │   ToyUSDT    │  │AcceptAllVerifier│
│ (rollup bridge) │  │ (test ERC20) │  │ (stub verifier) │
└─────────┬───────┘  └──────────────┘  └─────────────────┘
          │
 ┌────────┴────────┐
 │ Demo Sequencer  │  :3000
 └────────┬────────┘
          │
  ┌───────┼───────┐
  │       │       │
  v       v       v
┌────┐  ┌────┐  ┌────┐
│ Op1│  │ Op2│  │ Op3│   Subpool Operators (poll sequencer + DB)
└──┬─┘  └──┬─┘  └──┬─┘
   │       │       │
   v       v       v
┌────┐  ┌────┐  ┌────┐
│DB 1│  │DB 2│  │DB 3│   Subpool DB APIs (:8081, :8082, :8083)
└──┬─┘  └──┬─┘  └──┬─┘
   │       │       │
   └───────┼───────┘
           v
     ┌────────────┐
     │ PostgreSQL │  :5432 (Docker)
     │ subpool_1  │
     │ subpool_2  │
     │ subpool_3  │
     └────────────┘
```

## Configuration reference

### services.env

| Variable | Default | Used by |
|----------|---------|---------|
| `RPC_URL` | `http://localhost:8545` | Sequencer, Operators, DB APIs |
| `CHAIN_ID` | `31337` | Sequencer |
| `BRIDGE_ADDRESS` | `0x`-prefixed address | Sequencer, Operators |
| `TOKEN_ADDRESS` | `0x`-prefixed address | Sequencer, DB APIs |
| `OPERATOR_KEY` | Anvil key #0, hex with or without `0x` | Sequencer, DB APIs (faucet) |
| `POSTGRES_USER` | `tessera` | PostgreSQL |
| `POSTGRES_PASSWORD` | `tessera` | PostgreSQL |
| `POSTGRES_DB` | `tessera` | PostgreSQL |
| `POSTGRES_PORT` | `5432` | PostgreSQL, DB APIs, Operators |
| `POSTGRES_CONTAINER_NAME` | `tessera-postgres` | Docker |
| `BIND_ADDR` | `127.0.0.1:3000` | Sequencer, Operators (derived) |
| `BATCH_TIMEOUT_SECS` | `10` | Sequencer |
| `PROVE_DELAY_SECS` | `10` | Sequencer |
| `DB_API_PORT_1` / `_2` / `_3` | `8081` / `8082` / `8083` | DB APIs |
| `DATABASE_MAX_CONNECTIONS` | `10` | DB APIs |
| `APPROVAL_PRIVATE_KEY` | Hex with or without `0x` | Operators |
| `POLL_INTERVAL_SECS` | `5` | Operators |
| `OPERATOR_DB_MAX_CONNECTIONS` | `5` | Operators |

## Scripts reference

| Script | Description |
|--------|-------------|
| `tessera-demo/scripts/services.env` | Shared configuration for all services |
| `tessera-demo/scripts/services_db.sh` | Start PostgreSQL + initialize schemas (standalone) |
| `tessera-demo/scripts/services_start.sh` | Start PostgreSQL + build + start all 7 Rust daemons |
| `tessera-demo/scripts/services_stop.sh` | Stop all services (supports `--keep-db`) |
| `tessera-demo/scripts/services_status.sh` | Show running/stopped status of each service |

## Troubleshooting

**Port already in use**: A previous run may not have been stopped cleanly.
Run `services_stop.sh`, or check for stale processes:
```bash
lsof -i :3000 -i :8081 -i :8082 -i :8083 -i :5432
```

**Database migration errors**: Check the DB API logs (`db-N.log`). The most
common cause is a stale schema from a previous run. Drop and recreate:
```bash
docker exec tessera-postgres psql -U tessera -d tessera \
  -c "DROP SCHEMA subpool_1 CASCADE; DROP SCHEMA subpool_2 CASCADE; DROP SCHEMA subpool_3 CASCADE;"
# Then re-run services_start.sh
```

**Operator connection refused**: Operators depend on both the sequencer and their
DB API being ready. Check that the sequencer is running (`curl localhost:3000/status`)
and the DB API is up before investigating operator logs.
