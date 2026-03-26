# tessera-subpool-operator

Operator service that processes pending requests for a Tessera subpool:

- **FreshAcc** — approves new account registrations, signs and posts to the sequencer
- **Deposits** — broadcasts deposit txs on-chain, creates deposit note commitments, updates account balances
- **Spend Txs** — validates private transactions, marks input notes as consumed, creates output notes for recipients

## Architecture

```
                         ┌──────────────┐
                         │   Sequencer  │
                         │  :3000       │
                         └──────┬───────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          │                     │                     │
  ┌───────┴────────┐   ┌───────┴────────┐   ┌───────┴────────┐
  │  Operator 1    │   │  Operator 2    │   │  Operator 3    │
  │  SUBPOOL_ID=1  │   │  SUBPOOL_ID=2  │   │  SUBPOOL_ID=3  │
  └───────┬────────┘   └───────┬────────┘   └───────┬────────┘
          │                     │                     │
  ┌───────┴────────┐   ┌───────┴────────┐   ┌───────┴────────┐
  │  DB API 1      │   │  DB API 2      │   │  DB API 3      │
  │  :8081         │   │  :8082         │   │  :8083         │
  └───────┬────────┘   └───────┬────────┘   └───────┬────────┘
          │                     │                     │
          └─────────────────────┼─────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    │  PostgreSQL           │
                    │  tessera DB           │
                    │  schemas: subpool_1,  │
                    │  subpool_2, subpool_3 │
                    └───────────────────────┘
```

Each operator + DB API pair connects to the same PostgreSQL database but with a different schema (`search_path`), providing full data isolation without separate databases.

### Cross-subpool note forwarding

When a spend tx has output notes destined for a different subpool, the operator forwards them through the sequencer which acts as a relay:

```
  Operator 1                  Sequencer                   Operator 2
  (subpool 1)                (central relay)              (subpool 2)
      │                           │                           │
      │  POST /forward_note       │                           │
      │  {target_subpool_id: 2,   │                           │
      │   identifier, amount, …}  │                           │
      │──────────────────────────>│                           │
      │                           │  note queued in pool[2]   │
      │                           │                           │
      │                           │  GET /pending_notes/2     │
      │                           │<──────────────────────────│
      │                           │                           │
      │                           │  [note1, note2, …]        │
      │                           │──────────────────────────>│
      │                           │                           │
      │                           │           insert_input_note()
      │                           │                           │
```

The target subpool ID is derived from the first 8 bytes of the recipient's account address (LE-encoded `SubpoolId`).

---

## Prerequisites

- Docker (for PostgreSQL)
- Rust toolchain
- Foundry (`anvil`, `forge`, `cast`)

---

## Single-subpool setup (quick start)

### 1. Start PostgreSQL

```bash
docker run -d \
  --name tessera-pg \
  -e POSTGRES_USER=tessera \
  -e POSTGRES_PASSWORD=tessera \
  -e POSTGRES_DB=tessera_subpool \
  -p 5432:5432 \
  postgres:16
```

### 2. Start Anvil

```bash
anvil --gas-limit 300000000
```

### 3. Deploy contracts

```bash
bash scripts/demo_b_deploy.sh
```

Note the `TesseraContract` and `ToyUSDT` addresses from the output.

### 4. Start the sequencer

```bash
bash scripts/demo_c_sequencer.sh
```

### 5. Start the DB API

```bash
DATABASE_URL=postgres://tessera:tessera@localhost:5432/tessera_subpool \
FAUCET_PRIVATE_KEY=0000000000000000000000000000000000000000000000000000000000000001 \
SEPOLIA_RPC_URL=http://localhost:8545 \
USDX_CONTRACT_ADDR=0x0000000000000000000000000000000000000000 \
cargo run -p tessera-subpool-database
```

### 6. Start the operator

Update `tessera-subpool-operator/.env` with the contract addresses from step 3, then:

```bash
cargo run -p tessera-subpool-operator
```

The operator reads its `.env` file automatically. Key variables:

```
DATABASE_URL=postgres://tessera:tessera@localhost:5432/tessera_subpool
SEQUENCER_URL=http://127.0.0.1:3000
APPROVAL_PRIVATE_KEY=deadbeef
RPC_URL=http://localhost:8545
ROLLUP_ADDRESS=<TesseraContract from step 3>
TOKEN_ADDRESS=<ToyUSDT from step 3>
```

### 7. Run the deposit test

```bash
cargo run -p tessera-subpool-operator --bin test-deposit
```

---

## Multi-subpool setup (3 subpools, manual)

This runs 3 subpools on a single machine: one PostgreSQL container with 3 schemas, 3 DB API instances, and 3 operator instances.

### 1. Start PostgreSQL with 3 schemas

```bash
docker run -d \
  --name tessera-pg \
  -e POSTGRES_USER=tessera \
  -e POSTGRES_PASSWORD=tessera \
  -e POSTGRES_DB=tessera \
  -p 5432:5432 \
  -v $(pwd)/docker/init-schemas.sql:/docker-entrypoint-initdb.d/01-init-schemas.sql \
  postgres:16
```

This creates database `tessera` with schemas `subpool_1`, `subpool_2`, `subpool_3`.

### 2. Start Anvil + deploy contracts + start sequencer

```bash
# Terminal 1
anvil --gas-limit 300000000

# Terminal 2
bash scripts/demo_b_deploy.sh

# Terminal 3
bash scripts/demo_c_sequencer.sh
```

### 3. Start 3 DB API instances

Each connects to a different schema via `search_path` and binds on a different port:

```bash
# Terminal 4 — subpool 1
DATABASE_URL="postgres://tessera:tessera@localhost:5432/tessera?options=-c search_path=subpool_1" \
TESSERA_SUBPOOL_API_ADDR="0.0.0.0:8081" \
SUBPOOL_ID=1 \
FAUCET_PRIVATE_KEY=0000000000000000000000000000000000000000000000000000000000000001 \
SEPOLIA_RPC_URL=http://localhost:8545 \
USDX_CONTRACT_ADDR=0x0000000000000000000000000000000000000000 \
cargo run -p tessera-subpool-database

# Terminal 5 — subpool 2
DATABASE_URL="postgres://tessera:tessera@localhost:5432/tessera?options=-c search_path=subpool_2" \
TESSERA_SUBPOOL_API_ADDR="0.0.0.0:8082" \
SUBPOOL_ID=2 \
FAUCET_PRIVATE_KEY=0000000000000000000000000000000000000000000000000000000000000001 \
SEPOLIA_RPC_URL=http://localhost:8545 \
USDX_CONTRACT_ADDR=0x0000000000000000000000000000000000000000 \
cargo run -p tessera-subpool-database

# Terminal 6 — subpool 3
DATABASE_URL="postgres://tessera:tessera@localhost:5432/tessera?options=-c search_path=subpool_3" \
TESSERA_SUBPOOL_API_ADDR="0.0.0.0:8083" \
SUBPOOL_ID=3 \
FAUCET_PRIVATE_KEY=0000000000000000000000000000000000000000000000000000000000000001 \
SEPOLIA_RPC_URL=http://localhost:8545 \
USDX_CONTRACT_ADDR=0x0000000000000000000000000000000000000000 \
cargo run -p tessera-subpool-database
```

### 4. Start 3 operator instances

```bash
# Terminal 7 — operator for subpool 1
DATABASE_URL="postgres://tessera:tessera@localhost:5432/tessera?options=-c search_path=subpool_1" \
SEQUENCER_URL=http://127.0.0.1:3000 \
APPROVAL_PRIVATE_KEY=deadbeef \
RPC_URL=http://localhost:8545 \
ROLLUP_ADDRESS=<TesseraContract from step 2> \
SUBPOOL_ID=1 \
cargo run -p tessera-subpool-operator

# Terminal 8 — operator for subpool 2
DATABASE_URL="postgres://tessera:tessera@localhost:5432/tessera?options=-c search_path=subpool_2" \
SEQUENCER_URL=http://127.0.0.1:3000 \
APPROVAL_PRIVATE_KEY=deadbeef \
RPC_URL=http://localhost:8545 \
ROLLUP_ADDRESS=<TesseraContract from step 2> \
SUBPOOL_ID=2 \
cargo run -p tessera-subpool-operator

# Terminal 9 — operator for subpool 3
DATABASE_URL="postgres://tessera:tessera@localhost:5432/tessera?options=-c search_path=subpool_3" \
SEQUENCER_URL=http://127.0.0.1:3000 \
APPROVAL_PRIVATE_KEY=deadbeef \
RPC_URL=http://localhost:8545 \
ROLLUP_ADDRESS=<TesseraContract from step 2> \
SUBPOOL_ID=3 \
cargo run -p tessera-subpool-operator
```

### 5. Run the E2E test

```bash
ROLLUP_ADDRESS=0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9 \
TOKEN_ADDRESS=0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0 \
cargo run -p tessera-subpool-operator --bin test-e2e
```

The test will:
1. Register 3 accounts (one per subpool, on ports 8081/8082/8083)
2. Wait for operator approval on each
3. Deposit funds for each client
4. Wait for deposits to be processed
5. Submit spend txs in a ring: client 1 → 2, client 2 → 3, client 3 → 1
6. Wait for spend txs to be approved

Cross-subpool spend txs (e.g. client 1 on subpool 1 sending to client 2 on subpool 2) are handled automatically by the operators via the sequencer's note forwarding relay:
1. Operator 1 approves the spend tx and POSTs the output note to the sequencer (`POST /forward_note`) with `target_subpool_id=2`
2. Operator 2 polls `GET /pending_notes/2` each tick, receives the note, and creates a local `input_note` for the recipient

---

## Multi-subpool setup (docker compose)

All services can also be started via docker compose:

```bash
docker compose up --build
```

This starts all 9 services (postgres, anvil, sequencer, 3 DB APIs, 3 operators). Note that contracts must be deployed separately after anvil is ready, and the `DEMO_BRIDGE_ADDRESS` / `DEMO_TOKEN_ADDRESS` in `docker-compose.yml` must be updated to match.

---

## Resetting the database

### Single-subpool (separate database)

```bash
docker exec -it tessera-pg psql -U tessera -c "DROP DATABASE tessera_subpool;"
docker exec -it tessera-pg psql -U tessera -c "CREATE DATABASE tessera_subpool;"
```

Then restart the DB API (it runs migrations on startup).

### Multi-subpool (schemas)

Reset all 3 schemas:

```bash
docker exec -it tessera-pg psql -U tessera -d tessera -c "
  DROP SCHEMA IF EXISTS subpool_1 CASCADE;
  DROP SCHEMA IF EXISTS subpool_2 CASCADE;
  DROP SCHEMA IF EXISTS subpool_3 CASCADE;
  CREATE SCHEMA subpool_1;
  CREATE SCHEMA subpool_2;
  CREATE SCHEMA subpool_3;
"
```

Then restart the 3 DB API instances (each will re-run migrations in its schema).

To reset a single subpool (e.g. subpool 2):

```bash
docker exec -it tessera-pg psql -U tessera -d tessera -c "
  DROP SCHEMA IF EXISTS subpool_2 CASCADE;
  CREATE SCHEMA subpool_2;
"
```

Then restart only the subpool-2 DB API.

### Full nuke (remove container and data)

```bash
docker rm -f tessera-pg
```

---

## Environment variables

### Operator (`tessera-subpool-operator`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | yes | | PostgreSQL connection string |
| `SEQUENCER_URL` | yes | | Sequencer HTTP endpoint |
| `APPROVAL_PRIVATE_KEY` | yes | | Hex-encoded Schnorr private key |
| `RPC_URL` | yes | | Ethereum JSON-RPC URL |
| `ROLLUP_ADDRESS` | yes | | Deployed TesseraRollupV2 contract address |
| `SUBPOOL_ID` | no | `1` | Subpool identifier for this operator |
| `POLL_INTERVAL_SECS` | no | `5` | Polling interval in seconds |
| `DATABASE_MAX_CONNECTIONS` | no | `5` | Max DB pool connections |

### DB API (`tessera-subpool-database`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | yes | | PostgreSQL connection string |
| `TESSERA_SUBPOOL_API_ADDR` | no | `0.0.0.0:8080` | HTTP bind address |
| `SUBPOOL_ID` | no | `1` | Subpool identifier (must match operator) |
| `FAUCET_PRIVATE_KEY` | yes | | Faucet wallet private key (hex) |
| `SEPOLIA_RPC_URL` | yes | | RPC URL for faucet |
| `USDX_CONTRACT_ADDR` | yes | | Faucet token contract address |
| `DATABASE_MAX_CONNECTIONS` | no | `10` | Max DB pool connections |

### E2E test (`test-e2e`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ROLLUP_ADDRESS` | yes | | Deployed TesseraContract address |
| `TOKEN_ADDRESS` | yes | | Deployed ToyUSDT address |
| `RPC_URL` | no | `http://localhost:8545` | Anvil RPC |
| `DB_API_BASE` | no | `http://localhost` | Base URL (ports 8081-8083 appended) |
| `DEPOSIT_AMOUNT` | no | `1000` | Deposit amount per client |
| `ASSET_ID` | no | `1` | Asset ID |

---

## Transaction lifecycle

This section describes how each transaction type flows through the system, which services interact, and how the database is updated at each step.

### Database tables

| Table | Purpose |
|-------|---------|
| `freshacc_requests` | Pending/approved account registration requests |
| `accounts` | Approved accounts with balance, nonce, AST |
| `users` | User KYC data linked to accounts |
| `deposit_tx_requests` | Pending/approved deposit requests with signed ETH tx |
| `input_notes` | Notes available to spend (PENDING → APPROVED → REJECTED) |
| `output_notes` | Output notes created by spend txs |
| `spend_tx_requests` | Pending/approved private spend transactions |

### 1. Account registration (FreshAcc)

```
 Client              DB API             DB                Operator           Sequencer         Chain
   │                   │                 │                   │                  │                │
   │ POST /register    │                 │                   │                  │                │
   │──────────────────>│                 │                   │                  │                │
   │                   │ INSERT INTO     │                   │                  │                │
   │                   │ freshacc_requests                   │                  │                │
   │                   │ (status=PENDING)│                   │                  │                │
   │                   │────────────────>│                   │                  │                │
   │  {acc_address}    │                 │                   │                  │                │
   │<──────────────────│                 │                   │                  │                │
   │                   │                 │                   │                  │                │
   │                   │                 │  poll PENDING     │                  │                │
   │                   │                 │  freshacc_requests│                  │                │
   │                   │                 │<──────────────────│                  │                │
   │                   │                 │                   │                  │                │
   │                   │                 │                   │ POST /transaction│                │
   │                   │                 │                   │ (accin_null,     │                │
   │                   │                 │                   │  accout_comm,    │                │
   │                   │                 │                   │  approval_sig)   │                │
   │                   │                 │                   │─────────────────>│                │
   │                   │                 │                   │                  │ batch + prove  │
   │                   │                 │                   │                  │───────────────>│
   │                   │                 │                   │                  │                │
   │                   │                 │  UPDATE           │                  │                │
   │                   │                 │  freshacc_requests│                  │                │
   │                   │                 │  SET status=      │                  │                │
   │                   │                 │  APPROVED         │                  │                │
   │                   │                 │<──────────────────│                  │                │
   │                   │                 │                   │                  │                │
   │                   │                 │  INSERT INTO      │                  │                │
   │                   │                 │  accounts + users │                  │                │
   │                   │                 │<──────────────────│                  │                │
   │                   │                 │                   │                  │                │
```

**DB changes:**
1. `freshacc_requests`: INSERT with status=PENDING (by DB API on `/register`)
2. `freshacc_requests`: UPDATE status=APPROVED (by operator after sequencer accepts)
3. `accounts`: INSERT new account row with zero balance (by operator)
4. `users`: INSERT KYC row (by operator)

### 2. Deposit

```
 Client              DB API             DB                Operator           Sequencer         Chain
   │                   │                 │                   │                  │                │
   │ mint + approve    │                 │                   │                  │                │
   │ (on-chain ERC20)  │                 │                   │                  │       ┌────────│
   │──────────────────────────────────────────────────────────────────────────────────> │  ERC20 │
   │                   │                 │                   │                  │       └────────│
   │                   │                 │                   │                  │                │
   │ build signed      │                 │                   │                  │                │
   │ depositAndRegister│                 │                   │                  │                │
   │ tx (NOT broadcast)│                 │                   │                  │                │
   │                   │                 │                   │                  │                │
   │ POST /deposit     │                 │                   │                  │                │
   │ {signed_tx,       │                 │                   │                  │                │
   │  note_id, amount} │                 │                   │                  │                │
   │──────────────────>│                 │                   │                  │                │
   │                   │ INSERT INTO     │                   │                  │                │
   │                   │ deposit_tx_     │                   │                  │                │
   │                   │ requests        │                   │                  │                │
   │                   │ (status=PENDING)│                   │                  │                │
   │                   │────────────────>│                   │                  │                │
   │                   │                 │                   │                  │                │
   │                   │                 │  poll PENDING     │                  │                │
   │                   │                 │  deposit_tx_      │                  │                │
   │                   │                 │  requests         │                  │                │
   │                   │                 │<──────────────────│                  │                │
   │                   │                 │                   │                  │                │
   │                   │                 │                   │ broadcast signed │                │
   │                   │                 │                   │ deposit tx       │                │
   │                   │                 │                   │─────────────────────────────────> │
   │                   │                 │                   │                  │   confirmed    │
   │                   │                 │                   │<──────────────────────────────────│
   │                   │                 │                   │                  │                │
   │                   │                 │                   │ POST /deposit    │                │
   │                   │                 │                   │ (note_commitment)│                │
   │                   │                 │                   │─────────────────>│                │
   │                   │                 │                   │                  │ batch + prove  │
   │                   │                 │                   │                  │───────────────>│
   │                   │                 │                   │                  │                │
   │                   │                 │  UPDATE           │                  │                │
   │                   │                 │  deposit_tx_      │                  │                │
   │                   │                 │  requests         │                  │                │
   │                   │                 │  SET status=      │                  │                │
   │                   │                 │  APPROVED         │                  │                │
   │                   │                 │<──────────────────│                  │                │
   │                   │                 │                   │                  │                │
   │                   │                 │  UPDATE accounts  │                  │                │
   │                   │                 │  SET balance,     │                  │                │
   │                   │                 │  nonce, ast       │                  │                │
   │                   │                 │<──────────────────│                  │                │
   │                   │                 │                   │                  │                │
   │                   │                 │  INSERT INTO      │                  │                │
   │                   │                 │  input_notes      │                  │                │
   │                   │                 │  (status=PENDING, │                  │                │
   │                   │                 │   note_commitment)│                  │                │
   │                   │                 │<──────────────────│                  │                │
   │                   │                 │                   │                  │                │
   │                   │                 │         ... later, on-chain confirmation ...          │
   │                   │                 │                   │                  │                │
   │                   │                 │                   │ getDeposit(comm) │                │
   │                   │                 │                   │──────────────────────────────────>│
   │                   │                 │                   │                  │  status=2      │
   │                   │                 │                   │<──────────────────────────────────│
   │                   │                 │                   │                  │  (Validated)   │
   │                   │                 │                   │                  │                │
   │                   │                 │  UPDATE           │                  │                │
   │                   │                 │  input_notes      │                  │                │
   │                   │                 │  SET status=      │                  │                │
   │                   │                 │  APPROVED         │                  │                │
   │                   │                 │<──────────────────│                  │                │
   │                   │                 │                   │                  │                │
```

**DB changes:**
1. `deposit_tx_requests`: INSERT with status=PENDING, signed_public_tx (by DB API on `/deposit`)
2. `deposit_tx_requests`: UPDATE status=APPROVED (by operator after broadcast + sequencer accepts)
3. `accounts`: UPDATE balance, nonce, AST (by operator)
4. `input_notes`: INSERT with status=PENDING, note_commitment (by operator)
5. `input_notes`: UPDATE status=APPROVED (by operator after on-chain `getDeposit()` returns Validated)

### 3. Spend transaction (same subpool)

```
 Client              DB API             DB                Operator           Sequencer         Chain
   │                   │                 │                   │                  │                │
   │ POST /spend_tx    │                 │                   │                  │                │
   │ {acc_addr,        │                 │                   │                  │                │
   │  input_notes: [], │                 │                   │                  │                │
   │  output_notes:    │                 │                   │                  │                │
   │  [{recipient,     │                 │                   │                  │                │
   │    amount}]}      │                 │                   │                  │                │
   │──────────────────>│                 │                   │                  │                │
   │                   │ INSERT INTO     │                   │                  │                │
   │                   │ spend_tx_       │                   │                  │                │
   │                   │ requests        │                   │                  │                │
   │                   │ (status=PENDING)│                   │                  │                │
   │                   │────────────────>│                   │                  │                │
   │                   │ INSERT INTO     │                   │                  │                │
   │                   │ output_notes    │                   │                  │                │
   │                   │────────────────>│                   │                  │                │
   │                   │                 │                   │                  │                │
   │                   │                 │  poll PENDING     │                  │                │
   │                   │                 │  spend_tx_requests│                  │                │
   │                   │                 │<──────────────────│                  │                │
   │                   │                 │                   │                  │                │
   │                   │                 │     sanity checks:│                  │                │
   │                   │                 │     - account exists                 │                │
   │                   │                 │     - input notes APPROVED           │                │
   │                   │                 │     - balance equation               │                │
   │                   │                 │                   │                  │                │
   │                   │                 │                   │ POST /transaction│                │
   │                   │                 │                   │─────────────────>│                │
   │                   │                 │                   │                  │ batch + prove  │
   │                   │                 │                   │                  │───────────────>│
   │                   │                 │                   │                  │                │
   │                   │                 │  UPDATE input_notes                  │                │
   │                   │                 │  SET status=      │                  │                │
   │                   │                 │  REJECTED         │                  │                │
   │                   │                 │  (consumed)       │                  │                │
   │                   │                 │<──────────────────│                  │                │
   │                   │                 │                   │                  │                │
   │                   │                 │  UPDATE           │                  │                │
   │                   │                 │  spend_tx_requests│                  │                │
   │                   │                 │  SET status=      │                  │                │
   │                   │                 │  APPROVED         │                  │                │
   │                   │                 │<──────────────────│                  │                │
   │                   │                 │                   │                  │                │
   │                   │                 │  UPDATE accounts  │                  │                │
   │                   │                 │  SET balance,     │                  │                │
   │                   │                 │  nonce            │                  │                │
   │                   │                 │<──────────────────│                  │                │
   │                   │                 │                   │                  │                │
   │                   │                 │  INSERT INTO      │                  │                │
   │                   │                 │  input_notes      │                  │                │
   │                   │                 │  (for local       │                  │                │
   │                   │                 │   recipient,      │                  │                │
   │                   │                 │   status=APPROVED)│                  │                │
   │                   │                 │<──────────────────│                  │                │
   │                   │                 │                   │                  │                │
```

**DB changes:**
1. `spend_tx_requests`: INSERT with status=PENDING (by DB API on `/spend_tx`)
2. `output_notes`: INSERT output note rows (by DB API on `/spend_tx`)
3. `input_notes`: UPDATE status=REJECTED for consumed input notes (by operator)
4. `spend_tx_requests`: UPDATE status=APPROVED (by operator)
5. `accounts`: UPDATE balance, nonce (by operator)
6. `input_notes`: INSERT with status=APPROVED for local recipient (by operator)

### 4. Spend transaction (cross-subpool)

Same as above for steps 1–5 on the sender's subpool. The difference is in step 6: if the recipient is on a different subpool, the operator forwards the note through the sequencer relay instead of inserting locally.

```
 Operator 1          Sequencer           Operator 2          DB (subpool 2)
 (sender's           (relay)             (recipient's
  subpool)                                subpool)
   │                    │                    │                    │
   │ POST /forward_note │                    │                    │
   │ {target_subpool: 2,│                    │                    │
   │  identifier,       │                    │                    │
   │  amount, asset_id, │                    │                    │
   │  recipient_addr,   │                    │                    │
   │  sender_addr}      │                    │                    │
   │───────────────────>│                    │                    │
   │                    │ queue in pool[2]   │                    │
   │                    │                    │                    │
   │                    │                    │  (next poll tick)  │
   │                    │ GET /pending_notes/2                    │
   │                    │<───────────────────│                    │
   │                    │                    │                    │
   │                    │ [{note1}, ...]     │                    │
   │                    │───────────────────>│                    │
   │                    │                    │                    │
   │                    │                    │ INSERT INTO        │
   │                    │                    │ input_notes        │
   │                    │                    │ (status=APPROVED)  │
   │                    │                    │───────────────────>│
   │                    │                    │                    │
```

**DB changes (on recipient's subpool):**
1. `input_notes`: INSERT with status=APPROVED (by recipient's operator after polling sequencer)

### Note lifecycle summary

```
                    ┌──────────────────────────────────────────────┐
                    │              input_notes.status               │
                    │                                              │
  deposit approved  │   PENDING ──── on-chain confirmed ──> APPROVED
                    │                (getDeposit → Validated)      │
                    │                                              │
  forwarded note    │                              ┌────> APPROVED │
  received          │                              │               │
                    │                              │               │
  spend tx consumes │   APPROVED ──── consumed ──> REJECTED       │
                    │                                              │
                    └──────────────────────────────────────────────┘
```

- **PENDING**: Note commitment exists but not yet confirmed on-chain. Cannot be spent.
- **APPROVED**: Note is confirmed and available to spend.
- **REJECTED**: Note has been consumed by a spend tx. Cannot be spent again.

---

## Binaries

| Binary | Command | Description |
|--------|---------|-------------|
| `tessera-subpool-operator` | `cargo run -p tessera-subpool-operator` | Main operator service |
| `test-deposit` | `cargo run -p tessera-subpool-operator --bin test-deposit` | Single-client deposit test |
| `test-e2e` | `cargo run -p tessera-subpool-operator --bin test-e2e` | 3-client multi-subpool E2E test |
