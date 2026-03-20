# tessera-e2e

End-to-end testing framework and artifact generation tooling for the Tessera
proving stack.

This crate provides:
- **Artifact generation binaries** — build and serialize all Plonky2, BN128, and
  Groth16 proving keys needed by the sequencer and E2E tests.
- **`InProcessProver`** — wraps `ProverRuntimeV2` so E2E tests can run the full
  proving pipeline in-process without an HTTP server.
- **`TesseraClientState`** — client-side state manager that builds PrivTx
  circuit inputs, generates real Plonky2 proofs, and tracks account/note
  commitments in a local flat commitment tree.
- **E2E tests** — four test scenarios that exercise the full pipeline from
  client proof to on-chain Groth16 verification.

---

## Proving Pipeline Overview

A single on-chain batch flows through four proving stages:

```
Client                        Sequencer / ProverRuntimeV2
──────                        ───────────────────────────
PrivTx proof  ──leaf──►  TX Aggregator  ──root──►  SuperAggregatorV2  ──►  BN128  ──►  Groth16
                                                         ▲
NC commitments  ─────────────────────────►  SubtreeRootCircuit  ──────┘
```

| Stage | Circuit | Artifact directory |
|---|---|---|
| **PrivTx** | Inner leaf circuit for each private transaction | _(embedded in aggregator artifacts)_ |
| **TX Aggregator** | `GenericAggregator` binary tree, depth 6, 64 leaves | `v2-tx-aggregator/` |
| **SubtreeRoot** | Proves `batchPoseidonRoot = Poseidon(512 NC leaves)` | `subtree-root/` |
| **SuperAggregatorV2** | Merges TX-agg root + SR proof → 8-word PI commitment | `super-aggregator-v2/` |
| **BN128 + Groth16** | Wraps SAV2 Plonky2 proof into on-chain Groth16 proof | `super-aggregator-v2/plonky2-proof/` + `groth-artifacts/` |

All five stages are built by a **single binary**: `super_aggregator_v2_artifacts`.
The prover (`ProverRuntimeV2`) can be deserialised from these artifacts alone.

Consume-validation proofs (deposit pipeline) additionally require the
`consume_artifacts` binary (see below).

---

## Prerequisites

| Tool | Purpose |
|------|---------|
| Rust (stable) | Build everything |
| Go ≥ 1.21 | CGo/gnark Groth16 wrapper (`tessera-trees/src/groth`) |
| [Foundry](https://getfoundry.sh) (`forge`) | Compile Solidity verifier after artifact generation |
| [Anvil](https://book.getfoundry.sh/anvil/) | Local EVM node for E2E tests (ships with Foundry) |

---

## Generating Artifacts

All artifact binaries read the output directory from `TESSERA_ARTIFACTS_DIR`.
If unset they default to `<workspace-root>/artifacts/`.

### Step 1 — All prover artifacts (main)

Runs every proving stage in sequence and verifies a full end-to-end dummy
round-trip (Plonky2 → BN128 → Groth16) before writing anything to disk.

The TX aggregator step uses an **O(log N) doubling trick**: one dummy PrivTx
leaf proof is proved once, then merged with itself at each tree level
(`merge(p, p) → p_next`).  For depth 6 this is 6 prove calls instead of 127.

```bash
TESSERA_ARTIFACTS_DIR=/path/to/artifacts \
cargo run -p tessera-e2e --bin super_aggregator_v2_artifacts --release
```

Expected output layout:

```
$TESSERA_ARTIFACTS_DIR/
  v2-tx-aggregator/                 TX GenericAggregator circuits (depth 6)
  v2-tx-aggregator/dummy_inner_tx_proof.bin
  subtree-root/                     SubtreeRootCircuit (512 NC leaves)
  super-aggregator-v2/              SAV2 Plonky2 circuit + dummy root proof
  super-aggregator-v2/dummy_inner_tx_proof.bin
  super-aggregator-v2/plonky2-proof/    BN128 wrapper circuit
  super-aggregator-v2/groth-artifacts/  Groth16 proving/verifying keys + Verifier.sol
```

After this step, `ProverRuntimeV2` can be deserialised and is ready to prove
real batches:

```rust
ProverRuntimeV2::init(
    artifacts_dir.join("subtree-root"),
    /* sr_batch_size */ 512,
    artifacts_dir.join("super-aggregator-v2"),
    Some(artifacts_dir.join("v2-tx-aggregator")),
    vec![],   // aggregation_prover_urls
    60,       // aggregation_prover_timeout_secs
)
```

> **Idempotency:** Steps 9 (BN128) and 10 (Groth16 trusted setup) are skipped
> when their output directories already exist.  Delete them to force a rebuild:
> ```bash
> rm -rf $TESSERA_ARTIFACTS_DIR/super-aggregator-v2/plonky2-proof
> rm -rf $TESSERA_ARTIFACTS_DIR/super-aggregator-v2/groth-artifacts
> ```

### Step 2 — Consume-circuit artifacts

Required for the deposit-validation pipeline.  Produces the leaf circuit used
by the client to prove each note consumption:

```bash
TESSERA_ARTIFACTS_DIR=/path/to/artifacts \
cargo run -p tessera-e2e --bin consume_artifacts --release
```

Output: `$TESSERA_ARTIFACTS_DIR/consume/{leaf_common,leaf_verifier,leaf_prover}.bin`

### Step 3 — Compile the Solidity verifier

After step 1 writes `tessera-solidity/src/VerifierSuperAggregatorV2.sol`,
compile it with Foundry so the Groth16 E2E test can load the bytecode:

```bash
cd tessera-solidity
forge build
```

Compiled artifact: `tessera-solidity/out/VerifierSuperAggregatorV2.sol/VerifierSuperAggregatorV2.json`

### Legacy V1 aggregator (rarely needed)

```bash
TESSERA_ARTIFACTS_DIR=/path/to/artifacts \
cargo run -p tessera-e2e --bin aggregator_artifacts --release
```

Output: `$TESSERA_ARTIFACTS_DIR/associated-input-aggregator/`

---

## Running the E2E Tests

```bash
# All tests — skip gracefully when TESSERA_ARTIFACTS_DIR is not set.
TESSERA_ARTIFACTS_DIR=/path/to/artifacts \
cargo test -p tessera-e2e --release -- --nocapture
```

Individual tests:

```bash
# FreshAcc TX → AcceptAll verifier (fastest)
cargo test -p tessera-e2e --release test_e2e_freshacc_real_proof -- --nocapture

# FreshAcc + Spend TX → AcceptAll verifier
cargo test -p tessera-e2e --release test_e2e_spend_real_proof -- --nocapture

# Deposit lifecycle → AcceptAll verifier
cargo test -p tessera-e2e --release test_e2e_deposit_real_proof -- --nocapture

# FreshAcc TX → real on-chain Groth16 verifier (requires steps 1–3 above)
cargo test -p tessera-e2e --release test_e2e_freshacc_groth16 -- --nocapture
```

`test_e2e_freshacc_groth16` additionally requires the Foundry `out/` directory
to be populated (step 3 above).  Override with `TESSERA_FOUNDRY_OUT`.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TESSERA_ARTIFACTS_DIR` | `<workspace>/artifacts` | Where artifact binaries write output and E2E tests read artifacts |
| `TESSERA_FOUNDRY_OUT` | `<workspace>/tessera-solidity/out` | Foundry output directory (used by `test_e2e_freshacc_groth16` to load verifier bytecode) |
| `TESSERA_DEBUG` | `0` | Set to `1` for verbose artifact-builder output |

---

## Artifact Compatibility

The batch size is fixed at `tessera_client::PRIV_TX_BATCH_SIZE = 64` and
compiled into all artifacts, the sequencer, and the on-chain contract tree
depth.  It cannot be changed at runtime.

After any change to the PrivTx circuit **all artifacts must be rebuilt** from
scratch:

```bash
rm -rf $TESSERA_ARTIFACTS_DIR
TESSERA_ARTIFACTS_DIR=/path/to/artifacts \
cargo run -p tessera-e2e --bin super_aggregator_v2_artifacts --release
TESSERA_ARTIFACTS_DIR=/path/to/artifacts \
cargo run -p tessera-e2e --bin consume_artifacts --release
cd tessera-solidity && forge build
```
