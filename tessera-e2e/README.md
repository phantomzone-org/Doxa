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
- **E2E tests** — test scenarios that exercise the full pipeline from
  client proof to on-chain Groth16 verification.

---

## Proving Pipeline Overview

### TX pipeline

```
Client                        Sequencer / ProverRuntimeV2
──────                        ───────────────────────────
PrivTx proof  ──leaf──►  TX Aggregator  ──root──►  SuperAggregator  ──►  BN128  ──►  Groth16
                                                         ▲
NC commitments  ─────────────────────────►  SubtreeRootCircuit  ──────┘
```

| Stage | Circuit | Artifact directory |
|---|---|---|
| **PrivTx** | Inner leaf circuit for each private transaction | _(embedded in aggregator artifacts)_ |
| **TX Aggregator** | `GenericAggregator` binary tree, depth 6, 64 leaves | `v2-tx-aggregator/` |
| **SubtreeRoot** | Proves `batchPoseidonRoot = Poseidon(512 SR leaves: 7 NC + 1 AC per slot)` | `subtree-root/` |
| **SuperAggregator** | Merges TX-agg root + SR proof → 8-word PI commitment | `super-aggregator-v2/` |
| **BN128 + Groth16** | Wraps Final Plonky2 Proof Plonky2 proof into on-chain Groth16 proof | `super-aggregator-v2/plonky2-proof/` + `super-aggregator-v2/groth-artifacts/` |

All TX stages are built by: `super_aggregator_v2_artifacts`.
This binary also copies `TesseraBatchTransactionVerifier.sol` into `tessera-solidity/src/`
and runs `forge build` automatically.

### Deposit pipeline

```
Client                        Sequencer / ProverRuntimeV2
──────                        ───────────────────────────
Deposit-TX proof  ──leaf──►  Deposit Aggregator  ──root──►  DepositSuperAggregatorV2  ──►  BN128  ──►  Groth16
                                                                    ▲
Deposit NCs  ──────────────────────────────────►  SubtreeRootCircuit  ──────────────┘
```

| Stage | Circuit | Artifact directory |
|---|---|---|
| **Deposit-TX** | Inner leaf circuit for each deposit (31 PIs) | _(embedded in aggregator artifacts)_ |
| **Deposit Aggregator** | `GenericAggregator` binary tree, depth 9, 512 leaves | `deposit-tx-aggregator/` |
| **Deposit SubtreeRoot** | Proves `batchPoseidonRoot = Poseidon(512 deposit NCs)` | `deposit-subtree-root/` |
| **DepositSuperAggregatorV2** | Merges deposit-agg root + SR proof → 8-word PI commitment | `deposit-super-aggregator-v2/` |
| **BN128 + Groth16** | Wraps DSAV2 Plonky2 proof into on-chain Groth16 proof | `deposit-super-aggregator-v2/plonky2-proof/` + `deposit-super-aggregator-v2/groth-artifacts/` |

All deposit stages are built by: `deposit_tx_artifacts`.
This binary also copies `VerifierDepositSuperAggregatorV2.sol` into `tessera-solidity/src/`
and runs `forge build` automatically.

---

## Prerequisites

| Tool | Purpose |
|------|---------|
| Rust (stable) | Build everything |
| Go >= 1.21 | CGo/gnark Groth16 wrapper (`tessera-trees/src/groth`) |
| [Foundry](https://getfoundry.sh) (`forge`) | Compile Solidity verifiers (invoked automatically by artifact binaries) |
| [Anvil](https://book.getfoundry.sh/anvil/) | Local EVM node for E2E tests (ships with Foundry) |

---

## Generating Artifacts

All artifact binaries read the output directory from `TESSERA_ARTIFACTS_DIR`.
If unset they default to `<workspace-root>/artifacts/`. The commands below pin
it to `tessera-e2e/artifacts` (relative to the workspace root).

### Generate everything

```bash
export TESSERA_ARTIFACTS_DIR=$(pwd)/tessera-e2e/artifacts

# TX pipeline: inner PrivTx circuit, aggregator, SubtreeRoot, Final Plonky2 Proof, BN128, Groth16, consume circuit
cargo run -p tessera-e2e --bin tx_artifacts --release
```

Both binaries invoke `forge build` internally once they have written their
respective `Verifier*.sol` files — no manual Foundry step required.

### Step 1 — TX artifacts (`tx_artifacts`)

Builds every artifact needed for the TX proving pipeline in one shot:

- **Step 0** — consume-request leaf circuit (`consume/`)
- **Steps 1–3** — inner PrivTx circuit, TX aggregator (O(log N) doubling trick), tree aggregation
- **Steps 4–5** — extract SR leaves, build + prove SubtreeRootCircuit
- **Steps 6–8** — build + prove SuperAggregator, store artifacts
- **Steps 9–11** — BN128 wrap, Groth16 trusted setup, round-trip verification
- **Step 12** — copy `TesseraBatchTransactionVerifier.sol` → `tessera-solidity/src/`, run `forge build`
- **Step 13** — build 2-slot unit-test Final Plonky2 Proof circuit (used by `cargo test`)

```bash
TESSERA_ARTIFACTS_DIR=$(pwd)/tessera-e2e/artifacts \
cargo run -p tessera-e2e --bin tx_artifacts --release
```

Output layout:

```
$TESSERA_ARTIFACTS_DIR/
  consume/                                 Consume-request leaf circuit
  consume/leaf_common.bin
  consume/leaf_verifier.bin
  consume/leaf_prover.bin
  v2-tx-aggregator/                        TX GenericAggregator circuits (depth 6)
  v2-tx-aggregator/dummy_inner_tx_proof.bin
  subtree-root/                            SubtreeRootCircuit (512 SR leaves)
  super-aggregator-v2/                     Final Plonky2 Proof Plonky2 circuit + dummy root proof
  super-aggregator-v2/dummy_inner_tx_proof.bin
  super-aggregator-v2/plonky2-proof/       BN128 wrapper circuit
  super-aggregator-v2/groth-artifacts/     Groth16 proving/verifying keys + Verifier.sol
  sav2-unit-test/                          2-slot Final Plonky2 Proof for unit tests

tessera-solidity/src/TesseraBatchTransactionVerifier.sol   ← written by this binary
tessera-solidity/out/                                ← populated by forge build
```

After this step, `ProverRuntimeV2` can be initialised for TX proving:

```rust
ProverRuntimeV2::init(
    artifacts_dir.join("subtree-root"),
    /* sr_batch_size */ 512,
    artifacts_dir.join("super-aggregator-v2"),
    Some(artifacts_dir.join("v2-tx-aggregator")),
    vec![],   // aggregation_prover_urls
    60,       // aggregation_prover_timeout_secs
    None,     // deposit — pass DepositPipelineConfig after step 2
)
```

> **Idempotency:** The BN128 and Groth16 trusted-setup steps are skipped
> when their output directories already exist.  Delete them to force a rebuild:
> ```bash
> rm -rf $TESSERA_ARTIFACTS_DIR/super-aggregator-v2/plonky2-proof
> rm -rf $TESSERA_ARTIFACTS_DIR/super-aggregator-v2/groth-artifacts
> ```

### Step 2 — Deposit artifacts (`deposit_artifacts`)

Builds every artifact needed for the deposit proving pipeline in one shot:

- **Steps 1–3** — deposit-TX circuit, deposit aggregator (O(log N) doubling), tree aggregation
- **Steps 4–5** — extract deposit NC leaves, build + prove deposit SubtreeRootCircuit
- **Steps 6–8** — build + prove DepositSuperAggregatorV2, store artifacts
- **Steps 9–11** — BN128 wrap, Groth16 trusted setup (label=`"deposit"`), round-trip verification
- **Step 12** — copy `VerifierDepositSuperAggregatorV2.sol` → `tessera-solidity/src/`, run `forge build`

```bash
TESSERA_ARTIFACTS_DIR=$(pwd)/tessera-e2e/artifacts \
cargo run -p tessera-e2e --bin deposit_artifacts --release
```

Output layout:

```
$TESSERA_ARTIFACTS_DIR/
  deposit-tx-aggregator/                        Deposit GenericAggregator circuits (depth 9)
  deposit-tx-aggregator/dummy_inner_deposit_proof.bin
  deposit-subtree-root/                         SubtreeRootCircuit (512 deposit NCs)
  deposit-super-aggregator-v2/                  DSAV2 Plonky2 circuit + dummy root proof
  deposit-super-aggregator-v2/dummy_root_proof.bin
  deposit-super-aggregator-v2/dummy_inner_deposit_proof.bin
  deposit-super-aggregator-v2/plonky2-proof/    BN128 wrapper circuit
  deposit-super-aggregator-v2/groth-artifacts/  Groth16 proving/verifying keys (label="deposit")

tessera-solidity/src/VerifierDepositSuperAggregatorV2.sol  ← written by this binary
tessera-solidity/test/fixtures/groth16_deposit_proof.json  ← written by this binary
tessera-solidity/out/                                      ← updated by forge build
```

After both steps, pass `DepositPipelineConfig` to enable the deposit pipeline:

```rust
ProverRuntimeV2::init(
    ...,
    Some(DepositPipelineConfig {
        deposit_tx_aggregator_path:    artifacts_dir.join("deposit-tx-aggregator"),
        deposit_subtree_root_path:     artifacts_dir.join("deposit-subtree-root"),
        deposit_super_aggregator_path: artifacts_dir.join("deposit-super-aggregator-v2"),
    }),
)
```

> **Idempotency:** Same as step 1 — delete the inner directories to force a rebuild:
> ```bash
> rm -rf $TESSERA_ARTIFACTS_DIR/deposit-super-aggregator-v2/plonky2-proof
> rm -rf $TESSERA_ARTIFACTS_DIR/deposit-super-aggregator-v2/groth-artifacts
> ```

---

## Running the E2E Tests

```bash
export TESSERA_ARTIFACTS_DIR=$(pwd)/tessera-e2e/artifacts

# All tests — skip gracefully when artifacts are absent.
cargo test -p tessera-e2e --release -- --nocapture
```

Individual tests and their artifact requirements:

| Test | Requires | Description |
|------|----------|-------------|
| `test_e2e_freshacc_groth16` | Step 1 | FreshAcc TX → real on-chain Groth16 TX verifier |
| `test_e2e_deposit_groth16` | Steps 1 + 2 | Deposit lifecycle → real on-chain Groth16 deposit verifier |

```bash
# FreshAcc TX → real on-chain Groth16 verifier (requires step 1)
TESSERA_ARTIFACTS_DIR=$(pwd)/tessera-e2e/artifacts \
cargo test -p tessera-e2e --release test_e2e_freshacc_groth16 -- --nocapture

# Deposit lifecycle → real on-chain Groth16 deposit verifier (requires steps 1 + 2)
TESSERA_ARTIFACTS_DIR=$(pwd)/tessera-e2e/artifacts \
cargo test -p tessera-e2e --release test_e2e_deposit_groth16 -- --nocapture
```

Tests skip with a clear message when their required artifacts are absent — they
do not fail.  Override the Foundry output directory with `TESSERA_FOUNDRY_OUT`
if the compiled contracts live elsewhere.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TESSERA_ARTIFACTS_DIR` | `<workspace>/artifacts` | Where artifact binaries write output and E2E tests read artifacts |
| `TESSERA_FOUNDRY_OUT` | `<workspace>/tessera-solidity/out` | Foundry output directory (used by E2E tests to load verifier bytecode) |
| `TESSERA_DEBUG` | `0` | Set to `1` for verbose artifact-builder output |

---

## Artifact Compatibility

The batch size is fixed at `tessera_client::PRIV_TX_BATCH_SIZE = 64` and
compiled into all artifacts, the sequencer, and the on-chain contract tree
depth.  It cannot be changed at runtime.

After any change to the PrivTx or deposit-TX circuit **all artifacts must be
rebuilt** from scratch:

```bash
export TESSERA_ARTIFACTS_DIR=$(pwd)/tessera-e2e/artifacts
rm -rf $TESSERA_ARTIFACTS_DIR

cargo run -p tessera-e2e --bin tx_artifacts --release && \
cargo run -p tessera-e2e --bin deposit_artifacts --release
```
