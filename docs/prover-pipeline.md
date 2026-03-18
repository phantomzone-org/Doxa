# Prover Pipeline

Sources: `tessera-trees/src/proof_aggregation/`, `tessera-server/src/prover_v2.rs`

---

## Purpose

The prover takes a `ProveRequestV2` (128 NC leaves + per-slot PrivTx proofs) and produces a Groth16 `SolidityProof` that the contract can verify on-chain. It does so through five successive layers of proof work.

---

## End-to-End Flow

```
ProveRequestV2
  │
  ├─[1]─ TX Aggregation Tree          (GenericAggregator, arity=2 depth=7)
  │       128 leaf proofs → 1 root proof
  │
  ├─[2]─ SubtreeRootCircuit           (Poseidon Merkle over 128 NC leaves)
  │       Input: nc_leaves[0..128]
  │       Output: batchPoseidonRoot proof
  │
  ├─[3]─ Off-circuit NC cross-check
  │       Assert TX NC[s][j] == nc_leaves[s*8 + j]  for all s, j
  │
  ├─[4]─ SuperAggregatorV2            (Plonky2 recursive circuit)
  │       Verify TX agg proof + SR proof in-circuit
  │       Build Keccak-256 piCommitment → 8 u32 public inputs
  │       Output: ProofNative
  │
  ├─[5]─ BN128Wrapper                 (field translation Goldilocks → BN254)
  │       Output: ProofBN128
  │
  └─[6]─ Groth16 (gnark FFI)
          Input: ProofBN128, proving key
          Output: SolidityProof { proof[8], commitments[2], commitmentPok[2] }
```

---

## Layer 1 — TX Aggregation (`GenericAggregator`)

Source: `tessera-trees/src/proof_aggregation/generic.rs`

A binary tree of recursive verifier circuits (arity=2, depth=7) reduces 128 leaf proofs to a single root proof. The root proof's public inputs are the concatenation of all 128 leaf PI arrays (each 77 elements), totalling 128 × 77 = 9856 field elements.

**Leaf inputs:**
- Real TX slots: the PrivTx proof supplied by the client (85 PIs, but the aggregator reads the first 77 as `TX_LEAF_PI_SIZE`).
- Empty/deposit slots: a pre-built dummy proof (`not_fake_tx = 0`).

**Aggregation node (`level l`, `node n`):**
- Verifies `arity` proofs from level `l-1` (or leaf proofs at level 0).
- Concatenates their public inputs as the node's own public inputs.
- Recurses until the root.

**Streaming / parallel execution** (`aggregation_pipeline/session.rs`):
- Each leaf proof is submitted independently via `AggregationInputHandle::submit(leaf_idx, proof)`.
- An actor tracks `NodeState` per tree node; once all children of a node are filled it dispatches `prove_node_blocking()`.
- Dispatching goes through `NodeProverPool` (round-robin, local threads or remote HTTP workers).
- The root proof resolves an `AggregationRootFuture`.

**Artifacts:** `artifacts/aggregator/` — must be built once, loaded for all subsequent proving runs.

---

## Layer 2 — Subtree Root Circuit (`SubtreeRootCircuit`)

Source: `tessera-trees/src/proof_aggregation/subtree_root.rs`

Proves `batchPoseidonRoot = PoseidonMerkle(nc_leaves[0..128])` in-circuit (depth-7 binary tree, no direction bit).

**Public inputs:** `[root[4] | leaf0[4] | … | leaf127[4]]` — 4 + 128 × 4 = 516 field elements.

**Native helper (used off-circuit to sanity-check):**
```rust
SubtreeRootCircuit::compute_root_native(leaves) → HashOutput
```

**Artifacts:** `artifacts/subtree-root/`

---

## Layer 3 — Off-Circuit NC Cross-Check

Before entering `SuperAggregatorV2`, the prover verifies natively that:

```
∀ slot s ∈ [0, 16), note j ∈ [0, 8):
    tx_agg_pi[s * TX_LEAF_PI_SIZE + NC_OFF + j*4 .. +4]
        == nc_leaves[s * 8 + j]
```

where `NC_OFF = TX_DATA_OFFSET + 40 = 45`. This ensures the NC leaves committed to by the TX proofs are exactly the leaves handed to the SubtreeRootCircuit. If this check fails the prover aborts before building the expensive SA circuit.

---

## Layer 4 — SuperAggregatorV2

Source: `tessera-trees/src/proof_aggregation/super_aggregator_v2.rs`

A Plonky2 circuit that:

1. **Verifies the TX aggregation root proof** in-circuit (inner verifier for `GenericAggregator`).
2. **Verifies the SubtreeRoot proof** in-circuit (inner verifier for `SubtreeRootCircuit`).
3. **Cross-checks NC leaves** — for every slot `s` and note index `j`, asserts that `TX_PI[s][NC_OFF+j*4..+4] == SR_PI[1 + (s*8+j)*4 .. +4]`. This is the in-circuit counterpart of the Layer 3 native check.
4. **Allocates private witnesses** for `ac_root`, `nc_root`, `mainPoolConfigRoot` (not derived from inner proofs; the sequencer supplies them and the contract verifies they match on-chain).
5. **Builds the Keccak-256 preimage** (all batch fields in Solidity ABI order; see [contract-pipeline.md](contract-pipeline.md) for the exact layout).
6. **Hashes with in-circuit Keccak-256** (custom generator `Keccak256StarkProofGenerator`) to produce 256 bits.
7. **Outputs `piCommitment`** as 8 × u32 big-endian public inputs.

**PI layout of the SA proof:**

| Index | Content |
|-------|---------|
| `[0..8]` | `piCommitment` — 8 × u32 big-endian Keccak-256 words |

**Generator serializer:** `TesseraGeneratorSerializer` (24 standard + 10 custom generators, including `Keccak256SingleGenerator` and `Keccak256StarkProofGenerator<F, ConfigNative, D>`).

**Artifacts:** `artifacts/super-aggregator-v2/`

---

## Layer 5 — BN128Wrapper

Source: `tessera-trees/src/groth/wrapper.rs`

Translates the Plonky2 `ProofNative` (Goldilocks field, p = 2⁶⁴ − 2³² + 1) into a `ProofBN128` compatible with the BN254 scalar field used by gnark.

- Goldilocks field elements are decomposed into BN254-compatible witnesses.
- G1/G2 curve points from the Plonky2 proof are converted.
- Polynomial constraint witnesses are re-encoded under the BN254 R1CS.

Output is a `ProofBN128` struct carrying the translated proof and witness values.

---

## Layer 6 — Groth16 (gnark FFI)

Source: `tessera-trees/src/groth/`

Calls the gnark prover via FFI:

```
Input:  ProofBN128 (serialised to JSON), ProvingKey (from artifacts)
Output: (proof_bytes, pub_input_bytes)
```

The Groth16 proof uses Pedersen commitments + a proof-of-knowledge of the commitment randomness (required by the gnark `CommitmentScheme`).

**SolidityProof format:**
```json
{
  "proof":         [u256 × 8],   // A (G1), B (G2), C (G1) encoded
  "commitments":   [u256 × 2],   // Pedersen commitment point
  "commitmentPok": [u256 × 2]    // Proof of knowledge
}
```

This is passed directly to `proveTransactionBatch(piCommitment, proof)` on the contract.

---

## Artifact Lifecycle

All circuit artifacts (proving key, verifying key, circuit data) are built once and stored on disk. The prover binary checks for their existence at startup and rebuilds if missing.

```
artifacts/
  aggregator/           — GenericAggregator (all levels)
  subtree-root/         — SubtreeRootCircuit
  super-aggregator-v2/  — SuperAggregatorV2
  groth16/              — gnark R1CS, ProvingKey, VerifyingKey
```

**Important:** artifacts become stale whenever circuit logic or PI layout changes (e.g., after the Keccak-256 migration). Always `rm -rf artifacts/` and rebuild before deployment.

**Artifact build order:** GenericAggregator → SubtreeRootCircuit → SuperAggregatorV2 → Groth16 setup. Each step depends on the verifier data produced by the previous.

---

## `ProverRuntimeV2` API

```rust
pub struct ProverRuntimeV2 { /* circuit data, proving keys */ }

impl ProverRuntimeV2 {
    pub fn from_artifacts(path: &Path) -> Self;

    pub async fn prove(&self, req: ProveRequestV2) -> Result<ProveOutcomeV2>;
}

pub enum ProveOutcomeV2 {
    Success {
        batch_id:           BatchId,
        batch_poseidon_root: HashOutput,
        solidity_proof:     SolidityProof,
        super_pi_commitment: [u32; 8],
    },
    Failure { batch_id: BatchId, error: String },
}
```

The server calls `prove()` and awaits the outcome. For remote provers the server serialises `ProveRequestV2` to JSON and POSTs it to the prover's HTTP endpoint; the response is deserialised into `ProveOutcomeV2`.

---

## Key Constants

| Constant | Value | Location |
|----------|-------|----------|
| `NOTE_BATCH` | 8 | `tessera-client/src/lib.rs` |
| `ACCOUNT_BATCH_SIZE` | 16 | server config |
| Total NC leaves | 128 | 16 × 8 |
| Aggregator arity | 2 | `prover_v2.rs` |
| Aggregator depth | 7 | `prover_v2.rs` (2⁷ = 128 leaves) |
| `TX_LEAF_PI_SIZE` | 77 | `super_aggregator_v2.rs` |
| `TX_DATA_OFFSET` | 5 | same |
| `IS_REAL_OFFSET` | 4 | same |
| `NC_OFF` | 45 | `TX_DATA_OFFSET + 40` |
| SA public inputs | 8 u32 | Keccak-256 piCommitment |
| SR public inputs | 516 field elements | `root[4] + 128×leaf[4]` |
