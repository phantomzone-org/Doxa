# W7: Generic Proof Aggregator Plan

Status date: 2026-02-24
Status: planned

## Objective

Implement a reusable recursive proof aggregator in `tessera-trees` that:

- Supports a runtime arity `2^k` tree.
- Aggregates exactly `(2^k)^d` leaf proofs into one root proof.
- Works for independent leaf proofs that share the same circuit (no root-chaining assumption).
- Can be initialized quickly from serialized artifacts, similarly to `BN128Wrapper::from_artifacts`.

## Scope

In scope:

- New generic aggregation module under `tessera-trees`.
- Circuit construction for each aggregation level.
- In-memory cache of per-level aggregation circuits.
- Artifact persistence and fast reload APIs.
- Unit/integration tests and benchmark hooks.

Out of scope (first iteration):

- On-chain verifier integration changes.
- Replacing the current dummy associated-input aggregation in `tessera-server` in the same PR.
- Cross-circuit aggregation (leaf proofs must share the same circuit data).

## Design Constraints

- Arity must be a power of two.
- Input proof count must equal `arity^depth`.
- All leaf proofs must verify against the same `CommonCircuitData` and `VerifierOnlyCircuitData`.
- Parent-level aggregation circuits are homogeneous per level and reusable.

## Proposed Module Layout

Add a new top-level module:

- `tessera-trees/src/proof_aggregation/mod.rs`
- `tessera-trees/src/proof_aggregation/generic.rs`
- `tessera-trees/src/proof_aggregation/artifacts.rs`

Re-export from:

- `tessera-trees/src/lib.rs`

## Public API (Planned)

```rust
pub struct GenericAggregatorConfig {
    pub arity: usize,    // must be a power of two, >= 2
    pub depth: usize,    // number of aggregation levels, >= 1
    pub reducer: ReducerKind,
}

pub enum ReducerKind {
    Keccak256,
    Poseidon,
}

/// A root proof produced by GenericAggregator::aggregate.
/// Wraps a ProofWithPublicInputs whose PI shape matches the reducer output:
///   Keccak256 → 8 u32 words (256-bit digest, big-endian)
///   Poseidon  → 4 Goldilocks field elements
pub struct AggregatedProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub config: GenericAggregatorConfig,
}

pub struct GenericAggregator<...> { ... }

impl GenericAggregator<...> {
    /// Build all aggregation-level circuits from scratch.
    /// Only the circuit schema (CommonCircuitData + VerifierOnlyCircuitData)
    /// of the leaf circuit is required — no concrete proof values.
    pub fn new(
        config: GenericAggregatorConfig,
        leaf_common: CommonCircuitData<F, C, D>,
        leaf_verifier: VerifierOnlyCircuitData<F, C>,
    ) -> Result<Self>;

    /// Aggregate exactly `config.arity^config.depth` leaf proofs into one root proof.
    pub fn aggregate(
        &self,
        proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<AggregatedProof<F, C, D>>;

    pub fn store_artifacts(&self, path: &Path) -> Result<()>;
    pub fn from_artifacts(path: &Path) -> Result<Self>;
    pub fn has_full_artifacts(path: &Path) -> Result<bool>;
}
```

## Aggregation Semantics

- Leaf proofs are independent.
- Level `i` circuit verifies `arity` child proofs from level `i-1`.
- No child-to-child chaining constraints are enforced.
- Parent public inputs are derived by a reducer over child public inputs.

### PI format contract

Every aggregation level outputs the same fixed-length PI regardless of level or arity:

- `Keccak256` reducer: always 8 `u32` words (256-bit digest, big-endian). At each level the
  circuit Keccak-256-hashes `arity * child_pi_len` `u32` words — the concatenated children's PIs —
  down to 8 `u32` words.  This matches the on-chain PI shape consumed by `BN128Wrapper` and the
  Groth16 verifier.
- `Poseidon` reducer: always 4 Goldilocks field elements.

This means leaf PIs of any length are valid inputs to level-0, and every intermediate level
outputs the same shape as the root, making the tree homogeneous.

### Reducer / serializer pairing

| Reducer | Generators added to aggregation circuit | Required serializer |
|---|---|---|
| `Keccak256` | `Keccak256SingleGenerator`, `Keccak256StarkProofGenerator<F, ConfigNative, D>` | `TesseraGeneratorSerializer` |
| `Poseidon` | standard plonky2 generators only | default plonky2 serializer |

Every `CircuitData::to_bytes` / `from_bytes` call on a `Keccak256` aggregation circuit **must**
use `TesseraGeneratorSerializer`.  Omitting it causes the same `IoError` ("serialize native
circuit failed") documented for the leaf circuit.

## Artifact Format

Store enough data to avoid rebuilding circuits on restart.

Planned files under `<path>`:

- `manifest.json`
- `leaf_common.bin`
- `leaf_verifier.bin`
- `level_0_circuit_data.bin`
- `level_1_circuit_data.bin`
- `...`
- `level_{depth-1}_circuit_data.bin`

Manifest fields:

- version
- arity
- depth
- reducer
- leaf_pi_len
- levels

### `from_artifacts` loading order (bottom-up)

Level circuits have a hard dependency on the circuit data of the level below them: the level-N
circuit embeds the `CommonCircuitData` of level-(N-1) inside its verifier targets.  Targets must
be reconstructed by re-running the builder in the same bottom-up order used during `new`:

```
1.  Load leaf_common.bin  → leaf_common: CommonCircuitData<F, C, D>
2.  Load leaf_verifier.bin → leaf_verifier: VerifierOnlyCircuitData<F, C>
3.  Re-run level-0 builder(leaf_common, leaf_verifier) → level-0 targets
4.  Load level_0_circuit_data.bin → level-0 CircuitData
5.  Extract level-0 CommonCircuitData + VerifierOnlyCircuitData
6.  Re-run level-1 builder(level-0 data) → level-1 targets
7.  Load level_1_circuit_data.bin → level-1 CircuitData
...repeat until level_{depth-1}
```

Failing to follow this order produces mismatched targets and incorrect witness assignment at
prove time.

## Validation Rules

At initialization:

- `arity >= 2`
- `arity.is_power_of_two()`
- `depth >= 1`
- `arity.pow(depth as u32) <= MAX_AGGREGATION_LEAVES` (v1 cap, to be documented)

At aggregation time:

- `proofs.len() == arity.pow(depth as u32)`
- each proof verifies against leaf circuit data
- aggregation proceeds level-by-level until one root proof remains

## Implementation Phases

Phase 1: Core generic aggregator

- Implement config, init, level-circuit builder, and synchronous `aggregate`.
- Support one reducer (`Keccak256`) first for deterministic rollout.

Phase 2: Artifact lifecycle

- Implement `store_artifacts`, `from_artifacts`, `has_full_artifacts`.
- Add compatibility checks and clear load-time errors.

Phase 3: Extended reducer support

- Add Poseidon reducer option.
- Validate PI shape consistency across levels.

Phase 4: Server integration

- Replace `dummy_verify_and_aggregate_associated_input_proofs` in `tessera-server/src/prover.rs`.
- Wire aggregator artifacts into prover bootstrap path.

## Test Plan

Unit tests in `tessera-trees`:

- invalid config rejection (`arity`, `depth`)
- wrong proof count rejection
- non-matching leaf circuit rejection
- deterministic result for fixed fixtures
- artifact roundtrip (`new` vs `from_artifacts`)
- **circuit/native Keccak-256 agreement**: build a minimal aggregation proof from known leaf PIs,
  compute the expected digest using `keccak256_field_elements_native` (or equivalent concatenated-PI
  native computation) on the same input, assert the circuit output matches byte-for-byte.

Integration tests:

- end-to-end aggregation of `(2^k)^d` proofs with `k=1,2` and small `d`
- prover integration path replacing dummy aggregation

Performance checks:

- cold init vs artifact-based init latency
- aggregation latency by `(arity, depth)`

## Risks and Mitigations

- Serializer mismatch across plonky2 revisions
  Mitigation: include manifest version and fail-fast diagnostics.

- Large memory footprint for high `(arity, depth)`
  Mitigation: enforce `MAX_AGGREGATION_LEAVES` cap in v1 and document limits.

- PI format drift between reducer implementations and downstream verifier usage
  Mitigation: explicit reducer enum in manifest, per-level PI shape contract above, and tests with
  known vectors (including circuit/native agreement test).

## Acceptance Criteria

- Generic aggregator can produce one root proof from `(2^k)^d` leaf proofs.
- Aggregator can be restored from disk without rebuilding circuits.
- Artifact-loaded aggregator reproduces the same verification behavior as fresh init.
- Tests cover positive paths, tampering paths, artifact roundtrip, and circuit/native Keccak-256
  output agreement.
