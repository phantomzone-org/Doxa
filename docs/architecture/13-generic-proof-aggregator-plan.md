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
    pub arity: usize,      // must be power of two
    pub depth: usize,      // number of aggregation levels
    pub reducer: ReducerKind,
}

pub enum ReducerKind {
    Keccak256,
    Poseidon,
}

pub struct GenericAggregator<...> { ... }

impl GenericAggregator<...> {
    pub fn new_from_pair(
        config: GenericAggregatorConfig,
        left: &ProofWithPublicInputs<...>,
        right: &ProofWithPublicInputs<...>,
        leaf_common: CommonCircuitData<...>,
        leaf_verifier: VerifierOnlyCircuitData<...>,
    ) -> Result<Self>;

    pub fn aggregate(
        &self,
        proofs: Vec<ProofWithPublicInputs<...>>,
    ) -> Result<AggregatedProof<...>>;

    pub fn store_artifacts(&self, path: &Path) -> Result<()>;
    pub fn from_artifacts(path: &Path) -> Result<Self>;
    pub fn has_full_artifacts(path: &Path) -> bool;
}
```

## Aggregation Semantics

- Leaf proofs are independent.
- Level `i` circuit verifies `arity` child proofs from level `i-1`.
- No child-to-child chaining constraints are enforced.
- Parent public inputs are derived by a reducer over child public inputs.

Planned reducer behavior:

- `Keccak256`: commit concatenated child public inputs to 8 `u32` words (same shape as existing on-chain PI handling).
- `Poseidon`: commit concatenated child public inputs to 4 field elements.

## Artifact Format

Store enough data to avoid rebuilding circuits on restart.

Planned files under `<path>`:

- `manifest.json`
- `leaf_common.json`
- `leaf_verifier.json`
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

Serialization approach:

- Use `CircuitData::to_bytes` / `from_bytes` with existing serializers (`TesseraGeneratorSerializer` where needed).
- Reconstruct targets deterministically after load (same pattern as `BN128Wrapper::from_artifacts`).

## Validation Rules

At initialization:

- `arity >= 2`
- `arity.is_power_of_two()`
- `depth >= 1`

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
- artifact roundtrip (`new_from_pair` vs `from_artifacts`)

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
  Mitigation: enforce config caps in v1 and document limits.

- PI format drift between reducer implementations and downstream verifier usage  
  Mitigation: explicit reducer enum in manifest and tests with known vectors.

## Acceptance Criteria

- Generic aggregator can produce one root proof from `(2^k)^d` leaf proofs.
- Aggregator can be restored from disk without rebuilding circuits.
- Artifact-loaded aggregator reproduces the same verification behavior as fresh init.
- Tests cover positive paths, tampering paths, and artifact roundtrip.
