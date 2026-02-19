# Tessera — Claude Code Instructions

## Workspace layout

```
Tessera/
├── tessera-trees/      # ZK circuit library (plonky2 gadgets, Merkle/nullifier trees, proof targets)
├── tessera-server/     # Prover service, sequencer, artifact-generation binaries
└── tessera-solidity/   # Solidity bridge contract + gnark-generated Groth16 verifiers
```

Rust workspace root: `Cargo.toml`. Members: `tessera-trees`, `tessera-server`.
`tessera-solidity` is a Foundry project (not a Cargo member).

### Key type aliases (`tessera-trees/src/lib.rs`)

```rust
pub type F = GoldilocksField;
pub type ConfigNative = PoseidonGoldilocksConfig;
pub const D: usize = 2;
```

### plonky2 / starky dependency

Pinned to the 0xPARC fork at a specific commit — do not change the git rev without understanding downstream effects on circuit serialization.

```toml
plonky2 = { git = "https://github.com/0xPARC/plonky2.git", rev = "109d517d09c210ae4c2cee381d3e3fbc04aa3812" }
```

---

## Proof pipeline

```
Plonky2 native proof
  → BN128Wrapper (recursion into PoseidonBN128GoldilocksConfig)
  → Groth16Wrapper (gnark FFI → Go)
  → Solidity IGroth16Verifier.verifyProof(proof[8], commitments[2], commitmentPok[2], input[8])
```

Public inputs are always **8 × `uint32` words** (a 256-bit digest, big-endian).

---

## DataCommitment trait

**File:** `tessera-trees/src/tree/hasher.rs`

Abstracts the hash that binds proof public inputs to a short digest. Three implementations:

| Struct | Hash | PI size | Status |
|---|---|---|---|
| `PoseidonCommitment` | Poseidon | 4 Goldilocks elements | available |
| `Sha256Commitment` | SHA-256 | 8 `u32` words | available |
| `Keccak256Commitment<C, D>` | Keccak-256 | 8 `u32` words | **active** |

### Active commitment: Keccak-256

The prover and bridge currently use Keccak-256 for the PI commitment (migrated from SHA-256).

**Preimage encoding:** each Goldilocks `u64` → big-endian 8 bytes → `[hi_u32, lo_u32]`.
This matches `abi.encodePacked(bytes32...)` in Solidity.

| Layer | Code |
|---|---|
| Circuit | `builder.keccak256::<C>(&u32_targets)` in `Keccak256Commitment::commit_public_inputs` |
| Native | `keccak256_field_elements_native` in `tessera-trees/src/plonky2_gadgets/keccak256/utils.rs` |
| Solidity | `keccak256(abi.encodePacked(oldRoot, newRoot, packedLeaves))` → `keccakToPublicInputs(digest)` |

### Consensus boundary (critical)

**All three layers must agree on the same hash function and encoding.**
Changing one without the others breaks on-chain proof verification silently — the Groth16 verifier will reject the proof.

`sha256ToPublicInputs` is kept in the Solidity contract for reference only; it is not called by any active proof path.

---

## TesseraGeneratorSerializer

**File:** `tessera-trees/src/groth/serializer.rs`

Every `SimpleGenerator` added to the native circuit **must** be registered here. The serializer currently covers 24 standard plonky2 generators + 10 custom Tessera generators:

```
ByteDecompositionGenerator, ChunkDecompositionGenerator,
U16LimbDecompositionGenerator, LimbByteDecompositionGenerator,
U32WrappingAddGenerator, SplitLowHighGenerator,
FieldDecompositionGenerator, CanonicalCheckGenerator,
Keccak256SingleGenerator,
Keccak256StarkProofGenerator<F, ConfigNative, D>
```

A missing generator causes an `IoError` from `CircuitData::to_bytes` with the message "serialize native circuit failed".

---

## U32Target naming collision

`tessera-trees/src/plonky2_gadgets/keccak256/mod.rs` defines:
```rust
pub type U32Target = Target;   // plain Target, NOT a newtype
```

The u32 gadget's `U32Target` is a newtype `pub struct U32Target(pub Target)`.
When passing u32-gadget targets into the keccak builder, extract the inner target with `.0`.

---

## Artifact rebuild (after any circuit change)

Circuit changes invalidate all downstream artifacts. Always delete and regenerate:

```bash
rm -rf tessera-server/artifacts/commitment-tree tessera-server/artifacts/nullifier-tree
cargo run --bin commitment_tree_artifacts --release
cargo run --bin nullifier_tree_artifacts --release
bash scripts/sync_verifiers_from_artifacts.sh
```

Then redeploy the bridge contract with the new `VerifierCommitment.sol` / `VerifierNullifier.sol`.

The artifact bins skip regeneration if their output directory already exists — always `rm -rf` first.

---

## Key file locations

| Purpose | Path |
|---|---|
| DataCommitment / MerkleHash traits | `tessera-trees/src/tree/hasher.rs` |
| Keccak-256 native helper | `tessera-trees/src/plonky2_gadgets/keccak256/utils.rs` |
| Keccak-256 circuit builder | `tessera-trees/src/plonky2_gadgets/keccak256/builder.rs` |
| Field-to-u32 decomposition | `tessera-trees/src/plonky2_gadgets/sha256/circuit.rs` (`decompose_field_to_u32_pair`, `pub(crate)`) |
| Generator serializer | `tessera-trees/src/groth/serializer.rs` |
| BN128 / Groth16 wrappers | `tessera-trees/src/groth/wrapper.rs` |
| Prover service (circuit init) | `tessera-server/src/prover.rs` |
| Sample proof builders | `tessera-server/src/lib.rs` |
| Bridge contract | `tessera-solidity/src/TesseraRollup.sol` |
| Verifier sync script | `scripts/sync_verifiers_from_artifacts.sh` |

---

## Deposit commitment (separate from PI commitment)

`computeDepositCommitment` in `TesseraRollup.sol` and `tessera-server/src/data_types/deposit.rs` use **SHA-256** for leaf hashing of deposit metadata. This is **intentional and independent** of the PI commitment hash — do not change it to Keccak-256.

---

## Feature flags (`tessera-server`)

| Flag | Effect |
|---|---|
| `insecure-stub-proof-verify` | Bypasses Groth16 verification — **never enable in production** |
| `integration-tests` | Enables heavy e2e tests that orchestrate local devnet scripts |

---

## Local dev commands

```bash
# Build (check only, fast)
cargo check -p tessera-trees -p tessera-server

# Unit tests
cargo test -p tessera-trees
cargo test -p tessera-server

# Solidity tests (Foundry)
cd tessera-solidity && forge test

# Full e2e (four consoles required — see scripts/README.md)
scripts/local_e2e_toy_a_anvil.sh     # Console A: Anvil
scripts/local_e2e_toy_b_deploy.sh    # Console B: deploy contracts
scripts/local_run_prover.sh          # Console C: prover service
scripts/local_e2e_toy_c_sequencer.sh # Console D: sequencer
scripts/local_e2e_toy_d_flow.sh 256 128  # Console E: traffic + verification
```

### Sequencer environment variables (required)

`TESSERA_RPC_URL`, `TESSERA_OPERATOR_KEY`, `TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS`, `TESSERA_CHAIN_ID`, `TESSERA_PENDING_DEPOSITS_ARTIFACTS_PATH`, `TESSERA_NULLIFIER_TREE_ARTIFACTS_PATH`

See `docs/architecture/01-component-inventory.md` for the full list including optional vars.
