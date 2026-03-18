# Private Transaction Circuit

Source: `tessera-client/src/plonky2_gadgets/priv_tx/`

---

## Purpose

The PrivTx circuit proves a state transition of the form:

```
AccIn  +  [INote₀ … INoteₙ]  →  AccOut  +  [ONote₀ … ONoteₙ]
```

A single proof covers one account state change and up to `NOTE_BATCH` (= 8) input notes and 8 output notes. Real proofs have `not_fake_tx = 1`; dummy/padding proofs have `not_fake_tx = 0` and enforce no meaningful constraints.

---

## Transaction Kinds

Exactly one flag is set per real proof (all false for fake proofs):

| Flag | Meaning |
|------|---------|
| `is_fresh_acc` | Account activation (nonce 0 → 1, no ACT membership check) |
| `is_rjct` | Reject: return input notes to sender, AST unchanged |
| `is_update_auth` | Update spend/consume auth keys only |
| `is_priv_tx` | General spend: consume input notes, produce output notes |

---

## What the Circuit Proves

### Account constraints
- **ACT membership**: `Commit(AccIn)` exists in the Account Commitment Tree (ACT), verified via a Poseidon Merkle path. Gated off for `is_fresh_acc` and `not_fake_tx = 0`.
- **Transition invariants** (enforced by `assert_account_invariants`):
  - `private_identifier` and `subpool_id` are immutable across all tx kinds.
  - Nonce increments by 1.
  - `is_fresh_acc`: `AccIn` must match the default fresh-account template (zero nonce, zero AST, default auth).
  - `is_rjct`: only nonce changes; spend/consume auth and AST are immutable.
  - `is_update_auth` / `is_priv_tx`: auth keys and AST may change.

### Note constraints
- **NCT membership**: each active input note's commitment exists in the Note Commitment Tree (NCT), verified via a conditional Poseidon Merkle path.
- **Ownership**: `INote.recipient.public_identifier` must equal the circuit-derived `public_identifier` of `AccIn`.
- **Shared asset**: all active inotes and onotes share the same `asset_id`.
- **Note nullifiers**: each inote's nullifier is derived as `Poseidon(Commit(INote) ∥ position ∥ nk)` where `nk = Poseidon(private_identifier)`.
- **Reject invariant**: for `is_rjct`, every active inote must have a corresponding active onote (`is_rjct → ∀i, inotes_isactive[i] == onotes_isactive[i]`).

### Balance invariant
```
AccIn.amt + Σ active_inote.amt  ==  AccOut.amt + Σ active_onote.amt
```
Enforced over 256-bit arithmetic on the transacted `asset_id`.

### Subpool membership
The three authority keys (approval, rejection, consume) are proven to belong to the declared subpool via a depth-2 Merkle proof within `SubpoolConfigTree`, and the subpool itself is proven to exist in `MainPoolConfigTree`. Gated off when `not_fake_tx = 0`.

### Signatures
| Signature | Key | Required when |
|-----------|-----|---------------|
| Approval | `approval_key` | Always (for real TXs) |
| Spend | `AccIn.spend_auth.spend_pk` | Active output notes exist (`!is_rjct`) |
| Consume | `AccIn.consume_auth.pk` or `subpool_consume_key` | Active input notes exist and no spend required |

All signature checks are gated off when `not_fake_tx = 0`.

### Tx hash (signed message)
```
TxHash = Poseidon(AN ∥ AC ∥ NN[0..7] ∥ NC[0..7])
```
where AN/AC/NN/NC are the four free override targets (see below).

---

## Public Input Layout

**Total: 85 field elements.**
Constants `IS_REAL_OFFSET = 4` and `TX_DATA_OFFSET = 5` are defined in
`tessera-trees/src/proof_aggregation/super_aggregator_v2.rs`.

| Index | Field | Notes |
|-------|-------|-------|
| `[0]` | `subpool_id_in` | Auto-registered via `add_virtual_public_input` inside `add_virtual_account_target` |
| `[1]` | `subpool_id_out` | Same mechanism; both accounts share the same `subpool_id` wire |
| `[2]` | `subpool_id_in` | Explicitly re-registered; same wire as `[0]` |
| `[3]` | `subpool_id_out` | Explicitly re-registered; same wire as `[1]` |
| `[4]` | `not_fake_tx` | **`IS_REAL_OFFSET`** — 1 for real proof, 0 for dummy |
| `[5–8]` | AN (account nullifier) | **`TX_DATA_OFFSET`** — `accin_null` (4 Goldilocks fields) |
| `[9–12]` | AC (account commitment) | `accout_comm` (4 fields) |
| `[13–44]` | NN[0..7] (note nullifiers) | 8 × 4 fields; `TX_DATA_OFFSET + 8` |
| `[45–76]` | NC[0..7] (note commitments) | 8 × 4 fields; `TX_DATA_OFFSET + 40` |
| `[77–80]` | `act_root` | Binds proof to ACT state |
| `[81–84]` | `nct_root` | Binds proof to NCT state |

**Note on double-registration of `subpool_id` (`[0,1]` vs `[2,3]`)**:
`add_virtual_account_target` internally calls `add_virtual_public_input` for the `subpool_id` target (auto-registers at `[0]` for AccIn and `[1]` for AccOut). The explicit `register_public_input` calls at the end of `priv_tx_circuit` re-register the same wires at `[2]` and `[3]`. PI `[0]` and PI `[2]` are backed by identical circuit wires; same for `[1]`/`[3]`. The super aggregator reads subpool_ids from `[2]` and `[3]`.

**`TX_LEAF_PI_SIZE = 77`**:
The super aggregator exposes only PI `[0..76]` per TX slot in the batched aggregated proof output. PI `[77–84]` (act_root, nct_root) are validated by the aggregator circuit internally but are not propagated per-slot — they are uniform across all TXs in a batch and handled at the batch level.

**PI `[77–84]` in real proofs**: The `act_root` and `nct_root` fields in each input struct (`FreshAccInputs`, `SpendTxInputs`, `RejectTxInputs`) are explicitly set in PI `[77–80]` and `[81–84]`. For `FreshAcc` the circuit does not constrain these values (no ACT/NCT membership check); for `Spend` and `Reject` they must match the Merkle proofs supplied. The SA currently treats these as private witnesses rather than reading them from the inner proofs — see Layer 2 gap in the architecture notes.

Aggregated proof offsets for slot `s`:
```
an_off  = s * TX_LEAF_PI_SIZE + TX_DATA_OFFSET           = s*77 + 5
ac_off  = s * TX_LEAF_PI_SIZE + TX_DATA_OFFSET + 4        = s*77 + 9
nn_off  = s * TX_LEAF_PI_SIZE + TX_DATA_OFFSET + 8        = s*77 + 13
nc_off  = s * TX_LEAF_PI_SIZE + TX_DATA_OFFSET + 40       = s*77 + 45
```

---

## Free Virtual Override Targets (AN, AC, NN, NC)

All four PI data fields are **free virtual targets**: the prover assigns them directly rather than the circuit computing them. For real proofs the circuit enforces equality with the derived values; for fake proofs the prover supplies arbitrary padding.

The enforcement pattern (applied to each component):
```rust
let diff   = builder.sub(override_val, derived_val);
let gated  = builder.mul(not_fake_tx.target, diff);
builder.assert_zero(gated);
// ⟹  not_fake_tx=1 → override_val == derived_val
// ⟹  not_fake_tx=0 → constraint trivially satisfied (0 * anything = 0)
```

| Field | Derived from |
|-------|-------------|
| AN (`accin_null`) | `Poseidon(Commit(AccIn) ∥ accin_pos ∥ nk)`, or fresh-account variant when `is_fresh_acc` |
| AC (`accout_comm`) | `Poseidon(AccOut fields…)` |
| NN[i] (`override_nn[i]`) | Real nullifier when `inotes_isactive[i]`, else `double_hash(dinotes[i])` |
| NC[i] (`override_nc[i]`) | Real commitment when `onotes_isactive[i]`, else `double_hash(donotes[i])` |

---

## Dummy / Fake Proof Behaviour (`not_fake_tx = 0`)

A dummy proof is a valid plonky2 proof that satisfies all circuit constraints but carries no meaningful transaction data. It is used to pad empty slots in the TX aggregation tree.

**What is enforced regardless of `not_fake_tx`:**
- Boolean checks on all flag targets (is_rjct, is_fresh_acc, etc.)
- Curve-point validity of all signature public keys
- Subpool key-membership proofs (internal Merkle paths within `SubpoolConfigTree` are real; the main-pool inclusion proof is zeroed out)
- Balance arithmetic (trivially satisfied since all notes are inactive and all amounts are zero)

**What is gated off when `not_fake_tx = 0`:**
- ACT membership check for AccIn
- NCT membership checks for all inotes
- All three signature verifications
- Subpool main-pool inclusion proof
- AN, AC, NN, NC equality constraints (free virtual targets)

**Override parameters** (exposed via `prove_dummy_priv_tx`, which wraps `PrivTxInputs::Fake`):

```rust
pub fn prove_dummy_priv_tx(
    circuit:     &CircuitDataNative,
    targets:     &PrivTxTargets<D>,
    override_an: [F; 4],          // PI[5–8]
    override_nn: [[F; 4]; 8],     // PI[13–44]
    override_ac: [F; 4],          // PI[9–12]
    override_nc: [[F; 4]; 8],     // PI[45–76]
) -> ProofNative
```

These control the exact values that appear in the dummy proof's public inputs, allowing the sequencer to align padding leaves with specific positions in the nullifier/commitment trees.

---

## Proving API

The public entry point is `prove_real_priv_tx` in `mod.rs`. It accepts a `PrivTxInputs` enum that selects the TX kind and bundles all required witness data:

```rust
pub enum PrivTxInputs {
    FreshAcc(FreshAccInputs),
    Spend(SpendTxInputs),
    Reject(RejectTxInputs),
    Fake(FakeTxInputs),
}

pub fn prove_real_priv_tx(
    circuit: &CircuitDataNative,
    targets: &PrivTxTargets<D>,
    inputs:  PrivTxInputs,
) -> ProofNative
```

The `FreshAcc`, `Spend`, and `Reject` variants produce real proofs (`not_fake_tx = 1`); `Fake` produces a dummy proof (`not_fake_tx = 0`). Each struct carries `act_root` and `nct_root` as explicit fields so they are always bound to the proof's PI `[77–84]`.

**Input struct fields (common across real variants):**

| Field | Type | Purpose |
|-------|------|---------|
| `accin` | `StandardAccount` | Input account |
| `act_root` | `HashOutput` | ACT root registered as PI[77–80] |
| `nct_root` | `HashOutput` | NCT root registered as PI[81–84] |
| `approval_key`, `rejection_key`, `consume_key` | `CompPubKey` | Subpool authority keys |
| `subpool_id` | `SubpoolId` | Pool membership identifier |
| `main_pool` | `MainPoolConfigTree` | Full pool config for Merkle proofs |
| `approval_sig` | `Signature` | Operator approval signature |
| `dinotes`, `donotes` | `[[F;4]; NOTE_BATCH]` | Dummy note hashes for inactive slots |

**Variant-specific fields:**

| Variant | Extra fields |
|---------|-------------|
| `FreshAcc` | `new_spend_auth`, `new_consume_auth` |
| `Spend` | `accin_merkle_proof`, `inotes`, `inotes_nct_proofs`, `onotes`, `spend_sig`, `consume_sig` |
| `Reject` | `accin_act_merkle_proof`, `inotes`, `inotes_nct_proofs`, `onotes`, `consume_sig` |
| `Fake` | `mainpool_config_root`, `override_an`, `override_ac`, `override_nn`, `override_nc` |

**Other public helpers:**

| Function | Purpose |
|----------|---------|
| `prove_dummy_priv_tx(circuit, targets, override_an, override_nn, override_ac, override_nc)` | Convenience wrapper: builds `PrivTxInputs::Fake` with zero roots |
| `prove_real_priv_tx_seeded(circuit, targets, seed)` | Testing/demo only — generates synthetic FreshAcc data from `seed`; act_root/nct_root are zero (valid for FreshAcc) |

---

## Witness Setter Summary

| Function | File | `not_fake_tx` | Notes |
|----------|------|---------------|-------|
| `set_spend_tx_witness` | `spend.rs` | `true` | Real spend with inotes/onotes |
| `set_reject_tx_witness` | `reject.rs` | `true` | Inotes returned to sender |
| `set_freshacc_tx_witness` | `freshacc.rs` | `true` | Account activation |
| `set_fake_tx_witness` | `spend.rs` | `false` | All-zero padding proof |

These are `pub(crate)` low-level setters invoked by `prove_real_priv_tx`. All four explicitly set AN, AC, NN, and NC targets. For real setters these equal the natively-computed values (matching what the circuit derives). For `set_fake_tx_witness` they are caller-supplied overrides.

---

## Key Constants

| Constant | Value | Location |
|----------|-------|----------|
| `NOTE_BATCH` | `8` | `tessera-client/src/lib.rs` |
| `IS_REAL_OFFSET` | `4` | `tessera-trees/src/proof_aggregation/super_aggregator_v2.rs` |
| `TX_DATA_OFFSET` | `5` | same |
| `TX_LEAF_PI_SIZE` | `77` | same |
| `ACT_DEPTH` | see lib | `tessera-client/src/lib.rs` |
| `NCT_DEPTH` | see lib | same |
