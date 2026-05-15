# E2E Report: Posting Transactions (All Kinds)

**Scope:** Everything needed to construct and submit a private transaction to the
sequencer — all four kinds: FreshAcc, Spend, Reject, and Fake/Dummy.
**Reuse:** Self-contained. Cross-reference with
[e2e-report-transaction-validation.md](e2e-report-transaction-validation.md) for how
transactions are proven on-chain.

---

## Transaction taxonomy

There are **4 kinds** of PrivTx, all proved by the same `PrivTxCircuit`:

| Kind | `not_fake_tx` | `is_fresh_acc` | `is_priv_tx` | `is_rjct` | Description |
|------|:---:|:---:|:---:|:---:|-------------|
| FreshAcc | 1 | 1 | 0 | 0 | Creates a new account — no ACT/NCT membership proofs needed |
| Spend | 1 | 0 | 1 | 0 | Spends input notes from NCT, creates output notes |
| Reject | 1 | 0 | 0 | 1 | Operator rejects notes — no balance invariant |
| Fake/Dummy | 0 | — | — | — | Padding slot — all constraints bypassed |

The sequencer exposes **one** interface for real transactions (all three real kinds
map to the same call). Fake/Dummy proofs are generated internally by the sequencer
for padding and are never submitted by callers.

---

## Sequencer submission API

Source: [tessera-server/src/sequencer/handle.rs](../tessera-server/src/sequencer/handle.rs)

```rust
pub async fn submit_private_tx(
    &self,
    tx_id:               Option<String>,   // optional label for logging
    input_account_leaf:  [u8; 32],         // AN — account nullifier (bytes32 LE-packed)
    output_account_leaf: [u8; 32],         // AC — account commitment (bytes32 LE-packed)
    input_notes:         Vec<[u8; 32]>,    // NN — note nullifiers, up to 8
    output_notes:        Vec<[u8; 32]>,    // NC — note commitments, up to 8
    tx_proof:            Vec<u8>,          // serialized Plonky2 proof bytes
) -> anyhow::Result<()>
```

---

## Public input (PI) layout of PrivTxCircuit

Source: [tessera-client/src/plonky2_gadgets/priv_tx/mod.rs](../tessera-client/src/plonky2_gadgets/priv_tx/mod.rs)

```
Index     Field
-------   -----
[0]       subpool_id_in   (auto-registered by add_virtual_account_target)
[1]       subpool_id_out
[2]       subpool_id_in   (explicit, same wire as [0])
[3]       subpool_id_out  (explicit, same wire as [1])
[4]       not_fake_tx     (IS_REAL_OFFSET = 4)
[5-8]     AN              AccountNullifier, 4×F   (TX_DATA_OFFSET = 5)
[9-12]    AC              AccountCommitment, 4×F
[13-44]   NN[0..8]        NoteNullifier×8, each 4×F = 32 elements total
[45-76]   NC[0..8]        NoteCommitment×8, each 4×F = 32 elements total
[77-80]   root            on-chain Poseidon IMT root, 4×F  (V2: same as [81-84])
[81-84]   root            on-chain Poseidon IMT root, 4×F  (V2: same as [77-80])
Total: 85 public inputs
```

In V2 both slots carry the same confirmed root (one on-chain IMT for accounts and notes).
The two separate slots are a circuit artifact from V1, where ACT and NCT were genuinely
separate trees. The SAV2 circuit forwards both into the `piCommitment` hash.

Constants (from `tessera-trees::proof_aggregation`):
```rust
pub const IS_REAL_OFFSET: usize = 4;
pub const TX_DATA_OFFSET: usize = 5;
```

---

## Step 1 — Build the circuit (once per process)

Source: [tessera-client/src/lib.rs](../tessera-client/src/lib.rs)

```rust
use tessera_client::{build_priv_tx_circuit, PrivTxTargets};
use tessera_trees::{CircuitDataNative, D};

let (circuit, targets): (CircuitDataNative, PrivTxTargets<D>) = build_priv_tx_circuit();
// Slow to build (~1-2 min in --release). Cache and reuse across proofs.
```

---

## Step 2a — Prove: FreshAcc

Creates a brand-new account. The account has nonce=0, no spend/consume keys, empty AST.
No ACT or NCT membership proofs required.

Source: [tessera-client/src/plonky2_gadgets/priv_tx/freshacc.rs](../tessera-client/src/plonky2_gadgets/priv_tx/freshacc.rs)

```rust
use tessera_client::{
    FreshAccInputs, PrivTxInputs, StandardAccount, SubpoolId, SpendAuth, ConsumeAuth,
    prove_real_priv_tx, PrivateIdentifier,
    pool_config::{MainPoolConfigTree, SubpoolConfigTree, CompPubKey},
    schnorr::{PrivateKey, Scalar, schnorr_sign},
    derive_priv_tx_hash,
};
use tessera_client::plonky2_gadgets::priv_tx::sample_dummy_notes;
use tessera_trees::{F, tree::hasher::HashOutput};
use rand::{SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::array;

let mut rng = ChaCha8Rng::seed_from_u64(42);

// Subpool authority keys (must match poolConfigRoot deployed to contract)
let approval_sk  = PrivateKey::new(Scalar::sample(&mut rng));
let rejection_sk = PrivateKey::new(Scalar::sample(&mut rng));
let consume_sk   = PrivateKey::new(Scalar::sample(&mut rng));
let approval_cpk:  CompPubKey = approval_sk.public_key::<F>().into();
let rejection_cpk: CompPubKey = rejection_sk.public_key::<F>().into();
let consume_cpk:   CompPubKey = consume_sk.public_key::<F>().into();

let subpool_id = SubpoolId(F::ONE);
let subpool = SubpoolConfigTree::new(approval_cpk, rejection_cpk, consume_cpk);
let mut main_pool = MainPoolConfigTree::new();
main_pool.set_subpool(0, subpool_id, subpool.root());
// main_pool.root() == poolConfigRoot registered on the contract

// Fresh account (nonce=0, no keys)
let private_id = PrivateIdentifier::sample(&mut rng);
let accin = StandardAccount::new_with(private_id, subpool_id);

// Output account: same private_id + subpool_id, incremented nonce, new spend key
let new_spend_sk = PrivateKey::new(Scalar::sample(&mut rng));
let new_spend_pk: CompPubKey = new_spend_sk.public_key::<F>().into();
let mut accout = accin.clone_with_incremented_nonce();
accout.spend_auth = SpendAuth { spend_pk: Some(new_spend_pk) };

// Dummy notes (padding for empty note slots)
let (dinotes, donotes) = sample_dummy_notes(&mut rng);
let dinote_nulls: [_; 8] = array::from_fn(|i| {
    use plonky2::plonk::config::Hasher;
    use plonky2::hash::poseidon::PoseidonHash;
    let h0 = <PoseidonHash as Hasher<F>>::hash_no_pad(&dinotes[i]).elements;
    tessera_client::NoteNullifier((<PoseidonHash as Hasher<F>>::hash_no_pad(&h0)).elements.into())
});
let donote_comms: [_; 8] = array::from_fn(|i| {
    use plonky2::plonk::config::Hasher;
    use plonky2::hash::poseidon::PoseidonHash;
    let h0 = <PoseidonHash as Hasher<F>>::hash_no_pad(&donotes[i]).elements;
    tessera_client::NoteCommitment((<PoseidonHash as Hasher<F>>::hash_no_pad(&h0)).elements.into())
});

// Sign
let tx_hash = derive_priv_tx_hash(
    accin.nullifier(None),
    accout.commitment(),
    dinote_nulls,
    donote_comms,
);
let k = Scalar::from_raw(array::from_fn(|_| 1u64));
let approval_sig = schnorr_sign(&approval_sk, &tx_hash, k);

let proof = prove_real_priv_tx(
    &circuit, &targets,
    PrivTxInputs::FreshAcc(FreshAccInputs {
        accin,
        new_spend_auth:   SpendAuth { spend_pk: Some(new_spend_pk) },
        new_consume_auth: ConsumeAuth::default(),
        root:             HashOutput([F::ZERO; 4]),  // ignored for FreshAcc (not in IMT yet)
        approval_key:     approval_cpk,
        rejection_key:    rejection_cpk,
        consume_key:      consume_cpk,
        subpool_id,
        main_pool,
        approval_sig,
        dinotes,
        donotes,
    }),
);
```

**Quick test shortcut** (seeded, self-contained, zero roots):
```rust
use tessera_client::{build_circuit_and_real_proof_seeded};
let (circuit, proof) = build_circuit_and_real_proof_seeded(42u64);
// Different seeds produce unique AN/AC/NN/NC — safe to use multiple times in one test.
```

---

## Step 2b — Prove: Spend

Transfers assets between accounts / notes. Requires:
- ACT membership proof for `accin`
- NCT membership proof for each consumed input note

Source: [tessera-client/src/plonky2_gadgets/priv_tx/spend.rs](../tessera-client/src/plonky2_gadgets/priv_tx/spend.rs)

```rust
use tessera_client::{SpendTxInputs, PrivTxInputs, prove_real_priv_tx};

let proof = prove_real_priv_tx(
    &circuit, &targets,
    PrivTxInputs::Spend(SpendTxInputs {
        accin:              accin,                    // StandardAccount (nonce > 0)
        root:               root,                     // confirmed on-chain IMT root
        accin_merkle_proof: accin_act_proof,          // MerkleProof of accin.commitment() in ACT
        inotes:             input_notes,              // Vec<PositionedStandardNode>
        inotes_nct_proofs:  inote_nct_proofs,         // Vec<MerkleProof> per input note
        onotes:             output_notes,             // Vec<StandardNote>
        dinotes:            dummy_nullifier_hashes,   // [[F;4]; 8]
        donotes:            dummy_commitment_hashes,  // [[F;4]; 8]
        approval_key:       approval_cpk,
        rejection_key:      rejection_cpk,
        consume_key:        consume_cpk,
        subpool_id,
        main_pool,
        spend_sig:          spend_sig,     // signed by accin.spend_sk
        consume_sig:        consume_sig,   // signed by subpool consume key
        approval_sig:       approval_sig,  // signed by subpool approval key
    }),
);
```

**Key circuit constraint (balance invariant):**
```
accin.balance + Σ(input_note.amount) == accout.balance + Σ(output_note.amount)
```
All input and output notes must share the same `asset_id`.

---

## Step 2c — Prove: Reject

Operator (subpool authority) rejects notes without a balance constraint.
No spend signature required — uses approval + consume keys.

Source: [tessera-client/src/plonky2_gadgets/priv_tx/reject.rs](../tessera-client/src/plonky2_gadgets/priv_tx/reject.rs)

```rust
use tessera_client::{RejectTxInputs, PrivTxInputs, prove_real_priv_tx};

let proof = prove_real_priv_tx(
    &circuit, &targets,
    PrivTxInputs::Reject(RejectTxInputs {
        accin:                  accin,
        accin_act_merkle_proof: accin_act_proof,
        root,
        inotes:                 input_notes,
        inotes_nct_proofs:      inote_nct_proofs,
        onotes:                 output_notes,
        dinotes,
        donotes,
        approval_key:           approval_cpk,
        rejection_key:          rejection_cpk,
        consume_key:            consume_cpk,
        subpool_id,
        main_pool,
        consume_sig,
        approval_sig,
    }),
);
```

The `is_rjct=1` circuit flag disables balance and spend-auth checks.

---

## Step 2d — Fake/Dummy (internal only)

The sequencer injects dummy proofs automatically for padding empty batch slots.
Callers never submit fake transactions. Documented here for completeness.

```rust
// tessera-client/src/lib.rs — prove_dummy_priv_tx
let proof = prove_dummy_priv_tx(
    &circuit, &targets,
    override_an,   // [F;4]     — AN override injected as PI
    override_nn,   // [[F;4];8] — NN overrides
    override_ac,   // [F;4]
    override_nc,   // [[F;4];8]
);
// PI[IS_REAL_OFFSET] == 0  (not_fake_tx = false)
```

---

## Step 3 — Extract leaf values from proof PIs

```rust
use tessera_trees::proof_aggregation::{TX_DATA_OFFSET};
use tessera_trees::F;

let pis = &proof.public_inputs;

// LE packing: uint256 = e0 | (e1<<64) | (e2<<128) | (e3<<192)
fn goldilocks_4_to_bytes32(elems: &[F]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, e) in elems[..4].iter().enumerate() {
        out[i*8..(i+1)*8].copy_from_slice(&e.to_canonical_u64().to_le_bytes());
    }
    out
}

let an = goldilocks_4_to_bytes32(&pis[TX_DATA_OFFSET..]);        // [5-8]
let ac = goldilocks_4_to_bytes32(&pis[TX_DATA_OFFSET+4..]);      // [9-12]
let nn: Vec<[u8; 32]> = (0..8)
    .map(|i| goldilocks_4_to_bytes32(&pis[TX_DATA_OFFSET+8+i*4..]))
    .collect();  // [13-44]
let nc: Vec<[u8; 32]> = (0..8)
    .map(|i| goldilocks_4_to_bytes32(&pis[TX_DATA_OFFSET+8+32+i*4..]))
    .collect();  // [45-76]
```

---

## Step 4 — Serialize proof bytes

```rust
use plonky2::util::serialization::Write;
use tessera_client::TesseraGateSerializer;
use tessera_trees::ConfigNative;

let mut buf = Vec::new();
proof.write(&mut buf).expect("proof serialization failed");
let proof_bytes: Vec<u8> = buf;
```

---

## Step 5 — Submit to sequencer

```rust
sequencer_handle.submit_private_tx(
    Some("tx-freshacc-0".to_string()),
    an,           // [u8; 32] input_account_leaf
    ac,           // [u8; 32] output_account_leaf
    nn,           // Vec<[u8; 32]> input notes (nullifiers)
    nc,           // Vec<[u8; 32]> output notes (commitments)
    proof_bytes,
).await?;
```

The sequencer:
1. Validates AN and NN are not duplicated within the current batch (in-memory check only).
2. Calls `BatchBuilder::add_private_tx(proof_bytes, ac, an, nc_arr, nn_arr)`.
3. Returns `true` if the batch is now full (triggers immediate flush).

---

## Test-mode shortcut (no real proofs)

When `TESSERA_TESTING=1`, the test API accepts raw leaf values without proof bytes.

### Shell (HTTP)
```bash
AN=$(printf '0x%064x' 100)
AC=$(printf '0x%064x' 101)
NN_JSON=$(printf '"0x%064x",' $(seq 201 208) | sed 's/,$//')
NC_JSON=$(printf '"0x%064x",' $(seq 301 308) | sed 's/,$//')

curl -sS -X POST "$TESSERA_TEST_API_URL/test/transactions" \
  -H 'content-type: application/json' \
  -d "{\"an\":\"$AN\",\"ac\":\"$AC\",\"nn\":[$NN_JSON],\"nc\":[$NC_JSON]}"
# => {"accepted":true}
```

### Rust
```rust
let an  = [0u8; 31].iter().chain(&[100u8]).copied().collect::<Vec<_>>().try_into().unwrap();
let ac  = [0u8; 31].iter().chain(&[101u8]).copied().collect::<Vec<_>>().try_into().unwrap();
let nn: [[u8;32];8] = std::array::from_fn(|i| {
    let mut b = [0u8; 32]; b[31] = (201 + i) as u8; b
});
let nc: [[u8;32];8] = std::array::from_fn(|i| {
    let mut b = [0u8; 32]; b[31] = (301 + i) as u8; b
});
handle.test_submit_tx(an, ac, nn, nc).await?;
```

---

## Constraint summary per kind

| Kind | ACT membership | NCT proofs | Balance check | Spend sig | Subpool sigs |
|------|:--------------:|:----------:|:-------------:|:---------:|:------------:|
| FreshAcc | no | no | no | no | approval only |
| Spend | yes | yes (input notes) | yes | yes | approval + consume |
| Reject | yes | yes (input notes) | no | no | approval + consume |
| Fake | n/a | n/a | n/a | n/a | n/a |

---

## Important notes

- `poolConfigRoot` in the proof (`main_pool.root()`) **must match** the value stored
  in the deployed contract, otherwise `proveTransactionBatch` will fail (the SAV2
  circuit enforces this as part of `piCommitment`).
- `root` in the proof must be a confirmed root (in `confirmedRoots` on-chain). For
  FreshAcc with a zero root this works because the genesis root (all-zeros tree) is
  always confirmed. Both PI[77-80] and PI[81-84] are set to the same `root` value.
- All 8 note slots are always present; unused slots carry dummy values padded with zeros.
- For Spend and Reject, the sequencer does **not** verify Merkle proofs — that is the
  circuit's job. The sequencer only checks for duplicate AN/NN within the batch.
