# AGENTS.md — `doxa-client`

## Crate role

Implements client-side primitives and Plonky2 circuits for the Doxa privacy protocol. It is responsible for:

- Account related primitives: StandardAccount, PrivateIdentifier, PublicIdentifier, SpendAuth, ConsumeAuth, AccountCommitment, AccountNullifier, AccountStateTree.
- Note related primitives: StandardNote, DepositNote, AccountCommitment, NoteNullifier, NoteIdentifier, AssetId.
- Schnorr signatures over GFp5 elliptic curve and plonky2 signature verifier circuit.
- MainPool/Subpool related primitives: MainPoolConfigTree, SubpoolId, SubpoolConfig, SubpoolFullProof.
- Plonky2 circuits, proof builders for 3 transaction flows:
  - Deposit transaction
  - Private transaction: of 2 kinds:
    - FreshAccount transaction
    - Spend transaction
  - Withdrawal transaction

## Constructing transaction proofs

Transaction proofs for all 3 tx types are built with the builder pattern. For instance, to construct deposit tx proof:
```
1. Construct deposit tx using DepositTxBuilder.
2. DepositTxBuilder::build() -> BuiltRealDepositTx.
3. BuiltRealDepositTx::into_deposit_tx() -> BuiltDepositTx.
4. BuiltDepositTx::prove(deposit_circuit) -> DepositProof.
```

Or to construct private tx for fresh account:
```
1. Construct fresh acc tx using FreshAccTxBuilder.
2. FreshAccTxBuilder::build() -> BuiltFreshAccTx.
3. BuiltFreshAccTx::into_priv_tx() -> BuiltPrivTx.
4. BuiltPrivTx::prove(priv_tx_circuit) -> PrivTxProof
```

Similar pattern follows for other transactions, like withdrawal tx or private tx for spend. 

Note that all tx types have fake tx builder to produce fake proofs.
