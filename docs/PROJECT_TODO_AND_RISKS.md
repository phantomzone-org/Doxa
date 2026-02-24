# Tessera TODO, Risks, and Current-State Guide

Status date: 2026-02-24
Scope: current code + current architecture docs

## 1. What Is Implemented Today

- [x] ERC20 deposit escrow flow with `depositAndRegister` / `depositAndRegisterFor`.
- [x] Pending deposit withdrawal via `withdrawPendingDeposit`.
- [x] Four-tree sequencing pipeline:
  - `notes_commitment`
  - `notes_nullifier`
  - `accounts_commitment`
  - `accounts_nullifier`
- [x] Sequencer API intake for:
  - `/consume-request` (deposit-only path)
  - `/private-tx` (optimistic two-phase path)
  - per-tree direct endpoints (`/notes/nullifier`, `/accounts/*`)
- [x] **Optimistic two-phase throughput** (all 7 slices complete):
  - `registerTransactionBatchUpdate` — registers all 4 roots atomically; output notes validated immediately
  - `confirmTreeUpdate` — confirms each tree independently as its Groth16 proof arrives
  - `MAX_PENDING_BATCHES = 128` pre-allocated on-chain batch buffer
  - `TxBatch` / `registered_pending_batches` sequencer state map
  - 4 independent prove tasks per private TX batch, keyed by `(batch_id, tree_index)`
  - Two-pass startup recovery: confirmed trees via `ValidatedBatchFinalized`, pending batches via `TransactionBatchRegistered`
  - `TransactionBatchRegistered`, `TreeUpdateConfirmed`, `TransactionBatchConfirmed` on-chain events
- [x] Batch proving pipeline (Plonky2 → BN128 → Groth16) for both deposit-only and two-phase paths.
- [x] Chain recovery from `ValidatedBatchFinalized` logs (deposit-only path) and `TransactionBatchRegistered` logs (two-phase path) with local tree-store replay.
- [x] Fixed-rate partial-batch flush:
  - pools flush when full or timeout elapses
  - deterministic dummy padding off-chain
  - omitted dummies re-derived on-chain

## 2. How To Use Current Implementation Safely (Dev/Test)

- [ ] Run as a devnet/testnet stack first; do not treat as production-ready.
- [ ] Configure sequencer timeout explicitly with `TESSERA_BATCH_TIMEOUT_SECS`.
- [ ] Keep sequencer API private to trusted callers only (network-level ACL).
- [ ] Use health/log monitoring for:
  - queue depth (`registered_pending_batches.len()`)
  - batch retries and confirm retries
  - receipt timeouts
  - recovery progress
- [ ] Private-tx output notes are registered (Validated) atomically but confirmed asynchronously per tree; clients should wait for `confirmedNotesCommitmentRoot()` to advance before treating notes as ZK-final.

## 3. Missing Features / Functional TODO

- [ ] Replace dummy private-tx proof checks (`0x01`) with real cryptographic verification in API path.
- [ ] Replace dummy associated-input aggregation with real prover-side aggregation and real on-chain verifier.
- [ ] Persist original `tx_proof` bytes to WAL so recovered two-phase prove jobs use real proofs (currently uses dummy on restart).
- [ ] Add production-grade sequencer authn/authz for all intake endpoints.
- [ ] Add rate limiting / anti-spam controls at API boundary.
- [ ] Add configurable/fair scheduling instead of hardcoded tree priority to avoid starvation.
- [ ] Add tx lifecycle management:
- nonce control
- replacement/speed-up
- gas policy
- [ ] Add stronger operator management:
- multisig / role separation
- rotation procedures
- emergency controls/runbooks
- [ ] Expose queue-full (`registered_pending_batches >= MAX_PENDING_BATCHES`) as an HTTP 429 response to `/private-tx` callers rather than silent drop.
- [ ] Add production observability:
- metrics
- tracing standards
- alert rules
- [ ] Add integration tests for:
- timed partial flush across all 4 pools
- restart/recovery with partial-batch calldata and dummy re-derivation
- private-tx high-throughput and starvation scenarios

## 4. Security Issues and Deployment Blockers

Critical blockers before public deployment:

- [ ] Aggregated input proof is stubbed (`DummyVerifier` accepts placeholder proof).
- [ ] Private transaction proof verification is stubbed (`0x01` check).
- [ ] Sequencer API has no built-in authentication.
- [ ] No API rate limiting; channel capacity is the only backpressure.
- [ ] Single-operator trust model with centralized control.
- [ ] Optional insecure proof-verify feature flag exists and must be disabled/guarded in production pipelines.

Important security caveats:

- [ ] Nullifier correctness currently relies on tx-proof soundness; with stubbed tx-proof this is not a complete security boundary.
- [ ] Open API + centralized operator + dummy proofing can permit malicious spam or invalid business actions even if tree math verifies.

## 5. Operational Pitfalls in Current State

- [ ] Deposit-only path (`/consume-request`) still limited to one batch in-flight globally; private-TX path (`/private-tx`) supports up to `MAX_PENDING_BATCHES = 128` concurrent batches.
- [ ] Prover runtime is effectively single-threaded due to global FFI singleton / mutex model.
- [ ] Hardcoded tree priority can starve lower-priority pools under sustained load.
- [ ] Receipt polling timeout causes requeue; without robust tx tracking, duplicate/in-flight ambiguity can occur until recovery reconciles.
- [ ] Tree depth is fixed (32); long-term capacity and migration strategy must be planned.
- [ ] Partial-batch dummy derivation must remain byte-for-byte stable across Rust and Solidity; any drift breaks proof/finalization.

## 6. Production Readiness Checklist

- [ ] Real tx-proof verification integrated and audited.
- [ ] Real aggregated-input verifier integrated on-chain and wired to prover output.
- [ ] API authentication + authorization + transport security in place.
- [ ] Rate limiting and abuse controls enabled.
- [ ] Operator model hardened (multisig / HSM / rotation / incident process).
- [ ] Transaction manager implemented (nonce, replacement, gas strategy, reconciliation).
- [ ] End-to-end chaos/recovery tests passing (including crash, reorg, restart, backfill).
- [ ] Security review/audit completed for:
- contract logic
- sequencer/prover trust boundaries
- proving pipeline and feature flags
- [ ] Runbooks prepared for pause/recovery/key compromise scenarios.

## 7. Suggested Tracking Labels (for issues/board)

- `security-blocker`
- `prod-readiness`
- `proof-system`
- `sequencer-reliability`
- `api-hardening`
- `recovery`
- `performance`
- `docs`

