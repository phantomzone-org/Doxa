//! `PrivTxAggregator` — reduces a finalized [`PrivateTxBatch`] of 64 proofs to a
//! single Plonky2 proof whose only public output is `super_pi_commitment`.
//!
//! # Circuit pipeline
//!
//! ```text
//! 64 PrivTx proofs
//!     └─ GenericAggregator (arity=8, depth=2)  →  tx_agg_proof
//! 512 leaves from output_commitments
//!     └─ SubtreeRootCircuit (512 leaves)        →  sr_proof
//!                       ↓
//!            PrivTxSuperCircuit
//!  (verify both, cross-check, common-PI check, Keccak)
//!                       ↓
//!            final_proof  [8 u32 public inputs = super_pi_commitment]
//! ```
//!
//! # super_pi_commitment preimage (matches [`BatchHelper::pi_commitment`])
//!
//! ```text
//! sr_root[4 GL] | act_root[4 GL] | mainpool_config_root[4 GL]
//! | unique_pis_slot_0 | ... | unique_pis_slot_63
//! ```
//!
//! Each GL field → `[lo_u32, hi_u32]` (matching `BatchHelper::push_fields`).

mod aggregator;
mod circuit;
mod circuit_builder;
pub mod targets;

pub use aggregator::PrivTxAggregator;
pub use circuit::PrivTxSuperCircuit;
pub use targets::PrivTxSuperCircuitData;

#[cfg(test)]
mod tests;
