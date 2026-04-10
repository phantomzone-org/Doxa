//! `BridgeTxAggregator` — reduces a finalized [`BridgeTxBatch`] of
//! 256 Withdraw + 256 Deposit proofs into a single Plonky2 proof whose only
//! public output is `super_pi_commitment`.
//!
//! # Circuit pipeline
//!
//! ```text
//! 256 Withdraw proofs
//!     └─ GenericAggregator (arity=4, depth=4)  →  w_agg_proof
//! 256 Deposit proofs
//!     └─ GenericAggregator (arity=4, depth=4)  →  d_agg_proof
//! 512 leaves from output_commitments
//!     └─ SubtreeRootCircuit (512 leaves)        →  sr_proof
//!                       ↓
//!            BridgeTxSuperCircuit
//! (verify all three, cross-check, common-PI check, Keccak)
//!                       ↓
//!            final_proof  [8 u32 public inputs = super_pi_commitment]
//! ```
//!
//! # SR leaf layout
//!
//! Withdraw slots → SR[0..256), one leaf = accout_comm per slot.
//! Deposit slots  → SR[256..512), one leaf = accout_comm per slot.
//!
//! # super_pi_commitment preimage (matches [`BatchHelper::pi_commitment`])
//!
//! ```text
//! sr_root[4 GL] | act_root[4 GL] | mainpool_config_root[4 GL]
//! | unique_pis_w_slot_0 | … | unique_pis_w_slot_255
//! | unique_pis_d_slot_0 | … | unique_pis_d_slot_255
//! ```
//!
//! Each GL field → `[lo_u32, hi_u32]` (matching `BatchHelper::push_fields`).

mod aggregator;
mod circuit;
mod circuit_builder;
pub mod targets;

pub use aggregator::BridgeTxAggregator;
pub use circuit::BridgeTxSuperCircuit;
pub use targets::BridgeTxSuperCircuitData;

#[cfg(test)]
mod tests;
