//! Transaction builder pattern for PrivTx circuit.
//!
//! This module provides ergonomic builders for constructing private transactions
//! with validation, replacing the manual witness-setting pattern with a type-safe,
//! chainable API.
//!
//! # Architecture
//!
//! The builder pattern consists of three layers:
//!
//! 1. **Transaction-specific builders** (`SpendTxBuilder`, `FreshAccTxBuilder`)
//!    - Ergonomic, chainable API for constructing transactions
//!    - Early validation of transaction constraints
//!    - Type-safe handling of transaction-specific requirements
//!
//! 2. **Built transaction types** (`BuiltSpendTx`, `BuiltFreshAccTx`)
//!    - Validated transactions ready for signing
//!    - Provide methods for generating required signatures
//!    - Verify signing key correctness
//!
//! 3. **Unified representation** (`BuiltPrivTx`)
//!    - Common representation for all transaction kinds
//!    - Handles witness setting for the circuit
//!    - Generates zero-knowledge proofs
//!
//! # Example: Spend Transaction
//!
//! ```ignore
//! use std::sync::Arc;
//! use tessera_client::plonky2_gadgets::priv_tx::builder::{
//!     SpendTxBuilder, SpendTxSignatures,
//! };
//!
//! // Build the transaction
//! let built_tx = SpendTxBuilder::new(
//!         account,
//!         asset_id,
//!         approval_key,
//!     )?
//!     .add_input_note(note0)?
//!     .add_input_note(note1)?
//!     .add_output_note(recipient_addr, amount, memo, &mut rng)?
//!     .build()?;
//!
//! // Check which signatures are required
//! let required = built_tx.required_signatures();
//!
//! // Generate signatures
//! let mut rng = rand::thread_rng();
//! let spend_sig = if required.spend {
//!     built_tx.spend_sign(&spend_sk, &mut rng)?
//! } else {
//!     None
//! };
//! let consume_sig = if required.consume {
//!     built_tx.consume_sign(&consume_sk, &mut rng)?
//! } else {
//!     None
//! };
//! let approval_sig = built_tx.approval_sign(&approval_sk, &mut rng)?;
//!
//! // Create signatures bundle
//! let signatures = SpendTxSignatures::new(spend_sig, consume_sig, approval_sig);
//!
//! // Generate proof (now requires state_tree and main_pool)
//! let proven_tx = built_tx.prove(
//!     &circuit_data,
//!     &targets,
//!     signatures,
//!     &state_tree,
//!     Arc::new(main_pool),
//! )?;
//! ```
//!
//! # Example: FreshAcc Transaction
//!
//! ```ignore
//! use std::sync::Arc;
//! use tessera_client::plonky2_gadgets::priv_tx::builder::FreshAccTxBuilder;
//!
//! // Build the transaction
//! let built_tx = FreshAccTxBuilder::new(
//!         fresh_account,
//!         subpool_id,
//!         approval_key,
//!     )?
//!     .with_new_spend_key(spend_pk)?
//!     .with_new_consume_key(consume_pk)?
//!     .build()?;
//!
//! // Generate signature (only approval needed for FreshAcc)
//! let mut rng = rand::thread_rng();
//! let approval_sig = built_tx.approval_sign(&approval_sk, &mut rng)?;
//!
//! // Generate proof (now requires state_tree and main_pool)
//! let proven_tx = built_tx.prove(
//!     &circuit_data,
//!     &targets,
//!     approval_sig,
//!     &state_tree,
//!     Arc::new(main_pool),
//! )?;
//! ```

mod built_priv_tx;
mod errors;
mod fake_builder;
mod freshacc_builder;
mod spend_builder;

pub use built_priv_tx::{BuiltPrivTx, PrivTxPublicInputs, ProvenPrivTx};
pub use errors::{
	FakeTxBuilderError, FreshAccTxBuilderError, PrivTxProveError, SpendTxBuilderError, TxSignError,
};
pub use fake_builder::{BuiltFakeTx, FakeTxBuilder};
pub use freshacc_builder::{BuiltFreshAccTx, FreshAccTxBuilder};
pub use spend_builder::{BuiltSpendTx, RequiredSignatures, SpendTxBuilder, SpendTxSignatures};
