//! Demo sequencer library.
//!
//! Provides [`DemoSequencer`] — an HTTP sequencer service that connects to
//! a deployed TesseraContract (with AcceptAllVerifier) and exposes endpoints
//! for deposits and private transactions.
//!
//! The sequencer batches incoming requests, submits them on-chain, and after
//! a configurable delay sends a zero Groth16 proof (accepted by
//! AcceptAllVerifier) with the correct piCommitment to confirm the batch.

pub mod sequencer;

pub use sequencer::{DemoSequencer, DemoSequencerConfig, RunningSequencer};
