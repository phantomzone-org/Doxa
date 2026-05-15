//! Doxa State Sync Service
//!
//! Standalone service that tracks on-chain state from DoxaContract and exposes
//! it via HTTP API for other Doxa components.

pub mod api;
pub mod constants;
pub mod contract;
pub mod state;
pub mod sync;

pub use state::*;
pub use sync::*;
pub use api::*;