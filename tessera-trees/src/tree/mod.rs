mod commitment_tree;
#[allow(clippy::module_inception)]
mod tree;
pub(crate) mod verification;

pub mod error;
pub mod hasher;

pub use commitment_tree::*;
pub use tree::*;

/// Size of a hash in field elements (Poseidon outputs 4 Goldilocks elements)
pub const HASH_SIZE: usize = 4;
