pub(crate) mod account;
pub(crate) mod commitment;
pub(crate) mod ecgfp5;
pub(crate) mod note;
pub(crate) mod p2;
pub(crate) mod schnorr;
pub(crate) mod tree;

pub const DS_NULLIFIER_KEY: u64 = 12;
pub const DS_PUBLIC_IDENTIFIER: u64 = 13;
pub const DS_ACC_AST: u64 = 1312;

// TODO: set this to H("tessera::account::ast::emptyLeaf")
pub const AST_DEFAULT_LEAF: [u64; HASH_SIZE] = [0u64; HASH_SIZE];

pub const NOTE_BATCH: usize = 8;
pub const ACC_AST_DEPTH: usize = 10;
pub const NCT_DEPTH: usize = 32;
pub const ACT_DEPTH: usize = 32;
pub const ANT_DEPTH: usize = 32;
pub const NNT_DEPTH: usize = 32;

pub use account::*;
pub use note::*;
use tessera_trees::tree::{HASH_SIZE, hasher::HashOutput};
