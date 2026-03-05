pub(crate) mod account;
pub(crate) mod commitment;
pub(crate) mod ecgfp5;
pub(crate) mod note;
pub(crate) mod p2;
pub(crate) mod pool_config;
pub(crate) mod schnorr;
pub(crate) mod tree;

pub const DS_NULLIFIER_KEY: u64 = 12;
pub const DS_PUBLIC_IDENTIFIER: u64 = 13;
pub const DS_ACC_AST: u64 = 1312;

// TODO: set this to H("tessera::account::ast::emptyLeaf")
pub const AST_DEFAULT_LEAF: [u64; HASH_SIZE] = [0u64; HASH_SIZE];
// TODO: set this to root of merkle tree with depth `ACC_AST_DEPTH` with leafs set to
// `AST_DEFAULT_LEAF`
pub const AST_DEFAULT_ROOT: [u64; HASH_SIZE] = [
	14769473886748754115,
	10513963056908986963,
	8105478726930894327,
	14014796621245524545,
];
// this is set to H("tesseta::account::consume::invalidPubKey"). It's not a valid point on the curve
pub const DEFAULT_CONSUME_INVALID_PK: [u64; 5] = [0u64; 5];
// this is set to H("tesseta::account::spend::invalidPubKey"). It's not a valid point on the curve
pub const DEFAULT_SPEND_AUTH_INVALID_PK: [u64; 5] = [0u64; 5];

pub const NOTE_BATCH: usize = 8;
pub const ACC_AST_DEPTH: usize = 10;
pub const NCT_DEPTH: usize = 32;
pub const ACT_DEPTH: usize = 32;
pub const ANT_DEPTH: usize = 32;
pub const NNT_DEPTH: usize = 32;
pub const SUBPOOL_CONFIG_DEPTH: usize = 2;
pub const MAIN_POOL_CONFIG_DEPTH: usize = 20;

pub use account::*;
pub use note::*;
use tessera_trees::tree::HASH_SIZE;

#[cfg(test)]
mod tests {
	use plonky2::hash::poseidon::PoseidonHash;
	use plonky2_field::types::{Field, PrimeField64};
	use tessera_trees::F;

	use super::*;
}
