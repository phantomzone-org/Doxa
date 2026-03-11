#![allow(clippy::all)]
#![allow(warnings)]
pub(crate) mod account;
pub(crate) mod commitment;
pub(crate) mod ecgfp5;
pub(crate) mod note;
pub(crate) mod plonky2_gadgets;
pub use plonky2_gadgets::serialization::TesseraGateSerializer;
pub(crate) mod pool_config;
pub(crate) mod schnorr;
pub(crate) mod tree;
pub(crate) mod utils;

pub const DS_NULLIFIER_KEY: u64 = 12;
pub const DS_PUBLIC_IDENTIFIER: u64 = 13;
pub const DS_ACC_AST_LEAF: u64 = 1312;

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
// this is set to H("tesseta::account::commitment::consumePk::placeholder"). It's not a valid point
// on the curve
pub const DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER: [u64; 5] = [1u64; 5];
// this is set to random point on the curve with seed H("tesseta::account::spend::defaultSpendKey").
// TODO: atm the point is a random point but not
pub const DEFAULT_SPEND_AUTH_PK: [u64; 5] = [
	7613690455422068269,
	12930951591626745075,
	16103143792840800039,
	4657200339622395349,
	3857357297380158342,
];

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
pub use plonky2_gadgets::priv_tx::{
	PrivTxTargets, build_circuit_and_dummy_proof, build_circuit_and_real_proof,
	build_priv_tx_circuit, prove_dummy_priv_tx, prove_real_priv_tx,
};
use tessera_trees::tree::HASH_SIZE;
