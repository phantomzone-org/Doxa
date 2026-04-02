//! Tessera client library.
//!
//! Provides all client-side primitives and Plonky2 ZK circuit gadgets needed
//! to participate in the Tessera privacy protocol:
//!
//! - **Account / note primitives** — [`StandardAccount`], [`StandardNote`], commitment and
//!   nullifier derivation.
//! - **Plonky2 circuit gadgets** — three transaction circuits (deposit, private-spend, withdraw)
//!   with witness helpers and proof generation.
//! - **Schnorr / EC** — GFp5 elliptic-curve arithmetic and Schnorr signatures used for
//!   spend/consume/approval authorization.
//! - **Merkle infrastructure** — generic Merkle tree, commitment-tree (append-only,
//!   position-embedded) and account-state-tree proofs.
//! - **Pool configuration** — subpool and main-pool authority-key trees.

#![allow(dead_code, unused_imports, unused_variables)]
pub(crate) mod account;
pub(crate) mod commitment;
pub(crate) mod ecgfp5;
pub(crate) mod note;
pub(crate) mod plonky2_gadgets;
use plonky2::plonk::proof::ProofWithPublicInputs;
pub use plonky2_gadgets::serialization::TesseraGateSerializer;
pub mod pool_config;
pub mod schnorr;
pub(crate) mod utils;

pub use account::*;
pub use note::*;
pub use plonky2_gadgets::{
	deposit_tx::{DepositProof, DepositTxCircuit, build_deposit_tx_circuit},
	priv_tx::{
		FakeTxInputs, FreshAccInputs, PrivTxInputs, PrivTxTargets, PrivateTransactionProof,
		RejectTxInputs, SpendTxInputs, build_circuit_and_dummy_proof, build_circuit_and_real_proof,
		build_priv_tx_circuit, double_hash_native, prove_dummy_priv_tx, prove_real_priv_tx,
		prove_real_priv_tx_seeded, sample_dummy_notes,
	},
	withdraw_tx::WithdrawProof,
};
pub use tessera_utils::hasher::HashOutput;
use tessera_utils::{ConfigNative, D, F, HASH_SIZE};

// ── Domain-separation tags ────────────────────────────────────────────────────
// Each tag is prepended to a Poseidon hash input to prevent cross-domain
// collisions between structurally similar inputs.

/// Domain separator for nullifier-key derivation:
/// `nk = H(DS_NULLIFIER_KEY || private_identifier)`.
pub const DS_NULLIFIER_KEY: u64 = 12;

/// Domain separator for public-identifier derivation:
/// `public_id = H(DS_PUBLIC_IDENTIFIER || private_identifier)`.
pub const DS_PUBLIC_IDENTIFIER: u64 = 13;

/// Domain separator for Account State Tree leaf hashing:
/// `leaf = H(DS_ACC_AST_LEAF || asset_id || amount_limbs[8])`.
pub const DS_ACC_AST_LEAF: u64 = 1312;

// ── Account State Tree defaults ───────────────────────────────────────────────

// TODO: set this to H("tessera::account::ast::emptyLeaf")
/// Hash value of an empty AST leaf (all-zero field elements).
/// Used as the default leaf for uninitialised asset slots.
pub const AST_DEFAULT_LEAF: [u64; HASH_SIZE] = [0u64; HASH_SIZE];

// TODO: set this to root of merkle tree with depth `ACC_AST_DEPTH` with leafs set to
// `AST_DEFAULT_LEAF`
/// Root of an empty Account State Tree of depth [`ACC_AST_DEPTH`] where every
/// leaf is [`AST_DEFAULT_LEAF`]. Pre-computed so circuits can start from a
/// known initial root without rebuilding the whole tree.
pub const AST_DEFAULT_ROOT: [u64; HASH_SIZE] = [
	14769473886748754115,
	10513963056908986963,
	8105478726930894327,
	14014796621245524545,
];

// ── Placeholder / default authority values ────────────────────────────────────

// this is set to H("tesseta::account::commitment::consumePk::placeholder"). It's not a valid point
// on the curve
/// Placeholder consume-key stored in an account commitment when
/// `consume_auth.config = false` (subpool-delegated consume).
/// This is **not** a valid curve point — it only pads the commitment hash to a
/// fixed width and must never be used as an actual public key.
pub const DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER: [u64; 5] = [1u64; 5];

// this is set to random point on the curve with seed H("tesseta::account::spend::defaultSpendKey").
// TODO: atm the point is a random point but not
/// Default spend-auth public key used in account commitments before a real
/// spend key has been set (i.e. nonce = 0 / pre-FreshAcc state).
/// A random-but-fixed curve point derived from
/// `H("tessera::account::spend::defaultSpendKey")`.
pub const DEFAULT_SPEND_AUTH_PK: [u64; 5] = [
	7613690455422068269,
	12930951591626745075,
	16103143792840800039,
	4657200339622395349,
	3857357297380158342,
];

// ── Circuit / tree size parameters ───────────────────────────────────────────

/// Number of input/output note slots per private transaction.
/// All note arrays are padded to this length with dummy entries.
pub const NOTE_BATCH: usize = 7;

/// Maximum number of private transactions aggregated into a single rollup batch.
pub const PRIV_TX_BATCH_SIZE: usize = 64;

/// Maximum number of deposit note commitments aggregated into a single deposit batch.
pub const DEPOSIT_BATCH_SIZE: usize = 512;

/// Depth of the per-account Asset State Tree (supports 2^10 = 1024 assets).
pub const ACC_AST_DEPTH: usize = 10;

/// Depth of the global Account Commitment Tree (supports 2^32 accounts).
pub const COM_TREE_DEPTH: usize = 32;

/// Depth of each per-subpool authority-key configuration tree
/// (3 leaves: approval / rejection / consume keys).
pub const SUBPOOL_CONFIG_DEPTH: usize = 2;

/// Depth of the main pool configuration tree (supports 2^20 subpools).
pub const MAIN_POOL_CONFIG_DEPTH: usize = 20;

pub trait PIHelper {
	fn pis(&self) -> &[F] {
		&self.proof().public_inputs
	}
	fn pi_len(&self) -> usize {
		self.pis().len()
	}
	fn proof(&self) -> &ProofWithPublicInputs<F, ConfigNative, D>;

	fn act_root(&self) -> HashOutput;

	fn mainpool_config_root(&self) -> HashOutput;

	fn not_fake_tx(&self) -> bool;

	fn accout_commitment(&self) -> HashOutput;

	fn accin_nullifier(&self) -> HashOutput;

	fn acc_out_subpool_id(&self) -> SubpoolId;

	fn acc_in_subpool_id(&self) -> SubpoolId;
}
