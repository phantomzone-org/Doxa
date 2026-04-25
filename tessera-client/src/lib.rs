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
pub(crate) mod ecgfp5;
pub(crate) mod note;
pub mod plonky2_gadgets;
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
		PrivTxProof, build_priv_tx_circuit,
		builder::{FakeSpendTxBuilder, SpendTxBuilder},
	},
	withdraw_tx::{WithdrawProof, WithdrawTxCircuit, build_withdraw_tx_circuit},
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

/// Root of a default Account State Tree of depth [`ACC_AST_DEPTH`]. Pre-computed so circuits can
/// start from a known initial root without rebuilding the whole tree.
pub const AST_DEFAULT_ROOT: [u64; HASH_SIZE] = [
	2537328717772714990,
	1534150781011785517,
	14977255124160483673,
	9325839111461431495,
];

// ── Placeholder / default authority values ────────────────────────────────────

// this is set to H("tesseta::account::commitment::consumePk::placeholder"). It's not a valid point
// on the curve
/// Placeholder consume-key stored in an account commitment when
/// `consume_auth.config = false` (subpool-delegated consume).
/// This is **not** a valid curve point — it only pads the commitment hash to a
/// fixed width and must never be used as an actual public key.
pub const DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER: [u64; 5] = [
	7613690455422068269,
	12930951591626745075,
	16103143792840800039,
	4657200339622395349,
	3857357297380158342,
];

// this is set to random point on the curve with seed H("tesseta::account::spend::defaultSpendKey").
// TODO: atm the point is a random point but not
/// Default spend-auth public key used in account commitments before a real
/// spend key has been set (i.e. nonce = 0 / pre-FreshAcc state).
/// A random curve point derived from
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

/// Number of proof slots per batch, shared across all BatchHelper implementations
/// (private TX, mixed deposit/withdraw).  Drives the Poseidon subtree size:
/// each proof contributes `output_commitments().len()` leaves, and the total
/// must be a power of two for `SubtreeRootCircuit`.
pub const PRIV_TX_BATCH_SIZE: usize = 64;

/// Number of proof slots per bridge batch (deposit + withdraw combined).
/// Each half holds 256 proofs; each proof contributes 1 output commitment
/// (account commitment only), giving 512 leaves = SUBTREE_BATCHSIZE.
pub const BRIDGE_TX_BATCH_SIZE: usize = 512;

/// Size of the subtree to be inserted on chain.
pub const SUBTREE_BATCHSIZE: usize = 512;

/// Depth of the per-account Asset State Tree (supports 2^10 = 1024 assets).
pub const ACC_AST_DEPTH: usize = 10;

/// Depth of the global Account Commitment Tree (supports 2^32 accounts).
pub const STATE_TREE_DEPTH: usize = 32;

/// Depth of each per-subpool authority-key configuration tree
/// (3 leaves: approval / rejection / consume keys).
pub const SUBPOOL_CONFIG_DEPTH: usize = 2;

/// Depth of the main pool configuration tree (supports 2^20 subpools).
pub const MAIN_POOL_CONFIG_DEPTH: usize = 20;

/// Shared interface for all three transaction proof types.
///
/// # Uniform PI prefix (first 17 elements, all types)
/// ```text
/// [0..4]  act_root            (ACT Merkle root, 4 field elements)
/// [4..8]  mainpool_config_root (main pool config root, 4 field elements)
/// [8]     not_fake_tx          (F::ONE = real, F::ZERO = dummy/padding)
/// [9..13] accin_nullifier      (input account nullifier, 4 field elements)
/// [13..17] accout_commitment   (output account commitment, 4 field elements)
/// ```
/// Elements beyond [17] are type-specific (see each concrete proof type).
pub trait PIHelper {
	fn pis(&self) -> &[F] {
		&self.proof().public_inputs
	}
	fn pi_len(&self) -> usize {
		self.pis().len()
	}
	fn proof(&self) -> &ProofWithPublicInputs<F, ConfigNative, D>;

	/// PI[0..4]: Account Commitment Tree root.
	fn act_root(&self) -> HashOutput {
		HashOutput(self.pis()[0..4].try_into().unwrap())
	}

	/// PI[4..8]: Main pool configuration tree root.
	fn mainpool_config_root(&self) -> HashOutput {
		HashOutput(self.pis()[4..8].try_into().unwrap())
	}

	/// PI[8]: `F::ONE` for a real transaction, `F::ZERO` for a dummy/padding proof.
	fn not_fake_tx(&self) -> F {
		self.pis()[8]
	}

	/// PI[9..13]: Input account nullifier.
	fn accin_nullifier(&self) -> HashOutput {
		HashOutput(self.pis()[9..13].try_into().unwrap())
	}

	/// PI[13..17]: Output account commitment.
	fn accout_commitment(&self) -> HashOutput {
		HashOutput(self.pis()[13..17].try_into().unwrap())
	}

	/// PIs shared across every TX of the same kind in a batch:
	/// `act_root[0..4] | mainpool_config_root[4..8]`.
	fn batch_common_pis(&self) -> Vec<F> {
		self.pis()[0..8].to_vec()
	}

	/// PIs that are unique per TX in a batch: everything from PI[8] onward
	/// (`not_fake_tx`, nullifiers, commitments, and type-specific fields).
	fn batch_unique_pis(&self) -> Vec<F> {
		self.pis()[8..].to_vec()
	}

	/// All output commitments produced by this transaction, in order.
	///
	/// Used to build the Poseidon subtree root over a batch.
	/// Only account commitments (and private note commitments) are inserted into
	/// the commitment tree — deposit note commitments are not:
	///
	/// - [`PrivateTransactionProof`]: `[accout_comm, nc0, .., nc6]`  (8 leaves)
	/// - [`DepositProof`]:            `[accout_comm]`                  (1 leaf)
	/// - [`WithdrawProof`]:           `[accout_comm]`                  (1 leaf)
	fn output_commitments(&self) -> Vec<HashOutput>;
}
