use plonky2::plonk::{
	circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
	proof::ProofWithPublicInputsTarget,
};
use doxa_utils::{ConfigNative, D, F};

/// Inner circuit data needed to build a (Withdraw, Deposit) pair leaf circuit.
///
/// The pair leaf circuit verifies one W proof and one D proof, connects their
/// common public inputs, and exposes:
/// ```text
/// PI layout: [act_root(4) | mainpool(4) | w_unique | d_unique]
/// ```
pub struct BridgeTxPairLeafData {
	pub withdraw_common: CommonCircuitData<F, D>,
	pub withdraw_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
	pub deposit_common: CommonCircuitData<F, D>,
	pub deposit_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
}

/// Inner circuit data required to build [`super::circuit::BridgeTxSuperCircuit`].
///
/// The super circuit now takes only two inner proofs:
/// - `pair_agg`: the root of the pair-aggregation tree (256 W+D pairs collapsed into one).
/// - `poseidon_root`: the SR proof over 512 output commitments.
pub struct BridgeTxSuperCircuitData {
	pub pair_common: CommonCircuitData<F, D>,
	pub pair_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
	pub poseidon_root_common: CommonCircuitData<F, D>,
	pub poseidon_root_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
	/// Number of W-unique PI fields per pair slot (= W total PI count − 8 common PIs).
	pub w_unique_size: usize,
	/// Number of D-unique PI fields per pair slot (= D total PI count − 8 common PIs).
	pub d_unique_size: usize,
}

/// Circuit targets allocated by [`super::circuit_builder::setup_super_builder`].
pub(super) struct BridgeTxSuperTargets {
	pub(super) pair_proof: ProofWithPublicInputsTarget<D>,
	pub(super) poseidon_root_proof: ProofWithPublicInputsTarget<D>,
}
