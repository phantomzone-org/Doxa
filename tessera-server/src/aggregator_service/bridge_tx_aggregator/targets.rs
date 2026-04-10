use plonky2::plonk::{
	circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
	proof::ProofWithPublicInputsTarget,
};
use tessera_utils::{ConfigNative, D, F};

/// Inner circuit data required to build [`super::circuit::BridgeTxSuperCircuit`].
pub struct BridgeTxSuperCircuitData {
	pub withdraw_common: CommonCircuitData<F, D>,
	pub withdraw_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
	pub deposit_common: CommonCircuitData<F, D>,
	pub deposit_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
	pub poseidon_root_common: CommonCircuitData<F, D>,
	pub poseidon_root_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
}

/// Circuit targets allocated by [`super::circuit_builder::setup_super_builder`].
pub(super) struct BridgeTxSuperTargets {
	pub(super) withdraw_proof: ProofWithPublicInputsTarget<D>,
	pub(super) deposit_proof: ProofWithPublicInputsTarget<D>,
	pub(super) poseidon_root_proof: ProofWithPublicInputsTarget<D>,
}
