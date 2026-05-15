use plonky2::{
	plonk::{
		circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
		proof::ProofWithPublicInputsTarget,
	},
};
use tessera_utils::{ConfigNative, D, F};

/// Inner circuit data required to build [`super::circuit::PrivTxSuperCircuit`].
pub struct PrivTxSuperCircuitData {
	pub tx_common: CommonCircuitData<F, D>,
	pub tx_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
	pub sr_common: CommonCircuitData<F, D>,
	pub sr_verifier: VerifierOnlyCircuitData<ConfigNative, D>,
}

/// Circuit targets allocated by [`super::circuit_builder::setup_super_builder`].
pub(super) struct PrivTxSuperTargets {
	pub(super) tx_proof: ProofWithPublicInputsTarget<D>,
	pub(super) sr_proof: ProofWithPublicInputsTarget<D>,
}
