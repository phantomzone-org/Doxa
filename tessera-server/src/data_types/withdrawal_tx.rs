use plonky2::{field::extension::Extendable, hash::hash_types::RichField, plonk::{config::GenericConfig, proof::ProofWithPublicInputs}};
use serde::{Deserialize, Serialize};
use tessera_client::{AccountCommitment, AccountNullifier, NoteCommitment, NoteNullifier};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]

pub struct WithdrawalTx<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>{
    pub address: [u8; 20],
    pub input_account_state: AccountNullifier,
    pub output_account_state: AccountCommitment,
    pub proof: ProofWithPublicInputs<F, C, D>
}