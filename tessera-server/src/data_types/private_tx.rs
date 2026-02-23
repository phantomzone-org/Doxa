use plonky2::{field::extension::Extendable, hash::hash_types::RichField, plonk::{config::GenericConfig, proof::ProofWithPublicInputs}};
use serde::{Deserialize, Serialize};
use tessera_client::{NoteCommitment, NoteNullifier};

use crate::{AccounteState};



#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PrivateTx<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>{
    pub input_notes: Vec<NoteNullifier>,
    pub output_notes: Vec<NoteCommitment>,
    pub input_account_state: AccounteState,
    pub output_account_state: AccounteState,
    pub proof: ProofWithPublicInputs<F, C, D>
}

