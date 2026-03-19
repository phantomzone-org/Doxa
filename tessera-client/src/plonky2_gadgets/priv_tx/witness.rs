use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use tessera_trees::{F, tree::hasher::HashOutput};

use super::targets::TxCircuitTargets;
use crate::{
	StandardAccount,
	plonky2_gadgets::{
		set_hash,
		witness::{set_authority_keys, set_hash_blocks},
	},
	pool_config::CompPubKey,
};

#[derive(Clone, Copy)]
pub(crate) struct TxKindFlags {
	pub(crate) is_rjct: bool,
	pub(crate) is_fresh_acc: bool,
	pub(crate) is_update_auth: bool,
	pub(crate) is_priv_tx: bool,
	pub(crate) not_fake_tx: bool,
}

pub(crate) fn set_tx_kind_flags(
	pw: &mut PartialWitness<F>,
	t: &TxCircuitTargets,
	flags: TxKindFlags,
) {
	pw.set_bool_target(t.is_rjct, flags.is_rjct).unwrap();
	pw.set_bool_target(t.is_fresh_acc, flags.is_fresh_acc)
		.unwrap();
	pw.set_bool_target(t.is_update_auth, flags.is_update_auth)
		.unwrap();
	pw.set_bool_target(t.is_priv_tx, flags.is_priv_tx).unwrap();
	pw.set_bool_target(t.not_fake_tx, flags.not_fake_tx)
		.unwrap();
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn set_common_tx_witness(
	pw: &mut PartialWitness<F>,
	t: &TxCircuitTargets,
	mainpool_config_root: HashOutput,
	root: HashOutput,
	approval_key: &CompPubKey,
	rejection_key: &CompPubKey,
	consume_key: &CompPubKey,
	accin: &StandardAccount,
	accout: &StandardAccount,
) {
	set_hash(pw, t.mainpool_config_root.0, mainpool_config_root.0);
	// V2 uses a single on-chain IMT; both circuit slots carry the same root.
	set_hash(pw, t.act_root.0, root.0);
	set_hash(pw, t.nct_root.0, root.0);
	set_authority_keys(
		pw,
		&t.approval_key,
		&t.rejection_key,
		&t.subpool_consume_key,
		approval_key,
		rejection_key,
		consume_key,
	);
	t.accin.set_witness(pw, accin);
	t.accout.set_witness(pw, accout);
}

pub(crate) fn set_note_hash_overrides(
	pw: &mut PartialWitness<F>,
	t: &TxCircuitTargets,
	override_nn: &[[F; 4]; crate::NOTE_BATCH],
	override_nc: &[[F; 4]; crate::NOTE_BATCH],
) {
	set_hash_blocks(pw, &t.override_nn, override_nn);
	set_hash_blocks(pw, &t.override_nc, override_nc);
}
