use plonky2::{hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder};
use plonky2_field::extension::Extendable;

use crate::plonky2_gadgets::priv_tx::targets::AccountTarget;

pub(crate) trait DepositTxCircuitBuilder {
	fn assert_account_invariants(&mut self, accin: AccountTarget, accout: AccountTarget);
}

impl<F: RichField + Extendable<D>, const D: usize> DepositTxCircuitBuilder
	for CircuitBuilder<F, D>
{
	fn assert_account_invariants(&mut self, accin: AccountTarget, accout: AccountTarget) {
		// AccIn, AccOut must have private_identifier, subpool_id
		self.connect_array(accin.private_identifier.0, accout.private_identifier.0);
		self.connect(accin.subpool_id.0, accout.subpool_id.0);

		// Nonce is always incremented by 1 for every tx kind
		let one = self.one();
		let expected_nonce = self.add(accin.nonce, one);
		self.connect(accout.nonce, expected_nonce);

		// spend_auth and consume_auth are not changed
		self.connect_array(accin.spend_auth.0.0, accout.spend_auth.0.0);
		self.connect_array(accin.consume_auth.pk.0.0, accout.consume_auth.pk.0.0);
		self.connect(
			accin.consume_auth.config.target,
			accout.consume_auth.config.target,
		);
	}
}
