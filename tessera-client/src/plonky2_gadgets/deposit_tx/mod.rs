use plonky2::{
	hash::{
		hash_types::{HashOut, RichField},
		hashing::hash_n_to_m_no_pad,
		poseidon::{Poseidon, PoseidonHash},
	},
	iop::{
		target::Target,
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};
use plonky2_field::{
	extension::Extendable,
	types::{Field, PrimeField64},
};
use primitive_types::{H160, U256};
use tessera_trees::{
	F, plonky2_gadgets::u32::add_u8_range_check_lookup_table, tree::hasher::HashOutput,
};

use crate::{
	ACC_AST_DEPTH, ACT_DEPTH, AssetId, DS_PUBLIC_IDENTIFIER, MAIN_POOL_CONFIG_DEPTH, Nonce,
	SUBPOOL_CONFIG_DEPTH, StandardAccount, SubpoolId,
	account::{AccountStateTreeLeaf, PublicIdentifier},
	derive_deposit_tx_hash,
	ecgfp5::{CompressedPoint, PointEw},
	note::DepositNote,
	plonky2_gadgets::{
		deposit_tx::{
			cb::DepositTxCircuitBuilder,
			targets::{
				DepositNoteCommitmentTarget, DepositNoteTarget, DepositTxSignatureTargets,
				DepositTxTargets,
			},
		},
		merkle::{MerkleSiblingsBits, merkle_verify_gadget, set_merkle_siblings_and_bits},
		priv_tx::{
			cb::PrivTxCircuitBuilder,
			targets::{
				AccountNullifierTarget, ActMerkleTarget, ActRootTarget, AssetIdTarget,
				MainPoolConfigRootTarget, PublicIdentifierTaregt, SubpoolIdTarget,
			},
		},
		set_hash,
		signature::{
			LocalQuinticExtension, PubkeyTarget, conditional_schnorr_verify_gadget,
			set_schnorr_witness,
		},
		u256::CircuitBuilderU256,
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
	schnorr::{Scalar, Signature, schnorr_challenge},
	utils::map_h160_to_f,
};

pub(crate) mod cb;
pub(crate) mod targets;

pub fn deposit_tx_circuit<F: RichField + Extendable<D> + Poseidon, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
) -> DepositTxTargets {
	let ds_public_identifier = builder.constant(F::from_canonical_u64(DS_PUBLIC_IDENTIFIER));

	// Authority keys
	let approval_key = PubkeyTarget(LocalQuinticExtension(builder.add_virtual_target_arr()));
	let rejection_key = PubkeyTarget(LocalQuinticExtension(builder.add_virtual_target_arr()));
	let subpool_consume_key = PubkeyTarget(LocalQuinticExtension(builder.add_virtual_target_arr()));

	// Tree roots
	let act_root = ActRootTarget(builder.add_virtual_hash());
	let mainpool_config_root = MainPoolConfigRootTarget(builder.add_virtual_hash());

	// Accounts
	let accin = builder.add_virtual_account_target();
	let accout = builder.add_virtual_account_target();

	// Asset / amounts
	let asset_id = AssetIdTarget(builder.add_virtual_target());
	let accin_amt = builder.add_virtual_u256_target();
	let accout_amt = builder.add_virtual_u256_target();
	let asset_exists_in_accin = builder.add_virtual_bool_target_safe();
	let asset_exists_in_accout = builder.add_virtual_bool_target_safe();

	// AccIn position in ACT
	let accin_pos = builder.add_virtual_target();

	// Deposit note fields
	let deposit_note = DepositNoteTarget {
		identifier: builder.add_virtual_target_arr(),
		recipient_subpool_id: SubpoolIdTarget(builder.add_virtual_target()),
		recipient_public_id: PublicIdentifierTaregt(builder.add_virtual_hash()),
		amount: builder.add_virtual_u256_target(),
		asset_id: AssetIdTarget(builder.add_virtual_target()),
	};

	// Ethereum address (5 u32 field elements)
	let eth_address: [Target; 5] = builder.add_virtual_target_arr();

	// Derive public_identifier from accin.private_identifier
	let public_identifier = {
		let mut inp = vec![ds_public_identifier];
		inp.extend(accin.private_identifier.0);
		PublicIdentifierTaregt(builder.hash_n_to_hash_no_pad::<PoseidonHash>(inp))
	};

	// Derive nullifier key
	let nk = builder.derive_nullifier_key(accin.private_identifier);

	// Derive AccIn commitment
	let accin_comm = builder.derive_account_commitment(accin);

	// Derive AccOut commitment
	let accout_comm = builder.derive_account_commitment(accout);

	// AccIn nullifier (always position-based for deposit — account must exist in ACT)
	let accin_null = AccountNullifierTarget(
		builder
			.derive_account_nullifier(accin_comm, accin_pos, nk)
			.0,
	);

	// Connect deposit_note.asset_id with the circuit-level asset_id
	builder.connect(deposit_note.asset_id.0, asset_id.0);

	// Assert ACT membership (always enforced — deposit_tx requires a live account)
	let accin_act_merkle = merkle_verify_gadget(builder, accin_comm.0);
	builder.connect_array(accin_act_merkle.root, act_root.0.elements);

	// Enforce recipient match: deposit_note must target accin
	builder.connect(deposit_note.recipient_subpool_id.0, accin.subpool_id.0);
	builder.connect_array(
		deposit_note.recipient_public_id.0.elements,
		public_identifier.0.elements,
	);

	// Account invariants: is_priv_tx = true, is_fresh_acc = false, is_update_auth = false
	DepositTxCircuitBuilder::assert_account_invariants(builder, accin, accout);

	// AST update: verify asset/amt proofs and enforce same leaf position
	let accin_ast_merkle = builder.assert_ast_update(
		asset_id,
		accin_amt,
		accout_amt,
		accin,
		accout,
		asset_exists_in_accin,
		asset_exists_in_accout,
	);

	// Balance invariant: accout_amt = accin_amt + deposit_note.amount
	let range_lut = add_u8_range_check_lookup_table(builder);
	let sum = builder.u256_addition_chain::<1>(&accin_amt, &[deposit_note.amount], range_lut);
	builder.connect_u256(&sum, &accout_amt);

	// Derive deposit note commitment:
	// H(identifier[2] || recipient_subpool_id[1] || recipient_public_id[4]
	//   || amount[8] || asset_id[1])  → 16 elements
	let deposit_note_comm = {
		let mut inp: Vec<Target> = Vec::with_capacity(16);
		inp.extend_from_slice(&deposit_note.identifier);
		inp.push(deposit_note.recipient_subpool_id.0);
		inp.extend_from_slice(&deposit_note.recipient_public_id.0.elements);
		for u32t in deposit_note.amount.0.iter() {
			inp.push(u32t.0);
		}
		inp.push(deposit_note.asset_id.0);
		assert_eq!(inp.len(), 16);
		DepositNoteCommitmentTarget(builder.hash_n_to_hash_no_pad::<PoseidonHash>(inp))
	};

	// Derive TxHash = H(accin_null[4] || accout_comm[4] || deposit_note_comm[4] || eth_address[5])
	// = 17 elements
	let tx_hash = {
		let mut inp: Vec<Target> = Vec::with_capacity(17);
		inp.extend_from_slice(&accin_null.0.elements);
		inp.extend_from_slice(&accout_comm.0.elements);
		inp.extend_from_slice(&deposit_note_comm.0.elements);
		inp.extend_from_slice(&eth_address);
		assert_eq!(inp.len(), 17);
		builder.hash_n_to_hash_no_pad::<PoseidonHash>(inp)
	};

	// Assert subpool full proof (always enforced for deposit)
	let always_true = builder._true();
	let subpool_proof_targets = builder.assert_subpool_full_proof(
		SubpoolIdTarget(accin.subpool_id.0),
		approval_key,
		rejection_key,
		subpool_consume_key,
		mainpool_config_root,
		always_true,
	);

	// Assert signatures — consume and approval both always required
	// Consume key: accin.consume_auth.config selects between accin's own key or subpool key
	let effective_consume_key = PubkeyTarget(LocalQuinticExtension(core::array::from_fn(|i| {
		builder._if(
			accin.consume_auth.config,
			accin.consume_auth.pk.0.0[i],
			subpool_consume_key.0.0[i],
		)
	})));
	let consume =
		conditional_schnorr_verify_gadget(builder, tx_hash, effective_consume_key, always_true);
	let approval = conditional_schnorr_verify_gadget(builder, tx_hash, approval_key, always_true);

	DepositTxTargets {
		act_root,
		mainpool_config_root,
		approval_key,
		rejection_key,
		subpool_consume_key,
		accin,
		accout,
		accin_amt,
		accout_amt,
		asset_id,
		asset_exists_in_accin,
		asset_exists_in_accout,
		accin_pos,
		accin_act_merkle,
		accin_ast_merkle,
		accout_ast_merkle,
		deposit_note,
		deposit_note_comm,
		eth_address,
		subpool_proof_targets,
		sig_targets: DepositTxSignatureTargets {
			consume,
			approval,
		},
	}
}

/// Compute circuit-compatible Merkle root using `two_to_one` at every level.
fn circuit_merkle_root<const DEPTH: usize>(
	leaf: [F; 4],
	siblings: &[[F; 4]; DEPTH],
	bits: [bool; DEPTH],
) -> [F; 4] {
	let mut cur = leaf;
	for level in 0..DEPTH {
		let sib = siblings[level];
		let result = if bits[level] {
			<PoseidonHash as Hasher<F>>::two_to_one(
				HashOut {
					elements: sib,
				},
				HashOut {
					elements: cur,
				},
			)
		} else {
			<PoseidonHash as Hasher<F>>::two_to_one(
				HashOut {
					elements: cur,
				},
				HashOut {
					elements: sib,
				},
			)
		};
		cur = result.elements;
	}
	cur
}

/// Fill `pw` with a complete DepositTx witness.
///
/// `accout` is derived internally: cloned from `accin`, nonce incremented by one,
/// AST updated with `deposit_note.amount` credited to `deposit_note.asset_id`.
pub(crate) fn set_deposit_tx_witness(
	pw: &mut PartialWitness<F>,
	t: &DepositTxTargets,
	accin: &StandardAccount,
	accin_act_pos: usize,
	accin_act_siblings: &[HashOutput],
	deposit_note: &DepositNote,
	eth_address: &H160,
	approval_key: &CompPubKey,
	rejection_key: &CompPubKey,
	consume_key: &CompPubKey,
	subpool_id: SubpoolId,
	main_pool: &MainPoolConfigTree,
	consume_sig: Signature,
	approval_sig: Signature,
) {
	let asset_id = deposit_note.asset_id;
	let deposit_amt = deposit_note.amount;

	// ── Build accout ──────────────────────────────────────────────────────────
	let (ast_index, old_bal) = accin
		.ast
		.amount_for(asset_id)
		.unwrap_or_else(|| (accin.ast.next_index(), U256::zero()));
	let new_bal = old_bal + deposit_amt;
	let mut accout = accin.clone();
	accout.nonce = Nonce(F::from_canonical_u64(accin.nonce.0.to_canonical_u64() + 1));
	accout.ast.set_leaf(
		ast_index,
		AccountStateTreeLeaf {
			asset_id,
			amount: new_bal,
		},
	);

	// ── Amounts and exists flags ───────────────────────────────────────────────
	let (_, accin_amt) = accin.ast.amount_for(asset_id).unwrap_or((0, U256::zero()));
	let (_, accout_amt) = accout.ast.amount_for(asset_id).unwrap_or((0, U256::zero()));
	let asset_exists_in_accin = accin.ast.amount_for(asset_id).is_some();
	let asset_exists_in_accout = true; // always true after deposit

	// ── ACT circuit-compatible root ───────────────────────────────────────────
	let act_sibs: [[F; 4]; ACT_DEPTH] = core::array::from_fn(|i| accin_act_siblings[i].0);
	let act_bits: [bool; ACT_DEPTH] = core::array::from_fn(|i| (accin_act_pos >> i) & 1 == 1);
	let act_root = HashOutput(circuit_merkle_root(
		accin.commitment().0.0,
		&act_sibs,
		act_bits,
	));

	// ── Native TxHash ─────────────────────────────────────────────────────────
	// H(accin_null[4] || accout_comm[4] || deposit_note_comm[4] || eth_address[5])
	let accin_null = accin.nullifier(Some(accin_act_pos as u64));
	let deposit_note_comm_native = deposit_note.commitment();
	let tx_hash = derive_deposit_tx_hash(
		accin_null,
		accout.commitment(),
		deposit_note_comm_native,
		*eth_address,
	);
	// ── Tree roots ────────────────────────────────────────────────────────────
	set_hash(pw, t.act_root.0, act_root.0);
	set_hash(pw, t.mainpool_config_root.0, main_pool.root().0);

	// ── Authority keys ────────────────────────────────────────────────────────
	t.approval_key.set_witness(pw, approval_key);
	t.rejection_key.set_witness(pw, rejection_key);
	t.subpool_consume_key.set_witness(pw, consume_key);

	// ── Accounts ──────────────────────────────────────────────────────────────
	t.accin.set_witness(pw, accin);
	t.accout.set_witness(pw, &accout);

	// ── Asset / amounts ───────────────────────────────────────────────────────
	pw.set_target(t.asset_id.0, asset_id.0).unwrap();
	t.accin_amt.set_witness(pw, accin_amt);
	t.accout_amt.set_witness(pw, accout_amt);
	pw.set_bool_target(t.asset_exists_in_accin, asset_exists_in_accin)
		.unwrap();
	pw.set_bool_target(t.asset_exists_in_accout, asset_exists_in_accout)
		.unwrap();
	pw.set_target(t.accin_pos, F::from_canonical_usize(accin_act_pos))
		.unwrap();

	// ── ACT Merkle proof ──────────────────────────────────────────────────────
	// TODO: move the function as a method on ActMerkle. Make sure this is only a single call
	// everywhere
	set_merkle_siblings_and_bits(pw, &t.accin_act_merkle, act_sibs, act_bits);

	// ── AccIn AST Merkle proof ────────────────────────────────────────────────
	let ast_proof = accin.ast.merkle_proof_at(ast_index);
	t.accin_ast_merkle.0.set_witness(pw, &ast_proof);

	// ── Deposit note ─────────────────────────────────────────────────────────
	t.deposit_note.set_witness(pw, deposit_note);

	// ── Eth address ───────────────────────────────────────────────────────────
	pw.set_target_arr(&t.eth_address, &map_h160_to_f(&eth_address))
		.unwrap();

	// ── Subpool full proof ────────────────────────────────────────────────────
	let subpool = SubpoolConfigTree::new(*approval_key, *rejection_key, *consume_key);
	let full_proof = main_pool
		.full_subpool_proof(&subpool, subpool_id)
		.expect("subpool not in main_pool at the given subpool_id");

	t.subpool_proof_targets
		.approval_proof
		.set_witness(pw, &full_proof.approval_proof);
	t.subpool_proof_targets
		.rejection_proof
		.set_witness(pw, &full_proof.rejection_proof);
	t.subpool_proof_targets
		.consume_proof
		.set_witness(pw, &full_proof.consume_proof);
	t.subpool_proof_targets
		.main_pool_proof
		.set_witness(pw, &full_proof.main_pool_proof);

	pw.set_target_arr(
		&t.subpool_proof_targets.subpool_config_root.0.elements,
		&subpool.root().0,
	)
	.unwrap();

	// ── Signatures ────────────────────────────────────────────────────────────

	// Consume: uses accin.consume_auth.config to pick key (same as circuit)
	{
		let cq = if accin.consume_auth.config {
			accin.consume_auth.pk.unwrap().0
		} else {
			consume_key.0
		};
		let cr = consume_sig.r.encode();
		let e = schnorr_challenge(&cr, &cq, &tx_hash.0);
		set_schnorr_witness(
			pw,
			&t.sig_targets.consume,
			PointEw::decode(cq).unwrap(),
			cr,
			e,
			consume_sig.s,
		);
	}

	// Approval (always real)
	{
		let cq = approval_key.0;
		let cr = approval_sig.r.encode();
		let e = schnorr_challenge(&cr, &cq, &tx_hash.0);
		set_schnorr_witness(
			pw,
			&t.sig_targets.approval,
			PointEw::decode(cq).unwrap(),
			cr,
			e,
			approval_sig.s,
		);
	}
}
#[cfg(test)]
mod tests {
	use std::array;

	use plonky2::{
		hash::poseidon::PoseidonHash,
		iop::witness::PartialWitness,
		plonk::{
			circuit_builder::CircuitBuilder,
			circuit_data::CircuitConfig,
			config::{GenericConfig, Hasher, PoseidonGoldilocksConfig},
		},
	};
	use plonky2_field::types::{Field, PrimeField64};
	use primitive_types::{H160, U256};
	use rand::SeedableRng;
	use rand_chacha::ChaCha8Rng;
	use tessera_trees::tree::{CommitmentTree, hasher::HashOutput};

	use super::*;
	use crate::{
		ACT_DEPTH, AccountAddress, AssetId, Nonce, StandardAccount, SubpoolId,
		account::AccountStateTreeLeaf,
		derive_deposit_tx_hash,
		note::DepositNote,
		pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
		schnorr::{PrivateKey, Scalar, schnorr_sign},
	};

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = <C as GenericConfig<D>>::F;

	#[test]
	fn test_prove_deposit_tx() {
		// ── Keys for subpool ──────────────────────────────────────────────────
		let approval_sk = PrivateKey::from_raw([1, 2, 3, 4, 5]);
		let approval_cpk: CompPubKey = approval_sk.public_key::<F>().into();
		let rejection_sk = PrivateKey::from_raw([5, 6, 7, 8, 0]);
		let rejection_cpk: CompPubKey = rejection_sk.public_key::<F>().into();
		let consume_sk = PrivateKey::from_raw([9, 10, 11, 12, 0]);
		let consume_cpk: CompPubKey = consume_sk.public_key::<F>().into();

		let subpool_id = SubpoolId(F::ONE);
		let subpool = SubpoolConfigTree::new(approval_cpk, rejection_cpk, consume_cpk);
		let mut main_pool = MainPoolConfigTree::new();
		main_pool.set_subpool(0, subpool_id, subpool.root());

		// ── Sample accin ──────────────────────────────────────────────────────
		let mut rng = ChaCha8Rng::seed_from_u64(42);
		let mut accin = StandardAccount::sample(&mut rng, subpool_id);

		// --- Simulate FreshAcc ------------------------------------------------
		accin.nonce = Nonce(F::ONE);
		accin.spend_auth = crate::SpendAuth {
			spend_pk: Some(PrivateKey::from_raw([8, 7, 6, 5, 4]).public_key().into()),
		};

		// ── Insert accin into ACT ─────────────────────────────────────────────
		let mut act = CommitmentTree::<HashOutput>::new(ACT_DEPTH);
		let acc_act_pos = act.insert(accin.commitment().0).unwrap().path;
		let acc_act_siblings = act.merkle_path(acc_act_pos, 0, ACT_DEPTH).unwrap();

		// ── DepositNote targeting accin ───────────────────────────────────────
		let asset_id = AssetId(F::from_canonical_u64(7));
		let deposit_note = DepositNote {
			identifier: [F::from_canonical_u64(11), F::from_canonical_u64(22)],
			recipient: AccountAddress::from_acc(&accin),
			amount: U256::from(1000u64),
			asset_id,
		};
		let eth_address = H160::random();

		// ── Compute native TxHash ─────────────────────────────────────────────
		// Mirror the circuit formula so we can sign it.
		let mut accout = accin.clone();
		accout.nonce = Nonce(F::from_canonical_u64(accin.nonce.0.to_canonical_u64() + 1));
		accout.ast.set_leaf(
			0,
			AccountStateTreeLeaf {
				asset_id,
				amount: deposit_note.amount,
			},
		);

		let accin_null = accin.nullifier(Some(acc_act_pos as u64));
		let deposit_note_comm = deposit_note.commitment();
		let tx_hash = derive_deposit_tx_hash(
			accin_null,
			accout.commitment(),
			deposit_note_comm,
			eth_address,
		);

		// ── Sign ──────────────────────────────────────────────────────────────
		let k = Scalar::from_raw([1, 2, 3, 4, 5]);
		let consume_sig = schnorr_sign(&consume_sk, &tx_hash.0, k);
		let approval_sig = schnorr_sign(&approval_sk, &tx_hash.0, k);

		// ── Build circuit ─────────────────────────────────────────────────────
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let t = deposit_tx_circuit(&mut builder);
		let data = builder.build::<C>();

		// ── Fill witness ──────────────────────────────────────────────────────
		let mut pw = PartialWitness::new();
		set_deposit_tx_witness(
			&mut pw,
			&t,
			&accin,
			acc_act_pos,
			&acc_act_siblings,
			&deposit_note,
			&eth_address,
			&approval_cpk,
			&rejection_cpk,
			&consume_cpk,
			subpool_id,
			&main_pool,
			consume_sig,
			approval_sig,
		);

		// ── Prove & verify ────────────────────────────────────────────────────
		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}
}
