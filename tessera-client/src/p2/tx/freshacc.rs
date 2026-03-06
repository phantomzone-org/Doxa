#[cfg(test)]
mod tests {
	use std::array;

	use plonky2::{
		hash::{hashing::hash_n_to_m_no_pad, poseidon::PoseidonHash},
		iop::witness::{PartialWitness, WitnessWrite},
		plonk::{
			circuit_builder::CircuitBuilder,
			circuit_data::CircuitConfig,
			config::{GenericConfig, Hasher, PoseidonGoldilocksConfig},
		},
	};
	use plonky2_field::types::Field;
	use rand::SeedableRng;
	use rand_chacha::ChaCha8Rng;

	use crate::{
		DEFAULT_SPEND_AUTH_PK, MAIN_POOL_CONFIG_DEPTH, NOTE_BATCH, Nonce, NoteCommitment,
		NoteNullifier, SUBPOOL_CONFIG_DEPTH, SpendAuth, StandardAccount, SubpoolId,
		default_ast_siblings, derive_tx_hash,
		ecgfp5::{CompressedPoint, PointEw},
		p2::{
			merkle::{
				AccountTarget, proof_siblings_bits, set_merkle_siblings_and_bits, tx_circuit,
			},
			set_gfp5, set_hash, set_u256_zero,
			signature::set_schnorr_witness,
		},
		pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
		schnorr::{
			CompressedPublicKey, PrivateKey, PublicKey, Scalar, poseidon_hash_to_scalar,
			schnorr_sign,
		},
		tree::Node,
	};

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = <C as GenericConfig<D>>::F;

	fn double_hash_native(elems: [F; 4]) -> [F; 4] {
		use plonky2::plonk::config::Hasher;
		let h0 = <PoseidonHash as Hasher<F>>::hash_no_pad(&elems).elements;
		<PoseidonHash as Hasher<F>>::hash_no_pad(&h0).elements
	}

	// ── test_prove_fresh_acc_tx ───────────────────────────────────────────────

	#[test]
	fn test_prove_fresh_acc_tx() {
		// ── Keys for one subpool ──────────────────────────────────────────────
		let approval_sk = PrivateKey::from_raw([2, 3, 4, 5, 6]);
		let approval_q: PointEw<F> = PointEw::generator().scalar_mul(&approval_sk.as_scalar());
		let approval_cpk: CompPubKey = approval_sk.public_key::<F>().into();

		let rejection_sk = PrivateKey::from_raw([5, 6, 7, 8, 0]);
		// let rejection_q: PointEw<F> = PointEw::generator().scalar_mul(&rejection_sk.as_scalar());
		let rejection_cpk: CompPubKey = rejection_sk.public_key::<F>().into();

		let consume_sk = PrivateKey::from_raw([9, 10, 11, 12, 0]);
		let consume_q: PointEw<F> = PointEw::generator().scalar_mul(&consume_sk.as_scalar());
		let consume_cpk: CompPubKey = consume_sk.public_key::<F>().into();

		// Build subpool config tree and main pool tree
		let subpool = SubpoolConfigTree::new(approval_cpk, rejection_cpk, consume_cpk);
		let subpool_id = SubpoolId(F::ONE);

		let mut main_pool = MainPoolConfigTree::new();
		main_pool.set_subpool(0, subpool_id, subpool.root());

		// ── Account setup ─────────────────────────────────────────────────────
		let mut rng = ChaCha8Rng::seed_from_u64(0);
		let accin = StandardAccount::sample(&mut rng, subpool_id);

		// Setup AccOut
		let nspend_sk = PrivateKey::from_raw([999, 1000, 1001, 1002, 0]);
		let spend_pk = nspend_sk.public_key();
		let spend_cpk = CompressedPublicKey::from(spend_pk);
		let mut accout = accin.clone();
		accout.nonce = Nonce(F::ONE);
		accout.spend_auth = SpendAuth {
			spend_pk: Some(spend_cpk),
		};

		// ── Native computation ────────────────────────────────────────────────

		// All notes inactive — dummy hashes are double_hash([0;4])
		let dinotes: [[F; 4]; NOTE_BATCH] = array::from_fn(|i| [F::from_canonical_usize(i); 4]);
		let donotes: [[F; 4]; NOTE_BATCH] =
			array::from_fn(|i| [F::from_canonical_usize(i + NOTE_BATCH); 4]);
		let dinote_nulls = array::from_fn(|i| NoteNullifier(double_hash_native(dinotes[i]).into()));
		let donote_comms =
			array::from_fn(|i| NoteCommitment(double_hash_native(donotes[i]).into()));
		let tx_hash = derive_tx_hash(
			accin.nullifier(None),
			accout.commitment(),
			dinote_nulls,
			donote_comms,
		);

		// ── Build circuit ─────────────────────────────────────────────────────
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let t = tx_circuit(&mut builder);
		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		// ── Fill witness ──────────────────────────────────────────────────────

		// Tx kind flags
		pw.set_bool_target(t.is_rjct, false).unwrap();
		pw.set_bool_target(t.is_fresh_acc, true).unwrap();
		pw.set_bool_target(t.is_update_auth, false).unwrap();
		pw.set_target(t.is_priv_tx, F::ZERO).unwrap();

		// Main pool root
		set_hash(&mut pw, t.main_pool_root.0, main_pool.root().0);
		set_hash(&mut pw, t.act_root.0, [F::ZERO; 4]);
		set_hash(&mut pw, t.nct_root.0, [F::ZERO; 4]);

		// Authority keys
		t.approval_key.set_witness(&mut pw, approval_cpk);
		t.rejection_key.set_witness(&mut pw, rejection_cpk);
		t.subpool_consume_key.set_witness(&mut pw, consume_cpk);

		// accin
		t.accin.set_witness(&mut pw, &accin);

		// accout (private_identifier and subpool_id are free targets not used in commitment)
		t.accout.set_witness(&mut pw, &accout);

		// Asset / amounts
		pw.set_target(t.asset_id.0, F::ZERO).unwrap();
		set_u256_zero(&mut pw, t.accin_amt);
		set_u256_zero(&mut pw, t.accout_amt);
		pw.set_bool_target(t.asset_exists_in_accin, false).unwrap();
		pw.set_bool_target(t.asset_exists_in_accout, false).unwrap();
		pw.set_target(t.accin_pos, F::ZERO).unwrap();

		set_merkle_siblings_and_bits(
			&mut pw,
			&t.accin_act_merkle.0,
			[[F::ZERO; 4]; crate::ACT_DEPTH],
			[false; crate::ACT_DEPTH],
		);

		// AST Merkle: always active (selector = true). Leaf = default_leaf (asset not in tree).
		// Siblings and bits match the empty AST at index 0.
		let ast_sibs = default_ast_siblings();
		set_merkle_siblings_and_bits(
			&mut pw,
			&t.accin_ast_merkle.0,
			ast_sibs,
			[false; crate::ACC_AST_DEPTH],
		);
		// accout_ast_merkle siblings + bits are auto-filled via connect_array

		// inotes: all identical
		// spend_cond = accin's recipient; reject_cond = zeroed sender
		let inote = crate::note::StandardNote {
			identifier: crate::note::NodeIdentifier([F::ZERO; 2]),
			asset_id: crate::note::AssetId(F::ZERO),
			amt: primitive_types::U256::zero(),
			recipient: crate::note::RecipientCond::from_acc(&accin),
			sender: crate::note::SenderCond {
				subpool_id: SubpoolId(F::ZERO),
				public_id: crate::account::PublicIdentifier(
					tessera_trees::tree::hasher::HashOutput([F::ZERO; 4]),
				),
			},
		};
		for i in 0..crate::NOTE_BATCH {
			t.inotes[i].set_witness(&mut pw, &inote);
			pw.set_target(t.inotes_pos[i], F::ZERO).unwrap();
			pw.set_bool_target(t.inotes_isactive[i], false).unwrap();
		}

		// NCT Merkle proofs: selector = false → root check not enforced.
		for i in 0..crate::NOTE_BATCH {
			set_merkle_siblings_and_bits(
				&mut pw,
				&t.inotes_nct_merkle[i],
				[[F::ZERO; 4]; crate::NCT_DEPTH],
				[false; crate::NCT_DEPTH],
			);
		}

		// onotes: all zero / inactive
		let zero_cond = crate::note::SenderCond {
			subpool_id: SubpoolId(F::ZERO),
			public_id: crate::account::PublicIdentifier(tessera_trees::tree::hasher::HashOutput(
				[F::ZERO; 4],
			)),
		};
		let onote = crate::note::StandardNote {
			identifier: crate::note::NodeIdentifier([F::ZERO; 2]),
			asset_id: crate::note::AssetId(F::ZERO),
			amt: primitive_types::U256::zero(),
			recipient: crate::note::RecipientCond {
				subpool_id: SubpoolId(F::ZERO),
				public_id: zero_cond.public_id,
			},
			sender: zero_cond,
		};
		for i in 0..crate::NOTE_BATCH {
			t.onotes[i].set_witness(&mut pw, &onote);
			pw.set_bool_target(t.onotes_isactive[i], false).unwrap();
		}

		// dinotes / donotes: all zero field elements
		for i in 0..crate::NOTE_BATCH {
			for j in 0..4 {
				pw.set_target(t.dinotes[i].0[j], dinotes[i][j]).unwrap();
				pw.set_target(t.donotes[i].0[j], donotes[i][j]).unwrap();
			}
		}

		// ── Subpool full proof ────────────────────────────────────────────────
		let full_proof = main_pool
			.full_subpool_proof(&subpool, subpool_id)
			.expect("subpool proof must be Some");

		let (sib, bit) =
			proof_siblings_bits::<_, _, SUBPOOL_CONFIG_DEPTH>(&full_proof.approval_proof);
		set_merkle_siblings_and_bits(&mut pw, &t.subpool_proof_targets.approval_proof, sib, bit);

		let (sib, bit) =
			proof_siblings_bits::<_, _, SUBPOOL_CONFIG_DEPTH>(&full_proof.rejection_proof);
		set_merkle_siblings_and_bits(&mut pw, &t.subpool_proof_targets.rejection_proof, sib, bit);

		let (sib, bit) =
			proof_siblings_bits::<_, _, SUBPOOL_CONFIG_DEPTH>(&full_proof.consume_proof);
		set_merkle_siblings_and_bits(&mut pw, &t.subpool_proof_targets.consume_proof, sib, bit);

		let (sib, bit) =
			proof_siblings_bits::<_, _, MAIN_POOL_CONFIG_DEPTH>(&full_proof.main_pool_proof);
		set_merkle_siblings_and_bits(&mut pw, &t.subpool_proof_targets.main_pool_proof, sib, bit);

		// ── Signatures ────────────────────────────────────────────────────────

		// Spend (fake): is_spend_req = false → apply_check = false.
		// Must set spend_dummy_pk to a valid EC point so DoubleAdd4x gate is satisfied.
		let spend_q: PointEw<F> =
			PointEw::decode(CompressedPoint::from(DEFAULT_SPEND_AUTH_PK)).unwrap();
		let spend_e = Scalar::from_raw([42, 8, 2, 5, 1]);
		let spend_s = Scalar::from_raw([7, 12, 13, 14, 14]);
		let spend_r: PointEw<F> = PointEw::generator()
			.scalar_mul(&spend_s)
			.add(&spend_q.scalar_mul(&spend_e));
		let spend_cr = spend_r.encode();
		set_schnorr_witness(
			&mut pw,
			&t.sig_targets.spend,
			spend_q,
			spend_cr,
			spend_e,
			spend_s,
		);

		// Consume (fake): is_consume_req = false → apply_check = false.
		// consume_auth.config = false → circuit uses subpool_consume_key (already a valid
		// point).
		let consume_e = Scalar::from_raw([13, 13, 5, 6, 7]);
		let consume_s = Scalar::from_raw([17, 19, 12, 13, 16]);
		let consume_r: PointEw<F> = PointEw::generator()
			.scalar_mul(&consume_s)
			.add(&consume_q.scalar_mul(&consume_e));
		let consume_cr = consume_r.encode();
		set_schnorr_witness(
			&mut pw,
			&t.sig_targets.consume,
			consume_q,
			consume_cr,
			consume_e,
			consume_s,
		);

		// Approval (real): always required (apply_check = true).
		let approval_pub = approval_sk.public_key::<F>();
		let k = Scalar::from_raw([1, 2, 3, 4, 5]);
		let sig = schnorr_sign(&approval_sk, &approval_pub, &tx_hash, k);
		let approval_cr = sig.r.encode();
		let approval_cq = approval_q.encode();
		let mut h_inp: Vec<F> = approval_cr.w.0.to_vec();
		h_inp.extend_from_slice(&approval_cq.w.0);
		h_inp.extend_from_slice(&tx_hash);
		let h_out = hash_n_to_m_no_pad::<F, <PoseidonHash as Hasher<F>>::Permutation>(&h_inp, 5);
		let approval_e = Scalar::from_hash(array::from_fn(|i| h_out[i]));
		{
			let g = PointEw::generator();
			let sg = g.scalar_mul(&sig.s);
			let eq = approval_q.scalar_mul(&approval_e);
			let result = sg.add(&eq);
			assert_eq!(result.encode(), approval_cr);
		}
		set_schnorr_witness(
			&mut pw,
			&t.sig_targets.approval,
			approval_q,
			approval_cr,
			approval_e,
			sig.s,
		);

		// ── Prove & verify ────────────────────────────────────────────────────
		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}
}
