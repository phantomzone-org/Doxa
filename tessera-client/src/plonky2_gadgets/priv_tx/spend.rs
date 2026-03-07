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
	use primitive_types::U256;
	use rand::SeedableRng;
	use rand_chacha::ChaCha8Rng;
	use tessera_trees::tree::{CommitmentTree, hasher::HashOutput};

	use crate::{
		DEFAULT_SPEND_AUTH_PK, MAIN_POOL_CONFIG_DEPTH, NOTE_BATCH, Nonce, NoteCommitment,
		NoteNullifier, SUBPOOL_CONFIG_DEPTH, SpendAuth, StandardAccount, SubpoolId,
		account::AccountStateTreeLeaf,
		default_ast_siblings, derive_tx_hash,
		ecgfp5::{CompressedPoint, PointEw},
		note::{
			AssetId, NodeIdentifier, PositionedStandardNode, RecipientCond, SenderCond,
			StandardNote,
		},
		plonky2_gadgets::{
			merkle::{proof_siblings_bits, set_merkle_siblings_and_bits, tx_circuit},
			set_hash, set_u256_zero,
			signature::set_schnorr_witness,
		},
		pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
		schnorr::{CompressedPublicKey, PrivateKey, PublicKey, Scalar, schnorr_sign},
	};

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = <C as GenericConfig<D>>::F;

	fn double_hash_native(elems: [F; 4]) -> [F; 4] {
		let h0 = <PoseidonHash as Hasher<F>>::hash_no_pad(&elems).elements;
		<PoseidonHash as Hasher<F>>::hash_no_pad(&h0).elements
	}

	/// Compute the circuit-compatible Merkle root using two_to_one at all levels.
	/// CommitmentTree uses hash_root (with num_leaves) at the top level, which
	/// doesn't match the circuit's merkle_verify_gadget. Use this instead.
	fn circuit_merkle_root<const DEPTH: usize>(
		leaf: [F; 4],
		siblings: &[[F; 4]; DEPTH],
		bits: [bool; DEPTH],
	) -> [F; 4] {
		use plonky2::hash::hash_types::HashOut;
		let mut cur = leaf;
		for level in 0..DEPTH {
			let sib = siblings[level];
			let result = if bits[level] {
				// current is right child
				<PoseidonHash as Hasher<F>>::two_to_one(
					HashOut {
						elements: sib,
					},
					HashOut {
						elements: cur,
					},
				)
			} else {
				// current is left child
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

	#[test]
	fn test_prove_priv_tx() {
		// ── Keys for subpool ──────────────────────────────────────────────────
		let approval_sk = PrivateKey::from_raw([2, 3, 4, 5, 6]);
		let approval_q: PointEw<F> = PointEw::generator().scalar_mul(&approval_sk.as_scalar());
		let approval_cpk: CompPubKey = approval_sk.public_key::<F>().into();

		let rejection_sk = PrivateKey::from_raw([5, 6, 7, 8, 0]);
		let rejection_cpk: CompPubKey = rejection_sk.public_key::<F>().into();

		let consume_sk = PrivateKey::from_raw([9, 10, 11, 12, 0]);
		let consume_q: PointEw<F> = PointEw::generator().scalar_mul(&consume_sk.as_scalar());
		let consume_cpk: CompPubKey = consume_sk.public_key::<F>().into();

		let subpool = SubpoolConfigTree::new(approval_cpk, rejection_cpk, consume_cpk);
		let subpool_id = SubpoolId(F::ONE);

		let mut main_pool = MainPoolConfigTree::new();
		main_pool.set_subpool(0, subpool_id, subpool.root());

		// ── Create commitment trees ───────────────────────────────────────────
		let mut act = CommitmentTree::<HashOutput>::new(crate::ACT_DEPTH);
		let mut nct = CommitmentTree::<HashOutput>::new(crate::NCT_DEPTH);

		// ── Sample accounts ───────────────────────────────────────────────────
		let mut rng = ChaCha8Rng::seed_from_u64(1);
		let mut acc0 = StandardAccount::sample(&mut rng, subpool_id);
		let acc1 = StandardAccount::sample(&mut rng, SubpoolId(F::from_canonical_u64(2)));

		// ── Simulate FreshAcc for acc0 ────────────────────────────────────────
		// Advance acc0 to post-FreshAcc state (nonce=1, spend_auth set, consume_auth unchanged)
		let spend_sk = PrivateKey::from_raw([999, 1000, 1001, 1002, 0]);
		let spend_cpk = CompressedPublicKey::from(spend_sk.public_key::<F>());
		acc0.nonce = Nonce(F::ONE);
		acc0.spend_auth = SpendAuth {
			spend_pk: Some(spend_cpk),
		};

		// Insert acc0 commitment into ACT
		let acc0_act_proof = act.insert(acc0.commitment().0).unwrap();
		let acc0_pos = acc0_act_proof.path; // = 0

		// ── Create notes N0, N1 ───────────────────────────────────────────────
		let asset_id_val = F::ONE;
		let n0 = StandardNote {
			identifier: NodeIdentifier::from_rng(&mut rng),
			asset_id: AssetId(asset_id_val),
			amt: U256::from(100u64),
			recipient: RecipientCond::from_acc(&acc0),
			sender: SenderCond::from_acc(&acc1),
		};
		let n1 = StandardNote {
			identifier: NodeIdentifier::from_rng(&mut rng),
			asset_id: AssetId(asset_id_val),
			amt: U256::from(50u64),
			recipient: RecipientCond::from_acc(&acc0),
			sender: SenderCond::from_acc(&acc1),
		};

		// Insert note commitments into NCT
		let n0_pos = nct.insert(n0.commitment().0).unwrap().path;
		let n1_pos = nct.insert(n1.commitment().0).unwrap().path;

		// ── Build accout (post-consume state) ─────────────────────────────────
		let mut accout = acc0.clone();
		accout.nonce = Nonce(F::from_canonical_u64(2));
		// spend_auth and consume_auth are immutable in PrivTx — kept from acc0
		// Update AST: position 0 gets asset_id=1 with amount=150
		accout.ast.set_leaf(
			0,
			AccountStateTreeLeaf {
				asset_id: asset_id_val,
				amount: U256::from(150u64),
			},
		);

		// ── Compute note nullifiers and tx_hash ───────────────────────────────
		let nk0 = acc0.nk();
		// After Part 1 fix, native order matches circuit: commitment || position || nk
		let n0_null_arr: [F; 4] =
			PositionedStandardNode::from_note(n0, F::from_canonical_usize(n0_pos))
				.nullifier(&nk0)
				.0
				.0;
		let n1_null_arr: [F; 4] =
			PositionedStandardNode::from_note(n1, F::from_canonical_usize(n1_pos))
				.nullifier(&nk0)
				.0
				.0;

		// Dummy notes (same pattern as freshacc)
		let dinotes: [[F; 4]; NOTE_BATCH] = array::from_fn(|i| [F::from_canonical_usize(i); 4]);
		let donotes: [[F; 4]; NOTE_BATCH] =
			array::from_fn(|i| [F::from_canonical_usize(i + NOTE_BATCH); 4]);

		// tx_hash: real nullifiers for active notes (0, 1), dummy for rest
		let tx_inote_nulls: [NoteNullifier; NOTE_BATCH] = array::from_fn(|i| {
			let arr: [F; 4] = match i {
				0 => n0_null_arr,
				1 => n1_null_arr,
				_ => double_hash_native(dinotes[i]),
			};
			NoteNullifier(HashOutput(arr))
		});
		let tx_onote_comms: [NoteCommitment; NOTE_BATCH] =
			array::from_fn(|i| NoteCommitment(HashOutput(double_hash_native(donotes[i]))));

		let accin_null = acc0.nullifier(Some(acc0_pos as u64));
		let tx_hash = derive_tx_hash(
			accin_null,
			accout.commitment(),
			tx_inote_nulls,
			tx_onote_comms,
		);

		// ── Build circuit ──────────────────────────────────────────────────────
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let t = tx_circuit(&mut builder);
		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		// ── Fill witness ──────────────────────────────────────────────────────

		// Tx kind flags
		pw.set_bool_target(t.is_rjct, false).unwrap();
		pw.set_bool_target(t.is_fresh_acc, false).unwrap();
		pw.set_bool_target(t.is_update_auth, false).unwrap();
		pw.set_target(t.is_priv_tx, F::ONE).unwrap();

		// Tree roots
		set_hash(&mut pw, t.main_pool_root.0, main_pool.root().0);
		// act_root and nct_root are set below after computing circuit-compatible roots

		// Authority keys
		t.approval_key.set_witness(&mut pw, approval_cpk);
		t.rejection_key.set_witness(&mut pw, rejection_cpk);
		t.subpool_consume_key.set_witness(&mut pw, consume_cpk);

		// AccIn (acc0 at post-FreshAcc state)
		t.accin.set_witness(&mut pw, &acc0);

		// AccOut (acc0 after consuming N0+N1)
		t.accout.set_witness(&mut pw, &accout);

		// Asset / amounts
		pw.set_target(t.asset_id.0, asset_id_val).unwrap();

		// accin_amt = 0 (acc0 has no balance for asset_id=1 before this tx)
		set_u256_zero(&mut pw, t.accin_amt);

		// accout_amt = 150: U256::from(150u64).0 = [150,0,0,0] in LE u64 word order
		// limbs[2*i] = lo u32 of word i, limbs[2*i+1] = hi u32 of word i
		pw.set_target(t.accout_amt.0[0].0, F::from_canonical_u32(150u32))
			.unwrap();
		for j in 1..8usize {
			pw.set_target(t.accout_amt.0[j].0, F::ZERO).unwrap();
		}

		pw.set_bool_target(t.asset_exists_in_accin, false).unwrap();
		pw.set_bool_target(t.asset_exists_in_accout, true).unwrap();

		// accin_pos and ACT Merkle path
		pw.set_target(t.accin_pos, F::from_canonical_usize(acc0_pos))
			.unwrap();
		let act_sibs_arr: [[F; 4]; crate::ACT_DEPTH] =
			core::array::from_fn(|i| acc0_act_proof.siblings_new[i].0);
		let act_bits: [bool; crate::ACT_DEPTH] = core::array::from_fn(|i| (acc0_pos >> i) & 1 == 1);
		// CommitmentTree uses hash_root (with num_leaves) at the top level, but the circuit's
		// merkle_verify_gadget uses two_to_one at all levels. Compute circuit-compatible root.
		let act_circuit_root = circuit_merkle_root::<{ crate::ACT_DEPTH }>(
			acc0.commitment().0.0,
			&act_sibs_arr,
			act_bits,
		);
		set_hash(&mut pw, t.act_root.0, act_circuit_root);
		set_merkle_siblings_and_bits(&mut pw, &t.accin_act_merkle.0, act_sibs_arr, act_bits);

		// AST Merkle: accin has empty AST → default siblings at position 0
		let ast_sibs = default_ast_siblings();
		set_merkle_siblings_and_bits(
			&mut pw,
			&t.accin_ast_merkle.0,
			ast_sibs,
			[false; crate::ACC_AST_DEPTH],
		);
		// accout_ast_merkle siblings are auto-connected to accin_ast_merkle in circuit

		// ── Input Notes ──────────────────────────────────────────────────────

		// N0 (index 0) — active
		t.inotes[0].set_witness(&mut pw, &n0);
		pw.set_target(t.inotes_pos[0], F::from_canonical_usize(n0_pos))
			.unwrap();
		pw.set_bool_target(t.inotes_isactive[0], true).unwrap();
		let n0_nct_path = nct.merkle_path(n0_pos, 0, crate::NCT_DEPTH).unwrap();
		let n0_nct_sibs: [[F; 4]; crate::NCT_DEPTH] = core::array::from_fn(|i| n0_nct_path[i].0);
		let n0_nct_bits: [bool; crate::NCT_DEPTH] =
			core::array::from_fn(|i| (n0_pos >> i) & 1 == 1);
		// Circuit-compatible NCT root (no hash_root at top level).
		let nct_circuit_root = circuit_merkle_root::<{ crate::NCT_DEPTH }>(
			n0.commitment().0.0,
			&n0_nct_sibs,
			n0_nct_bits,
		);
		set_hash(&mut pw, t.nct_root.0, nct_circuit_root);
		set_merkle_siblings_and_bits(&mut pw, &t.inotes_nct_merkle[0], n0_nct_sibs, n0_nct_bits);

		// N1 (index 1) — active
		t.inotes[1].set_witness(&mut pw, &n1);
		pw.set_target(t.inotes_pos[1], F::from_canonical_usize(n1_pos))
			.unwrap();
		pw.set_bool_target(t.inotes_isactive[1], true).unwrap();
		let n1_nct_path = nct.merkle_path(n1_pos, 0, crate::NCT_DEPTH).unwrap();
		let n1_nct_sibs: [[F; 4]; crate::NCT_DEPTH] = core::array::from_fn(|i| n1_nct_path[i].0);
		let n1_nct_bits: [bool; crate::NCT_DEPTH] =
			core::array::from_fn(|i| (n1_pos >> i) & 1 == 1);
		set_merkle_siblings_and_bits(&mut pw, &t.inotes_nct_merkle[1], n1_nct_sibs, n1_nct_bits);

		// Indices 2..NOTE_BATCH — inactive
		// All notes must share the same asset_id (connected by circuit), even inactive ones.
		let zero_note = StandardNote {
			identifier: NodeIdentifier([F::ZERO; 2]),
			asset_id: AssetId(asset_id_val),
			amt: U256::zero(),
			recipient: RecipientCond::from_acc(&acc0),
			sender: SenderCond {
				subpool_id: SubpoolId(F::ZERO),
				public_id: crate::account::PublicIdentifier(HashOutput([F::ZERO; 4])),
			},
		};
		for i in 2..NOTE_BATCH {
			t.inotes[i].set_witness(&mut pw, &zero_note);
			pw.set_target(t.inotes_pos[i], F::ZERO).unwrap();
			pw.set_bool_target(t.inotes_isactive[i], false).unwrap();
			set_merkle_siblings_and_bits(
				&mut pw,
				&t.inotes_nct_merkle[i],
				[[F::ZERO; 4]; crate::NCT_DEPTH],
				[false; crate::NCT_DEPTH],
			);
		}

		// ── Output Notes — all inactive ────────────────────────────────────────
		let onote = StandardNote {
			identifier: NodeIdentifier([F::ZERO; 2]),
			asset_id: AssetId(asset_id_val),
			amt: U256::zero(),
			recipient: RecipientCond {
				subpool_id: SubpoolId(F::ZERO),
				public_id: crate::account::PublicIdentifier(HashOutput([F::ZERO; 4])),
			},
			sender: SenderCond {
				subpool_id: SubpoolId(F::ZERO),
				public_id: crate::account::PublicIdentifier(HashOutput([F::ZERO; 4])),
			},
		};
		for i in 0..NOTE_BATCH {
			t.onotes[i].set_witness(&mut pw, &onote);
			pw.set_bool_target(t.onotes_isactive[i], false).unwrap();
		}

		// dinotes / donotes (same pattern as freshacc)
		for i in 0..NOTE_BATCH {
			for j in 0..4 {
				pw.set_target(t.dinotes[i].0[j], dinotes[i][j]).unwrap();
				pw.set_target(t.donotes[i].0[j], donotes[i][j]).unwrap();
			}
		}

		// ── Subpool full proof ─────────────────────────────────────────────────
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

		// Spend (fake): is_spend_req = false (no active onotes)
		let spend_q: PointEw<F> = PointEw::decode(spend_cpk.0).unwrap();
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

		// Consume (REAL): is_consume_req = true (N0+N1 active, no onotes)
		// consume_auth.config = false → circuit uses subpool consume key (consume_cpk)
		let consume_pub = consume_sk.public_key::<F>();
		let k_c = Scalar::from_raw([7, 8, 9, 10, 11]);
		let sig_c = schnorr_sign(&consume_sk, &consume_pub, &tx_hash, k_c);
		let consume_cr = sig_c.r.encode();
		let consume_cq = consume_q.encode();
		let mut h_inp_c: Vec<F> = consume_cr.w.0.to_vec();
		h_inp_c.extend_from_slice(&consume_cq.w.0);
		h_inp_c.extend_from_slice(&tx_hash);
		let h_out_c =
			hash_n_to_m_no_pad::<F, <PoseidonHash as Hasher<F>>::Permutation>(&h_inp_c, 5);
		let consume_e = Scalar::from_hash(array::from_fn(|i| h_out_c[i]));
		{
			let g = PointEw::generator();
			let sg = g.scalar_mul(&sig_c.s);
			let eq = consume_q.scalar_mul(&consume_e);
			let result = sg.add(&eq);
			assert_eq!(
				result.encode(),
				consume_cr,
				"consume sig verification failed"
			);
		}
		set_schnorr_witness(
			&mut pw,
			&t.sig_targets.consume,
			consume_q,
			consume_cr,
			consume_e,
			sig_c.s,
		);

		// Approval (REAL): always required
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
			assert_eq!(
				result.encode(),
				approval_cr,
				"approval sig verification failed"
			);
		}
		set_schnorr_witness(
			&mut pw,
			&t.sig_targets.approval,
			approval_q,
			approval_cr,
			approval_e,
			sig.s,
		);

		// ── Prove & verify ─────────────────────────────────────────────────────
		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}
}
