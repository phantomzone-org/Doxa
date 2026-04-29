//! End-to-end test: operator + subpool owner setup, 3 FreshAcc private TXs,
//! PrivateTxBatch → PrivTxAggregator → Groth16, settled on-chain via the real
//! `TesseraBatchTransactionVerifier` contract.
//!
//! # Requirements
//!
//! Before running this test you must:
//!
//! 1. **Build the Solidity contracts** (produces verifier + rollup bytecode): ```text cd
//!    tessera-solidity && forge build ```
//!
//! 2. **Generate PrivTxAggregator artifacts**: ```text cargo run -p tessera-e2e --bin
//!    priv_tx_artifacts --release ``` Artifacts are written to `tessera-server/artifacts/priv-tx/`.
//!
//! # Running
//!
//! ```text
//! cargo test -p tessera-e2e --release \
//!   -- --include-ignored test_e2e_setup_operators_and_freshacc_batch
//! ```

use std::sync::Arc;

use alloy::{
	network::{EthereumWallet, TransactionBuilder},
	node_bindings::Anvil,
	primitives::{Bytes, U256},
	providers::{Provider, ProviderBuilder},
	rpc::types::TransactionRequest,
	signers::local::PrivateKeySigner,
	sol,
	sol_types::SolValue,
};
use plonky2::field::types::{Field, PrimeField64};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use tessera_client::{
	build_priv_tx_circuit,
	plonky2_gadgets::priv_tx::builder::FreshAccTxBuilder,
	pool_config::{CompPubKey, MainPoolConfigLeaf, MainPoolConfigTree, SubpoolConfig},
	schnorr::PrivateKey,
	HashOutput, PIHelper, PrivTxProof, StandardAccount, SubpoolId, TesseraGateSerializer,
	MAIN_POOL_CONFIG_DEPTH, PRIV_TX_BATCH_SIZE, STATE_TREE_DEPTH,
};
use tessera_server::{
	aggregator_service::PrivTxAggregator,
	batch_helper::{BatchHelper, SolidityKeccak256},
	prover_service::priv_tx::PrivateTxBatch,
};
use tessera_trees::MerkleTree;
use tessera_utils::{
	groth::{BN128Wrapper, Groth16Wrapper},
	F,
};

// ---------------------------------------------------------------------------
// Alloy on-chain interface (TesseraContract — new 8-param constructor)
// ---------------------------------------------------------------------------

sol! {
	#[sol(rpc)]
	interface ITessera {
		struct Proof {
			uint256[8] proof;
			uint256[2] commitments;
			uint256[2] commitmentPok;
		}

		// Subpool owner registry
		function assignSubpoolOwner(uint64 subpoolId, address owner) external;
		function updateSubpoolRoot(
			uint64 subpoolId,
			uint256 newSubpoolRoot,
			uint256[] calldata siblings
		) external;

		// Batch lifecycle
		function submitTransactionBatch(bytes calldata batchPreimage) external;
		function proveTransactionBatch(
			bytes calldata batchPreimage,
			Proof calldata proof
		) external;

		// Views
		function imtCurrentRoot() external view returns (uint256);
		function mainPoolConfigRoot() external view returns (uint256);
		function isConfirmedRoot(uint256 root) external view returns (bool);

		event TransactionBatchProven(
			bytes32 indexed piCommitment,
			uint256 newTreeRoot,
			uint256 leafIndex
		);
	}
}

// ---------------------------------------------------------------------------
// Bytecode / artifact loading
// ---------------------------------------------------------------------------

fn workspace_root() -> std::path::PathBuf {
	// CARGO_MANIFEST_DIR = <workspace>/tessera-e2e
	std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
		.parent()
		.expect("workspace root")
		.to_path_buf()
}

/// Load deployment bytecode (hex, no leading `0x`) from a Foundry JSON artifact.
/// Panics with build instructions if the file is absent or the bytecode is empty.
fn load_foundry_bytecode(sol_file: &str, contract: &str) -> String {
	let path = workspace_root()
		.join("tessera-solidity/out")
		.join(sol_file)
		.join(format!("{contract}.json"));

	assert!(
		path.exists(),
		"Foundry artifact not found at {path:?}.\n\
		 Run:  cd tessera-solidity && forge build",
	);

	let content = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
	let json: serde_json::Value =
		serde_json::from_str(&content).unwrap_or_else(|e| panic!("parse {path:?}: {e}"));
	let hex = json["bytecode"]["object"]
		.as_str()
		.unwrap_or_else(|| panic!("no bytecode.object in {path:?}"));
	let hex = hex.strip_prefix("0x").unwrap_or(hex);
	assert!(
		!hex.is_empty(),
		"Empty bytecode in {path:?} — did `forge build` succeed?",
	);
	hex.to_string()
}

// ---------------------------------------------------------------------------
// Deployment helpers
// ---------------------------------------------------------------------------

async fn deploy_no_args<P: Provider + Clone>(
	provider: &P,
	bytecode_hex: &str,
) -> alloy::primitives::Address {
	let code = Bytes::from(hex::decode(bytecode_hex).expect("hex decode"));
	provider
		.send_transaction(TransactionRequest::default().with_deploy_code(code))
		.await
		.expect("deploy send")
		.get_receipt()
		.await
		.expect("deploy receipt")
		.contract_address
		.expect("no contract_address in receipt")
}

async fn deploy_with_args<P: Provider + Clone>(
	provider: &P,
	bytecode_hex: &str,
	constructor_args: Vec<u8>,
) -> alloy::primitives::Address {
	let mut code = hex::decode(bytecode_hex).expect("hex decode");
	code.extend_from_slice(&constructor_args);
	provider
		.send_transaction(TransactionRequest::default().with_deploy_code(Bytes::from(code)))
		.await
		.expect("deploy_with_args send")
		.get_receipt()
		.await
		.expect("deploy_with_args receipt")
		.contract_address
		.expect("no contract_address in receipt")
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

/// Pack `HashOutput` into a LE-packed `U256` (el0 | el1<<64 | el2<<128 | el3<<192).
fn hash_to_u256_le(h: &HashOutput) -> U256 {
	U256::from_limbs([h.0[0].0, h.0[1].0, h.0[2].0, h.0[3].0])
}

/// Parse a Groth16 solidity JSON string into `(proof[8], commitments[2], pok[2])`.
fn parse_groth16_solidity_json(json: &str) -> ([U256; 8], [U256; 2], [U256; 2]) {
	let v: serde_json::Value = serde_json::from_str(json).expect("parse groth16 json");
	let parse_u256_vec = |key: &str, len: usize| -> Vec<U256> {
		v[key]
			.as_array()
			.unwrap_or_else(|| panic!("missing {key}"))
			.iter()
			.take(len)
			.map(|s| {
				let hex = s.as_str().expect("string element").trim_start_matches("0x");
				U256::from_str_radix(hex, 16).expect("parse U256")
			})
			.collect()
	};
	let proof: [U256; 8] = parse_u256_vec("proof", 8)
		.try_into()
		.expect("proof: 8 elements");
	let commitments: [U256; 2] = parse_u256_vec("commitments", 2)
		.try_into()
		.expect("commitments: 2 elements");
	let pok: [U256; 2] = parse_u256_vec("commitmentPok", 2)
		.try_into()
		.expect("commitmentPok: 2 elements");
	(proof, commitments, pok)
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_setup_operators_and_freshacc_batch() {
	let _ = tracing_subscriber::fmt().with_test_writer().try_init();

	// ── Prerequisite checks ───────────────────────────────────────────────────
	//
	// All panics include actionable instructions for the developer.

	let rollup_bytecode = load_foundry_bytecode("TesseraContract.sol", "TesseraContract");
	let poseidon_bytecode = load_foundry_bytecode("PoseidonGoldilocks.sol", "PoseidonGoldilocks");
	let token_bytecode = load_foundry_bytecode("ToyUSDTWOperator.sol", "ToyUSDT");
	let verifier_bytecode = load_foundry_bytecode(
		"TesseraBatchTransactionVerifier.sol",
		"TesseraBatchTransactionVerifier",
	);

	let ws = workspace_root();
	let agg_path = ws.join("tessera-server/artifacts/priv-tx");
	let plonky2_path = agg_path.join("plonky2-proof");
	let groth_path = agg_path.join("groth-artifacts");

	const GEN_CMD: &str = "  cargo run -p tessera-server --bin priv_tx_artifacts --release";

	if !PrivTxAggregator::has_full_artifacts(&agg_path).unwrap_or(false) {
		panic!(
			"PrivTxAggregator artifacts not found at {agg_path:?}.\n\
			 Generate them with:\n{GEN_CMD}"
		);
	}
	if !BN128Wrapper::has_full_artifacts(&plonky2_path) {
		panic!(
			"BN128 plonky2-proof artifacts not found at {plonky2_path:?}.\n\
			 Generate them with:\n{GEN_CMD}"
		);
	}
	let (pk, vk, r1cs) = (
		groth_path.join("proving.key"),
		groth_path.join("verifying.key"),
		groth_path.join("r1cs"),
	);
	if !pk.exists() || !vk.exists() || !r1cs.exists() {
		panic!(
			"Groth16 artifacts not found at {groth_path:?} \
			 (missing proving.key / verifying.key / r1cs).\n\
			 Generate them with:\n{GEN_CMD}"
		);
	}

	// ── Phase 1: Deploy ───────────────────────────────────────────────────────

	let anvil = Anvil::new().try_spawn().expect("anvil spawn");

	let op_signer: PrivateKeySigner = anvil.keys()[0].clone().into();
	let operator_addr = op_signer.address();
	let op_provider = ProviderBuilder::new()
		.wallet(EthereumWallet::from(op_signer))
		.connect_http(anvil.endpoint_url());

	let verifier_addr = deploy_no_args(&op_provider, &verifier_bytecode).await;
	let poseidon_addr = deploy_no_args(&op_provider, &poseidon_bytecode).await;
	let token_addr =
		deploy_with_args(&op_provider, &token_bytecode, operator_addr.abi_encode()).await;

	// TesseraContract(txVerifier, bridgeTxVerifier, poseidon, operator, token,
	//                 treeDepth=32, configTreeDepth=20, withdrawalDelay=0)
	//
	// treeDepth = STATE_TREE_DEPTH = 32 → genesis IMT root = zeros[32]
	//                                      = genesis ACT root used in FreshAcc proofs
	//                                      → confirmedRoots[genesis_ACT_root] = true ✓
	//
	// configTreeDepth = MAIN_POOL_CONFIG_DEPTH = 20 → on-chain config root matches
	//                                                   the ZK circuit's depth ✓
	let constructor_args = (
		verifier_addr,
		verifier_addr,
		poseidon_addr,
		operator_addr,
		token_addr,
		U256::from(STATE_TREE_DEPTH as u64),
		U256::from(MAIN_POOL_CONFIG_DEPTH as u64),
		U256::from(0u64), // withdrawalDelay
	)
		.abi_encode();

	let rollup_addr = deploy_with_args(&op_provider, &rollup_bytecode, constructor_args).await;
	let rollup = ITessera::ITesseraInstance::new(rollup_addr, &op_provider);

	// ── Phase 2: Define 3 subpool owners ─────────────────────────────────────
	//
	// subpool_id ∈ {1, 2, 3}  (0 is reserved by the contract).
	// Each owner has an Ethereum account (anvil key[1..3]) and an approval key.
	// SubpoolConfig::commitment() = Poseidon(approval_pk) is stored on-chain
	// as the subpool root.

	let mut rng = ChaCha8Rng::seed_from_u64(42);

	struct SubpoolOwner {
		subpool_id: SubpoolId,
		addr: alloy::primitives::Address,
		signer: PrivateKeySigner,
		approval_sk: PrivateKey,
		approval_cpk: CompPubKey,
		subpool_root: HashOutput,
	}

	let owners: Vec<SubpoolOwner> = (1u64..=3)
		.zip(1usize..=3)
		.map(|(id, key_idx)| {
			let signer: PrivateKeySigner = anvil.keys()[key_idx].clone().into();
			let addr = signer.address();
			let approval_sk = PrivateKey::sample(&mut rng);
			let approval_cpk: CompPubKey = approval_sk.public_key::<F>().into();
			let subpool = SubpoolConfig::<HashOutput>::new(approval_cpk);
			let subpool_root = subpool.commitment();
			SubpoolOwner {
				subpool_id: SubpoolId(F::from_canonical_u64(id)),
				addr,
				signer,
				approval_sk,
				approval_cpk,
				subpool_root,
			}
		})
		.collect();

	// Operator assigns each subpool owner on-chain.
	for o in &owners {
		rollup
			.assignSubpoolOwner(o.subpool_id.0.to_canonical_u64(), o.addr)
			.send()
			.await
			.expect("assignSubpoolOwner send")
			.get_receipt()
			.await
			.expect("assignSubpoolOwner receipt");
	}

	// ── Phase 3: Each subpool owner calls updateSubpoolRoot ───────────────────
	//
	// We use a single MainPoolConfigTree to track state locally and to supply
	// Merkle siblings for the on-chain call.
	//
	// Key insight: Merkle siblings at position P are determined by the *adjacent
	// subtrees*, not by the leaf at P itself.  Therefore the siblings computed
	// **after** insert_subpool_at_position are identical to the siblings the
	// contract needs to verify the old (zero) leaf at that position.  So we can
	// safely insert locally first, read siblings, then call on-chain.
	//
	// On-chain leaf  = poseidon.compress(uint256(subpoolId), subpoolRoot)
	// Rust leaf      = MainPoolConfigLeaf::commit()
	//                = poseidon_two_to_one([subpool_id,0,0,0], subpool_root_hash)
	// Both use the same Goldilocks Poseidon → leaves and roots agree ✓

	let mut config_tree = MainPoolConfigTree::<HashOutput>::new();

	for o in &owners {
		// 1. Insert locally first so subpool_proof can return the sibling path.
		config_tree
			.insert_subpool_at_position(o.subpool_id, o.subpool_root)
			.expect("insert_subpool_at_position");

		// 2. Read siblings from the local tree.  Because siblings are determined by nodes *other*
		//    than position subpool_id, they are the same whether the leaf at that position is zero
		//    (old on-chain state) or the new digest (post-local-insert state).
		let siblings_u256: Vec<U256> = config_tree
			.subpool_proof(o.subpool_id, o.subpool_root)
			.expect("subpool_proof for siblings")
			.siblings
			.iter()
			.map(hash_to_u256_le)
			.collect();

		// 3. Subpool owner submits the update on-chain.
		let spowner_provider = ProviderBuilder::new()
			.wallet(EthereumWallet::from(o.signer.clone()))
			.connect_http(anvil.endpoint_url());
		ITessera::ITesseraInstance::new(rollup_addr, &spowner_provider)
			.updateSubpoolRoot(
				o.subpool_id.0.to_canonical_u64(),
				hash_to_u256_le(&o.subpool_root),
				siblings_u256,
			)
			.send()
			.await
			.expect("updateSubpoolRoot send")
			.get_receipt()
			.await
			.expect("updateSubpoolRoot receipt");
	}

	// Sanity-check: Rust root must match on-chain mainPoolConfigRoot.
	let on_chain_cfg_root = rollup
		.mainPoolConfigRoot()
		.call()
		.await
		.expect("mainPoolConfigRoot");
	assert_eq!(
		hash_to_u256_le(&config_tree.root()),
		on_chain_cfg_root,
		"Rust MainPoolConfigTree root must match on-chain mainPoolConfigRoot"
	);

	// ── Phase 4: 3 FreshAcc proofs ────────────────────────────────────────────
	//
	// For FreshAcc, state_root = genesis ACT root = zeros[STATE_TREE_DEPTH = 32].
	// Since treeDepth = STATE_TREE_DEPTH, this equals the genesis IMT root, which
	// is in confirmedRoots from the very start → submitTransactionBatch succeeds.

	let state_tree = MerkleTree::<HashOutput>::new(STATE_TREE_DEPTH);
	let genesis_act_root_u256 = hash_to_u256_le(&state_tree.root());

	// Verify genesis ACT root is in on-chain confirmedRoots.
	assert!(
		rollup
			.isConfirmedRoot(genesis_act_root_u256)
			.call()
			.await
			.expect("confirmedRoots"),
		"genesis ACT root must be in on-chain confirmedRoots"
	);

	let circuit = build_priv_tx_circuit();
	let config_tree_arc = Arc::new(config_tree);
	let mut priv_tx_proofs: Vec<PrivTxProof> = Vec::new();

	for o in &owners {
		let accin = StandardAccount::sample(&mut rng, o.subpool_id);
		let spend_sk = PrivateKey::sample(&mut rng);
		let spend_cpk: CompPubKey = spend_sk.public_key::<F>().into();

		let built = FreshAccTxBuilder::new(accin)
			.expect("FreshAccTxBuilder::new")
			.with_new_spend_key(spend_cpk)
			.with_delegated_consume()
			.fill_dinotes(&mut rng)
			.fill_donotes(&mut rng)
			.build()
			.expect("FreshAccTxBuilder::build");

		let approval_sig = built
			.approval_sign(&o.approval_sk, &mut rng)
			.expect("approval_sign");

		let priv_tx = built
			.into_priv_tx_with_signature(
				approval_sig,
				&state_tree,
				Arc::clone(&config_tree_arc),
				o.approval_cpk,
			)
			.expect("into_priv_tx_with_signature");

		let proven = priv_tx
			.prove(&circuit.circuit_data, &circuit.targets)
			.expect("prove FreshAcc TX");

		assert_eq!(
			proven.not_fake_tx().to_canonical_u64(),
			1,
			"subpool_id {}: not_fake_tx must be 1",
			o.subpool_id.0.to_canonical_u64()
		);

		priv_tx_proofs.push(proven);
	}

	// ── Phase 5: PrivateTxBatch ───────────────────────────────────────────────

	let mut batch = PrivateTxBatch::new();
	for proof in priv_tx_proofs {
		batch.add_proof(proof).expect("add_proof");
	}
	batch.finalize().expect("batch finalize");
	assert_eq!(batch.proofs().len(), PRIV_TX_BATCH_SIZE);

	// ── Phase 6: PrivTxAggregator → Groth16 ──────────────────────────────────

	let agg = PrivTxAggregator::from_artifacts(&agg_path, &TesseraGateSerializer)
		.expect("PrivTxAggregator::from_artifacts");

	let super_proof = agg.prove(&batch).expect("PrivTxAggregator::prove");
	assert_eq!(super_proof.public_inputs.len(), 8);

	// Verify super-proof PIs match the batch pi_commitment.
	let pi_commitment = batch
		.pi_commitment::<SolidityKeccak256>()
		.expect("pi_commitment");
	// The 8 super-proof PIs each encode one u32 word of the keccak256 output.
	// keccak256 words are < 2^32, so the high 32 bits of each GL field element
	// must be zero.  We assert this explicitly rather than silently truncating.
	let pi_from_proof: [u8; 32] = {
		let mut out = [0u8; 32];
		for (i, f) in super_proof.public_inputs.iter().enumerate() {
			let val = f.to_canonical_u64();
			assert_eq!(
				val >> 32,
				0,
				"super proof PI[{i}] = {val:#x} has non-zero high bits; \
				 keccak256 output words must fit in u32"
			);
			out[i * 4..(i + 1) * 4].copy_from_slice(&(val as u32).to_be_bytes());
		}
		out
	};
	assert_eq!(
		pi_from_proof, pi_commitment,
		"super proof PIs must match pi_commitment"
	);

	// BN128 wrap.
	let bn128 = BN128Wrapper::new(agg.super_circuit_data().clone(), super_proof.clone())
		.expect("BN128Wrapper::new");

	// Load Groth16 artifacts and prove.
	let label = "e2e_freshacc";
	Groth16Wrapper::init_with_label(label, &plonky2_path, &groth_path)
		.expect("Groth16Wrapper::init_with_label");

	let bn128_proof = bn128
		.wrap_proof_to_bn128(super_proof)
		.expect("wrap_proof_to_bn128");
	let (g16_proof_bytes, g16_pub_inp_bytes) =
		Groth16Wrapper::prove_with_label(label, bn128_proof).expect("Groth16 prove");

	// Local verification.
	Groth16Wrapper::verify_with_label(label, g16_proof_bytes.clone(), g16_pub_inp_bytes.clone())
		.expect("Groth16 verify");

	// Parse proof into Alloy Proof struct for on-chain submission.
	let json = Groth16Wrapper::proof_to_solidity_json(&g16_proof_bytes, &g16_pub_inp_bytes)
		.expect("proof_to_solidity_json");
	let (g16_proof, g16_commitments, g16_pok) = parse_groth16_solidity_json(&json);

	// ── Phase 7: Settle on-chain ──────────────────────────────────────────────

	let preimage = batch.pi_preimage_bytes().expect("pi_preimage_bytes");

	// Phase 1 on-chain: submit (operator only).
	rollup
		.submitTransactionBatch(Bytes::from(preimage.clone()))
		.send()
		.await
		.expect("submitTransactionBatch send")
		.get_receipt()
		.await
		.expect("submitTransactionBatch receipt");

	// Phase 2 on-chain: prove (permissionless).
	rollup
		.proveTransactionBatch(
			Bytes::from(preimage),
			ITessera::Proof {
				proof: g16_proof,
				commitments: g16_commitments,
				commitmentPok: g16_pok,
			},
		)
		.send()
		.await
		.expect("proveTransactionBatch send")
		.get_receipt()
		.await
		.expect("proveTransactionBatch receipt");

	// ── Phase 8: Assert ───────────────────────────────────────────────────────

	let new_root = rollup
		.imtCurrentRoot()
		.call()
		.await
		.expect("imtCurrentRoot");

	assert_ne!(
		new_root, genesis_act_root_u256,
		"IMT must have advanced beyond the genesis root after the batch proof"
	);
	assert!(
		rollup
			.isConfirmedRoot(new_root)
			.call()
			.await
			.expect("confirmedRoots"),
		"new IMT root must be in confirmedRoots after proveTransactionBatch"
	);

	println!("✓  E2E test passed — new IMT root: {new_root:#066x}");
}
