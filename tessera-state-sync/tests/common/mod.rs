use std::sync::{
    OnceLock,
    atomic::{AtomicUsize, Ordering},
};

use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol_types::SolValue,
};
use tessera_client::{
    build_deposit_tx_circuit, build_priv_tx_circuit, build_withdraw_tx_circuit,
    FakeDepositTxBuilder, FakeSpendTxBuilder, FakeWithdrawTxBuilder,
};
use tessera_server::{
    batch_helper::BatchHelper,
    prover_service::{
        bridge_tx::{BridgeTxBatch, BridgeTxProof},
        priv_tx::PrivateTxBatch,
    },
};
use tessera_state_sync::{
    constants::{
        BATCH_SUBTREE_DEPTH, NOTE_BATCH, PRIV_TX_BATCH_SIZE, TX_ACCOUT_COMM_OFF, TX_HEADER_SIZE,
        TX_NOTE_OUT_OFF, TX_SLOT_SIZE,
    },
    contract::{
        ITesseraRollupV2, ITesseraRollupV2::Proof, bytes32_to_hash, preimage_bytes32_to_raw,
    },
};
use tessera_trees::MerkleTree;
use tessera_utils::hasher::HashOutput;

// ---------------------------------------------------------------------------
// Dummy proof (AcceptAllVerifier accepts any zero-filled proof)
// ---------------------------------------------------------------------------

pub fn dummy_proof() -> Proof {
    Proof {
        proof: [U256::ZERO; 8],
        commitments: [U256::ZERO; 2],
        commitmentPok: [U256::ZERO; 2],
    }
}

// ---------------------------------------------------------------------------
// Global shared test infrastructure (OnceLock — built once per test binary)
// ---------------------------------------------------------------------------

struct CompiledBytecodes {
    accept_all: Vec<u8>,
    poseidon: Vec<u8>,
    token: Vec<u8>,
}

struct TestInfra {
    anvil: AnvilInstance,
    bytecodes: CompiledBytecodes,
}

static TEST_INFRA: OnceLock<TestInfra> = OnceLock::new();
static ACCOUNT_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn read_bytecode_from_artifact(path: &str) -> Vec<u8> {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("Cannot read {}: {}", path, e));
    let json: serde_json::Value = serde_json::from_str(&text).expect("invalid JSON");
    let obj = json["bytecode"]["object"]
        .as_str()
        .expect("bytecode.object missing");
    let hex_str = obj.strip_prefix("0x").unwrap_or(obj);
    hex::decode(hex_str).expect("hex decode failed")
}

fn get_test_infra() -> &'static TestInfra {
    TEST_INFRA.get_or_init(|| {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let solidity_dir = format!("{}/../tessera-solidity", manifest_dir);
        let status = std::process::Command::new("forge")
            .args(["build"])
            .current_dir(&solidity_dir)
            .status()
            .expect("forge not found");
        assert!(status.success(), "forge build failed");

        let out_dir = format!("{}/../tessera-solidity/out", manifest_dir);
        let accept_all = read_bytecode_from_artifact(&format!(
            "{}/AcceptAllVerifier.sol/AcceptAllVerifier.json",
            out_dir
        ));
        let poseidon = read_bytecode_from_artifact(&format!(
            "{}/PoseidonGoldilocks.sol/PoseidonGoldilocks.json",
            out_dir
        ));
        let token = read_bytecode_from_artifact(&format!(
            "{}/ToyUSDT.sol/ToyUSDT.json",
            out_dir
        ));

        let anvil = Anvil::new().args(["--accounts", "70"]).try_spawn().expect("anvil spawn");

        TestInfra {
            anvil,
            bytecodes: CompiledBytecodes { accept_all, poseidon, token },
        }
    })
}

// ---------------------------------------------------------------------------
// V2 TesseraContract bytecode loader
// ---------------------------------------------------------------------------

/// Load V2 TesseraContract deployment bytecode from the Foundry artifact.
/// Path: <manifest_dir>/../tessera-solidity/out/TesseraContract.sol/TesseraContract.json
pub fn v2_contract_bytecode() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = format!(
        "{}/../tessera-solidity/out/TesseraContract.sol/TesseraContract.json",
        manifest_dir
    );
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Cannot read {}: {}", path, e));
    let json: serde_json::Value = serde_json::from_str(&text).expect("invalid JSON");
    let obj = json["bytecode"]["object"]
        .as_str()
        .expect("bytecode.object missing");
    obj.strip_prefix("0x").unwrap_or(obj).to_string()
}

// ---------------------------------------------------------------------------
// TestEnv + deployment helpers
// ---------------------------------------------------------------------------

pub struct TestEnv {
    pub rollup: Address,
    pub token: Address,
    pub operator: Address,
    pub operator_key_idx: usize,
    pub depositor_key_idx: usize,
}

/// Deploy a contract from raw bytecode bytes. Returns the deployed contract address.
pub async fn deploy_bytes<P: Provider>(provider: &P, bytecode: &[u8]) -> Address {
    let code = Bytes::from(bytecode.to_vec());
    let tx = TransactionRequest::default().with_deploy_code(code);
    let receipt = provider
        .send_transaction(tx)
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    receipt
        .contract_address
        .expect("no contract address in receipt")
}


async fn deploy_tessera_contract<P: Provider>(
    provider: &P,
    accept_all: Address,
    poseidon: Address,
    operator: Address,
    bytecodes: &CompiledBytecodes,
) -> Address {
    let _ = bytecodes; // bytecodes not used here; TesseraContract loaded from artifact
    let bytecode_hex = v2_contract_bytecode();
    let mut bytecode = hex::decode(&bytecode_hex).unwrap();
    let args = (
        accept_all,        // _txVerifier
        accept_all,        // _bridgeTxVerifier
        poseidon,          // _poseidon
        operator,          // _operator
        U256::from(23u64), // _treeDepth
        U256::from(20u64), // _configTreeDepth ← must equal MAIN_POOL_CONFIG_DEPTH = 20
        U256::ZERO,        // _withdrawalDelay
    );
    bytecode.extend_from_slice(&args.abi_encode());
    let code = Bytes::from(bytecode);
    let tx = TransactionRequest::default().with_deploy_code(code);
    let receipt = provider
        .send_transaction(tx)
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    receipt.contract_address.expect("rollup deploy failed")
}

/// Deploy AcceptAllVerifier (×2), Poseidon, V2 TesseraContract, ToyUSDT.
/// Constructor: (txVerifier, bridgeTxVerifier, poseidon, operator, treeDepth=23,
/// configTreeDepth=20, withdrawalDelay=0) configTreeDepth MUST equal
/// tessera_client::MAIN_POOL_CONFIG_DEPTH = 20.
pub async fn setup_env() -> (TestEnv, impl Provider + Clone) {
    let infra = get_test_infra();
    let base = ACCOUNT_COUNTER.fetch_add(2, Ordering::Relaxed);
    let operator_key_idx = base;
    let depositor_key_idx = base + 1;

    let signer: PrivateKeySigner = infra.anvil.keys()[operator_key_idx].clone().into();
    let operator = signer.address();
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(infra.anvil.endpoint_url());

    // Deploy AcceptAll (×1, used for both txVerifier and bridgeTxVerifier)
    let accept_all = deploy_bytes(&provider, &infra.bytecodes.accept_all).await;
    // Deploy Poseidon
    let poseidon = deploy_bytes(&provider, &infra.bytecodes.poseidon).await;
    // Deploy Token
    let token = deploy_bytes(&provider, &infra.bytecodes.token).await;
    // Deploy TesseraContract (bytecode + ABI-encoded constructor args)
    let rollup =
        deploy_tessera_contract(&provider, accept_all, poseidon, operator, &infra.bytecodes).await;

    let env = TestEnv { rollup, token, operator, operator_key_idx, depositor_key_idx };
    (env, provider)
}

/// Build a provider for the depositor account assigned to this TestEnv.
pub fn depositor_provider(env: &TestEnv) -> (Address, impl Provider + Clone) {
    let infra = get_test_infra();
    let signer: PrivateKeySigner = infra.anvil.keys()[env.depositor_key_idx].clone().into();
    let addr = signer.address();
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(infra.anvil.endpoint_url());
    (addr, provider)
}

// ---------------------------------------------------------------------------
// Genesis root helpers
// ---------------------------------------------------------------------------

/// Compute the genesis act_root for a fresh contract deployment with treeDepth=23.
///
/// This is the root of an empty Merkle tree of depth 23, which equals
/// `zeros[23]` in the on-chain IMT initialisation. The contract confirms this
/// root at deploy time; `submitTransactionBatch` rejects any batch whose
/// act_root is not confirmed.
pub fn genesis_act_root() -> HashOutput {
    tessera_trees::MerkleTree::<HashOutput>::new(23).root()
}

/// Compute the genesis mainpool_config_root for configTreeDepth=20.
///
/// Equals the root of an empty MainPoolConfigTree (depth 20), matching
/// the `mainPoolConfigRoot` stored on-chain immediately after construction.
pub fn genesis_config_root() -> HashOutput {
    tessera_client::pool_config::MainPoolConfigTree::<HashOutput>::new().root()
}

// ---------------------------------------------------------------------------
// Precomputed batch preimages (OnceLock — built once per test binary)
// ---------------------------------------------------------------------------

static TX_PREIMAGE: OnceLock<Vec<u8>> = OnceLock::new();
static BRIDGE_PREIMAGE: OnceLock<Vec<u8>> = OnceLock::new();

/// Finalized fake TX batch preimage.
/// OnceLock: built once per test binary (~30-60s first call, instant thereafter).
///
/// The act_root and mainpool_config_root are set to the deterministic genesis
/// values so that `submitTransactionBatch` on a freshly-deployed contract will
/// pass the `isConfirmedRoot` and `PoolConfigMismatch` checks.
pub fn tx_preimage() -> &'static Vec<u8> {
    TX_PREIMAGE.get_or_init(|| {
        let act_root = genesis_act_root();
        let config_root = genesis_config_root();
        let circuit = build_priv_tx_circuit();
        let proof = FakeSpendTxBuilder::new(act_root, config_root)
            .build()
            .into_priv_tx()
            .prove(&circuit.circuit_data, &circuit.targets)
            .expect("fake priv_tx prove");
        let mut batch = PrivateTxBatch::new(); // builds circuit again internally
        batch.add_proof(proof).unwrap();
        batch.finalize().expect("finalize TX batch");
        batch.pi_preimage_bytes().expect("TX preimage bytes")
    })
}

/// Finalized fake bridge batch preimage.
///
/// Same genesis-root requirement as `tx_preimage()`.
pub fn bridge_preimage() -> &'static Vec<u8> {
    BRIDGE_PREIMAGE.get_or_init(|| {
        let act_root = genesis_act_root();
        let config_root = genesis_config_root();
        let wc = build_withdraw_tx_circuit();
        let dc = build_deposit_tx_circuit();
        let w = FakeWithdrawTxBuilder::new(act_root, config_root)
            .build()
            .into_withdraw_tx()
            .prove(&wc)
            .expect("fake withdraw prove");
        let d = FakeDepositTxBuilder::new(act_root, config_root)
            .build()
            .into_deposit_tx()
            .prove(&dc)
            .expect("fake deposit prove");
        let mut batch = BridgeTxBatch::new(); // builds circuits again internally
        batch.add_proof(BridgeTxProof::WithdrawTxProof(w)).unwrap();
        batch.add_proof(BridgeTxProof::DepositTxProof(d)).unwrap();
        batch.finalize().expect("finalize bridge batch");
        batch.pi_preimage_bytes().expect("bridge preimage bytes")
    })
}

// ---------------------------------------------------------------------------
// On-chain submit/prove helpers
// ---------------------------------------------------------------------------

pub async fn submit_tx_batch<P: Provider>(provider: &P, rollup: Address, preimage: &[u8]) {
    ITesseraRollupV2::new(rollup, provider)
        .submitTransactionBatch(Bytes::from(preimage.to_vec()))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
}

pub async fn prove_tx_batch<P: Provider>(provider: &P, rollup: Address, preimage: &[u8]) {
    ITesseraRollupV2::new(rollup, provider)
        .proveTransactionBatch(Bytes::from(preimage.to_vec()), dummy_proof())
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
}

pub async fn submit_bridge_batch<P: Provider>(provider: &P, rollup: Address, preimage: &[u8]) {
    ITesseraRollupV2::new(rollup, provider)
        .submitBridgeTxBatch(Bytes::from(preimage.to_vec()))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
}

pub async fn prove_bridge_batch<P: Provider>(provider: &P, rollup: Address, preimage: &[u8]) {
    ITesseraRollupV2::new(rollup, provider)
        .proveBridgeTxBatch(Bytes::from(preimage.to_vec()), dummy_proof())
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// GL encoding helpers for deposit slot patching
// ---------------------------------------------------------------------------

/// Encode bool as GL field element (8 bytes): lo_u32 = 1 if true, else 0; hi = 0.
pub fn gl_encode_bool(v: bool) -> [u8; 8] {
    let mut out = [0u8; 8];
    if v {
        out[0..4].copy_from_slice(&1u32.to_be_bytes());
    }
    out
}

/// Encode u64 as GL field element (8 bytes): [lo_u32_BE4][hi_u32_BE4].
pub fn gl_encode_u64(v: u64) -> [u8; 8] {
    let lo = (v & 0xFFFF_FFFF) as u32;
    let hi = (v >> 32) as u32;
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&lo.to_be_bytes());
    out[4..8].copy_from_slice(&hi.to_be_bytes());
    out
}

/// Encode Ethereum address as 5 × GL elements (40 bytes).
///
/// The contract decodes the address as LE uint160 with each limb read as a
/// big-endian u32: `result |= uint160(lo[i]) << (32 * i)`.
/// Limb 0 = LS 32 bits = bytes[16..20], limb 4 = MS 32 bits = bytes[0..4].
pub fn gl_encode_address(addr: &alloy::primitives::Address) -> [u8; 40] {
    let bytes = addr.as_slice(); // 20 bytes, big-endian
    let mut out = [0u8; 40];
    for i in 0..5 {
        // limb i occupies bits [i*32 .. (i+1)*32) of uint160
        // in big-endian 20-byte repr, that chunk starts at bytes[16 - 4*i]
        let chunk_start = 16 - 4 * i;
        out[i * 8..i * 8 + 4].copy_from_slice(&bytes[chunk_start..chunk_start + 4]);
        // hi_u32 = 0 (already zero-initialized)
    }
    out
}

/// Encode U256 as 8 × GL elements (64 bytes).
/// Each of the 8 limbs is the (i*32)-bit slice of the value, encoded as [lo_BE4][0000_4B].
pub fn gl_encode_u256(v: alloy::primitives::U256) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..8 {
        let limb =
            ((v >> (i * 32usize)) & alloy::primitives::U256::from(0xFFFF_FFFFu64)).to::<u32>();
        out[i * 8..i * 8 + 4].copy_from_slice(&limb.to_be_bytes());
        // hi = 0
    }
    out
}

/// Patch a bridge preimage: set deposit slot `slot_idx` (0-based in deposit half) to is_real=true
/// with the given fields. Returns modified preimage bytes.
///
/// Offsets within a deposit slot:
///   0: is_real (8 bytes GL bool)
///  72: note_commitment (32 bytes GL-preimage bytes32)
/// 104: recipient address (40 bytes = 5 GL elements)
/// 144: amount (64 bytes = 8 GL elements)
/// 208: asset_id (8 bytes GL u64)
pub fn patch_bridge_deposit_slot(
    preimage: &[u8],
    slot_idx: usize,
    note_commitment: [u8; 32],
    recipient: alloy::primitives::Address,
    value: alloy::primitives::U256,
    asset_id: u64,
) -> Vec<u8> {
    use tessera_state_sync::constants::{D_NOTE_COMM_OFF, D_SECTION_OFF, D_SLOT_SIZE};

    // These offsets match TesseraContract.sol internal constants (not re-exported from
    // constants.rs)
    const D_ETH_ADDR_OFF: usize = 104; // D_NOTE_COMM_OFF + 32
    const D_AMT_OFF: usize = 144; // D_ETH_ADDR_OFF + 40
    const D_ASSET_ID_OFF: usize = 208; // D_AMT_OFF + 64

    let mut out = preimage.to_vec();
    let base = D_SECTION_OFF + slot_idx * D_SLOT_SIZE;

    // is_real = true at slot offset 0
    out[base..base + 8].copy_from_slice(&gl_encode_bool(true));

    // note_commitment as raw bytes32 at D_NOTE_COMM_OFF
    // The contract reads this via _cdB32 (plain 32-byte read) as the deposit lookup key,
    // so it must be the same bytes that were passed to depositAndRegister.
    out[base + D_NOTE_COMM_OFF..base + D_NOTE_COMM_OFF + 32].copy_from_slice(&note_commitment);

    // recipient as 5 × GL elements at D_ETH_ADDR_OFF
    out[base + D_ETH_ADDR_OFF..base + D_ETH_ADDR_OFF + 40]
        .copy_from_slice(&gl_encode_address(&recipient));

    // value as 8 × GL elements at D_AMT_OFF
    out[base + D_AMT_OFF..base + D_AMT_OFF + 64].copy_from_slice(&gl_encode_u256(value));

    // asset_id as GL u64 at D_ASSET_ID_OFF
    out[base + D_ASSET_ID_OFF..base + D_ASSET_ID_OFF + 8].copy_from_slice(&gl_encode_u64(asset_id));

    out
}

/// Patch bridge preimage: set withdrawal slot `slot_idx` to is_real=true with a unique
/// account-input nullifier derived from `slot_idx`.
pub fn patch_bridge_withdraw_slot(preimage: &[u8], slot_idx: usize) -> Vec<u8> {
    use tessera_state_sync::constants::{W_ACCIN_NULL_OFF, W_SLOT_SIZE};
    let mut out = preimage.to_vec();
    let base = TX_HEADER_SIZE + slot_idx * W_SLOT_SIZE;
    // is_real = true
    out[base..base + 8].copy_from_slice(&gl_encode_bool(true));
    // unique accinNull: first GL element = slot_idx*500 + 100_000 (separate namespace from TX slots)
    let null_base = base + W_ACCIN_NULL_OFF;
    out[null_base..null_base + 8].copy_from_slice(&gl_encode_u64((slot_idx * 500 + 100_000) as u64));
    out[null_base + 8..null_base + 32].fill(0);
    out
}

/// Patch a TX preimage: set slot `slot_idx` (0-based) to is_real=true and assign
/// unique nullifiers so that multiple patched batches can all be proven without
/// triggering `NullifierAlreadyUsed` on chain.
///
/// The `AcceptAllVerifier` accepts any proof, so we are free to write arbitrary
/// (but valid Goldilocks) nullifier values directly into the preimage bytes.
///
/// Nullifier assignment:
///   accinNull    = HashOutput([slot_idx*100 + 1, 0, 0, 0])
///   noteInNull j = HashOutput([slot_idx*100 + 10 + j, 0, 0, 0])   (j = 0..NOTE_BATCH-1)
///
/// Output commitment assignment:
///   accOutComm      = GL-preimage([slot_idx*1000 + 1, 0, 0, 0])
///   noteOutComm[j]  = GL-preimage([slot_idx*1000 + 200 + j, 0, 0, 0])  (j = 0..NOTE_BATCH-1)
///
/// All values are well within the Goldilocks prime (< 2^64 - 2^32 + 1).
pub fn patch_tx_slot_is_real(preimage: &[u8], slot_idx: usize) -> Vec<u8> {
    use tessera_state_sync::constants::{TX_ACCIN_NULL_OFF, TX_NOTE_IN_OFF};
    let mut out = preimage.to_vec();
    let base = TX_HEADER_SIZE + slot_idx * TX_SLOT_SIZE;

    // Mark slot as real (notFakeTx = true).
    out[base..base + 8].copy_from_slice(&gl_encode_bool(true));

    // Patch accin nullifier to a unique GL value: first element = slot_idx*100 + 1.
    // Layout: 4 GL elements × 8 bytes each = 32 bytes.
    let null_base = base + TX_ACCIN_NULL_OFF;
    out[null_base..null_base + 8].copy_from_slice(&gl_encode_u64((slot_idx * 100 + 1) as u64));
    out[null_base + 8..null_base + 32].fill(0); // elements 1-3 = 0

    // Patch 7 input-note nullifiers to unique GL values.
    for j in 0..NOTE_BATCH {
        let nn_base = base + TX_NOTE_IN_OFF + j * 32;
        out[nn_base..nn_base + 8].copy_from_slice(&gl_encode_u64((slot_idx * 100 + 10 + j) as u64));
        out[nn_base + 8..nn_base + 32].fill(0);
    }

    // Patch accout commitment: element-0 = slot_idx*1000 + 1, elements 1-3 = 0.
    let acc_out_base = base + TX_ACCOUT_COMM_OFF;
    out[acc_out_base..acc_out_base + 8]
        .copy_from_slice(&gl_encode_u64((slot_idx * 1000 + 1) as u64));
    out[acc_out_base + 8..acc_out_base + 32].fill(0);

    // Patch 7 output-note commitments: element-0 = slot_idx*1000 + 200 + j, elements 1-3 = 0.
    for j in 0..NOTE_BATCH {
        let note_out_base = base + TX_NOTE_OUT_OFF + j * 32;
        out[note_out_base..note_out_base + 8]
            .copy_from_slice(&gl_encode_u64((slot_idx * 1000 + 200 + j) as u64));
        out[note_out_base + 8..note_out_base + 32].fill(0);
    }

    out
}

/// Set bytes [0..8] of the preimage to `gl_encode_u64(value)` and bytes [8..32] to zero,
/// giving two preimages derived from the same base different `batchPoseidonRoot` values.
pub fn patch_batch_root_gl(preimage: &[u8], value: u64) -> Vec<u8> {
    let mut out = preimage.to_vec();
    out[0..8].copy_from_slice(&gl_encode_u64(value));
    out[8..32].fill(0);
    out
}

/// Compute the batch subtree root that `apply_tx_preimage` would produce for a given
/// TX preimage. Inserts all output commitments (acc + note) for every slot in the
/// same slot×8+j order used by the sync service.
pub fn batch_subtree_root_from_tx_preimage(preimage: &[u8]) -> HashOutput {
    let mut tree = MerkleTree::<HashOutput>::new(BATCH_SUBTREE_DEPTH);
    for s in 0..PRIV_TX_BATCH_SIZE {
        let slot_off = TX_HEADER_SIZE + s * TX_SLOT_SIZE;
        // leaf s*8+0 = accOutComm
        let acc_comm = read_preimage_hash(preimage, slot_off + TX_ACCOUT_COMM_OFF);
        tree.insert(acc_comm).expect("insert acc_comm");
        // leaves s*8+1 .. s*8+7 = noteOutComm[0..6]
        for j in 0..NOTE_BATCH {
            let note_comm = read_preimage_hash(preimage, slot_off + TX_NOTE_OUT_OFF + j * 32);
            tree.insert(note_comm).expect("insert note_comm");
        }
    }
    tree.root()
}

fn read_preimage_hash(preimage: &[u8], off: usize) -> HashOutput {
    let b: alloy::primitives::B256 = preimage[off..off + 32]
        .try_into()
        .expect("slice is always 32 bytes");
    let raw = preimage_bytes32_to_raw(&b);
    bytes32_to_hash(&alloy::primitives::B256::from(raw)).unwrap()
}

// ---------------------------------------------------------------------------
// Random GL field element helpers
// ---------------------------------------------------------------------------

/// Sample a random valid Goldilocks field element value (u64 < F::ORDER = 0xFFFF_FFFF_0000_0001).
pub fn random_gl_u64() -> u64 {
    use rand::RngExt;
    const ORDER: u64 = 0xFFFF_FFFF_0000_0001;
    let mut rng = rand::rng();
    loop {
        let v: u64 = rng.random();
        if v < ORDER {
            return v;
        }
    }
}

/// Build a random 32-byte GL-preimage bytes32: 4 × (lo_BE4, hi_BE4) GL field elements,
/// each value < F::ORDER.
pub fn random_gl_b32() -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        let v = random_gl_u64();
        let lo = (v & 0xFFFF_FFFF) as u32;
        let hi = (v >> 32) as u32;
        out[i * 8..i * 8 + 4].copy_from_slice(&lo.to_be_bytes());
        out[i * 8 + 4..i * 8 + 8].copy_from_slice(&hi.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Token helpers (for deposit tests)
// ---------------------------------------------------------------------------

use alloy::sol;

sol! {
    #[sol(rpc)]
    interface IToyUSDT {
        function mint(address to, uint256 amount) external;
        function approve(address spender, uint256 amount) external returns (bool);
    }
}

/// Mint `amount` tokens to `to` and approve `spender` to spend them.
pub async fn mint_and_approve<P: Provider>(
    token_addr: Address,
    spender: Address,
    to: Address,
    amount: U256,
    operator_provider: &impl Provider,
    to_provider: &P,
) {
    IToyUSDT::new(token_addr, operator_provider)
        .mint(to, amount)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    IToyUSDT::new(token_addr, to_provider)
        .approve(spender, amount)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
}
