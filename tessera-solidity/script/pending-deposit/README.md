# Local Development Workflow

End-to-end guide for running the Tessera sequencer against a local Anvil node.

This guide assumes three terminals:
- Terminal A: `anvil`
- Terminal B: sequencer
- Terminal C: posting deposits with `cast send`

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation) (`anvil`, `forge`, `cast`)
- Rust toolchain (`cargo`)
- Groth16 artifacts (see step 2 below)

## 1. Start Anvil

```bash
anvil
```

Anvil prints 10 pre-funded accounts. The default operator key used throughout this guide is **account 0**:

| Field       | Value                                                              |
|-------------|--------------------------------------------------------------------|
| Address     | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`                      |
| Private key | `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80` |

## 2. Generate Groth16 Artifacts (one-time)

The prover needs plonky2 circuit data and Groth16 proving/verifying keys. Generate them once:

```bash
cargo run -p tessera-server --bin pending_deposit_artifacts --release
```

This creates:
- `tessera-server/artifacts/pending-deposit/plonky2-proof/` — plonky2 circuit data for the R1CS compiler
- `tessera-server/artifacts/pending-deposit/groth-artifacts/` — Groth16 proving key, verifying key, and R1CS

Re-run only if the circuit shape changes (depth, batch size, or commitment scheme).

## 3. Deploy Contracts

Compute the genesis root (empty Poseidon Merkle tree) and deploy `Verifier` + `DepositsRollupBridge`:

```bash
cd /path/to/Tessera
export TESSERA_GENESIS_ROOT=$(cargo run -p tessera-server --example genesis_root --release)

(cd tessera-solidity && forge script script/pending-deposit/Deploy.s.sol \
  --rpc-url http://localhost:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast)
```

The script logs the deployed addresses:

```
Verifier deployed at: 0x5FbDB2315678afecb367f032d93F642f64180aa3
Bridge deployed at:   0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
```

Verify the on-chain state:

```bash
cast call 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 "merkleRoot()(bytes32)" --rpc-url http://localhost:8545
cast call 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 "nextDepositId()(uint256)" --rpc-url http://localhost:8545
cast call 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 "operator()(address)" --rpc-url http://localhost:8545
```

## 4. Start the Sequencer

In Terminal B, from the repo root, use the bridge address from the deploy output:

```bash
cd /path/to/Tessera
TESSERA_RPC_URL=http://localhost:8545 \
TESSERA_OPERATOR_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 \
TESSERA_CHAIN_ID=31337 \
TESSERA_PENDING_DEPOSITS_ARTIFACTS_PATH=./tessera-server/artifacts/pending-deposit \
cargo run -p tessera-server --bin sequencer --release
```

The sequencer initializes the prover (~2-3 min on first run) then logs:

```
INFO tessera_server::prover: prover initialized
INFO sequencer: sequencer running
```

## 5. Submit Deposits

In Terminal C, export the variables in the same shell where you run `cast send`:

```bash
export BRIDGE=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
export RPC=http://localhost:8545
export KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

echo "BRIDGE=$BRIDGE"
echo "RPC=$RPC"
echo "KEY=${KEY:+set}"
```

Deposits are submitted directly on-chain via the `deposit()` function. Each deposit has a 32-byte note commitment, a uint256 value, and a recipient address:

```bash
cast send "$BRIDGE" \
  "deposit(bytes32,uint256,address)" \
  0x0000000000000000000000000000000000000000000000000000000000000001 \
  1000000 \
  0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 \
  --rpc-url "$RPC" --private-key "$KEY"
```

To fill a batch, send 128 deposits. Example loop:

```bash
for i in $(seq 1 128); do
  NC=$(printf "0x%064x" $i)
  cast send "$BRIDGE" \
    "deposit(bytes32,uint256,address)" \
    "$NC" $i 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 \
    --rpc-url "$RPC" --private-key "$KEY"
done
```

After the 128th deposit, the sequencer automatically:

1. Detects the `DepositPending` events via polling
2. Seals the batch and inserts commitments into the Merkle tree
3. Sends the batch to the prover thread
4. Generates a Groth16 proof (plonky2 -> BN128 -> Groth16)
5. Calls `finalizeBatch(newRoot, depositStartIndex, proof)` on-chain
6. On-chain `merkleRoot` is updated and deposits are marked `Validated`

## Contracts

| Contract               | Description                                                    |
|------------------------|----------------------------------------------------------------|
| `Verifier.sol`         | Auto-generated Groth16 verifier (BN254 pairing check)         |
| `DepositsRollupBridge.sol` | Permissionless deposits + single-step batch finalization   |

### Deploy.s.sol

Forge deployment script. Reads `TESSERA_GENESIS_ROOT` from the environment and deploys both contracts with `batchSize = 128`. The deployer (`msg.sender`) is set as the initial operator.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Connection refused (os error 111)` | No Ethereum node running | Start `anvil` first |
| `error: invalid value '' for '[TO]'` (or function signature shown as `[TO]`) | `BRIDGE` is empty in the current shell | Run `echo "$BRIDGE"` and `export BRIDGE=...` in the same terminal before `cast send` |
| `Verifier mismatch: update src/pending-deposit/Verifier.sol ...` | `tessera-solidity/src/pending-deposit/Verifier.sol` does not match generated artifacts | Re-run step 2 and copy `tessera-server/artifacts/pending-deposit/groth-artifacts/Verifier.sol` into `tessera-solidity/src/pending-deposit/Verifier.sol` |
| `prover thread exiting` right after init | Sequencer exited before prover finished initializing (e.g. RPC error) | Fix the RPC error; the prover will stay alive once the sequencer loop is running |
| `genesis root mismatch` | Bridge deployed with wrong genesis root | Re-deploy with the correct `TESSERA_GENESIS_ROOT` |
| `InvalidProof()` on `finalizeBatch` | Stale Groth16 artifacts (circuit changed) | Delete `tessera-server/artifacts/pending-deposit/` and re-run step 2 |
