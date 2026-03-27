import init from "../../tessera-js/wasm/tessera_client_wasm.js";
import {
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  http,
  erc20Abi,
  formatUnits,
  maxUint256,
} from "viem";
import { sepolia } from "viem/chains";
import { PrivateKeyAccount, privateKeyToAccount } from "viem/accounts";
import {
  Account,
  AccountAddress,
  AssetId,
  DepositNote,
  InputNote,
  SpendTxBuilder,
  SubpoolId,
  SubpoolClient,
  derivePrivateIdentifier,
  derivePublicIdentifier,
} from "../../tessera-js/src/index";
import type { AccountResponse, NotePayload } from "../../tessera-js/src/index";

await init();

const status = document.getElementById("status") as HTMLPreElement;
function log(msg: string) {
  // status.textContent += "\n" + msg;
  // console.log(msg)clone(e
}

// ── constants ─────────────────────────────────────────────────────────────────

const TESSERA_CONTRACT = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
const USDX_CONTRACT_ADDR = import.meta.env
  .VITE_USDX_CONTRACT_ADDR as `0x${string}`;
const SEPOLIA_RPC_URL = import.meta.env.VITE_SEPOLIA_RPC_URL as string;
const API_BASE_URL = import.meta.env.API_BASE_URL ?? "http://localhost:8080";
const PRF_INPUT = new TextEncoder().encode("tessera::account::seed");
const SUBPOOL_ID = 1n;
const SUBPOOL_ID_HEX = "0100000000000000";
const ASSET_ID_HEX = "0100000000000000"; // u64(1) as 8-byte LE hex
const ASSET_ID = 1n;

// ── API client ────────────────────────────────────────────────────────────────

const subpoolClient = new SubpoolClient(API_BASE_URL);

// ── shared state ──────────────────────────────────────────────────────────────

let credentialId: Uint8Array | null = null;
let ethAddressFull: string | null = null;
let privateAccAddressFull: string | null = null;
let privateAccount: Account | null = null;
let publicAccount: PrivateKeyAccount | null = null;
let currentSeed: Uint8Array | null = null;
let privateBalance = 0;

// ── passkey helpers ───────────────────────────────────────────────────────────

async function registerAndGetSeed(): Promise<Uint8Array> {
  try {
    const cred = (await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: "Tessera Demo" },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: "demo",
          displayName: "Demo User",
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 }, // ES256
          { type: "public-key", alg: -257 }, // RS256
        ],
        authenticatorSelection: {
          residentKey: "required",
          userVerification: "required",
        },
        extensions: {
          prf: {},
        },
      },
    })) as PublicKeyCredential;

    credentialId = new Uint8Array(cred.rawId);
    const ext = cred.getClientExtensionResults() as any;
    const prfEnabled = !!ext?.prf?.enabled;

    log(`✓ Registered — credential ID: ${toHex(credentialId.slice(0, 8))}…`);
    log(`  PRF extension enabled by authenticator: ${prfEnabled}`);
    if (!prfEnabled) {
      log("⚠ Your authenticator does not support PRF. Derive will fail.");
    }
  } catch (err) {
    log(`✗ Registration failed: ${err}`);
  }

  return evalPrf();
}

async function evalPrf(): Promise<Uint8Array> {
  log("\nDeriving account from PRF output…");
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge,
      extensions: {
        prf: { eval: { first: PRF_INPUT } },
      },
    },
  })) as PublicKeyCredential;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ext = assertion.getClientExtensionResults() as any;
  const prfOutput: ArrayBuffer | undefined = ext?.prf?.results?.first;

  if (!prfOutput) {
    throw new Error(
      "WebAuthn PRF extension unavailable: authenticator did not return a PRF result",
    );
  }

  const seed = new Uint8Array(prfOutput);
  if (seed.byteLength !== 32) {
    throw new Error(`PRF output must be 32 bytes, got ${seed.byteLength}`);
  }

  return seed;
}

// ── misc helpers ──────────────────────────────────────────────────────────────

function toHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

function delay(ms: number) {
  return new Promise<void>((r) => setTimeout(r, ms));
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
}

async function deriveWalletAccount(
  seed: Uint8Array,
): Promise<PrivateKeyAccount> {
  const domain = new TextEncoder().encode("tessera::eth::privkey");
  const input = new Uint8Array(seed.length + domain.length);
  input.set(seed);
  input.set(domain, seed.length);
  const privKey = ("0x" + toHex(await sha256(input))) as `0x${string}`;
  return privateKeyToAccount(privKey);
}

async function deriveEthAddress(seed: Uint8Array): Promise<string> {
  return (await deriveWalletAccount(seed)).address;
}

// ── Tessera contract ABI fragment ─────────────────────────────────────────────

const TESSERA_ABI = [
  {
    name: "depositAndRegister",
    type: "function",
    inputs: [
      { name: "noteCommitment", type: "bytes32" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ type: "bytes32" }],
  },
] as const;

// ── helpers ────────────────────────────────────────────────────────────────────

/** Decode a hex string (no 0x prefix) to a Uint8Array. */
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Parse a little-endian hex string (32 bytes) as a BigInt (U256). */
function hexLeToU256(hex: string): bigint {
  const bytes = hexToBytes(hex);
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/** Parse a little-endian hex string (8 bytes) as a BigInt (u64). */
function hexLeToU64(hex: string): bigint {
  const bytes = hexToBytes(hex);
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

/** Encode a BigInt as a 32-byte little-endian hex string (U256 LE, no 0x prefix). */
function u256LeHex(v: bigint): string {
  const bytes = new Uint8Array(32);
  let tmp = v;
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(tmp & 0xffn);
    tmp >>= 8n;
  }
  return toHex(bytes);
}

// ── ABI encoding (hand-rolled, no library) ────────────────────────────────────

function padLeft32(hex: string): string {
  return hex.replace("0x", "").padStart(64, "0");
}

// ── p-step progress helper ────────────────────────────────────────────────────

function pStep(
  container: HTMLElement,
  text: string,
  cls: "active" | "done",
): HTMLElement {
  const el = document.createElement("div");
  el.className = `p-step ${cls}`;
  el.textContent = text;
  container.appendChild(el);
  return el;
}

// -- refresh -------------------------------------------------------------------

async function refreshAccountStates() {
  if (currentSeed) {
    await showPublicWallet(currentSeed!);
    await loadPrivateAccount(currentSeed!);
  }
}

// ── Section 1: Public account ─────────────────────────────────────────────────

const createWalletBtn = document.getElementById(
  "create-wallet-btn",
) as HTMLButtonElement;
const signInBtn = document.getElementById("sign-in-btn") as HTMLButtonElement;
const walletInfo = document.getElementById("wallet-info")!;
const ethAddressEl = document.getElementById("eth-address")!;
const usdcBalanceEl = document.getElementById("usdc-balance")!;
const walletError = document.getElementById("wallet-error")!;
const depositSection = document.getElementById("deposit-section")!;
const depositBtn = document.getElementById("deposit-btn") as HTMLButtonElement;
const depositProgress = document.getElementById("deposit-progress")!;
const depositBar = document.getElementById("deposit-bar") as HTMLElement;
const depositSteps = document.getElementById("deposit-steps")!;
const etherscanLink = document.getElementById("etherscan-link")!;
const etherscanAnchor = document.getElementById(
  "etherscan-anchor",
) as HTMLAnchorElement;

async function loadPublicBalance(address: string) {
  const client = createPublicClient({
    chain: sepolia,
    transport: http(SEPOLIA_RPC_URL),
  });
  const raw = await client.readContract({
    address: USDX_CONTRACT_ADDR,
    abi: erc20Abi,
    functionName: "balanceOf",
    args: [address as `0x${string}`],
  });
  const balance = Number(formatUnits(raw, 6));
  usdcBalanceEl.textContent =
    balance.toLocaleString("en-US", { minimumFractionDigits: 2 }) + " USDX";
}

async function showPublicWallet(seed: Uint8Array) {
  publicAccount = await deriveWalletAccount(seed);
  ethAddressFull = publicAccount.address;
  ethAddressEl.textContent =
    ethAddressFull.slice(0, 10) + "…" + ethAddressFull.slice(-8);
  ethAddressEl.title = ethAddressFull;
  await loadPublicBalance(ethAddressFull);
  setInterval(() => loadPublicBalance(ethAddressFull!), 10_000);
}

function renderVisiblePostSignIn() {
  walletInfo.classList.add("visible");
  depositSection.classList.add("visible");
}

async function loadPrivateAccount(seed: Uint8Array) {
  const privateId = derivePrivateIdentifier(seed);
  const publicId = derivePublicIdentifier(privateId);
  const privateAccAddress = AccountAddress.fromParts(
    SubpoolId.fromHex(SUBPOOL_ID_HEX),
    publicId,
  ).toHex();
  privateAccAddressFull = privateAccAddress;
  const accountData = await subpoolClient
    .getAccount(privateAccAddress)
    .catch(() => null);
  if (accountData) {
    privateAccount = Account.fromAccountData(accountData);
    enableP2pBtn();
  } else {
    console.log("Private account is null");
  }
  renderPrivateSection();
}

createWalletBtn.addEventListener("click", async () => {
  createWalletBtn.disabled = true;
  signInBtn.disabled = true;
  walletError.textContent = "";
  createWalletBtn.textContent = "⏳ Creating…";
  try {
    const seed = await registerAndGetSeed();
    currentSeed = seed;
    await showPublicWallet(seed);
    renderVisiblePostSignIn();
    await loadPrivateAccount(seed);
    createWalletBtn.textContent = "✓ Wallet created";
  } catch (err) {
    walletError.textContent = `Error: ${err}`;
    createWalletBtn.disabled = false;
    signInBtn.disabled = false;
    createWalletBtn.textContent = "🔑 Create Wallet";
  }
});

signInBtn.addEventListener("click", async () => {
  signInBtn.disabled = true;
  createWalletBtn.disabled = true;
  walletError.textContent = "";
  signInBtn.textContent = "⏳ Signing in…";
  try {
    const seed = await evalPrf();

    currentSeed = seed;
    await showPublicWallet(seed);
    renderVisiblePostSignIn();
    await loadPrivateAccount(seed);
    signInBtn.textContent = "✓ Signed in";
  } catch (err) {
    walletError.textContent = `Error: ${err}`;
    signInBtn.disabled = false;
    createWalletBtn.disabled = false;
    signInBtn.textContent = "Sign in with existing passkey";
  }
});

depositBtn.addEventListener("click", async () => {
  depositBtn.disabled = true;
  depositProgress.classList.add("visible");
  depositSteps.innerHTML = "";
  etherscanLink.classList.remove("visible");

  const step = pStep(depositSteps, "⏳ Submitting faucet request…", "active");
  depositBar.style.width = "50%";

  try {
    const { tx_hash } = await subpoolClient.requestFaucet(ethAddressFull!);

    step.className = "p-step done";
    step.textContent = "✓ Faucet transaction submitted";
    depositBar.style.width = "100%";

    etherscanAnchor.href = `https://sepolia.etherscan.io/tx/${tx_hash}`;
    etherscanAnchor.textContent =
      tx_hash.slice(0, 10) + "…" + tx_hash.slice(-8);
    etherscanLink.classList.add("visible");
  } catch (err) {
    step.className = "p-step done";
    step.textContent = `Error: ${err}`;
    depositBtn.disabled = false;
  }
});

// ── Section 2: Private account ────────────────────────────────────────────────

const kycForm = document.getElementById("kyc-form")!;
const kycDisplay = document.getElementById("kyc-display")!;
const nameInput = document.getElementById("kyc-name") as HTMLInputElement;
const streetInput = document.getElementById("kyc-street") as HTMLInputElement;
const dobInput = document.getElementById("kyc-dob") as HTMLInputElement;
const registerBtn = document.getElementById(
  "register-btn",
) as HTMLButtonElement;
const progressDiv = document.getElementById("progress")!;
const tesseraAddrBox = document.getElementById("tessera-address")!;
const tesseraAddrVal = document.getElementById("tessera-addr-value")!;
const registerError = document.getElementById("register-error")!;
const dispName = document.getElementById("disp-name")!;
const dispStreet = document.getElementById("disp-street")!;
const dispDob = document.getElementById("disp-dob")!;
const privBalanceRow = document.getElementById("priv-balance-row")!;
const privBalanceEl = document.getElementById("priv-balance")!;

function renderPrivateBalance() {
  privBalanceEl.textContent =
    privateBalance.toLocaleString("en-US", { minimumFractionDigits: 2 }) +
    " USDX";
  privBalanceRow.style.display = privateBalance > 0 ? "" : "none";
}

function renderPrivateSection() {
  if (privateAccount) {
    kycForm.style.display = "none";
    kycDisplay.style.display = "block";
    tesseraAddrVal.textContent = privateAccAddressFull;
    tesseraAddrBox.classList.add("visible");
    const balanceBigInt = privateAccount.balanceFor(AssetId.fromU64(ASSET_ID));
    privateBalance = Number(balanceBigInt) / 1e6;
    renderPrivateBalance();
  } else {
    kycForm.style.display = "block";
    kycDisplay.style.display = "none";
  }
}

for (const input of [nameInput, streetInput, dobInput]) {
  input.addEventListener("input", () => {
    registerBtn.disabled = !formFilled();
  });
}

function formFilled() {
  return (
    nameInput.value.trim() !== "" &&
    streetInput.value.trim() !== "" &&
    dobInput.value !== ""
  );
}

async function pollFreshAccApproval(privateAccAddress: string): Promise<void> {
  while (true) {
    await delay(1000);
    const res = await subpoolClient
      .getFreshAccStatus(privateAccAddress)
      .catch(() => null);
    if (res?.status === "APPROVED") return;
  }
}

function appendProgressLine(text: string, cls: "active" | "done"): HTMLElement {
  const el = document.createElement("div");
  el.className = `progress-line ${cls}`;
  el.textContent = text;
  progressDiv.appendChild(el);
  return el;
}

registerBtn.addEventListener("click", async () => {
  registerBtn.disabled = true;
  registerError.textContent = "";
  progressDiv.innerHTML = "";
  progressDiv.classList.add("visible");
  tesseraAddrBox.classList.remove("visible");
  try {
    const seed =
      currentSeed ??
      (credentialId ? await evalPrf() : await registerAndGetSeed());
    const account = Account.createWithSeed(seed, SUBPOOL_ID);
    const privateAccAddress = account.address().toHex();
    const s1 = appendProgressLine("⏳ Registering account…", "active");
    await subpoolClient.registerAccount(
      account.privateIdentifier(),
      account.spendAuthPk(),
      ethAddressFull!,
      {
        name: nameInput.value.trim(),
        physicalAddress: streetInput.value.trim(),
        dob: dobInput.value,
      },
    );
    s1.className = "progress-line done";
    s1.textContent = "✓ Account submitted";

    const s2 = appendProgressLine(
      "⏳ Waiting for approval from subpool owner…",
      "active",
    );
    await pollFreshAccApproval(privateAccAddress);

    s2.className = "progress-line done";
    s2.textContent = "✓ Approval received";

    appendProgressLine("✓ Account registered", "done");
    tesseraAddrVal.textContent = privateAccAddress;
    tesseraAddrBox.classList.add("visible");

    await refreshAccountStates();
  } catch (err) {
    registerError.textContent = `Error: ${err}`;
    registerBtn.disabled = false;
  }
});

// ── Section 3: Public → Private deposit ──────────────────────────────────────

const p2pAmountInput = document.getElementById(
  "p2p-amount",
) as HTMLInputElement;
const p2pBtn = document.getElementById("p2p-btn") as HTMLButtonElement;
const p2pHint = document.getElementById("p2p-hint")!;
const p2pTxWrap = document.getElementById("p2p-tx-wrap")!;
const p2pTxDisplay = document.getElementById("p2p-tx-display")!;
const p2pSigDisplay = document.getElementById("p2p-sig-display")!;
const p2pProgress = document.getElementById("p2p-progress")!;
const p2pBar = document.getElementById("p2p-bar") as HTMLElement;
const p2pSteps = document.getElementById("p2p-steps")!;
const p2pError = document.getElementById("p2p-error")!;

function enableP2pBtn() {
  p2pBtn.disabled = false;
  p2pHint.textContent = "Enter an amount and click Deposit.";
}

p2pBtn.addEventListener("click", async () => {
  const amount = parseFloat(p2pAmountInput.value);
  if (!amount || amount <= 0) {
    p2pError.textContent = "Enter a valid amount.";
    return;
  }
  if (!ethAddressFull) {
    p2pError.textContent = "Connect a wallet first.";
    return;
  }

  try {
    currentSeed = await evalPrf();
    await refreshAccountStates();

    p2pBtn.disabled = true;
    p2pError.textContent = "";
    p2pProgress.classList.add("visible");
    p2pSteps.innerHTML = "";
    p2pBar.style.width = "0%";

    const publicClient = createPublicClient({
      chain: sepolia,
      transport: http(SEPOLIA_RPC_URL),
    });

    // Check current USDX allowance for TESSERA_CONTRACT
    const allowance = await publicClient.readContract({
      address: USDX_CONTRACT_ADDR,
      abi: erc20Abi,
      functionName: "allowance",
      args: [publicAccount!.address, TESSERA_CONTRACT as `0x${string}`],
    });

    const walletClient = createWalletClient({
      account: publicAccount!,
      chain: sepolia,
      transport: http(SEPOLIA_RPC_URL),
    });

    if (allowance < maxUint256) {
      const step = pStep(p2pSteps, "⏳ Approving USDX transfer…", "active");
      p2pBar.style.width = "40%";

      const approveTxHash = await walletClient.writeContract({
        address: USDX_CONTRACT_ADDR,
        abi: erc20Abi,
        functionName: "approve",
        args: [TESSERA_CONTRACT as `0x${string}`, maxUint256],
      });

      await publicClient.waitForTransactionReceipt({ hash: approveTxHash });

      step.className = "p-step done";
      step.textContent = "✓ USDX transfer approved";
    }

    // ── Construct deposit note ────────────────────────────────────────────────
    const step2 = pStep(p2pSteps, "⏳ Constructing deposit note…", "active");
    p2pBar.style.width = "60%";

    const amountUnits = BigInt(Math.round(amount * 1_000_000)); // USDX 6 decimals
    const depositNote = DepositNote.create(
      AccountAddress.fromHex(privateAccAddressFull!),
      amountUnits,
      AssetId.fromU64(ASSET_ID),
    );
    const commitmentHex = ("0x" +
      depositNote.commitment().toHex()) as `0x${string}`;

    step2.className = "p-step done";
    step2.textContent = "✓ Deposit note constructed";

    // ── Sign transferDepositAndRegister tx (do NOT broadcast) ─────────────────
    const step3 = pStep(p2pSteps, "⏳ Signing deposit transaction…", "active");
    p2pBar.style.width = "80%";

    const calldata = encodeFunctionData({
      abi: TESSERA_ABI,
      functionName: "depositAndRegister",
      args: [commitmentHex, amountUnits],
    });

    const txRequest = await walletClient.prepareTransactionRequest({
      to: TESSERA_CONTRACT as `0x${string}`,
      data: calldata,
    });
    const signedTx = await walletClient.signTransaction(txRequest);
    const signedTxHex = signedTx.replace(/^0x/, "");

    step3.className = "p-step done";
    step3.textContent = "✓ Transaction signed";

    // ── Submit to backend ─────────────────────────────────────────────────────
    const step4 = pStep(p2pSteps, "⏳ Submitting deposit request…", "active");
    p2pBar.style.width = "90%";

    const { id: depositId } = await subpoolClient.submitDeposit({
      recipient_acc_address: privateAccAddressFull!,
      eth_address: ethAddressFull!,
      deposit_note_identifier: depositNote.identifierHex(),
      deposit_amount: u256LeHex(amountUnits),
      asset_id: ASSET_ID_HEX,
      signed_public_tx: signedTxHex,
    });

    step4.className = "p-step done";
    step4.textContent = "✓ Deposit submitted";

    // ── Poll for approval ─────────────────────────────────────────────────────
    const step5 = pStep(p2pSteps, "⏳ Waiting for approval…", "active");
    p2pBar.style.width = "95%";

    await new Promise<void>((resolve, reject) => {
      const timer = setInterval(async () => {
        try {
          const status = await subpoolClient.getDepositStatus(depositId);
          if (!status || status.status === "PENDING") return;
          clearInterval(timer);
          if (status.status === "REJECTED") {
            reject(new Error("Deposit rejected by operator"));
            return;
          }
          // APPROVED
          step5.className = "p-step done";
          step5.textContent = "✓ Deposit approved";
          if (status.deposit_tx_hash) {
            const link = document.createElement("a");
            link.href = `https://sepolia.etherscan.io/tx/${status.deposit_tx_hash}`;
            link.target = "_blank";
            link.rel = "noopener";
            link.textContent = `View on Etherscan ↗`;
            link.className = "tx-link";
            p2pSteps.appendChild(link);
          }
          p2pBar.style.width = "100%";
          // Refresh public + private balances
          await refreshAccountStates();

          resolve();
        } catch (e) {
          clearInterval(timer);
          reject(e);
        }
      }, 5_000);
    });
  } catch (err) {
    p2pError.textContent = `Error: ${err}`;
    p2pBtn.disabled = false;
  }
});

// ── Section 4: Private Transfer ───────────────────────────────────────────────

// 80-hex-char demo addresses: 16 hex subpool_id + 64 hex public_id
// Values are small so every u64 limb is well within Goldilocks field range.
const DEMO_ADDRESSES = [
  {
    label: "Alice",
    addr:
      "0000000000000001" +
      "0000000000000001" +
      "0000000000000002" +
      "0000000000000003" +
      "0000000000000004",
  },
  {
    label: "Bob",
    addr:
      "0000000000000002" +
      "0000000000000005" +
      "0000000000000006" +
      "0000000000000007" +
      "0000000000000008",
  },
  {
    label: "Charlie",
    addr:
      "0000000000000003" +
      "0000000000000009" +
      "000000000000000a" +
      "000000000000000b" +
      "000000000000000c",
  },
];

function validateTesseraAddr(hex: string): boolean {
  try {
    AccountAddress.fromHex(hex);
    return true;
  } catch {
    return false;
  }
}

// Render address book
const addrBook = document.getElementById("addr-book")!;
const xferAddrIn = document.getElementById("xfer-addr") as HTMLInputElement;
const xferAmtIn = document.getElementById("xfer-amount") as HTMLInputElement;
const xferBtn = document.getElementById("xfer-btn") as HTMLButtonElement;
const addrTick = document.getElementById("addr-tick")!;
const addrHint = document.getElementById("addr-hint")!;
const xferProgress = document.getElementById("xfer-progress")!;
const xferBar = document.getElementById("xfer-bar") as HTMLElement;
const xferSteps = document.getElementById("xfer-steps")!;
const xferError = document.getElementById("xfer-error")!;

for (const { label, addr } of DEMO_ADDRESSES) {
  const row = document.createElement("div");
  row.className = "addr-book-row";

  const lbl = document.createElement("span");
  lbl.className = "addr-label";
  lbl.textContent = label;

  const val = document.createElement("span");
  val.className = "addr-val";
  val.textContent = addr.slice(0, 12) + "…" + addr.slice(-10);
  val.title = addr;

  const btn = document.createElement("button");
  btn.className = "copy-btn";
  btn.textContent = "Copy";
  btn.addEventListener("click", async () => {
    await navigator.clipboard.writeText(addr);
    btn.textContent = "Copied!";
    setTimeout(() => {
      btn.textContent = "Copy";
    }, 1500);
  });

  row.append(lbl, val, btn);
  addrBook.appendChild(row);
}

function updateXferBtn() {
  const addrOk = validateTesseraAddr(xferAddrIn.value.trim());
  const amtOk = parseFloat(xferAmtIn.value) > 0;
  xferBtn.disabled = !(addrOk && amtOk);
}

xferAddrIn.addEventListener("input", () => {
  const v = xferAddrIn.value.trim();
  if (v === "") {
    addrTick.classList.add("hidden");
    addrHint.textContent = "";
  } else if (validateTesseraAddr(v)) {
    addrTick.classList.remove("hidden");
    addrHint.textContent = "";
  } else {
    addrTick.classList.add("hidden");
    addrHint.textContent =
      "Invalid address (must be 80 hex chars with valid field elements)";
  }
  updateXferBtn();
});

xferAmtIn.addEventListener("input", updateXferBtn);

xferBtn.addEventListener("click", async () => {
  xferBtn.disabled = true;
  xferError.textContent = "";
  xferProgress.classList.remove("visible");
  xferSteps.innerHTML = "";
  xferBar.style.width = "0%";

  const amount = parseFloat(xferAmtIn.value);

  try {
    const seed = await evalPrf();
    await loadPrivateAccount(seed);

    xferProgress.classList.add("visible");
    const step1 = pStep(xferSteps, "⏳ Fetching incoming notes…", "active");
    xferBar.style.width = "25%";

    const inotes = (
      await subpoolClient.getInputNotes(privateAccAddressFull!)
    ).filter((n) => n.asset_id === ASSET_ID_HEX);

    step1.className = "p-step done";
    step1.textContent = `✓ Found ${inotes.length} incoming note(s)`;

    // ── Build spend tx ────────────────────────────────────────────────────────
    const step2 = pStep(xferSteps, "⏳ Building spend tx…", "active");
    xferBar.style.width = "50%";

    const assetIdU64 = hexLeToU64(ASSET_ID_HEX);
    const builder = new SpendTxBuilder(privateAccount!, assetIdU64);

    for (const n of inotes) {
      const identBytes = hexToBytes(n.identifier); // 16 bytes
      const senderAddr = AccountAddress.fromHex(n.sender_address);
      builder.addInputNote(
        new InputNote(
          identBytes,
          assetIdU64,
          hexLeToU256(n.amount),
          privateAccount!.address(),
          senderAddr,
          0n, // position placeholder (not stored in DB)
        ),
      );
    }

    const transferAmount = BigInt(Math.round(amount * 1_000_000)); // USDX 6 decimals
    const recipientAddr = AccountAddress.fromHex(xferAddrIn.value.trim());
    builder.addOutputNote(recipientAddr, transferAmount, new Uint8Array(0));

    const spendTx = builder.build();
    step2.className = "p-step done";
    step2.textContent = "✓ Spend tx built";

    // ── Sign ─────────────────────────────────────────────────────────────────
    const step3 = pStep(xferSteps, "⏳ Signing…", "active");
    xferBar.style.width = "70%";

    const sigHex = toHex(spendTx.sign(seed));
    step3.className = "p-step done";
    step3.textContent = "✓ Signed";

    // ── Collect payloads ──────────────────────────────────────────────────────
    const inputNotePayloads: NotePayload[] = inotes.map((n) => ({
      identifier: n.identifier,
      asset_id: n.asset_id,
      amount: n.amount,
      recipient_address: n.recipient_address,
      sender_address: n.sender_address,
      memo: n.memo,
    }));

    const outputNotePayloads: NotePayload[] = spendTx
      .outputNotes()
      .map((n) => ({
        identifier: n.identifierHex(),
        asset_id: ASSET_ID_HEX,
        amount: n.amountHex(),
        recipient_address: n.recipientHex(),
        sender_address: n.senderHex(),
        memo: n.memoHex(),
      }));

    // ── Submit ────────────────────────────────────────────────────────────────
    const step4 = pStep(xferSteps, "⏳ Submitting spend tx…", "active");
    xferBar.style.width = "90%";

    const resp = await subpoolClient.submitSpendTx({
      priv_acc_address: privateAccAddressFull!,
      input_notes: inputNotePayloads,
      output_notes: outputNotePayloads,
      dinotes: spendTx.diNotes().map((d) => d.toHex()),
      donotes: spendTx.doNotes().map((d) => d.toHex()),
      spend_tx_signature: sigHex,
    });

    step4.className = "p-step done";
    step4.textContent = `✓ Submitted (id=${resp.id})`;
    xferBar.style.width = "100%";

    xferBtn.disabled = false;
    xferAmtIn.value = "";
    xferAddrIn.value = "";
    addrTick.classList.add("hidden");
    updateXferBtn();
  } catch (err) {
    xferError.textContent = `Error: ${err}`;
    xferBtn.disabled = false;
    updateXferBtn();
  }
});
