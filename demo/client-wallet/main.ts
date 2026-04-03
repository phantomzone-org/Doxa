import init from "../../tessera-js/wasm/tessera_client_wasm.js";
import {
  createPublicClient,
  createWalletClient,
  custom,
  encodeFunctionData,
  http,
  erc20Abi,
  formatUnits,
  maxUint256,
} from "viem";
import { sepolia } from "viem/chains";
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
import type {
  NotePayload,
  NotesBalanceResponse,
  UserResponse,
} from "../../tessera-js/src/index";
import {
  toHex,
  hexToBytes,
  hexLeToU256,
  hexLeToU64,
  leHexToU64,
  u256LeHex,
  sha256,
  deriveWalletAccount,
  delay,
  pStep,
} from "./helpers";

await init();

// ── Constants ─────────────────────────────────────────────────────────────────

const TESSERA_CONTRACT = import.meta.env
  .VITE_TESSERA_CONTRACT_ADDR as `0x${string}`;
const USDX_CONTRACT_ADDR = import.meta.env
  .VITE_USDX_CONTRACT_ADDR as `0x${string}`;
const SEPOLIA_RPC_URL = import.meta.env.VITE_SEPOLIA_RPC_URL as string;
const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";
const PRF_INPUT = new TextEncoder().encode("tessera::account::seed");
const SUBPOOL_ID_HEX =
  (import.meta.env.VITE_SUBPOOL_ID_HEX as string) ?? "0100000000000000";
const ASSET_ID_HEX =
  (import.meta.env.VITE_ASSET_ID_HEX as string) ?? "0100000000000000";
const SUBPOOL_ID = leHexToU64(SUBPOOL_ID_HEX);
const ASSET_ID = leHexToU64(ASSET_ID_HEX);

console.log("Subpool ID =", SUBPOOL_ID_HEX);
console.log("DB server =", API_BASE_URL);

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

// ── API client ────────────────────────────────────────────────────────────────

const subpoolClient = new SubpoolClient(API_BASE_URL);

// ── Shared state ──────────────────────────────────────────────────────────────

let credentialId: Uint8Array | null = null;
let currentSeed: Uint8Array | null = null;
let isMetaMaskUser = false;
let walletClient: ReturnType<typeof createWalletClient> | null = null;
let ethAddressFull: string | null = null;
let privateAccAddressFull: string | null = null;
let privateAccount: Account | null = null;
let notesBalance: NotesBalanceResponse | null = null;
let kycInfo: UserResponse | null = null;
let publicBalanceRaw = 0n;
let privateBalanceRaw = 0n;

// ── Passkey helpers ───────────────────────────────────────────────────────────

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
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        authenticatorSelection: {
          residentKey: "required",
          userVerification: "required",
        },
        extensions: { prf: { eval: { first: PRF_INPUT } } },
      },
    })) as PublicKeyCredential;

    credentialId = new Uint8Array(cred.rawId);
    const ext = cred.getClientExtensionResults() as any;
    const prfEnabled = !!ext?.prf?.enabled;
    console.log(`PRF enabled: ${prfEnabled}`);
    if (!prfEnabled)
      throw new Error("Authenticator does not support PRF extension.");

    const firstResult: ArrayBuffer | undefined = ext?.prf?.results?.first;
    if (firstResult) {
      const seed = new Uint8Array(firstResult);
      if (seed.byteLength !== 32)
        throw new Error(`PRF output must be 32 bytes, got ${seed.byteLength}`);
      return seed;
    }
  } catch (err) {
    console.log("credentials.create failed:", err);
  }
  return evalPrf();
}

async function evalPrf(): Promise<Uint8Array> {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      userVerification: "required",
      extensions: { prf: { eval: { first: PRF_INPUT } } },
    },
  })) as PublicKeyCredential;

  const ext = assertion.getClientExtensionResults() as any;
  const prfOutput: ArrayBuffer | undefined = ext?.prf?.results?.first;
  if (!prfOutput) throw new Error("Authenticator did not return a PRF result.");

  const seed = new Uint8Array(prfOutput);
  if (seed.byteLength !== 32)
    throw new Error(`PRF output must be 32 bytes, got ${seed.byteLength}`);
  return seed;
}

// ── MetaMask helper ───────────────────────────────────────────────────────────

async function signInWithMetaMask(): Promise<{
  seed: Uint8Array;
  ethAddr: string;
}> {
  const eth = (window as any).ethereum;
  if (!eth) throw new Error("MetaMask not detected.");
  const [ethAddr]: string[] = await eth.request({
    method: "eth_requestAccounts",
  });
  const sig: string = await eth.request({
    method: "personal_sign",
    params: ["tessera::login", ethAddr],
  });
  const seed = await sha256(hexToBytes(sig.slice(2)));
  console.log(seed);
  return { seed, ethAddr };
}

// ── View manager ──────────────────────────────────────────────────────────────

const loginPrivView = document.getElementById("login-priv-view")!;
const registerPrivView = document.getElementById("register-priv-view")!;
const displayPrivView = document.getElementById("display-priv-view")!;

type PrivView = "login" | "register" | "display";

function showPrivAccView(view: PrivView) {
  loginPrivView.style.display = view === "login" ? "" : "none";
  registerPrivView.style.display = view === "register" ? "" : "none";
  displayPrivView.style.display = view === "display" ? "" : "none";
}

// ── DOM refs — login view ─────────────────────────────────────────────────────

const createpasskeysBtn = document.getElementById(
  "createpasskeys-btn",
) as HTMLButtonElement;
const signinpasskeysBtn = document.getElementById(
  "signinpasskeys-btn",
) as HTMLButtonElement;
const signinmetamaskBtn = document.getElementById(
  "signinmetamask-btn",
) as HTMLButtonElement;
const loginError = document.getElementById("login-error")!;

// ── DOM refs — register view ──────────────────────────────────────────────────

const kycNameIn = document.getElementById("kyc-name") as HTMLInputElement;
const kycStreetIn = document.getElementById("kyc-street") as HTMLInputElement;
const kycDobIn = document.getElementById("kyc-dob") as HTMLInputElement;
const registerBtn = document.getElementById(
  "register-btn",
) as HTMLButtonElement;
const registerProgressDiv = document.getElementById("register-progress")!;
const registerError = document.getElementById("register-error")!;

// ── DOM refs — display view ───────────────────────────────────────────────────

const dispPrivBalance = document.getElementById("disp-priv-balance")!;
const dispPrivBalanceRow = document.getElementById("disp-priv-balance-row")!;
const dispName = document.getElementById("disp-name")!;
const dispStreet = document.getElementById("disp-street")!;
const dispDob = document.getElementById("disp-dob")!;
const dispTesseraAddr = document.getElementById("disp-tessera-addr")!;

const faucetBtn = document.getElementById("faucet-btn") as HTMLButtonElement;
const faucetProgress = document.getElementById("faucet-progress")!;
const faucetBar = document.getElementById("faucet-bar") as HTMLElement;
const faucetSteps = document.getElementById("faucet-steps")!;
const faucetEtherscanLink = document.getElementById("faucet-etherscan-link")!;
const faucetEtherscanAnchor = document.getElementById(
  "faucet-etherscan-anchor",
) as HTMLAnchorElement;

// ── Balance loading ───────────────────────────────────────────────────────────

const publicClient = createPublicClient({
  chain: sepolia,
  transport: http(SEPOLIA_RPC_URL),
});

async function loadPublicBalance(address: string) {
  const raw = await publicClient.readContract({
    address: USDX_CONTRACT_ADDR,
    abi: erc20Abi,
    functionName: "balanceOf",
    args: [address as `0x${string}`],
  });
  publicBalanceRaw = raw as bigint;
}

async function loadPrivateBalance() {
  if (!privateAccAddressFull) return;
  const accountData = await subpoolClient.getAccount(privateAccAddressFull);
  if (!accountData) return;
  privateAccount = Account.fromAccountData(accountData);
  notesBalance = await subpoolClient
    .getNotesBalance(privateAccAddressFull)
    .catch(() => null);
  renderPrivDisplayView();
}

async function refreshAll() {
  if (ethAddressFull) await loadPublicBalance(ethAddressFull);
  await loadPrivateBalance();
}

// ── Render display view ───────────────────────────────────────────────────────

function renderPrivDisplayView() {
  if (privateAccAddressFull) {
    dispTesseraAddr.textContent = privateAccAddressFull;
  }
  if (kycInfo) {
    dispName.textContent = kycInfo.name;
    dispStreet.textContent = kycInfo.physical_address;
    dispDob.textContent = kycInfo.dob;
  }
  if (privateAccount) {
    const accountBal = privateAccount.balanceFor(AssetId.fromU64(ASSET_ID));
    const notesAmountHex = notesBalance?.balances[ASSET_ID.toString()]?.amount;
    const notesBal = notesAmountHex ? BigInt("0x" + notesAmountHex) : 0n;
    privateBalanceRaw = accountBal + notesBal;
    const privFloat = Number(privateBalanceRaw) / 1e6;
    dispPrivBalance.textContent =
      privFloat.toLocaleString("en-US", { minimumFractionDigits: 2 }) + " USDX";
    dispPrivBalanceRow.style.display = "";
  }
}

// ── Common post-auth entry point ──────────────────────────────────────────────

async function onSeedAvailable(seed: Uint8Array) {
  currentSeed = seed;

  const privateId = derivePrivateIdentifier(seed);
  const publicId = derivePublicIdentifier(privateId);
  privateAccAddressFull = AccountAddress.fromParts(
    SubpoolId.fromHex(SUBPOOL_ID_HEX),
    publicId,
  ).toHex();

  const accountData = await subpoolClient.getAccount(privateAccAddressFull);
  if (!accountData) {
    showPrivAccView("register");
  } else {
    privateAccount = Account.fromAccountData(accountData);
    notesBalance = await subpoolClient
      .getNotesBalance(privateAccAddressFull)
      .catch(() => null);
    kycInfo = await subpoolClient
      .getUser(privateAccAddressFull)
      .catch(() => null);
    renderPrivDisplayView();
    showPrivAccView("display");
    enableTransactSections();
    setInterval(() => loadPrivateBalance(), 5_000);
  }
}

// ── Login view ────────────────────────────────────────────────────────────────

function setLoginBtnsDisabled(disabled: boolean) {
  createpasskeysBtn.disabled = disabled;
  signinpasskeysBtn.disabled = disabled;
  signinmetamaskBtn.disabled = disabled;
}

createpasskeysBtn.addEventListener("click", async () => {
  setLoginBtnsDisabled(true);
  loginError.textContent = "";
  createpasskeysBtn.textContent = "⏳ Creating…";
  try {
    isMetaMaskUser = false;
    await onSeedAvailable(await registerAndGetSeed());
    createpasskeysBtn.textContent = "✓ Created";
  } catch (err) {
    loginError.textContent = `${err}`;
    createpasskeysBtn.textContent = "Create with passkeys";
    setLoginBtnsDisabled(false);
  }
});

signinpasskeysBtn.addEventListener("click", async () => {
  setLoginBtnsDisabled(true);
  loginError.textContent = "";
  signinpasskeysBtn.textContent = "⏳ Signing in…";
  try {
    isMetaMaskUser = false;
    await onSeedAvailable(await evalPrf());
    signinpasskeysBtn.textContent = "✓ Signed in";
  } catch (err) {
    loginError.textContent = `${err}`;
    signinpasskeysBtn.textContent = "Sign in with passkeys";
    setLoginBtnsDisabled(false);
  }
});

signinmetamaskBtn.addEventListener("click", async () => {
  setLoginBtnsDisabled(true);
  loginError.textContent = "";
  signinmetamaskBtn.textContent = "⏳ Connecting…";
  try {
    const { seed, ethAddr } = await signInWithMetaMask();
    isMetaMaskUser = true;
    ethAddressFull = ethAddr;
    await onSeedAvailable(seed);
    signinmetamaskBtn.textContent = "✓ Connected";
  } catch (err) {
    loginError.textContent = `${err}`;
    signinmetamaskBtn.textContent = "Sign in with MetaMask";
    setLoginBtnsDisabled(false);
  }
});

// ── Register view ─────────────────────────────────────────────────────────────

for (const el of [kycNameIn, kycStreetIn, kycDobIn]) {
  el.addEventListener("input", () => {
    registerBtn.disabled = !(
      currentSeed !== null &&
      kycNameIn.value.trim() &&
      kycStreetIn.value.trim() &&
      kycDobIn.value
    );
  });
}

async function pollFreshAccApproval(addr: string) {
  while (true) {
    await delay(1000);
    const res = await subpoolClient.getFreshAccStatus(addr).catch(() => null);
    if (res?.status === "Approved") return;
  }
}

function appendRegProgressLine(
  text: string,
  cls: "active" | "done",
): HTMLElement {
  const el = document.createElement("div");
  el.className = `progress-line ${cls}`;
  el.textContent = text;
  registerProgressDiv.appendChild(el);
  return el;
}

registerBtn.addEventListener("click", async () => {
  registerBtn.disabled = true;
  registerError.textContent = "";
  registerProgressDiv.innerHTML = "";
  registerProgressDiv.classList.add("visible");
  try {
    const seed = currentSeed!;
    const account = Account.createWithSeed(seed, SUBPOOL_ID);
    const privAccAddr = account.address().toHex();

    const s1 = appendRegProgressLine("⏳ Registering account…", "active");
    await subpoolClient.registerAccount(
      account.privateIdentifier(),
      account.spendAuthPk(),
      ethAddressFull!,
      {
        name: kycNameIn.value.trim(),
        physicalAddress: kycStreetIn.value.trim(),
        dob: kycDobIn.value,
      },
    );
    s1.className = "progress-line done";
    s1.textContent = "✓ Account submitted";

    const s2 = appendRegProgressLine(
      "⏳ Waiting for subpool approval…",
      "active",
    );
    await pollFreshAccApproval(privAccAddr);
    s2.className = "progress-line done";
    s2.textContent = "✓ Approved";

    appendRegProgressLine("✓ Account registered", "done");

    privateAccAddressFull = privAccAddr;
    await loadPrivateBalance();
    kycInfo = await subpoolClient
      .getUser(privateAccAddressFull)
      .catch(() => null);
    renderPrivDisplayView();
    showPrivAccView("display");
    enableTransactSections();
    setInterval(() => loadPrivateBalance(), 5_000);
  } catch (err) {
    registerError.textContent = `${err}`;
    registerBtn.disabled = false;
  }
});

// ── Faucet (display view) ─────────────────────────────────────────────────────

faucetBtn.addEventListener("click", async () => {
  faucetBtn.disabled = true;
  faucetProgress.classList.add("visible");
  faucetSteps.innerHTML = "";
  faucetEtherscanLink.classList.remove("visible");

  const step = pStep(faucetSteps, "⏳ Submitting faucet request…", "active");
  faucetBar.style.width = "50%";
  try {
    const { tx_hash } = await subpoolClient.requestFaucet(ethAddressFull!);
    step.className = "p-step done";
    step.textContent = "✓ Faucet transaction submitted";
    faucetBar.style.width = "100%";
    faucetEtherscanAnchor.href = `https://sepolia.etherscan.io/tx/${tx_hash}`;
    faucetEtherscanAnchor.textContent =
      tx_hash.slice(0, 10) + "…" + tx_hash.slice(-8);
    faucetEtherscanLink.classList.add("visible");
  } catch (err) {
    step.className = "p-step done";
    step.textContent = `Error: ${err}`;
    faucetBtn.disabled = false;
  }
});

// ── Public → Private deposit section ─────────────────────────────────────────

const p2pSection = document.getElementById("p2p-section") as HTMLElement;
const p2pAmountIn = document.getElementById("p2p-amount") as HTMLInputElement;
const p2pBtn = document.getElementById("p2p-btn") as HTMLButtonElement;
const p2pHint = document.getElementById("p2p-hint")!;
const p2pProgress = document.getElementById("p2p-progress")!;
const p2pBar = document.getElementById("p2p-bar") as HTMLElement;
const p2pSteps = document.getElementById("p2p-steps")!;
const p2pError = document.getElementById("p2p-error")!;

// ── Private transfer section ──────────────────────────────────────────────────

const xferSection = document.getElementById("xfer-section") as HTMLElement;
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

function enableTransactSections() {
  p2pSection.style.opacity = "";
  p2pSection.style.pointerEvents = "";
  xferSection.style.opacity = "";
  xferSection.style.pointerEvents = "";
  p2pBtn.disabled = false;
  p2pHint.textContent = "Enter an amount and click Deposit.";
}

// ── p2p deposit ───────────────────────────────────────────────────────────────

p2pAmountIn.addEventListener("input", () => {
  const amount = parseFloat(p2pAmountIn.value);
  if (!amount || amount <= 0) {
    p2pBtn.disabled = false;
    p2pError.textContent = "";
    return;
  }
  const units = BigInt(Math.round(amount * 1_000_000));
  if (units > publicBalanceRaw) {
    p2pBtn.disabled = true;
    p2pError.textContent = "Amount exceeds your USDX balance.";
  } else {
    p2pBtn.disabled = false;
    p2pError.textContent = "";
  }
});

p2pBtn.addEventListener("click", async () => {
  const amount = parseFloat(p2pAmountIn.value);
  if (!amount || amount <= 0) {
    p2pError.textContent = "Enter a valid amount.";
    return;
  }

  try {
    if (!isMetaMaskUser) currentSeed = await evalPrf();
    await refreshAll();

    p2pBtn.disabled = true;
    p2pError.textContent = "";
    p2pProgress.classList.add("visible");
    p2pSteps.innerHTML = "";
    p2pBar.style.width = "0%";

    const depositAmountUnits = BigInt(Math.round(amount * 1_000_000));
    if (depositAmountUnits > publicBalanceRaw) {
      p2pError.textContent = "Amount exceeds your USDX balance.";
      p2pBtn.disabled = false;
      return;
    }

    const allowance = await publicClient.readContract({
      address: USDX_CONTRACT_ADDR,
      abi: erc20Abi,
      functionName: "allowance",
      args: [ethAddressFull as `0x${string}`, TESSERA_CONTRACT],
    });

    if (allowance < depositAmountUnits) {
      const step = pStep(p2pSteps, "⏳ Awaiting USDX approval…", "active");
      p2pBar.style.width = "30%";
      const approveTxHash = await walletClient!.writeContract({
        address: USDX_CONTRACT_ADDR,
        abi: erc20Abi,
        functionName: "approve",
        args: [TESSERA_CONTRACT, maxUint256],
      });
      await publicClient.waitForTransactionReceipt({
        hash: approveTxHash as `0x${string}`,
      });
      step.className = "p-step done";
      step.textContent = "✓ USDX approval given";
    }

    const step2 = pStep(p2pSteps, "⏳ Constructing deposit note…", "active");
    p2pBar.style.width = "55%";
    const depositNote = DepositNote.create(
      AccountAddress.fromHex(privateAccAddressFull!),
      depositAmountUnits,
      AssetId.fromU64(ASSET_ID),
    );
    const commitmentHex = ("0x" +
      depositNote.commitment().toHex()) as `0x${string}`;
    step2.className = "p-step done";
    step2.textContent = "✓ Deposit note constructed";

    const step3 = pStep(p2pSteps, "⏳ Signing deposit transaction…", "active");
    p2pBar.style.width = "75%";
    const calldata = encodeFunctionData({
      abi: TESSERA_ABI,
      functionName: "depositAndRegister",
      args: [commitmentHex, depositAmountUnits],
    });
    const txRequest = await walletClient!.prepareTransactionRequest({
      to: TESSERA_CONTRACT,
      data: calldata,
    });
    const signedTx = await walletClient!.signTransaction(txRequest as any);
    const signedTxHex = (signedTx as string).replace(/^0x/, "");
    step3.className = "p-step done";
    step3.textContent = "✓ Transaction signed";

    const step4 = pStep(p2pSteps, "⏳ Submitting deposit request…", "active");
    p2pBar.style.width = "88%";
    const { id: depositId } = await subpoolClient.submitDeposit({
      recipient_address: privateAccAddressFull!,
      eth_address: ethAddressFull!,
      deposit_note_identifier: depositNote.identifierHex(),
      deposit_amount: u256LeHex(depositAmountUnits),
      asset_id: ASSET_ID_HEX,
      signed_public_tx: signedTxHex,
    });
    step4.className = "p-step done";
    step4.textContent = "✓ Deposit submitted";

    const step5 = pStep(p2pSteps, "⏳ Waiting for approval…", "active");
    p2pBar.style.width = "95%";

    await new Promise<void>((resolve, reject) => {
      const timer = setInterval(async () => {
        try {
          const status = await subpoolClient.getDepositStatus(depositId);
          if (!status || status.status === "Pending") return;
          clearInterval(timer);
          if (status.status === "Rejected") {
            reject(new Error("Deposit rejected by operator"));
            return;
          }
          step5.className = "p-step done";
          step5.textContent = "✓ Deposit approved";
          if (status.deposit_tx_hash) {
            const a = document.createElement("a");
            a.href = `https://sepolia.etherscan.io/tx/${status.deposit_tx_hash}`;
            a.target = "_blank";
            a.rel = "noopener";
            a.textContent = "View deposit tx on Etherscan ↗";
            a.className = "tx-link";
            p2pSteps.appendChild(a);
          }
          p2pBar.style.width = "100%";
          await refreshAll();
          resolve();
        } catch (e) {
          clearInterval(timer);
          reject(e);
        }
      }, 5_000);
    });
  } catch (err) {
    p2pError.textContent = `${err}`;
    p2pBtn.disabled = false;
  }
});

// ── Private transfer ──────────────────────────────────────────────────────────

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

function validTesseraAddr(hex: string): boolean {
  try {
    AccountAddress.fromHex(hex);
    return true;
  } catch {
    return false;
  }
}

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
  const addrOk = validTesseraAddr(xferAddrIn.value.trim());
  const amount = parseFloat(xferAmtIn.value);
  const amtOk = amount > 0;
  if (amtOk && BigInt(Math.round(amount * 1_000_000)) > privateBalanceRaw) {
    xferBtn.disabled = true;
    xferError.textContent = "Amount exceeds your private balance.";
    return;
  }
  xferError.textContent = "";
  xferBtn.disabled = !(addrOk && amtOk);
}

xferAddrIn.addEventListener("input", () => {
  const v = xferAddrIn.value.trim();
  if (!v) {
    addrTick.classList.add("hidden");
    addrHint.textContent = "";
  } else if (validTesseraAddr(v)) {
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

  const transferAmount = BigInt(
    Math.round(parseFloat(xferAmtIn.value) * 1_000_000),
  );
  if (transferAmount > privateBalanceRaw) {
    xferBtn.disabled = false;
    xferError.textContent = "Amount exceeds your private balance.";
    return;
  }

  try {
    const seed = isMetaMaskUser ? currentSeed! : await evalPrf();
    await loadPrivateBalance();

    xferProgress.classList.add("visible");
    const step1 = pStep(xferSteps, "⏳ Fetching incoming notes…", "active");
    xferBar.style.width = "20%";

    const inotes = (
      await subpoolClient.getInputNotes(privateAccAddressFull!)
    ).filter((n) => n.asset_id === ASSET_ID_HEX);
    step1.className = "p-step done";
    step1.textContent = `✓ Found ${inotes.length} incoming note(s)`;

    const step2 = pStep(xferSteps, "⏳ Building spend tx…", "active");
    xferBar.style.width = "45%";

    const assetIdU64 = hexLeToU64(ASSET_ID_HEX);
    const builder = new SpendTxBuilder(privateAccount!, assetIdU64);
    for (const n of inotes) {
      builder.addInputNote(
        new InputNote(
          hexToBytes(n.identifier),
          assetIdU64,
          hexLeToU256(n.amount),
          privateAccount!.address(),
          AccountAddress.fromHex(n.sender_address),
          0n,
          hexToBytes(n.memo),
        ),
      );
    }
    builder.addOutputNote(
      AccountAddress.fromHex(xferAddrIn.value.trim()),
      transferAmount,
      new Uint8Array(0),
    );
    const spendTx = builder.build();
    step2.className = "p-step done";
    step2.textContent = "✓ Spend transaction built";

    const step3 = pStep(xferSteps, "⏳ Signing…", "active");
    xferBar.style.width = "65%";
    const sigHex = toHex(spendTx.sign(seed));
    step3.className = "p-step done";
    step3.textContent = "✓ Signed";

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

    const step4 = pStep(xferSteps, "⏳ Submitting spend tx…", "active");
    xferBar.style.width = "85%";
    const resp = await subpoolClient.submitSpendTx({
      priv_acc_address: privateAccAddressFull!,
      input_notes: inputNotePayloads,
      output_notes: outputNotePayloads,
      dinotes: spendTx.diNotes().map((d) => d.toHex()),
      donotes: spendTx.doNotes().map((d) => d.toHex()),
      spend_tx_signature: sigHex,
    });
    step4.className = "p-step done";
    step4.textContent = "✓ Submitted for approval";
    xferBar.style.width = "93%";

    const step5 = pStep(xferSteps, "⏳ Waiting for approval…", "active");
    await new Promise<void>((resolve, reject) => {
      const timer = setInterval(async () => {
        try {
          const status = await subpoolClient.getSpendTxStatus(resp.id);
          if (!status || status.status === "Pending") return;
          clearInterval(timer);
          if (status.status === "Rejected") {
            reject(
              new Error(
                `Spend tx rejected: ${status.rejection_reason ?? "unknown reason"}`,
              ),
            );
            return;
          }
          step5.className = "p-step done";
          step5.textContent = "✓ Transfer approved";
          xferBar.style.width = "100%";
          await refreshAll();
          resolve();
        } catch (e) {
          clearInterval(timer);
          reject(e);
        }
      }, 5_000);
    });

    xferBtn.disabled = false;
    xferAmtIn.value = "";
    xferAddrIn.value = "";
    addrTick.classList.add("hidden");
    updateXferBtn();
  } catch (err) {
    xferError.textContent = `${err}`;
    xferBtn.disabled = false;
    updateXferBtn();
  }
});
