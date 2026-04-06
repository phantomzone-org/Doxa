import init from "../../tessera-js/wasm/tessera_client_wasm.js";
import {
  createPublicClient,
  createWalletClient,
  custom,
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
import subpoolInstitutions from "./subpool_institutions.json";

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

function getInstitutionName(subpoolIdHex: string): string {
  return (
    (subpoolInstitutions as Record<string, string>)[subpoolIdHex] ??
    subpoolIdHex
  );
}

// ── EIP-712 deposit signing ────────────────────────────────────────────────────

const TESSERA_DEPOSIT_DOMAIN = {
  name: "TesseraDeposit",
  version: "1",
  chainId: 11155111,
  verifyingContract: TESSERA_CONTRACT,
} as const;

const TESSERA_DEPOSIT_TYPES = {
  Deposit: [
    { name: "depositNoteCommitment", type: "bytes32" },
    { name: "amount", type: "uint256" },
  ],
} as const;

// ── API client ────────────────────────────────────────────────────────────────

const subpoolClient = new SubpoolClient(API_BASE_URL);

const SUBPOOL_PORTS = [8081, 8082, 8083];

async function loadAllUsers(): Promise<UserResponse[]> {
  const results = await Promise.allSettled(
    SUBPOOL_PORTS.map((port) =>
      new SubpoolClient(`http://localhost:${port}`).listUsers(),
    ),
  );
  return results
    .filter(
      (r): r is PromiseFulfilledResult<UserResponse[]> =>
        r.status === "fulfilled",
    )
    .flatMap((r) => r.value);
}

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
let pubConnectedAddress: string | null = null;
let pubWalletClient: ReturnType<typeof createWalletClient> | null = null;
let pubEthBalanceRaw = 0n;
let pubUsdxBalanceRaw = 0n;
let pubAllowanceRaw = 0n;

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

// ── DOM refs — pub2priv section ───────────────────────────────────────────────

const pub2privMetamaskBtn = document.getElementById(
  "pub2priv-metamask-btn",
) as HTMLButtonElement;
const pub2privConnectError = document.getElementById("pub2priv-connect-error")!;
const pub2privConnectView = document.getElementById("pub2priv-connect-view")!;
const pub2privWalletView = document.getElementById("pub2priv-wallet-view")!;
const pub2privAddress = document.getElementById("pub2priv-address")!;
const pub2privNetwork = document.getElementById("pub2priv-network")!;
const pub2privEthBalance = document.getElementById("pub2priv-eth-balance")!;
const pub2privUsdxBalance = document.getElementById("pub2priv-usdx-balance")!;
const pub2privFaucetEthWrap = document.getElementById(
  "pub2priv-fauceteth-wrap",
)!;
const pub2privFaucetEthBtn = document.getElementById(
  "pub2priv-fauceteth-btn",
) as HTMLButtonElement;
const pub2privFaucetEthSteps = document.getElementById(
  "pub2priv-fauceteth-steps",
)!;
const pub2privFaucetUsdxBtn = document.getElementById(
  "pub2priv-faucetusdx-btn",
) as HTMLButtonElement;
const pub2privFaucetUsdxSteps = document.getElementById(
  "pub2priv-faucetusdx-steps",
)!;
const pub2privApprovalWrap = document.getElementById("pub2priv-approval-wrap")!;
const pub2privApprovalBtn = document.getElementById(
  "pub2priv-approval-btn",
) as HTMLButtonElement;
const pub2privApprovalSteps = document.getElementById(
  "pub2priv-approval-steps",
)!;
const pub2privDepositWrap = document.getElementById("pub2priv-deposit-wrap")!;
const pub2privAmountIn = document.getElementById(
  "pub2priv-amount",
) as HTMLInputElement;
const pub2privDepositBtn = document.getElementById(
  "pub2priv-deposit-btn",
) as HTMLButtonElement;
const pub2privHint = document.getElementById("pub2priv-hint")!;
const pub2privProgress = document.getElementById("pub2priv-progress")!;
const pub2privBar = document.getElementById("pub2priv-bar") as HTMLElement;
const pub2privSteps = document.getElementById("pub2priv-steps")!;
const pub2privError = document.getElementById("pub2priv-error")!;

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
    memoSenderName.textContent = kycInfo.name;
    memoSenderAddr.textContent = kycInfo.physical_address;
    updateMemoPreview();
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

// ── Public → Private Transfer section ────────────────────────────────────────

async function loadPubBalances() {
  if (!pubConnectedAddress) return;
  pubEthBalanceRaw = await publicClient.getBalance({
    address: pubConnectedAddress as `0x${string}`,
  });
  const usdxRaw = await publicClient.readContract({
    address: USDX_CONTRACT_ADDR,
    abi: erc20Abi,
    functionName: "balanceOf",
    args: [pubConnectedAddress as `0x${string}`],
  });
  pubUsdxBalanceRaw = usdxRaw as bigint;

  pub2privEthBalance.textContent =
    Number(formatUnits(pubEthBalanceRaw, 18)).toFixed(4) + " ETH";
  pub2privUsdxBalance.textContent =
    Number(formatUnits(pubUsdxBalanceRaw, 6)).toLocaleString("en-US", {
      minimumFractionDigits: 2,
    }) + " USDX";

  pub2privFaucetEthWrap.style.display =
    pubEthBalanceRaw < 69927000000000n ? "" : "none";

  pubAllowanceRaw = (await publicClient.readContract({
    address: USDX_CONTRACT_ADDR,
    abi: erc20Abi,
    functionName: "allowance",
    args: [pubConnectedAddress as `0x${string}`, TESSERA_CONTRACT],
  })) as bigint;
  updatePub2PrivVisibility();
  updatePub2PrivTransferBtn();
}

function updatePub2PrivVisibility() {
  const approved = pubAllowanceRaw >= 1_000_000_000n * 10n ** 18n;
  pub2privApprovalWrap.style.display = approved ? "none" : "";
  pub2privDepositWrap.style.display = approved ? "" : "none";
}

function updatePub2PrivTransferBtn() {
  if (!privateAccAddressFull) {
    pub2privHint.textContent =
      "Sign into your private account above to enable deposits.";
    pub2privDepositBtn.disabled = true;
    pub2privError.textContent = "";
    return;
  }
  pub2privHint.textContent = "Enter an amount and click Deposit.";
  const amount = parseFloat(pub2privAmountIn.value);
  if (!amount || amount <= 0) {
    pub2privDepositBtn.disabled = false;
    pub2privError.textContent = "";
    return;
  }
  const units = BigInt(Math.round(amount * 1_000_000));
  if (units > pubUsdxBalanceRaw) {
    pub2privDepositBtn.disabled = true;
    pub2privError.textContent =
      "Amount exceeds USDX balance of connected public account.";
  } else {
    pub2privDepositBtn.disabled = false;
    pub2privError.textContent = "";
  }
}

pub2privMetamaskBtn.addEventListener("click", async () => {
  pub2privMetamaskBtn.disabled = true;
  pub2privConnectError.textContent = "";
  try {
    const eth = (window as any).ethereum;
    if (!eth) throw new Error("MetaMask not detected.");
    const [addr]: string[] = await eth.request({
      method: "eth_requestAccounts",
    });

    // Switch to Sepolia (chain 0xaa36a7 = 11155111); add it if not present.
    try {
      await eth.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: "0xaa36a7" }],
      });
    } catch (switchErr: any) {
      if (switchErr?.code === 4902) {
        await eth.request({
          method: "wallet_addEthereumChain",
          params: [
            {
              chainId: "0xaa36a7",
              chainName: "Sepolia Testnet",
              nativeCurrency: { name: "ETH", symbol: "ETH", decimals: 18 },
              rpcUrls: [SEPOLIA_RPC_URL],
              blockExplorerUrls: ["https://sepolia.etherscan.io"],
            },
          ],
        });
      } else {
        throw switchErr;
      }
    }

    pubConnectedAddress = addr;
    pubWalletClient = createWalletClient({
      account: addr as `0x${string}`,
      chain: sepolia,
      transport: custom(eth),
    });
    pub2privMetamaskBtn.textContent = addr.slice(0, 8) + "…" + addr.slice(-6);
    pub2privAddress.textContent = addr.slice(0, 10) + "…" + addr.slice(-8);
    pub2privAddress.title = addr;
    pub2privNetwork.textContent = "Sepolia Testnet";
    pub2privConnectView.style.display = "none";
    pub2privWalletView.style.display = "";
    await loadPubBalances();
    setInterval(loadPubBalances, 10_000);
  } catch (err) {
    pub2privConnectError.textContent = `${err}`;
    pub2privMetamaskBtn.disabled = false;
  }
});

pub2privAmountIn.addEventListener("input", updatePub2PrivTransferBtn);

pub2privFaucetEthBtn.addEventListener("click", async () => {
  pub2privFaucetEthBtn.disabled = true;
  pub2privFaucetEthSteps.innerHTML = "";
  const step = pStep(
    pub2privFaucetEthSteps,
    "⏳ Requesting testnet ETH…",
    "active",
  );
  try {
    const { tx_hash } = await subpoolClient.requestFaucetEth(
      pubConnectedAddress!,
    );
    step.className = "p-step done";
    step.textContent = "✓ ETH sent";
    const a = document.createElement("a");
    a.href = `https://sepolia.etherscan.io/tx/${tx_hash}`;
    a.target = "_blank";
    a.rel = "noopener";
    a.textContent = "View on Etherscan ↗";
    a.className = "tx-link";
    pub2privFaucetEthSteps.appendChild(a);
    await loadPubBalances();
  } catch (err) {
    step.className = "p-step done";
    step.textContent = `Error: ${err}`;
    pub2privFaucetEthBtn.disabled = false;
  }
});

pub2privFaucetUsdxBtn.addEventListener("click", async () => {
  pub2privFaucetUsdxBtn.disabled = true;
  pub2privFaucetUsdxSteps.innerHTML = "";
  const step = pStep(pub2privFaucetUsdxSteps, "⏳ Requesting USDX…", "active");
  try {
    const { tx_hash } = await subpoolClient.requestFaucetUsdx(
      pubConnectedAddress!,
    );
    step.className = "p-step done";
    step.textContent = "✓ 10 USDX sent";
    const a = document.createElement("a");
    a.href = `https://sepolia.etherscan.io/tx/${tx_hash}`;
    a.target = "_blank";
    a.rel = "noopener";
    a.textContent = "View on Etherscan ↗";
    a.className = "tx-link";
    pub2privFaucetUsdxSteps.appendChild(a);
    await loadPubBalances();
  } catch (err) {
    step.className = "p-step done";
    step.textContent = `Error: ${err}`;
    pub2privFaucetUsdxBtn.disabled = false;
  }
});

pub2privApprovalBtn.addEventListener("click", async () => {
  pub2privApprovalBtn.disabled = true;
  pub2privApprovalSteps.innerHTML = "";
  const step = pStep(
    pub2privApprovalSteps,
    "⏳ Awaiting USDX approval…",
    "active",
  );
  try {
    const txHash = await pubWalletClient!.writeContract({
      address: USDX_CONTRACT_ADDR,
      abi: erc20Abi,
      functionName: "approve",
      args: [TESSERA_CONTRACT, maxUint256],
    });
    await publicClient.waitForTransactionReceipt({
      hash: txHash as `0x${string}`,
    });
    step.className = "p-step done";
    step.textContent = "✓ USDX approval given";
    await loadPubBalances();
  } catch (err) {
    step.className = "p-step done";
    step.textContent = `Error: ${err}`;
    pub2privApprovalBtn.disabled = false;
  }
});

pub2privDepositBtn.addEventListener("click", async () => {
  const amount = parseFloat(pub2privAmountIn.value);
  if (!amount || amount <= 0) {
    pub2privError.textContent = "Enter a valid amount.";
    return;
  }
  try {
    pub2privDepositBtn.disabled = true;
    pub2privError.textContent = "";
    pub2privProgress.classList.add("visible");
    pub2privSteps.innerHTML = "";
    pub2privBar.style.width = "0%";

    await loadPubBalances();

    const depositAmountUnits = BigInt(Math.round(amount * 1_000_000));
    if (depositAmountUnits > pubUsdxBalanceRaw) {
      pub2privError.textContent =
        "Amount exceeds USDX balance of connected public account.";
      pub2privDepositBtn.disabled = false;
      return;
    }

    const step2 = pStep(
      pub2privSteps,
      "⏳ Constructing deposit note…",
      "active",
    );
    pub2privBar.style.width = "55%";
    const depositNote = DepositNote.create(
      AccountAddress.fromHex(privateAccAddressFull!),
      depositAmountUnits,
      AssetId.fromU64(ASSET_ID),
    );
    const commitmentHex = ("0x" +
      depositNote.commitment().toHex()) as `0x${string}`;
    step2.className = "p-step done";
    step2.textContent = "✓ Deposit note constructed";

    const step3 = pStep(pub2privSteps, "⏳ Signing deposit message…", "active");
    pub2privBar.style.width = "75%";
    const depositSig = await pubWalletClient!.signTypedData({
      domain: TESSERA_DEPOSIT_DOMAIN,
      types: TESSERA_DEPOSIT_TYPES,
      primaryType: "Deposit",
      message: {
        depositNoteCommitment: commitmentHex,
        amount: depositAmountUnits,
      },
    });
    const depositSigHex = depositSig.replace(/^0x/, "");
    step3.className = "p-step done";
    step3.textContent = "✓ Deposit message signed";

    const step4 = pStep(
      pub2privSteps,
      "⏳ Submitting deposit request…",
      "active",
    );
    pub2privBar.style.width = "88%";
    const { id: depositId } = await subpoolClient.submitDeposit({
      recipient_address: privateAccAddressFull!,
      eth_address: pubConnectedAddress!,
      deposit_note_identifier: depositNote.identifierHex(),
      deposit_amount: u256LeHex(depositAmountUnits),
      asset_id: ASSET_ID_HEX,
      deposit_type_signature: depositSigHex,
    });
    step4.className = "p-step done";
    step4.textContent = "✓ Deposit submitted";

    const step5 = pStep(pub2privSteps, "⏳ Waiting for approval…", "active");
    pub2privBar.style.width = "95%";

    await new Promise<void>((resolve, reject) => {
      const timer = setInterval(async () => {
        try {
          const status = await subpoolClient.getDepositStatus(depositId);
          if (!status || status.status === "Pending") return;
          if (status.status == "Approved") return;
          clearInterval(timer);
          if (status.status === "Rejected") {
            step5.className = "p-step done";
            step5.textContent =
              "✗ Deposit request rejected by the subpool owner";
            step5.style.color = "red";
            resolve();
            return;
          }
          // status == Settled
          step5.className = "p-step done";
          step5.textContent = "✓ Deposit approved & settled";
          if (status.deposit_tx_hash) {
            const a = document.createElement("a");
            a.href = `https://sepolia.etherscan.io/tx/${status.deposit_tx_hash}`;
            a.target = "_blank";
            a.rel = "noopener";
            a.textContent = "View deposit tx on Etherscan ↗";
            a.className = "tx-link";
            pub2privSteps.appendChild(a);
          }
          pub2privBar.style.width = "100%";
          await loadPubBalances();
          if (privateAccAddressFull) await loadPrivateBalance();
          resolve();
        } catch (e) {
          // clearInterval(timer);
          // reject(e);
        }
      }, 5_000);
    });

    pub2privDepositBtn.disabled = false;
    pub2privAmountIn.value = "";
    updatePub2PrivTransferBtn();
  } catch (err) {
    pub2privError.textContent = `${err}`;
    pub2privDepositBtn.disabled = false;
  }
});

// ── Private transfer section ──────────────────────────────────────────────────

const xferSection = document.getElementById("xfer-section") as HTMLElement;
const xferAddrIn = document.getElementById("xfer-addr") as HTMLInputElement;
const xferAddrSelect = document.getElementById(
  "xfer-addr-select",
) as HTMLSelectElement;
const xferAmtIn = document.getElementById("xfer-amount") as HTMLInputElement;
const xferBtn = document.getElementById("xfer-btn") as HTMLButtonElement;
const addrTick = document.getElementById("addr-tick")!;
const addrHint = document.getElementById("addr-hint")!;
const xferProgress = document.getElementById("xfer-progress")!;
const xferBar = document.getElementById("xfer-bar") as HTMLElement;
const xferSteps = document.getElementById("xfer-steps")!;
const xferError = document.getElementById("xfer-error")!;
const memoGroup = document.getElementById("memo-group") as HTMLElement;
const memoSenderName = document.getElementById("memo-sender-name")!;
const memoSenderAddr = document.getElementById("memo-sender-addr")!;
const memoRcptName = document.getElementById("memo-rcpt-name")!;
const memoRcptAddr = document.getElementById("memo-rcpt-addr")!;
const memoReferenceIn = document.getElementById(
  "memo-reference",
) as HTMLInputElement;
const memoPreview = document.getElementById("memo-preview")!;

function enableTransactSections() {
  xferSection.style.opacity = "";
  xferSection.style.pointerEvents = "";
  updatePub2PrivTransferBtn();
  loadAllUsers().then((users) => {
    // Clear existing options except the placeholder
    while (xferAddrSelect.options.length > 1) xferAddrSelect.remove(1);
    const seen = new Set<string>();
    for (const u of users) {
      if (u.private_acc_address === privateAccAddressFull) continue;
      if (seen.has(u.private_acc_address)) continue;
      seen.add(u.private_acc_address);
      const opt = document.createElement("option");
      opt.value = u.private_acc_address;
      const addr = u.private_acc_address;
      const addrShort = addr.slice(0, 4) + "…" + addr.slice(-6);
      opt.textContent = `${u.name} (0x${addrShort})`;
      opt.dataset.name = u.name;
      opt.dataset.physicalAddress = u.physical_address;
      xferAddrSelect.appendChild(opt);
    }
  });
}

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

function updateXferBtn() {
  const addrOk = !!xferAddrSelect.value;
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

function updateMemoPreview() {
  const recipientSubpool = xferAddrIn.value
    ? xferAddrIn.value.slice(0, 16)
    : "";
  const memoObj = {
    sender: {
      institution_name: getInstitutionName(SUBPOOL_ID_HEX),
      name: memoSenderName.textContent ?? "",
      physical_address: memoSenderAddr.textContent ?? "",
    },
    recipient: {
      institution_name: recipientSubpool
        ? getInstitutionName(recipientSubpool)
        : "",
      name: memoRcptName.textContent ?? "",
      physical_address: memoRcptAddr.textContent ?? "",
    },
    reference: memoReferenceIn.value.trim(),
  };
  memoPreview.textContent = JSON.stringify(memoObj, null, 2);
}

xferAddrSelect.addEventListener("change", () => {
  const opt = xferAddrSelect.selectedOptions[0];
  xferAddrIn.value = opt?.value ?? "";
  if (opt?.value) {
    memoRcptName.textContent = opt.dataset.name ?? "";
    memoRcptAddr.textContent = opt.dataset.physicalAddress ?? "";
    updateMemoPreview();
    memoGroup.style.display = "";
    addrTick.classList.remove("hidden");
    addrHint.textContent = "";
  } else {
    memoGroup.style.display = "none";
    addrTick.classList.add("hidden");
    addrHint.textContent = "";
  }
  updateXferBtn();
});

memoReferenceIn.addEventListener("input", updateMemoPreview);

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
    const memoObj = {
      sender: {
        institution_name: getInstitutionName(SUBPOOL_ID_HEX),
        name: kycInfo?.name ?? "",
        physical_address: kycInfo?.physical_address ?? "",
      },
      recipient: {
        institution_name: getInstitutionName(xferAddrIn.value.slice(0, 16)),
        name: memoRcptName.textContent ?? "",
        physical_address: memoRcptAddr.textContent ?? "",
      },
      reference: memoReferenceIn.value.trim(),
    };
    const memoBytes = new TextEncoder().encode(JSON.stringify(memoObj));
    builder.addOutputNote(
      AccountAddress.fromHex(xferAddrIn.value.trim()),
      transferAmount,
      memoBytes,
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
          if (status.status === "Approved") return;
          clearInterval(timer);
          if (status.status === "Rejected") {
            step5.className = "p-step done";
            step5.textContent = `✗ Transaction rejected`;
            step5.style.color = "#dc2626";
            resolve();
            return;
          }
          step5.className = "p-step done";
          step5.textContent = "✓ Transfer approved & settled";
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
    xferAddrSelect.value = "";
    xferAddrIn.value = "";
    addrTick.classList.add("hidden");
    memoGroup.style.display = "none";
    memoRcptName.textContent = "";
    memoRcptAddr.textContent = "";
    memoReferenceIn.value = "";
    memoPreview.textContent = "";
    updateXferBtn();
  } catch (err) {
    xferError.textContent = `${err}`;
    xferBtn.disabled = false;
    updateXferBtn();
  }
});
