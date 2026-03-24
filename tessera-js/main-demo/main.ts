import init from "../wasm/tessera_client_wasm.js";
import { Account } from "../src/index";
import { AccountAddress } from "../src/account.js";

await init();

const status = document.getElementById("status") as HTMLPreElement;
function log(msg: string) {
  status.textContent += "\n" + msg;
  console.log(msg);
}

// ── constants ─────────────────────────────────────────────────────────────────

const TESSERA_CONTRACT = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
const USDX_TOKEN = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const PRF_INPUT = new TextEncoder().encode("tessera::account::seed");

// ── shared state ──────────────────────────────────────────────────────────────

let credentialId: Uint8Array | null = null;
let ethAddressFull: string | null = null;
let privateBalance = 0;

// ── localStorage ─────────────────────────────────────────────────────────────

interface KycRecord {
  name: string;
  street: string;
  dob: string;
  tesseraAddress: string;
  registeredAt: string;
}
function loadKyc(): KycRecord | null {
  const raw = localStorage.getItem("tessera::kyc");
  return raw ? JSON.parse(raw) : null;
}
function saveKyc(r: KycRecord) {
  localStorage.setItem("tessera::kyc", JSON.stringify(r));
}

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

function fakeTxHash(): string {
  return "0x" + toHex(crypto.getRandomValues(new Uint8Array(32)));
}

function delay(ms: number) {
  return new Promise<void>((r) => setTimeout(r, ms));
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

async function deriveEthAddress(seed: Uint8Array): Promise<string> {
  const domain = new TextEncoder().encode("tessera::eth::address");
  const input = new Uint8Array(seed.length + domain.length);
  input.set(seed);
  input.set(domain, seed.length);
  const hash = await sha256(input);
  return "0x" + toHex(hash.slice(12));
}

// ── ABI encoding (hand-rolled, no library) ────────────────────────────────────

function padLeft32(hex: string): string {
  return hex.replace("0x", "").padStart(64, "0");
}

function encodeDeposit(recipientAddr: string, amount: number): string {
  // deposit(address recipient, uint256 amount) — fake selector 0x47e7ef24
  const selector = "47e7ef24";
  const addr = padLeft32(recipientAddr);
  const amt = padLeft32(BigInt(amount * 1e6).toString(16)); // USDX uses 6 decimals
  return "0x" + selector + addr + amt;
}

function craftTx(from: string, amount: number): object {
  return {
    type: "0x2",
    chainId: "0x1",
    from,
    to: TESSERA_CONTRACT,
    data: encodeDeposit(from, amount),
    value: "0x0",
    nonce: "0x" + Math.floor(Math.random() * 256).toString(16),
    gas: "0x186a0",
    maxFeePerGas: "0x77359400",
    maxPriorityFeePerGas: "0x3b9aca00",
    _usdxToken: USDX_TOKEN,
    _depositAmount: amount + " USDX",
  };
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

let publicBalance = 0;

function renderPublicBalance() {
  usdcBalanceEl.textContent =
    publicBalance.toLocaleString("en-US", { minimumFractionDigits: 2 }) +
    " USDX";
}

async function showWallet(seed: Uint8Array) {
  ethAddressFull = await deriveEthAddress(seed);
  ethAddressEl.textContent =
    ethAddressFull.slice(0, 10) + "…" + ethAddressFull.slice(-8);
  ethAddressEl.title = ethAddressFull;
  publicBalance = 0;
  renderPublicBalance();
  walletInfo.classList.add("visible");
  depositSection.classList.add("visible");
  enableP2pBtn();
  onSignedIn();
}

createWalletBtn.addEventListener("click", async () => {
  createWalletBtn.disabled = true;
  signInBtn.disabled = true;
  walletError.textContent = "";
  createWalletBtn.textContent = "⏳ Creating…";
  try {
    await showWallet(await registerAndGetSeed());
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
    await showWallet(await evalPrf());
    signInBtn.textContent = "✓ Signed in";
  } catch (err) {
    walletError.textContent = `Error: ${err}`;
    signInBtn.disabled = false;
    createWalletBtn.disabled = false;
    signInBtn.textContent = "Sign in with existing passkey";
  }
});

// existing 1000 USDX deposit on public card
depositBtn.addEventListener("click", async () => {
  depositBtn.disabled = true;
  depositProgress.classList.add("visible");
  depositSteps.innerHTML = "";
  etherscanLink.classList.remove("visible");

  const steps = [
    { label: "Approving USDX transfer…", pct: 25, ms: 1200 },
    { label: "Submitting deposit transaction…", pct: 60, ms: 1800 },
    { label: "Waiting for block confirmation…", pct: 85, ms: 1500 },
    { label: "✓ Deposit confirmed", pct: 100, ms: 0 },
  ];

  let prev: HTMLElement | null = null;
  for (const step of steps) {
    if (prev) {
      prev.className = "p-step done";
      prev.textContent = "✓ " + prev.textContent!.replace(/^⏳ /, "");
    }
    const el = pStep(
      depositSteps,
      (step.pct < 100 ? "⏳ " : "") + step.label,
      step.pct < 100 ? "active" : "done",
    );
    depositBar.style.width = step.pct + "%";
    if (step.ms > 0) await delay(step.ms);
    prev = step.pct < 100 ? el : null;
  }

  publicBalance += 1000;
  renderPublicBalance();

  const txHash = fakeTxHash();
  etherscanAnchor.href = `https://etherscan.io/tx/${txHash}`;
  etherscanAnchor.textContent = txHash.slice(0, 10) + "…" + txHash.slice(-8);
  etherscanLink.classList.add("visible");
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

function onSignedIn() {
  const kyc = loadKyc();
  if (kyc) {
    kycForm.style.display = "none";
    dispName.textContent = kyc.name;
    dispStreet.textContent = kyc.street;
    dispDob.textContent = kyc.dob;
    kycDisplay.style.display = "block";
    tesseraAddrVal.textContent = kyc.tesseraAddress;
    tesseraAddrBox.classList.add("visible");
    renderPrivateBalance();
    registerError.style.color = "#5af0a0";
    registerError.textContent = `Registered on ${new Date(kyc.registeredAt).toLocaleDateString()}`;
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
    const seed = credentialId ? await evalPrf() : await registerAndGetSeed();
    const account = Account.createWithSeed(seed, 1n);

    const s1 = appendProgressLine(
      "⏳ Waiting for approval from subpool owner…",
      "active",
    );
    await delay(1800);
    s1.className = "progress-line done";
    s1.textContent = "✓ Approval received";

    const s2 = appendProgressLine("⚙️ Generating proof…", "active");
    await delay(2200);
    s2.className = "progress-line done";
    s2.textContent = "✓ Proof generated";

    appendProgressLine("✓ Account registered", "done");

    const tesseraAddress = account.address().toHex();
    tesseraAddrVal.textContent = tesseraAddress;
    tesseraAddrBox.classList.add("visible");
    saveKyc({
      name: nameInput.value.trim(),
      street: streetInput.value.trim(),
      dob: dobInput.value,
      tesseraAddress,
      registeredAt: new Date().toISOString(),
    });
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

  p2pBtn.disabled = true;
  p2pError.textContent = "";
  p2pTxWrap.style.display = "none";
  p2pProgress.classList.remove("visible");
  p2pSteps.innerHTML = "";
  p2pBar.style.width = "0%";

  try {
    // 1. Craft transaction
    const tx = craftTx(ethAddressFull, amount);
    p2pTxDisplay.textContent = JSON.stringify(tx, null, 2);

    // 2. Prompt passkey → sign
    p2pTxDisplay.textContent = JSON.stringify(tx, null, 2);
    p2pTxWrap.style.display = "block";

    const seed = await evalPrf();

    const txBytes = new TextEncoder().encode(JSON.stringify(tx));
    const txHash = await sha256(txBytes);
    const combined = new Uint8Array(seed.length + txHash.length);
    combined.set(seed);
    combined.set(txHash, seed.length);
    const sig = await sha256(combined); // demo signature: sha256(seed || sha256(tx))

    p2pSigDisplay.textContent = "0x" + toHex(sig);

    // 3. Progress bar
    p2pProgress.classList.add("visible");

    const relayTxHash = fakeTxHash();
    const shortHash = relayTxHash.slice(0, 10) + "…" + relayTxHash.slice(-8);

    const steps: Array<{
      label: string | (() => string | HTMLElement);
      pct: number;
      ms: number;
    }> = [
      { label: "⏳ Waiting for approval…", pct: 20, ms: 1600 },
      { label: "✓ Deposit approved", pct: 40, ms: 1200 },
      {
        label: () => {
          const span = document.createDocumentFragment();
          const txt = document.createTextNode("✓ Transaction relayed — ");
          const a = document.createElement("a");
          a.href = `https://etherscan.io/tx/${relayTxHash}`;
          a.target = "_blank";
          a.rel = "noopener";
          a.textContent = shortHash;
          span.append(txt, a);
          return span as any;
        },
        pct: 65,
        ms: 1800,
      },
      { label: "⚙️ Generating deposit proof…", pct: 85, ms: 2000 },
      { label: "✓ Deposit settled", pct: 100, ms: 0 },
    ];

    for (const step of steps) {
      const el = document.createElement("div");
      el.className = `p-step ${step.pct < 100 ? "active" : "done"}`;
      if (typeof step.label === "function") {
        el.appendChild(step.label() as any);
      } else {
        el.textContent = step.label;
      }
      p2pSteps.appendChild(el);
      p2pBar.style.width = step.pct + "%";
      if (step.ms > 0) {
        await delay(step.ms);
        if (
          step.pct < 100 &&
          typeof step.label === "string" &&
          step.label.startsWith("⏳")
        ) {
          el.className = "p-step done";
          el.textContent = step.label.replace("⏳ ", "✓ ").replace("…", "");
        } else if (
          step.pct < 100 &&
          typeof step.label === "string" &&
          step.label.startsWith("⚙️")
        ) {
          el.className = "p-step done";
          el.textContent = "✓ Deposit proof generated";
        }
      }
    }

    // 4. Update private balance
    privateBalance += amount;
    renderPrivateBalance();
    kycDisplay.style.display = "block";

    p2pBtn.disabled = false;
    p2pAmountInput.value = "";
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
    await evalPrf(); // prompt passkey — seed not needed for simulation

    xferProgress.classList.add("visible");

    const steps = [
      {
        label: "⏳ Waiting for approval from subpool owner…",
        pct: 33,
        ms: 1800,
      },
      { label: "⚙️ Generating proof…", pct: 66, ms: 2200 },
      { label: "✓ Send settled", pct: 100, ms: 0 },
    ];

    for (const step of steps) {
      const el = pStep(
        xferSteps,
        step.label,
        step.pct < 100 ? "active" : "done",
      );
      xferBar.style.width = step.pct + "%";
      if (step.ms > 0) {
        await delay(step.ms);
        el.className = "p-step done";
        el.textContent = step.label
          .replace("⏳ ", "✓ ")
          .replace("⚙️ ", "✓ ")
          .replace("…", "");
      }
    }

    privateBalance -= amount;
    renderPrivateBalance();

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
