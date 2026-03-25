import init from "../wasm/tessera_client_wasm.js";
import { Account } from "../src/index";

// Load and compile the WASM binary before any WASM functions are called.
await init();

// PRF eval input must match the one used in passkey.ts so the output is stable.
const PRF_INPUT = new TextEncoder().encode("tessera::account::seed");

const btnRegister = document.getElementById(
  "btn-register",
) as HTMLButtonElement;
const btnDerive = document.getElementById("btn-derive") as HTMLButtonElement;
const status = document.getElementById("status") as HTMLPreElement;

let credentialId: Uint8Array | null = null;

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function log(msg: string) {
  status.textContent += "\n" + msg;
  console.log(msg);
}

btnRegister.addEventListener("click", async () => {
  status.textContent = "Registering passkey…";
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
    // btnDerive.disabled = false;
  } catch (err) {
    log(`✗ Registration failed: ${err}`);
  }
});

btnDerive.addEventListener("click", async () => {
  log("\nDeriving account from PRF output…");
  try {
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
    console.log(seed);
    if (seed.byteLength !== 32) {
      throw new Error(`PRF output must be 32 bytes, got ${seed.byteLength}`);
    }

    const account = Account.createWithSeed(seed, BigInt("1"));

    log("✓ Account derived:");
    log(`  commitment:   ${toHex(account.commitment())}`);
    log(`  publicId:     ${toHex(account.publicId())}`);
    log(`  nullifierKey: ${toHex(account.nullifierKey())}`);
    log(`  address:      ${account.address().toHex()}`);
    log(`  isFresh:      ${account.isFresh()}`);
    console.log("account object:", account);
  } catch (err) {
    log(`✗ Derive failed: ${err}`);
  }
});
