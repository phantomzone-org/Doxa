import { describe, it, expect, vi, afterEach } from "vitest";
import { Account, deriveAccountFromPasskey } from "../src/index.js";

const CREDENTIAL_ID = new Uint8Array(16).fill(0xab);
const CHALLENGE = new Uint8Array(32).fill(0xcd);

/** Build a mock `navigator.credentials` that returns the given PRF output. */
function mockCredentials(prfFirst: ArrayBuffer | undefined) {
  vi.stubGlobal("navigator", {
    credentials: {
      get: vi.fn().mockResolvedValue({
        getClientExtensionResults: () => ({
          prf: prfFirst !== undefined ? { results: { first: prfFirst } } : {},
        }),
      }),
    },
  });
}

afterEach(() => vi.unstubAllGlobals());

describe("deriveAccountFromPasskey", () => {
  it("derives a valid account from a PRF output", async () => {
    const seed = new Uint8Array(32).fill(0x01);
    mockCredentials(seed.buffer);

    const account = await deriveAccountFromPasskey(CREDENTIAL_ID, CHALLENGE, 1n);
    expect(account.commitment()).toBeInstanceOf(Uint8Array);
    expect(account.commitment().byteLength).toBe(32);
  });

  it("is deterministic: same PRF output → same commitment", async () => {
    const seed = new Uint8Array(32).fill(0x42);
    mockCredentials(seed.buffer);
    const a = await deriveAccountFromPasskey(CREDENTIAL_ID, CHALLENGE, 1n);

    mockCredentials(seed.buffer);
    const b = await deriveAccountFromPasskey(CREDENTIAL_ID, CHALLENGE, 1n);

    expect(a.commitment()).toEqual(b.commitment());
  });

  it("different PRF outputs → different accounts", async () => {
    const seedA = new Uint8Array(32).fill(0x11);
    mockCredentials(seedA.buffer);
    const a = await deriveAccountFromPasskey(CREDENTIAL_ID, CHALLENGE, 1n);

    const seedB = new Uint8Array(32).fill(0x22);
    mockCredentials(seedB.buffer);
    const b = await deriveAccountFromPasskey(CREDENTIAL_ID, CHALLENGE, 1n);

    expect(
      Buffer.from(a.commitment()).toString("hex")
    ).not.toBe(
      Buffer.from(b.commitment()).toString("hex")
    );
  });

  it("throws when PRF result is missing", async () => {
    mockCredentials(undefined);
    await expect(
      deriveAccountFromPasskey(CREDENTIAL_ID, CHALLENGE, 1n)
    ).rejects.toThrow("PRF extension unavailable");
  });
});
