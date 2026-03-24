import { describe, it, expect, vi, afterEach } from "vitest";
import { Account, SubpoolClient, SubpoolApiError } from "../src/index.js";

const SEED = new Uint8Array(32).fill(42);
const SUBPOOL_ID = 1n;

const ETH_ADDRESS = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const KYC = { name: "Alice", physicalAddress: "123 Main St", dob: "1990-01-15" };
const FAKE_ADDRESS = "a".repeat(80);

function mockFetch(status: number, body: unknown): void {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: status >= 200 && status < 300,
      status,
      json: () => Promise.resolve(body),
    }),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("SubpoolClient.register", () => {
  it("returns RegisterResponse on 201", async () => {
    mockFetch(201, { private_acc_address: FAKE_ADDRESS });
    const client = new SubpoolClient("http://localhost:8080");
    const res = await client.register({
      privateIdentifier: "a".repeat(32),
      spendAuthPk: "b".repeat(80),
      ethAddress: ETH_ADDRESS,
      ...KYC,
    });
    expect(res.privateAccAddress).toBe(FAKE_ADDRESS);
  });

  it("throws SubpoolApiError with status 409 on duplicate", async () => {
    mockFetch(409, { error: "account already registered" });
    const client = new SubpoolClient("http://localhost:8080");
    await expect(
      client.register({
        privateIdentifier: "a".repeat(32),
        spendAuthPk: "b".repeat(80),
        ethAddress: ETH_ADDRESS,
        ...KYC,
      }),
    ).rejects.toSatisfy(
      (e: unknown) => e instanceof SubpoolApiError && e.status === 409,
    );
  });

  it("throws SubpoolApiError with status 400 on bad input", async () => {
    mockFetch(400, { error: "invalid private_identifier length" });
    const client = new SubpoolClient("http://localhost:8080");
    await expect(
      client.register({
        privateIdentifier: "deadbeef",
        spendAuthPk: "b".repeat(80),
        ethAddress: ETH_ADDRESS,
        ...KYC,
      }),
    ).rejects.toSatisfy(
      (e: unknown) => e instanceof SubpoolApiError && e.status === 400,
    );
  });

  it("serialises fields as snake_case in the request body", async () => {
    mockFetch(201, { private_acc_address: FAKE_ADDRESS });
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: () => Promise.resolve({ private_acc_address: FAKE_ADDRESS }),
    });
    vi.stubGlobal("fetch", fetchSpy);

    const client = new SubpoolClient("http://localhost:8080");
    await client.register({
      privateIdentifier: "aa".repeat(16),
      spendAuthPk: "bb".repeat(40),
      ethAddress: ETH_ADDRESS,
      name: "Alice",
      physicalAddress: "123 Main St",
      dob: "1990-01-15",
    });

    const [, options] = fetchSpy.mock.calls[0] as [string, RequestInit];
    const sent = JSON.parse(options.body as string);
    expect(sent).toHaveProperty("private_identifier", "aa".repeat(16));
    expect(sent).toHaveProperty("spend_auth_pk", "bb".repeat(40));
    expect(sent).toHaveProperty("eth_address", ETH_ADDRESS);
    expect(sent).toHaveProperty("physical_address", "123 Main St");
    expect(sent).not.toHaveProperty("privateIdentifier");
    expect(sent).not.toHaveProperty("spendAuthPk");
  });
});

describe("SubpoolClient.registerAccount", () => {
  it("extracts hex fields from Account and calls register", async () => {
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: () => Promise.resolve({ private_acc_address: FAKE_ADDRESS }),
    });
    vi.stubGlobal("fetch", fetchSpy);

    const account = Account.createWithSeed(SEED, SUBPOOL_ID);
    const client = new SubpoolClient("http://localhost:8080");
    const res = await client.registerAccount(account, ETH_ADDRESS, KYC);

    expect(res.privateAccAddress).toBe(FAKE_ADDRESS);

    const [, options] = fetchSpy.mock.calls[0] as [string, RequestInit];
    const sent = JSON.parse(options.body as string);

    // private_identifier must be 32 hex chars (16 bytes)
    expect(sent.private_identifier).toMatch(/^[0-9a-f]{32}$/);
    // spend_auth_pk must be 80 hex chars (40 bytes)
    expect(sent.spend_auth_pk).toMatch(/^[0-9a-f]{80}$/);

    // Values must match what the Account methods return directly
    expect(sent.private_identifier).toBe(account.privateIdentifierHex());
    expect(sent.spend_auth_pk).toBe(account.spendAuthPkHex());
  });

  it("privateIdentifierHex is 32 hex chars", () => {
    const account = Account.createWithSeed(SEED, SUBPOOL_ID);
    expect(account.privateIdentifierHex()).toMatch(/^[0-9a-f]{32}$/);
  });

  it("spendAuthPkHex is 80 hex chars", () => {
    const account = Account.createWithSeed(SEED, SUBPOOL_ID);
    expect(account.spendAuthPkHex()).toMatch(/^[0-9a-f]{80}$/);
  });

  it("different seeds produce different identifiers", () => {
    const a = Account.createWithSeed(new Uint8Array(32).fill(1), SUBPOOL_ID);
    const b = Account.createWithSeed(new Uint8Array(32).fill(2), SUBPOOL_ID);
    expect(a.privateIdentifierHex()).not.toBe(b.privateIdentifierHex());
    expect(a.spendAuthPkHex()).not.toBe(b.spendAuthPkHex());
  });
});
