import { describe, it, expect } from "vitest";
import {
  Account,
  AccountAddress,
  PrivateIdentifier,
  PublicIdentifier,
  SubpoolId,
  derivePublicIdentifier,
} from "../src/index.js";

const SEED_A = new Uint8Array(32).fill(1);
const SEED_B = new Uint8Array(32).fill(2);

describe("Account", () => {
  it("account has spend_auth set (not fresh)", () => {
    const account = Account.createWithSeed(SEED_A, 1n);
    expect(account.isFresh()).toBe(false);
  });

  it("commitment is 32 bytes", () => {
    const account = Account.createWithSeed(SEED_A, 1n);
    const commitment = account.commitment();
    expect(commitment.toHex()).toMatch(/^[0-9a-f]{64}$/);
    expect(commitment.toBytes().byteLength).toBe(32);
  });

  it("publicId is 32 bytes", () => {
    const account = Account.createWithSeed(SEED_A, 1n);
    expect(account.publicId().toHex()).toMatch(/^[0-9a-f]{64}$/);
  });

  it("nullifierKey is 32 bytes", () => {
    const account = Account.createWithSeed(SEED_A, 1n);
    expect(account.nullifierKey().byteLength).toBe(32);
  });

  it("nullifier is 32 bytes", () => {
    const account = Account.createWithSeed(SEED_A, 1n);
    const nullifier = account.nullifier();
    expect(nullifier.toHex()).toMatch(/^[0-9a-f]{64}$/);
    expect(nullifier.toBytes().byteLength).toBe(32);
  });

  it("two accounts with different seeds have different commitments", () => {
    const a = Account.createWithSeed(SEED_A, 1n);
    const b = Account.createWithSeed(SEED_B, 1n);
    expect(a.commitment().toHex()).not.toBe(b.commitment().toHex());
  });

  it("commitment is deterministic for the same seed", () => {
    const c1 = Account.createWithSeed(SEED_A, 1n).commitment();
    const c2 = Account.createWithSeed(SEED_A, 1n).commitment();
    expect(c1.toHex()).toBe(c2.toHex());
  });

  it("decodeHash returns 4 limbs", () => {
    const account = Account.createWithSeed(SEED_A, 1n);
    const limbs = Account.decodeHash(account.commitment());
    expect(limbs.length).toBe(4);
  });

  it("nullifier is non-zero", () => {
    const account = Account.createWithSeed(SEED_B, 2n);
    const nullifier = account.nullifier();
    expect(nullifier.toBytes().some((b) => b !== 0)).toBe(true);
  });
});

describe("SubpoolId", () => {
  it("fromHex / toHex round-trip", () => {
    const hex = SubpoolId.fromBytes(new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0])).toHex();
    expect(SubpoolId.fromHex(hex).toHex()).toBe(hex);
  });

  it("toHex is 16 hex chars", () => {
    expect(SubpoolId.fromHex("0100000000000000").toHex()).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe("PrivateIdentifier", () => {
  it("fromHex / toHex round-trip", () => {
    const account = Account.createWithSeed(SEED_A, 1n);
    const hex = account.privateIdentifier().toHex();
    expect(PrivateIdentifier.fromHex(hex).toHex()).toBe(hex);
  });

  it("toHex is 32 hex chars", () => {
    const account = Account.createWithSeed(SEED_A, 1n);
    expect(account.privateIdentifier().toHex()).toMatch(/^[0-9a-f]{32}$/);
  });

  it("different seeds → different private identifiers", () => {
    const a = Account.createWithSeed(SEED_A, 1n).privateIdentifier().toHex();
    const b = Account.createWithSeed(SEED_B, 1n).privateIdentifier().toHex();
    expect(a).not.toBe(b);
  });
});

describe("PublicIdentifier", () => {
  it("fromHex / toHex round-trip", () => {
    const account = Account.createWithSeed(SEED_A, 1n);
    const hex = derivePublicIdentifier(account.privateIdentifier()).toHex();
    expect(PublicIdentifier.fromHex(hex).toHex()).toBe(hex);
  });

  it("toHex is 64 hex chars", () => {
    const account = Account.createWithSeed(SEED_A, 1n);
    expect(derivePublicIdentifier(account.privateIdentifier()).toHex()).toMatch(
      /^[0-9a-f]{64}$/,
    );
  });

  it("derivePublicIdentifier is deterministic", () => {
    const pi = Account.createWithSeed(SEED_A, 1n).privateIdentifier();
    expect(derivePublicIdentifier(pi).toHex()).toBe(derivePublicIdentifier(pi).toHex());
  });
});

describe("AccountAddress.fromParts", () => {
  it("fromParts matches account.address().toHex()", () => {
    const account = Account.createWithSeed(SEED_A, 1n);
    const pubId = derivePublicIdentifier(account.privateIdentifier());
    const subpoolId = SubpoolId.fromHex("0100000000000000"); // subpool_id = 1
    const addr = AccountAddress.fromParts(subpoolId, pubId);
    expect(addr.toHex()).toBe(account.address().toHex());
  });
});
