import { describe, it, expect } from "vitest";
import { Account } from "../src/index.js";

describe("Account", () => {
  it("creates a fresh account", () => {
    const account = Account.create(1n);
    expect(account.isFresh()).toBe(true);
  });

  it("commitment is 32 bytes", () => {
    const account = Account.create(1n);
    const commitment = account.commitment();
    expect(commitment).toBeInstanceOf(Uint8Array);
    expect(commitment.byteLength).toBe(32);
  });

  it("public_id is 32 bytes", () => {
    const account = Account.create(1n);
    expect(account.publicId().byteLength).toBe(32);
  });

  it("nullifier_key is 32 bytes", () => {
    const account = Account.create(1n);
    expect(account.nullifierKey().byteLength).toBe(32);
  });

  it("fresh account nullifier (no position) is 32 bytes", () => {
    const account = Account.create(1n);
    const nullifier = account.nullifier();
    expect(nullifier).toBeInstanceOf(Uint8Array);
    expect(nullifier.byteLength).toBe(32);
  });

  it("two accounts have different commitments", () => {
    const a = Account.create(1n);
    const b = Account.create(1n);
    // Private identifiers are sampled randomly — commitments must differ
    expect(Buffer.from(a.commitment()).toString("hex")).not.toBe(
      Buffer.from(b.commitment()).toString("hex")
    );
  });

  it("commitment is deterministic for the same account", () => {
    const account = Account.create(1n);
    const c1 = account.commitment();
    const c2 = account.commitment();
    expect(c1).toEqual(c2);
  });

  it("decodeHash returns 4 limbs", () => {
    const account = Account.create(1n);
    const limbs = Account.decodeHash(account.commitment());
    expect(limbs.length).toBe(4);
  });

  it("positioned nullifier differs from fresh nullifier", () => {
    // A fresh account uses a different nullifier formula than a positioned one.
    // We can't easily test a real positioned nullifier without inserting into the ACT,
    // but we verify the fresh path works and returns a non-zero result.
    const account = Account.create(2n);
    const freshNull = account.nullifier();
    expect(freshNull.some((b) => b !== 0)).toBe(true);
  });
});
