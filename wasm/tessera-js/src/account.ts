import {
  WasmAccount,
  decodeHash,
} from "../wasm/tessera_client_wasm.js";

export type HashBytes = Uint8Array;

/**
 * A Tessera account. Wraps the WASM `WasmAccount` with a more ergonomic API.
 *
 * All hash outputs (commitment, public_id, nullifier) are 32-byte Uint8Arrays
 * representing 4 × u64 Goldilocks field elements in little-endian byte order.
 */
export class Account {
  private inner: WasmAccount;

  private constructor(inner: WasmAccount) {
    this.inner = inner;
  }

  /** Create a deterministic account from a 32-byte seed and subpool id. */
  static createWithSeed(seed: Uint8Array, subpoolId: bigint): Account {
    return new Account(WasmAccount.newWithSeed(seed, subpoolId));
  }

  /**
   * The Poseidon commitment of the full account state.
   * This is what gets inserted into the Account Commitment Tree.
   */
  commitment(): HashBytes {
    return this.inner.commitment();
  }

  /**
   * The public identifier — safe to share. Derived from the private identifier
   * via a one-way Poseidon hash.
   */
  publicId(): HashBytes {
    return this.inner.publicId();
  }

  /** The nullifier key used to derive note and account nullifiers. */
  nullifierKey(): HashBytes {
    return this.inner.nullifierKey();
  }

  /**
   * Returns `true` if the account has never been used:
   * nonce = 0, no spend/consume auth keys, no assets.
   */
  isFresh(): boolean {
    return this.inner.isFresh();
  }

  /**
   * The account nullifier.
   *
   * - Fresh accounts: call with no argument (or `undefined`).
   * - Existing accounts: pass the account's position in the ACT.
   */
  nullifier(position?: bigint): HashBytes {
    return this.inner.nullifier(position);
  }

  /** Returns the account address as a hex string (`hex(subpool_id) | hex(public_id)`). */
  address(): string {
    return this.inner.address().toHex();
  }

  /** Decode a 32-byte hash into 4 × u64 limbs (little-endian). Useful for debugging. */
  static decodeHash(bytes: HashBytes): BigInt64Array {
    const limbs = decodeHash(bytes);
    return BigInt64Array.from(limbs.map(BigInt));
  }
}
