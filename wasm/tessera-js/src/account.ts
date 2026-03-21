import {
  WasmAccount,
  WasmAccountAddress,
  WasmInputNote,
  WasmSpendTxBuilder,
  decodeHash,
} from "../wasm/tessera_client_wasm.js";

export type HashBytes = Uint8Array;

/** A Tessera account address (subpool_id + public_id). */
export class AccountAddress {
  readonly inner: WasmAccountAddress;

  private constructor(inner: WasmAccountAddress) {
    this.inner = inner;
  }

  /** Parse an 80-hex-char address (16 hex subpool_id + 64 hex public_id). */
  static fromHex(hex: string): AccountAddress {
    return new AccountAddress(WasmAccountAddress.fromHex(hex));
  }

  /** @internal Wrap a `WasmAccountAddress` returned by the WASM layer. */
  static fromWasm(inner: WasmAccountAddress): AccountAddress {
    return new AccountAddress(inner);
  }

  /** 80-hex-char string representation. */
  toHex(): string {
    return this.inner.toHex();
  }
}

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

  /** Returns the account address. */
  address(): AccountAddress {
    return AccountAddress.fromWasm(this.inner.address());
  }

  /** The raw WASM handle — needed to pass this account to `SpendTxBuilder`. */
  get wasmInner(): WasmAccount { return this.inner; }

  /** Decode a 32-byte hash into 4 × u64 limbs (little-endian). Useful for debugging. */
  static decodeHash(bytes: HashBytes): BigInt64Array {
    const h = decodeHash(bytes);
    return BigInt64Array.from(h.limbs().map(BigInt));
  }
}

/** A note positioned in the Note Commitment Tree — used as input to `SpendTxBuilder`. */
export class InputNote {
  readonly inner: WasmInputNote;

  constructor(
    identifier: Uint8Array,  // 16 bytes
    assetId: bigint,
    amount: bigint,
    recipient: Account,
    sender: Account,
    position: bigint,
  ) {
    this.inner = new WasmInputNote(
      identifier,
      assetId,
      amount,
      recipient.wasmInner,
      sender.wasmInner,
      position,
    );
  }
}

/** Builds a spend transaction by adding input/output notes, then calling `build()`. */
export class SpendTxBuilder {
  private builder: WasmSpendTxBuilder;

  constructor(accin: Account, assetId: bigint) {
    this.builder = new WasmSpendTxBuilder(accin.wasmInner, assetId);
  }

  /** Add an input note to consume (must share the same `assetId`). */
  addInputNote(note: InputNote): this {
    this.builder.addInputNote(note.inner);
    return this;
  }

  /** Add an output note to create, sending `amount` to `recipient`. */
  addOutputNote(recipient: AccountAddress, amount: bigint): this {
    this.builder.addOutputNote(recipient.inner, amount);
    return this;
  }

  /**
   * Compute the spend tx hash.
   *
   * - `actPosition`: position of the sender's account in the ACT.
   *   Pass `undefined` only for fresh accounts (nonce = 0).
   */
  build(actPosition?: bigint): HashBytes {
    return this.builder.build(actPosition).txHash();
  }
}
