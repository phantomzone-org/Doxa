import {
  WasmAccount,
  WasmAccountAddress,
  WasmInputNote,
  WasmPrivateIdentifier,
  WasmPublicIdentifier,
  WasmSpendTx,
  WasmSpendTxBuilder,
  WasmSubpoolId,
  decodeHash,
  derivePublicIdentifier as wasmDerivePublicIdentifier,
} from "../wasm/tessera_client_wasm.js";

export type HashBytes = Uint8Array;

// ── SubpoolId ─────────────────────────────────────────────────────────────────

/** A subpool identifier (1 Goldilocks field element, 8 bytes / 16 hex chars). */
export class SubpoolId {
  readonly inner: WasmSubpoolId;

  private constructor(inner: WasmSubpoolId) {
    this.inner = inner;
  }

  static fromWasm(inner: WasmSubpoolId): SubpoolId {
    return new SubpoolId(inner);
  }

  /** Parse from a 16-char hex string (u64 LE). */
  static fromHex(hex: string): SubpoolId {
    return new SubpoolId(WasmSubpoolId.fromHex(hex));
  }

  /** Parse from an 8-byte Uint8Array (u64 LE). */
  static fromBytes(bytes: Uint8Array): SubpoolId {
    return new SubpoolId(WasmSubpoolId.fromBytes(bytes));
  }

  /** 16 hex chars. */
  toHex(): string {
    return this.inner.toHex();
  }
}

// ── PrivateIdentifier ─────────────────────────────────────────────────────────

/** A private account identifier (2 Goldilocks field elements, 16 bytes / 32 hex chars). */
export class PrivateIdentifier {
  readonly inner: WasmPrivateIdentifier;

  private constructor(inner: WasmPrivateIdentifier) {
    this.inner = inner;
  }

  static fromWasm(inner: WasmPrivateIdentifier): PrivateIdentifier {
    return new PrivateIdentifier(inner);
  }

  /** Parse from a 32-char hex string (2 × u64 LE). */
  static fromHex(hex: string): PrivateIdentifier {
    return new PrivateIdentifier(WasmPrivateIdentifier.fromHex(hex));
  }

  /** Parse from a 16-byte Uint8Array (2 × u64 LE). */
  static fromBytes(bytes: Uint8Array): PrivateIdentifier {
    return new PrivateIdentifier(WasmPrivateIdentifier.fromBytes(bytes));
  }

  /** 32 hex chars. */
  toHex(): string {
    return this.inner.toHex();
  }
}

// ── PublicIdentifier ──────────────────────────────────────────────────────────

/** A public account identifier (4 Goldilocks field elements, 32 bytes / 64 hex chars). */
export class PublicIdentifier {
  readonly inner: WasmPublicIdentifier;

  private constructor(inner: WasmPublicIdentifier) {
    this.inner = inner;
  }

  static fromWasm(inner: WasmPublicIdentifier): PublicIdentifier {
    return new PublicIdentifier(inner);
  }

  /** Parse from a 64-char hex string (4 × u64 LE). */
  static fromHex(hex: string): PublicIdentifier {
    return new PublicIdentifier(WasmPublicIdentifier.fromHex(hex));
  }

  /** Parse from a 32-byte Uint8Array (4 × u64 LE). */
  static fromBytes(bytes: Uint8Array): PublicIdentifier {
    return new PublicIdentifier(WasmPublicIdentifier.fromBytes(bytes));
  }

  /** 64 hex chars. */
  toHex(): string {
    return this.inner.toHex();
  }
}

// ── AccountAddress ────────────────────────────────────────────────────────────

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

  /** Construct an address from a `SubpoolId` and a `PublicIdentifier`. */
  static fromParts(
    subpoolId: SubpoolId,
    publicId: PublicIdentifier,
  ): AccountAddress {
    return new AccountAddress(
      WasmAccountAddress.fromParts(subpoolId.inner, publicId.inner),
    );
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

// ── Account ───────────────────────────────────────────────────────────────────

/**
 * A Tessera account. Wraps the WASM `WasmAccount` with a more ergonomic API.
 *
 * All hash outputs (commitment, nullifier) are 32-byte Uint8Arrays
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

  /** The account nullifier. */
  nullifier(): HashBytes {
    return this.inner.nullifier();
  }

  /** Returns the account address. */
  address(): AccountAddress {
    return AccountAddress.fromWasm(this.inner.address());
  }

  /** Returns the private identifier as a typed `PrivateIdentifier`. */
  privateIdentifier(): PrivateIdentifier {
    return PrivateIdentifier.fromWasm(this.inner.privateIdentifier());
  }

  /**
   * The spend-auth public key as an 80-hex-char string (40 bytes, 5 × u64 LE).
   * Used as `spend_auth_pk` in the backend register request.
   */
  spendAuthPkHex(): string {
    const bytes = this.inner.spendAuthPkBytes();
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  /** The raw WASM handle — needed to pass this account to `SpendTxBuilder`. */
  get wasmInner(): WasmAccount {
    return this.inner;
  }

  /** Decode a 32-byte hash into 4 × u64 limbs (little-endian). Useful for debugging. */
  static decodeHash(bytes: HashBytes): BigInt64Array {
    const h = decodeHash(bytes);
    return BigInt64Array.from(h.limbs().map(BigInt));
  }
}

// ── deriveAccountFromPasskey ──────────────────────────────────────────────────

/**
 * Derive an `Account` from a WebAuthn passkey PRF output.
 *
 * Requests a WebAuthn assertion with the PRF extension, using the 32-byte PRF
 * result as the seed for `Account.createWithSeed`.
 *
 * Throws `"PRF extension unavailable"` if the authenticator does not return a
 * PRF result.
 *
 * TODO: why is this needed?
 */
export async function deriveAccountFromPasskey(
  credentialId: Uint8Array,
  challenge: Uint8Array,
  subpoolId: bigint,
): Promise<Account> {
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [{ id: credentialId, type: "public-key" }],
      extensions: {
        prf: { eval: { first: challenge } },
      } as AuthenticationExtensionsClientInputs,
    },
  } as CredentialRequestOptions)) as PublicKeyCredential;

  const ext = credential.getClientExtensionResults() as {
    prf?: { results?: { first?: ArrayBuffer } };
  };
  const prfFirst = ext?.prf?.results?.first;

  if (!prfFirst) {
    throw new Error("PRF extension unavailable");
  }

  const seed = new Uint8Array(prfFirst).slice(0, 32);
  return Account.createWithSeed(seed, subpoolId);
}

// ── derivePublicIdentifier ────────────────────────────────────────────────────

/**
 * Derive the `PublicIdentifier` from a `PrivateIdentifier`.
 *
 * Implements `Poseidon(DS_PUBLIC_IDENTIFIER || private_identifier)`,
 * matching `StandardAccount::public_id()` in tessera-client.
 */
export function derivePublicIdentifier(
  privateId: PrivateIdentifier,
): PublicIdentifier {
  return PublicIdentifier.fromWasm(wasmDerivePublicIdentifier(privateId.inner));
}

// ── InputNote ─────────────────────────────────────────────────────────────────

/** A note positioned in the Note Commitment Tree — used as input to `SpendTxBuilder`. */
export class InputNote {
  readonly inner: WasmInputNote;

  constructor(
    identifier: Uint8Array, // 16 bytes
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

// ── SpendTx ───────────────────────────────────────────────────────────────────

/** A built spend transaction. Call `txHash()` to get the hash to sign. */
export class SpendTx {
  private inner: WasmSpendTx;

  /** @internal */
  constructor(inner: WasmSpendTx) {
    this.inner = inner;
  }

  /** 32-byte transaction hash (4 × u64 little-endian). Sign this with the spend-auth key. */
  txHash(): HashBytes {
    return this.inner.txHash();
  }

  /** Sign the tx hash with the spend-auth key derived from `seed`. Returns 80 bytes (r || s). */
  sign(seed: Uint8Array): Uint8Array {
    return this.inner.sign(seed);
  }
}

// ── SpendTxBuilder ────────────────────────────────────────────────────────────

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

  /** Build the spend transaction. */
  build(): SpendTx {
    return new SpendTx(this.builder.build());
  }
}
