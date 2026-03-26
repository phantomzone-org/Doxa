import type { AccountResponse } from "./api/index.js";
import {
  WasmAccount,
  WasmAccountAddress,
  WasmAccountCommitment,
  WasmAccountNullifier,
  WasmAssetId,
  WasmDepositNote,
  WasmDepositNoteCommitment,
  WasmDummyNote,
  WasmInputNote,
  WasmOutputNote,
  WasmPrivateIdentifier,
  WasmPublicIdentifier,
  WasmSpendAuthPk,
  WasmSpendTx,
  WasmSpendTxBuilder,
  WasmSubpoolId,
  decodeHash,
  derivePrivateIdentifier as wasmDerivePrivateIdentifier,
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

// ── AccountCommitment ─────────────────────────────────────────────────────────

/** An account commitment (4 Goldilocks field elements, 32 bytes / 64 hex chars). */
export class AccountCommitment {
  readonly inner: WasmAccountCommitment;

  private constructor(inner: WasmAccountCommitment) {
    this.inner = inner;
  }

  static fromWasm(inner: WasmAccountCommitment): AccountCommitment {
    return new AccountCommitment(inner);
  }

  /** Parse from a 64-char hex string (4 × u64 LE). */
  static fromHex(hex: string): AccountCommitment {
    return new AccountCommitment(WasmAccountCommitment.fromHex(hex));
  }

  /** Parse from a 32-byte Uint8Array (4 × u64 LE). */
  static fromBytes(bytes: Uint8Array): AccountCommitment {
    return new AccountCommitment(WasmAccountCommitment.fromBytes(bytes));
  }

  /** 64 hex chars. */
  toHex(): string {
    return this.inner.toHex();
  }

  /** 32 bytes (4 × u64 little-endian). */
  toBytes(): Uint8Array {
    return this.inner.toBytes();
  }
}

// ── AccountNullifier ──────────────────────────────────────────────────────────

/** An account nullifier (4 Goldilocks field elements, 32 bytes / 64 hex chars). */
export class AccountNullifier {
  readonly inner: WasmAccountNullifier;

  private constructor(inner: WasmAccountNullifier) {
    this.inner = inner;
  }

  static fromWasm(inner: WasmAccountNullifier): AccountNullifier {
    return new AccountNullifier(inner);
  }

  /** Parse from a 64-char hex string (4 × u64 LE). */
  static fromHex(hex: string): AccountNullifier {
    return new AccountNullifier(WasmAccountNullifier.fromHex(hex));
  }

  /** Parse from a 32-byte Uint8Array (4 × u64 LE). */
  static fromBytes(bytes: Uint8Array): AccountNullifier {
    return new AccountNullifier(WasmAccountNullifier.fromBytes(bytes));
  }

  /** 64 hex chars. */
  toHex(): string {
    return this.inner.toHex();
  }

  /** 32 bytes (4 × u64 little-endian). */
  toBytes(): Uint8Array {
    return this.inner.toBytes();
  }
}

// ── SpendAuthPk ───────────────────────────────────────────────────────────────

/** A spend-auth compressed public key (5 × u64 LE, 40 bytes / 80 hex chars). */
export class SpendAuthPk {
  readonly inner: WasmSpendAuthPk;

  private constructor(inner: WasmSpendAuthPk) {
    this.inner = inner;
  }

  static fromWasm(inner: WasmSpendAuthPk): SpendAuthPk {
    return new SpendAuthPk(inner);
  }

  /** Parse from an 80-char hex string (5 × u64 LE). */
  static fromHex(hex: string): SpendAuthPk {
    return new SpendAuthPk(WasmSpendAuthPk.fromHex(hex));
  }

  /** Parse from a 40-byte Uint8Array (5 × u64 LE). */
  static fromBytes(bytes: Uint8Array): SpendAuthPk {
    return new SpendAuthPk(WasmSpendAuthPk.fromBytes(bytes));
  }

  /** 80 hex chars. */
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

  /** Reconstruct an Account from a server AccountResponse. No seed required. */
  static fromAccountData(accountData: AccountResponse): Account {
    return new Account(WasmAccount.fromAccountData(
      accountData.private_identifier,
      accountData.subpool_id,
      accountData.nonce,
      accountData.spend_auth,
      JSON.stringify(accountData.ast),
    ));
  }

  /**
   * The Poseidon commitment of the full account state.
   * This is what gets inserted into the Account Commitment Tree.
   */
  commitment(): AccountCommitment {
    return AccountCommitment.fromWasm(this.inner.commitment());
  }

  /**
   * The public identifier — safe to share. Derived from the private identifier
   * via a one-way Poseidon hash.
   */
  publicId(): PublicIdentifier {
    return PublicIdentifier.fromWasm(this.inner.publicId());
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
  nullifier(): AccountNullifier {
    return AccountNullifier.fromWasm(this.inner.nullifier());
  }

  /** Returns the account address. */
  address(): AccountAddress {
    return AccountAddress.fromWasm(this.inner.address());
  }

  /** Returns the private identifier as a typed `PrivateIdentifier`. */
  privateIdentifier(): PrivateIdentifier {
    return PrivateIdentifier.fromWasm(this.inner.privateIdentifier());
  }

  /** The spend-auth compressed public key. Used as `spend_auth_pk` in the backend register request. */
  spendAuthPk(): SpendAuthPk {
    return SpendAuthPk.fromWasm(this.inner.spendAuthPk());
  }

  /** The raw WASM handle — needed to pass this account to `SpendTxBuilder`. */
  get wasmInner(): WasmAccount {
    return this.inner;
  }

  /** Decode an account commitment into 4 × u64 limbs (little-endian). Useful for debugging. */
  static decodeHash(commitment: AccountCommitment): BigInt64Array {
    const h = decodeHash(commitment.toBytes());
    return BigInt64Array.from(h.limbs().map(BigInt));
  }
}

// ── AssetId ───────────────────────────────────────────────────────────────────

/** A Goldilocks field element identifying an asset type (u64 < `F::ORDER`). */
export class AssetId {
  readonly inner: WasmAssetId;

  private constructor(inner: WasmAssetId) {
    this.inner = inner;
  }

  static fromWasm(inner: WasmAssetId): AssetId {
    return new AssetId(inner);
  }

  /** Construct from a `bigint`, validating it is within the Goldilocks field range. */
  static fromU64(v: bigint): AssetId {
    return new AssetId(WasmAssetId.fromU64(v));
  }

  toU64(): bigint {
    return BigInt(this.inner.toU64());
  }
}

// ── DepositNoteCommitment ─────────────────────────────────────────────────────

/** A deposit-note commitment (4 Goldilocks field elements, 32 bytes / 64 hex chars). */
export class DepositNoteCommitment {
  readonly inner: WasmDepositNoteCommitment;

  private constructor(inner: WasmDepositNoteCommitment) {
    this.inner = inner;
  }

  static fromWasm(inner: WasmDepositNoteCommitment): DepositNoteCommitment {
    return new DepositNoteCommitment(inner);
  }

  /** Parse from a 64-char hex string (4 × u64 LE). */
  static fromHex(hex: string): DepositNoteCommitment {
    return new DepositNoteCommitment(WasmDepositNoteCommitment.fromHex(hex));
  }

  /** Parse from a 32-byte Uint8Array (4 × u64 LE). */
  static fromBytes(bytes: Uint8Array): DepositNoteCommitment {
    return new DepositNoteCommitment(WasmDepositNoteCommitment.fromBytes(bytes));
  }

  /** 64 hex chars. */
  toHex(): string {
    return this.inner.toHex();
  }

  /** 32 bytes (4 × u64 little-endian). */
  toBytes(): Uint8Array {
    return this.inner.toBytes();
  }
}

// ── DepositNote ───────────────────────────────────────────────────────────────

/**
 * A deposit note with a randomly-sampled identifier (sampled inside WASM as
 * two Goldilocks field elements in `[0, F::ORDER)`).
 */
export class DepositNote {
  private inner: WasmDepositNote;

  private constructor(inner: WasmDepositNote) {
    this.inner = inner;
  }

  /**
   * Create a deposit note. The identifier (`[F; 2]`) is sampled uniformly
   * inside WASM — no identifier parameter needed.
   *
   * @param recipient  The Tessera account address that will receive the deposit.
   * @param amount     Deposit amount as a `bigint` (U256).
   * @param assetId    Validated Goldilocks asset id.
   */
  static create(
    recipient: AccountAddress,
    amount: bigint,
    assetId: AssetId,
  ): DepositNote {
    return new DepositNote(
      WasmDepositNote.fromParts(recipient.inner, amount, assetId.inner),
    );
  }

  /** Poseidon commitment to this deposit note. */
  commitment(): DepositNoteCommitment {
    return DepositNoteCommitment.fromWasm(this.inner.commitment());
  }

  /** Hex-encoded identifier (`[F; 2]` = 16 bytes = 32 hex chars). */
  identifierHex(): string {
    return this.inner.identifierHex();
  }

  /** Identifier as raw bytes (16 bytes, 2 × u64 LE). */
  identifierBytes(): Uint8Array {
    return this.inner.identifierBytes();
  }

  /** Deposit amount as `bigint`. */
  amount(): bigint {
    return this.inner.amount();
  }

  /** Asset id. */
  assetId(): AssetId {
    return AssetId.fromWasm(this.inner.assetId());
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

// ── derivePrivateIdentifier ───────────────────────────────────────────────────

/**
 * Derive a `PrivateIdentifier` from a 32-byte seed using domain-separated SHA-256.
 *
 * Implements `sha256(seed || DS_WASM_SEEDED_PRIVATE_IDENTIFIER)` → `[F; 2]`.
 */
export function derivePrivateIdentifier(seed: Uint8Array): PrivateIdentifier {
  return PrivateIdentifier.fromWasm(wasmDerivePrivateIdentifier(seed));
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
    recipient: AccountAddress,
    sender: AccountAddress,
    position: bigint,
  ) {
    this.inner = new WasmInputNote(
      identifier,
      assetId,
      amount,
      recipient.inner,
      sender.inner,
      position,
    );
  }
}

// ── OutputNote ────────────────────────────────────────────────────────────────

/** An output note produced by a built spend transaction. */
export class OutputNote {
  constructor(private inner: WasmOutputNote) {}

  identifierHex(): string { return this.inner.identifierHex(); }
  assetId(): bigint       { return BigInt(this.inner.assetId()); }
  amountHex(): string     { return this.inner.amountHex(); }
  recipientHex(): string  { return this.inner.recipientHex(); }
  senderHex(): string     { return this.inner.senderHex(); }
}

// ── DummyNote ─────────────────────────────────────────────────────────────────

/** A dummy note seed — its raw 32-byte value is sent to the server. */
export class DummyNote {
  constructor(private inner: WasmDummyNote) {}
  toHex(): string { return this.inner.toHex(); }
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

  outputNotes(): OutputNote[] {
    return Array.from({ length: this.inner.outputNoteCount() }, (_, i) =>
      new OutputNote(this.inner.outputNoteAt(i)));
  }

  diNotes(): DummyNote[] {
    return Array.from({ length: this.inner.diNoteCount() }, (_, i) =>
      new DummyNote(this.inner.diNoteAt(i)));
  }

  doNotes(): DummyNote[] {
    return Array.from({ length: this.inner.doNoteCount() }, (_, i) =>
      new DummyNote(this.inner.doNoteAt(i)));
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
