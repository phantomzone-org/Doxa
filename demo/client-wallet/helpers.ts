import { PrivateKeyAccount, privateKeyToAccount } from "viem/accounts";

// ── Byte / hex utilities ──────────────────────────────────────────────────────

export function toHex(b: Uint8Array): string {
    return Array.from(b)
        .map((x) => x.toString(16).padStart(2, "0"))
        .join("");
}

export function hexToBytes(hex: string): Uint8Array {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

/** Parse a little-endian hex string (32 bytes) as a BigInt (U256). */
export function hexLeToU256(hex: string): bigint {
    const bytes = hexToBytes(hex);
    let result = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) {
        result = (result << 8n) | BigInt(bytes[i]);
    }
    return result;
}

/** Parse a little-endian hex string (8 bytes) as a BigInt (u64). */
export function hexLeToU64(hex: string): bigint {
    const bytes = hexToBytes(hex);
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
    return v;
}

/** Decode a LE-encoded hex string (8 bytes, from env) to a u64 bigint. */
export function leHexToU64(hex: string): bigint {
    const bytes = Uint8Array.from({ length: 8 }, (_, i) =>
        parseInt(hex.slice(i * 2, i * 2 + 2), 16),
    );
    bytes.reverse();
    return BigInt(
        "0x" +
            Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(""),
    );
}

/** Encode a BigInt as a 32-byte little-endian hex string (no 0x prefix). */
export function u256LeHex(v: bigint): string {
    const bytes = new Uint8Array(32);
    let tmp = v;
    for (let i = 0; i < 32; i++) {
        bytes[i] = Number(tmp & 0xffn);
        tmp >>= 8n;
    }
    return toHex(bytes);
}

// ── Crypto ────────────────────────────────────────────────────────────────────

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(
        await crypto.subtle.digest("SHA-256", data as BufferSource),
    );
}

/**
 * Deterministically derive an Ethereum private-key account from a seed.
 * Domain-separated so the key is distinct from the Tessera private identifier.
 */
export async function deriveWalletAccount(
    seed: Uint8Array,
): Promise<PrivateKeyAccount> {
    const domain = new TextEncoder().encode("tessera::eth::privkey");
    const input = new Uint8Array(seed.length + domain.length);
    input.set(seed);
    input.set(domain, seed.length);
    const privKey = ("0x" + toHex(await sha256(input))) as `0x${string}`;
    return privateKeyToAccount(privKey);
}

// ── DOM helpers ───────────────────────────────────────────────────────────────

export function delay(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
}

/** Append a styled progress-step div to a container and return it. */
export function pStep(
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
