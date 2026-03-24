import type { PrivateIdentifier, SpendAuthPk } from "../account.js";
import type { ApiError, RegisterRequest, RegisterResponse } from "./types.js";

/** Thrown when the server returns a non-2xx response. */
export class SubpoolApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: ApiError,
  ) {
    super(`SubpoolAPI ${status}: ${body.error}`);
    this.name = "SubpoolApiError";
  }
}

/**
 * HTTP client for the tessera-subpool-database API.
 *
 * Construct with the base URL of a running server:
 * ```ts
 * const client = new SubpoolClient("http://localhost:8080");
 * ```
 */
export class SubpoolClient {
  constructor(private readonly baseUrl: string) {}

  /**
   * POST /register — typed low-level call.
   *
   * Sends camelCase fields serialised to the snake_case JSON the Rust server expects.
   * Throws `SubpoolApiError` on non-2xx responses.
   */
  async register(req: RegisterRequest): Promise<RegisterResponse> {
    const body = JSON.stringify({
      private_identifier: req.privateIdentifier,
      spend_auth_pk: req.spendAuthPk,
      eth_address: req.ethAddress,
      name: req.name,
      physical_address: req.physicalAddress,
      dob: req.dob,
    });

    const res = await fetch(`${this.baseUrl}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });

    const json = await res.json();

    if (!res.ok) {
      throw new SubpoolApiError(res.status, json as ApiError);
    }

    return {
      privateAccAddress: (json as { private_acc_address: string })
        .private_acc_address,
    };
  }

  /**
   * Convenience wrapper around `register`.
   *
   * ```ts
   * const response = await client.registerAccount(
   *   account.privateIdentifier(),
   *   account.spendAuthPkHex(),
   *   "0xAbc...",
   *   { name: "Alice", physicalAddress: "123 Main St", dob: "1990-01-15" },
   * );
   * console.log(response.privateAccAddress);
   * ```
   */
  async registerAccount(
    privateIdentifier: PrivateIdentifier,
    spendAuthPk: SpendAuthPk,
    ethAddress: string,
    kyc: { name: string; physicalAddress: string; dob: string },
  ): Promise<RegisterResponse> {
    return this.register({
      privateIdentifier: privateIdentifier.toHex(),
      spendAuthPk: spendAuthPk.toHex(),
      ethAddress,
      ...kyc,
    });
  }
}
