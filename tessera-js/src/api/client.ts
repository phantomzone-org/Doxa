import type { PrivateIdentifier, SpendAuthPk } from "../account.js";
import type { AccountResponse, ApiError, DepositRequest, DepositResponse, FaucetResponse, FreshAccStatusResponse, InputNote, RegisterRequest, RegisterResponse, SpendTxRequest, SpendTxResponse } from "./types.js";

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
  /**
   * GET /account/:privateAccAddress
   *
   * Returns `null` when the account does not exist (HTTP 404).
   * Throws `SubpoolApiError` on any other non-2xx response.
   */
  async getAccount(privateAccAddress: string): Promise<AccountResponse | null> {
    const res = await fetch(`${this.baseUrl}/account/${privateAccAddress}`);
    if (res.status === 404) return null;
    const json = await res.json();
    if (!res.ok) throw new SubpoolApiError(res.status, json as ApiError);
    return json as AccountResponse;
  }

  /**
   * GET /freshacc/:privateAccAddress/status
   * Returns null on 404. Throws SubpoolApiError on other non-2xx responses.
   */
  async getFreshAccStatus(
    privateAccAddress: string,
  ): Promise<FreshAccStatusResponse | null> {
    const res = await fetch(
      `${this.baseUrl}/freshacc/${privateAccAddress}/status`,
    );
    if (res.status === 404) return null;
    const json = await res.json();
    if (!res.ok) throw new SubpoolApiError(res.status, json as ApiError);
    return json as FreshAccStatusResponse;
  }

  /**
   * POST /faucet — request a small ETH transfer on Sepolia.
   * Throws `SubpoolApiError` on non-2xx (e.g. 409 if address already funded).
   */
  async requestFaucet(ethAddress: string): Promise<FaucetResponse> {
    const res = await fetch(`${this.baseUrl}/faucet`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ eth_address: ethAddress }),
    });
    const json = await res.json();
    if (!res.ok) throw new SubpoolApiError(res.status, json as ApiError);
    return json as FaucetResponse;
  }

  /**
   * POST /deposit — submit a signed deposit request.
   * Throws `SubpoolApiError` on non-2xx responses.
   */
  async submitDeposit(req: DepositRequest): Promise<DepositResponse> {
    const res = await fetch(`${this.baseUrl}/deposit`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
    });
    const json = await res.json();
    if (!res.ok) throw new SubpoolApiError(res.status, json as ApiError);
    return json as DepositResponse;
  }

  /**
   * GET /input_notes/:recipientAddress — approved incoming notes for an account.
   */
  async getInputNotes(recipientAddress: string): Promise<InputNote[]> {
    const res = await fetch(`${this.baseUrl}/input_notes/${recipientAddress}`);
    const json = await res.json();
    if (!res.ok) throw new SubpoolApiError(res.status, json as ApiError);
    return json as InputNote[];
  }

  /**
   * POST /spend_tx — submit a signed spend transaction.
   * Throws `SubpoolApiError` on non-2xx responses.
   */
  async submitSpendTx(req: SpendTxRequest): Promise<SpendTxResponse> {
    const res = await fetch(`${this.baseUrl}/spend_tx`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
    });
    const json = await res.json();
    if (!res.ok) throw new SubpoolApiError(res.status, json as ApiError);
    return json as SpendTxResponse;
  }

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
