/** Request body for POST /register */
export interface RegisterRequest {
  /** 32 hex chars — 16-byte PrivateIdentifier([F; 2]), 2 × u64 LE */
  privateIdentifier: string;
  /** 80 hex chars — 40-byte CompressedPublicKey, 5 × u64 LE */
  spendAuthPk: string;
  /** Ethereum address, e.g. "0x..." (42 chars) */
  ethAddress: string;
  name: string;
  physicalAddress: string;
  /** ISO date string "YYYY-MM-DD" */
  dob: string;
}

/** Response body for a successful POST /register (HTTP 201) */
export interface RegisterResponse {
  /** 80-hex-char AccountAddress */
  privateAccAddress: string;
}

/** Body returned by the server on any error response */
export interface ApiError {
  error: string;
}

export type FreshAccStatus = "PENDING" | "APPROVED" | "REJECTED";

/** Response body for GET /freshacc/:private_acc_address/status */
export interface FreshAccStatusResponse {
  status: FreshAccStatus;
}

/** Response body for POST /faucet (HTTP 201) */
export interface FaucetResponse {
  tx_hash: string;
}

/** Response body for GET /account/:private_acc_address */
export interface AccountResponse {
  private_acc_address: string;
  eth_address: string;
  /** 32 hex chars — PrivateIdentifier */
  private_identifier: string;
  /** 16 hex chars — SubpoolId */
  subpool_id: string;
  /** 64 hex chars — U256 balance */
  balance: string;
  /** 16 hex chars — Nonce */
  nonce: string;
  /** 80 hex chars — spend-auth CompressedPublicKey; all-zeros if absent */
  spend_auth: string;
  /** 80 hex chars — consume-auth CompressedPublicKey; all-zeros if absent */
  consume_auth: string;
  ast: unknown;
  created_at: string;
  updated_at: string;
}
