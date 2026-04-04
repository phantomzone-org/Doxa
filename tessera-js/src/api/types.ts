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

export type FreshAccStatus = "Pending" | "Approved" | "Rejected";

/** Response body for GET /freshacc/:private_acc_address/status */
export interface FreshAccStatusResponse {
  status: FreshAccStatus;
}

/** Response body for POST /faucet (HTTP 201) */
export interface FaucetResponse {
  tx_hash: string;
}

/** Request body for POST /deposit */
export interface DepositRequest {
  recipient_address: string;
  eth_address: string;
  /** 32 hex chars — [F;2] identifier, 2 × u64 LE */
  deposit_note_identifier: string;
  /** 64 hex chars — U256 amount, 32 bytes LE */
  deposit_amount: string;
  /** 16 hex chars — u64 asset_id, 8 bytes LE */
  asset_id: string;
  /** hex-encoded EIP-712 typed-data signature (65 bytes, no 0x prefix) */
  deposit_type_signature: string;
}

/** Response body for a successful POST /deposit (HTTP 201) */
export interface DepositResponse {
  id: number;
}

export type DepositTxStatus = "Pending" | "Approved" | "Rejected";

/** Response body for GET /deposit/:id/status */
export interface DepositStatusResponse {
  id: number;
  status: DepositTxStatus;
  deposit_tx_hash: string | null;
}

/** Entry returned by GET /input_notes/:recipient_address */
export interface InputNote {
  /** 32 hex chars — [F;2] identifier */
  identifier: string;
  /** 16 hex chars — F asset_id, 8 bytes LE */
  asset_id: string;
  /** 64 hex chars — U256 amount, 32 bytes LE */
  amount: string;
  recipient_address: string;
  sender_address: string;
  /** hex-encoded memo (≤ 1024 hex chars = ≤ 512 bytes) */
  memo: string;
}

/** A note payload for POST /spend_tx */
export interface NotePayload {
  /** 32 hex chars */
  identifier: string;
  /** 16 hex chars — F asset_id, 8 bytes LE */
  asset_id: string;
  /** 64 hex chars — U256 amount, 32 bytes LE */
  amount: string;
  recipient_address: string;
  sender_address: string;
  /** hex-encoded memo (≤ 1024 hex chars = ≤ 512 bytes) */
  memo: string;
}

/** Request body for POST /spend_tx */
export interface SpendTxRequest {
  priv_acc_address: string;
  input_notes: NotePayload[];
  output_notes: NotePayload[];
  /** Raw 32-byte dummy input note seeds as 64 hex chars each */
  dinotes: string[];
  /** Raw 32-byte dummy output note seeds as 64 hex chars each */
  donotes: string[];
  /** 80-byte Schnorr signature as hex */
  spend_tx_signature: string;
}

/** Response body for a successful POST /spend_tx (HTTP 201) */
export interface SpendTxResponse {
  id: number;
}

export type SpendTxStatus = "Pending" | "Approved" | "Rejected";

/** Response body for GET /spend_tx/:id/status */
export interface SpendTxStatusResponse {
  id: number;
  status: SpendTxStatus;
  rejection_reason: string | null;
}

/** Per-asset entry in GET /notes_balance/:address */
export interface AssetBalance {
  /** hex-encoded U256 (big-endian, 64 chars) */
  amount: string;
}

/** Response body for GET /notes_balance/:address */
export interface NotesBalanceResponse {
  /** Keys are decimal asset_id strings (u64). */
  balances: Record<string, AssetBalance>;
}

/** Response body for GET /user/:private_acc_address */
export interface UserResponse {
  id: number;
  private_acc_address: string;
  name: string;
  physical_address: string;
  /** ISO date string "YYYY-MM-DD" */
  dob: string;
  created_at: string;
}

/** Response body for GET /account/:private_acc_address */
export interface AccountResponse {
  private_acc_address: string;
  eth_address: string;
  /** 32 hex chars — PrivateIdentifier */
  private_identifier: string;
  /** 16 hex chars — SubpoolId */
  subpool_id: string;
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
