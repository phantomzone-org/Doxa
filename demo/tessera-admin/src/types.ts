export type FreshAccStatus = "Pending" | "Approved" | "Rejected";

export interface FreshAccWithKyc {
  id: number;
  private_acc_address: string;
  private_identifier: string;
  status: FreshAccStatus;
  rejection_msg: string | null;
  created_at: string;
  updated_at: string;
  // KYC — null when no users row
  name: string | null;
  physical_address: string | null;
  dob: string | null;
}

export interface DepositCheckInfo {
  id: number | null;
  status: string | null;
  check_response: string | null;
  updated_at: string | null;
}

export interface AccountInfo {
  name: string | null;
  physical_address: string | null;
  dob: string | null;
}

export interface UnderReviewDeposit {
  id: number;
  recipient_address: string;
  eth_address: string;
  /** 64 hex chars — U256 amount, 32 bytes LE */
  deposit_amount: string;
  /** 16 hex chars — F asset_id, 8 bytes LE */
  asset_id: string;
  deposit_tx_hash: string | null;
  rejection_reason: string | null;
  created_at: string;
  deposit_check: DepositCheckInfo;
  account: AccountInfo;
}

export interface AccountWithKyc {
  private_acc_address: string;
  eth_address: string;
  /** 16 hex chars — Nonce(F) */
  nonce: string;
  /** 80 hex chars — spend-auth CompressedPublicKey */
  spend_auth: string;
  created_at: string;
  updated_at: string;
  // KYC — null when no users row
  name: string | null;
  physical_address: string | null;
  dob: string | null;
}
