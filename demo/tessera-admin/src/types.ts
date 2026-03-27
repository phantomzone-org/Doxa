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
