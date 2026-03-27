export type FreshAccStatus = "PENDING" | "APPROVED" | "REJECTED";

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
