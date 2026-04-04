import type { AccountWithKyc, DepositAdminRow, FreshAccWithKyc } from "../types";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";

export async function fetchFreshAccRequests(): Promise<FreshAccWithKyc[]> {
  const res = await fetch(`${API_BASE}/admin/freshacc`);
  if (!res.ok) {
    throw new Error(`GET /admin/freshacc failed: ${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<FreshAccWithKyc[]>;
}

export async function fetchAccounts(): Promise<AccountWithKyc[]> {
  const res = await fetch(`${API_BASE}/admin/accounts`);
  if (!res.ok) {
    throw new Error(`GET /admin/accounts failed: ${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<AccountWithKyc[]>;
}

export async function fetchAllDeposits(): Promise<DepositAdminRow[]> {
  const res = await fetch(`${API_BASE}/admin/deposit_tx_requests`);
  if (!res.ok) {
    throw new Error(`GET /admin/deposit_tx_requests failed: ${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<DepositAdminRow[]>;
}

export async function fetchUnderReviewDeposits(): Promise<DepositAdminRow[]> {
  const res = await fetch(`${API_BASE}/admin/deposit_tx_requests/underreview`);
  if (!res.ok) {
    throw new Error(`GET /admin/deposit_tx_requests/underreview failed: ${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<DepositAdminRow[]>;
}

export async function reviewDeposit(id: number, action: "approve" | "reject"): Promise<void> {
  const res = await fetch(`${API_BASE}/admin/deposit_tx_requests/${id}/review`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action }),
  });
  if (!res.ok) {
    throw new Error(`POST /admin/deposit_tx_requests/${id}/review failed: ${res.status} ${res.statusText}`);
  }
}
