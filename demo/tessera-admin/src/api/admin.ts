import type { AccountWithKyc, FreshAccWithKyc } from "../types";

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
