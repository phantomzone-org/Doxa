import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchUnderReviewDeposits, reviewDeposit } from "../api/admin";
import type { UnderReviewDeposit } from "../types";

function truncate(s: string, n = 14) {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

/** Convert a 64-char little-endian hex U256 to a USDX decimal string (6 decimals). */
function hexLeToUsdx(hexLe: string): string {
  const beHex = (hexLe.match(/.{2}/g) ?? []).reverse().join("");
  const raw = BigInt("0x" + (beHex || "0"));
  const whole = raw / 1_000_000n;
  const frac = (raw % 1_000_000n).toString().padStart(6, "0");
  return `${whole}.${frac}`;
}

function checkStatusBadge(status: string | null) {
  if (!status) return <span className="text-slate-400">—</span>;
  const color =
    status === "APPROVED"
      ? "bg-emerald-100 text-emerald-700"
      : status === "REJECTED"
        ? "bg-red-100 text-red-700"
        : "bg-amber-100 text-amber-700";
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${color}`}>
      {status}
    </span>
  );
}

function DetailField({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs font-medium uppercase tracking-wider text-slate-400">
        {label}
      </span>
      <span className="break-all text-xs text-slate-700">{value ?? "—"}</span>
    </div>
  );
}

function DepositRow({ row }: { row: UnderReviewDeposit }) {
  const [expanded, setExpanded] = useState(false);
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (action: "approve" | "reject") => reviewDeposit(row.id, action),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["deposits-underreview"] }),
  });

  const { deposit_check: dc, account: acc } = row;

  return (
    <>
      <tr
        className="cursor-pointer border-t border-slate-100 text-sm hover:bg-slate-50"
        onClick={() => setExpanded((v) => !v)}
      >
        <td className="px-4 py-3 text-slate-400">
          <span className="text-xs">{expanded ? "▾" : "▸"}</span>
        </td>
        <td className="px-4 py-3 font-mono text-slate-500">{row.id}</td>
        <td className="px-4 py-3 font-mono text-xs" title={row.eth_address}>
          {truncate(row.eth_address)}
        </td>
        <td
          className="px-4 py-3 font-mono text-xs"
          title={row.recipient_address}
        >
          {truncate(row.recipient_address)}
        </td>
        <td className="px-4 py-3 text-xs text-slate-700">
          {hexLeToUsdx(row.deposit_amount)} USDX
        </td>
        <td className="px-4 py-3 text-xs text-slate-500">
          {new Date(row.created_at).toLocaleString()}
        </td>
        <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
          {mutation.isError && (
            <p className="mb-1 text-xs text-red-500">
              {(mutation.error as Error).message}
            </p>
          )}
          <div className="flex gap-2">
            <button
              onClick={() => mutation.mutate("approve")}
              disabled={mutation.isPending}
              className="rounded-md bg-emerald-600 px-3 py-1 text-xs font-medium text-white transition hover:bg-emerald-700 disabled:opacity-50"
            >
              Accept
            </button>
            <button
              onClick={() => mutation.mutate("reject")}
              disabled={mutation.isPending}
              className="rounded-md bg-red-600 px-3 py-1 text-xs font-medium text-white transition hover:bg-red-700 disabled:opacity-50"
            >
              Reject
            </button>
          </div>
        </td>
      </tr>

      {expanded && (
        <tr className="border-t border-slate-100 bg-slate-50">
          <td colSpan={7} className="px-6 py-5">
            <div className="grid grid-cols-2 gap-6">
              {/* Deposit check */}
              <div className="rounded-lg border border-slate-200 bg-white p-4">
                <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                  AML / Sanctions Check
                </h3>
                <div className="flex flex-col gap-3">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-medium uppercase tracking-wider text-slate-400">
                      Status
                    </span>
                    {checkStatusBadge(dc.status)}
                  </div>
                  <DetailField label="Check ID" value={dc.id} />
                  <DetailField
                    label="Last updated"
                    value={
                      dc.updated_at
                        ? new Date(dc.updated_at).toLocaleString()
                        : null
                    }
                  />
                  {dc.check_response && (
                    <div className="flex flex-col gap-0.5">
                      <span className="text-xs font-medium uppercase tracking-wider text-slate-400">
                        Chainanalysis response
                      </span>
                      <pre className="max-h-40 overflow-auto rounded bg-slate-100 p-2 text-xs text-slate-600">
                        {(() => {
                          try {
                            return JSON.stringify(
                              JSON.parse(dc.check_response!),
                              null,
                              2,
                            );
                          } catch {
                            return dc.check_response;
                          }
                        })()}
                      </pre>
                    </div>
                  )}
                </div>
              </div>

              {/* Account info */}
              <div className="rounded-lg border border-slate-200 bg-white p-4">
                <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                  Account / KYC
                </h3>
                <div className="flex flex-col gap-3">
                  <DetailField label="Name" value={acc.name} />
                  <DetailField
                    label="Physical address"
                    value={acc.physical_address}
                  />
                  <DetailField label="Date of birth" value={acc.dob} />
                  <DetailField
                    label="Tessera address"
                    value={row.recipient_address}
                  />
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export function DepositsUnderReviewPage() {
  const {
    data,
    isLoading,
    isError,
    error,
    dataUpdatedAt,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: ["deposits-underreview"],
    queryFn: fetchUnderReviewDeposits,
    refetchInterval: 10_000,
  });

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-800">
            Deposits Under Review
          </h1>
          <p className="mt-0.5 text-sm text-slate-500">
            Deposits requiring manual approval or rejection.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {dataUpdatedAt > 0 && (
            <span className="text-xs text-slate-400">
              Updated {new Date(dataUpdatedAt).toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:opacity-50"
          >
            {isFetching ? "Refreshing…" : "Refresh"}
          </button>
        </div>
      </div>

      {/* Count */}
      {data && (
        <div className="w-48 rounded-xl border border-slate-200 bg-white px-5 py-4 shadow-sm">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
            Under Review
          </p>
          <p className="mt-1 text-3xl font-bold text-amber-500">
            {data.length}
          </p>
        </div>
      )}

      {/* Content */}
      {isLoading && (
        <div className="py-16 text-center text-slate-400">Loading…</div>
      )}
      {isError && (
        <div className="rounded-xl border border-red-200 bg-red-50 px-5 py-4 text-sm text-red-600">
          {(error as Error).message}
        </div>
      )}
      {data && data.length === 0 && (
        <div className="py-16 text-center text-slate-400">
          No deposits under review.
        </div>
      )}
      {data && data.length > 0 && (
        <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
          <table className="w-full">
            <thead>
              <tr className="bg-slate-50 text-left text-xs font-medium uppercase tracking-wider text-slate-400">
                <th className="px-4 py-3 w-6" />
                <th className="px-4 py-3">ID</th>
                <th className="px-4 py-3">ETH Address</th>
                <th className="px-4 py-3">Recipient</th>
                <th className="px-4 py-3">Amount (USDX)</th>
                <th className="px-4 py-3">Submitted</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {data.map((row) => (
                <DepositRow key={row.id} row={row} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
