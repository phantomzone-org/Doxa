import { useQuery } from "@tanstack/react-query";
import { fetchAccounts } from "../api/admin";
import { AccountsTable } from "../components/AccountsTable";

export function AccountsPage() {
  const { data, isLoading, isError, error, dataUpdatedAt, refetch, isFetching } =
    useQuery({
      queryKey: ["accounts"],
      queryFn: fetchAccounts,
    });

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-800">Accounts</h1>
          <p className="mt-0.5 text-sm text-slate-500">
            All approved accounts paired with KYC data.
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

      {data && (
        <div className="rounded-xl border border-slate-200 bg-white px-5 py-4 shadow-sm">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
            Total Accounts
          </p>
          <p className="mt-1 text-3xl font-bold text-slate-800">{data.length}</p>
        </div>
      )}

      {isLoading && (
        <div className="py-16 text-center text-slate-400">Loading…</div>
      )}
      {isError && (
        <div className="rounded-xl border border-red-200 bg-red-50 px-5 py-4 text-sm text-red-600">
          {(error as Error).message}
        </div>
      )}
      {data && <AccountsTable data={data} />}
    </div>
  );
}
