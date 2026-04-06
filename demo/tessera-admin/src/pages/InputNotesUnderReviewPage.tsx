import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchUnderReviewInputNotes, reviewInputNote } from "../api/admin";
import type { InputNoteAdminRow } from "../types";

function truncate(s: string, n = 14) {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

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

function parseMemo(hexMemo: string): Record<string, any> | null {
  if (!hexMemo) return null;
  try {
    const bytes = new Uint8Array(
      (hexMemo.match(/.{2}/g) ?? []).map((h) => parseInt(h, 16)),
    );
    const text = new TextDecoder().decode(bytes).replace(/\0+$/, "");
    return JSON.parse(text);
  } catch (e) {
    console.error("parseMemo failed:", e);
    return null;
  }
}

function MemoDisplay({ hexMemo }: { hexMemo: string }) {
  const memo = parseMemo(hexMemo);
  if (!memo) {
    return (
      <pre className="max-h-60 overflow-auto rounded bg-slate-100 p-2 text-xs text-slate-600">
        {hexMemo || "—"}
      </pre>
    );
  }

  const { sender, recipient, reference } = memo;

  return (
    <div className="flex flex-col gap-2">
      <div className="grid grid-cols-2 gap-2">
        {[
          { label: "From", party: sender },
          { label: "To", party: recipient },
        ].map(({ label, party }) => (
          <div key={label} className="rounded bg-slate-50 p-3">
            <div className="mb-1 text-xs font-bold uppercase tracking-wider text-slate-400">
              {label}
            </div>
            {party?.institution_name && (
              <div className="text-xs font-semibold text-indigo-500">
                {party.institution_name}
              </div>
            )}
            {party?.name && (
              <div className="text-xs font-semibold text-slate-700">
                {party.name}
              </div>
            )}
            {party?.physical_address && (
              <div className="text-xs text-slate-500">
                {party.physical_address}
              </div>
            )}
          </div>
        ))}
      </div>
      {reference && (
        <div className="border-t border-slate-100 pt-2 text-xs text-slate-500">
          <span className="font-semibold text-slate-600">Reference:</span>{" "}
          {reference}
        </div>
      )}
    </div>
  );
}

function InputNoteRow({ row }: { row: InputNoteAdminRow }) {
  const [expanded, setExpanded] = useState(false);
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (action: "approve" | "reject") =>
      reviewInputNote(row.id, action),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["input-notes-underreview"] }),
  });

  const { input_note_check: c, recipient } = row;

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
        <td className="px-4 py-3 font-mono text-xs" title={row.identifier}>
          {truncate(row.identifier, 20)}
        </td>
        <td
          className="px-4 py-3 font-mono text-xs"
          title={row.recipient_address}
        >
          {`0x${row.recipient_address.slice(0, 4)}…${row.recipient_address.slice(-6)}`}
        </td>
        <td className="px-4 py-3 font-mono text-xs" title={row.sender_address}>
          {`0x${row.sender_address.slice(0, 4)}…${row.sender_address.slice(-6)}`}
        </td>
        <td className="px-4 py-3 text-xs text-slate-700">
          {hexLeToUsdx(row.amount)} USDX
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
              Approve
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
          <td colSpan={8} className="px-6 py-5">
            <div className="grid grid-cols-3 gap-6">
              {/* Note check */}
              <div className="rounded-lg border border-slate-200 bg-white p-4">
                <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                  Note Check
                </h3>
                <div className="flex flex-col gap-3">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-medium uppercase tracking-wider text-slate-400">
                      Status
                    </span>
                    {checkStatusBadge(c.status)}
                  </div>
                  <DetailField label="Check ID" value={c.id} />
                  <DetailField label="Identifier" value={c.identifier} />
                  <DetailField
                    label="Last updated"
                    value={
                      c.updated_at
                        ? new Date(c.updated_at).toLocaleString()
                        : null
                    }
                  />
                  {c.check_response && (
                    <div className="flex flex-col gap-0.5">
                      <span className="text-xs font-medium uppercase tracking-wider text-slate-400">
                        Check response
                      </span>
                      <pre className="max-h-40 overflow-auto rounded bg-slate-100 p-2 text-xs text-slate-600">
                        {(() => {
                          try {
                            return JSON.stringify(
                              JSON.parse(c.check_response!),
                              null,
                              2,
                            );
                          } catch {
                            return c.check_response;
                          }
                        })()}
                      </pre>
                    </div>
                  )}
                </div>
              </div>

              {/* Recipient / KYC */}
              <div className="rounded-lg border border-slate-200 bg-white p-4">
                <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                  Recipient / KYC
                </h3>
                <div className="flex flex-col gap-3">
                  <DetailField label="Name" value={recipient.name} />
                  <DetailField
                    label="Physical address"
                    value={recipient.physical_address}
                  />
                  <DetailField label="Date of birth" value={recipient.dob} />
                  <DetailField
                    label="Tessera address"
                    value={`0x${row.recipient_address}`}
                  />
                </div>
              </div>

              {/* Memo */}
              <div className="rounded-lg border border-slate-200 bg-white p-4">
                <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
                  Memo
                </h3>
                <div className="rounded border border-slate-200 p-3">
                  <MemoDisplay hexMemo={row.memo} />
                </div>
                <div className="mt-3 border-t border-slate-100 pt-3">
                  <DetailField
                    label="Sender"
                    value={`0x${row.sender_address}`}
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

export function InputNotesUnderReviewPage() {
  const {
    data,
    isLoading,
    isError,
    error,
    dataUpdatedAt,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: ["input-notes-underreview"],
    queryFn: fetchUnderReviewInputNotes,
    refetchInterval: 10_000,
  });

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-800">
            Incoming Transactions to be Approved/Reject
          </h1>
          <p className="mt-0.5 text-sm text-slate-500">
            paired with recipient's account/KYC details and sender's AML check
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
        <div className="w-48 rounded-xl border border-slate-200 bg-white px-5 py-4 shadow-sm">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
            Under Review
          </p>
          <p className="mt-1 text-3xl font-bold text-amber-500">
            {data.length}
          </p>
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
      {data && data.length === 0 && (
        <div className="py-16 text-center text-slate-400">
          No input notes under review.
        </div>
      )}
      {data && data.length > 0 && (
        <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
          <table className="w-full">
            <thead>
              <tr className="bg-slate-50 text-left text-xs font-medium uppercase tracking-wider text-slate-400">
                <th className="px-4 py-3 w-6" />
                <th className="px-4 py-3">ID</th>
                <th className="px-4 py-3">Identifier</th>
                <th className="px-4 py-3">Recipient</th>
                <th className="px-4 py-3">Sender</th>
                <th className="px-4 py-3">Amount (USDX)</th>
                <th className="px-4 py-3">Created</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {data.map((row) => (
                <InputNoteRow key={row.id} row={row} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
