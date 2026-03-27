import { useState, useMemo } from "react";
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  flexRender,
  createColumnHelper,
  type SortingState,
} from "@tanstack/react-table";
import type { FreshAccWithKyc, FreshAccStatus } from "../types";

const col = createColumnHelper<FreshAccWithKyc>();

function StatusBadge({ status }: { status: FreshAccStatus }) {
  const classes: Record<FreshAccStatus, string> = {
    PENDING: "bg-amber-100 text-amber-700 ring-amber-300",
    APPROVED: "bg-emerald-100 text-emerald-700 ring-emerald-300",
    REJECTED: "bg-red-100 text-red-700 ring-red-300",
  };
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset ${classes[status]}`}
    >
      {status}
    </span>
  );
}

function truncate(s: string, head = 8, tail = 6) {
  if (s.length <= head + tail + 3) return s;
  return `${s.slice(0, head)}…${s.slice(-tail)}`;
}

const columns = [
  col.accessor("id", {
    header: "ID",
    size: 60,
    cell: (i) => <span className="text-slate-400">#{i.getValue()}</span>,
  }),
  col.accessor("name", {
    header: "Name",
    cell: (i) => i.getValue() ?? <span className="text-slate-300 italic">—</span>,
  }),
  col.accessor("dob", {
    header: "Date of Birth",
    cell: (i) => i.getValue() ?? <span className="text-slate-300 italic">—</span>,
  }),
  col.accessor("physical_address", {
    header: "Address",
    cell: (i) => i.getValue() ?? <span className="text-slate-300 italic">—</span>,
  }),
  col.accessor("private_acc_address", {
    header: "Tessera Address",
    cell: (i) => (
      <span
        className="font-mono text-xs text-slate-500 cursor-default"
        title={i.getValue()}
      >
        {truncate(i.getValue())}
      </span>
    ),
  }),
  col.accessor("status", {
    header: "Status",
    cell: (i) => <StatusBadge status={i.getValue()} />,
  }),
  col.accessor("rejection_msg", {
    header: "Rejection",
    cell: (i) =>
      i.getValue() ? (
        <span className="text-red-500 text-xs">{i.getValue()}</span>
      ) : (
        <span className="text-slate-300">—</span>
      ),
  }),
  col.accessor("created_at", {
    header: "Submitted",
    cell: (i) =>
      new Date(i.getValue()).toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }),
  }),
];

export function FreshAccTable({ data }: { data: FreshAccWithKyc[] }) {
  const [sorting, setSorting] = useState<SortingState>([
    { id: "created_at", desc: true },
  ]);
  const [globalFilter, setGlobalFilter] = useState("");

  const filtered = useMemo(() => {
    if (!globalFilter) return data;
    const q = globalFilter.toLowerCase();
    return data.filter((r) =>
      [r.name, r.physical_address, r.private_acc_address, r.status, r.dob]
        .join(" ")
        .toLowerCase()
        .includes(q)
    );
  }, [data, globalFilter]);

  const table = useReactTable({
    data: filtered,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
  });

  return (
    <div className="flex flex-col gap-4">
      {/* Search */}
      <input
        type="text"
        placeholder="Search by name, address, status…"
        value={globalFilter}
        onChange={(e) => setGlobalFilter(e.target.value)}
        className="w-full max-w-sm rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 placeholder-slate-400 shadow-sm focus:outline-none focus:ring-2 focus:ring-slate-400"
      />

      {/* Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-200 shadow-sm">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 border-b border-slate-200">
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((h) => (
                  <th
                    key={h.id}
                    onClick={h.column.getToggleSortingHandler()}
                    className={`px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 select-none ${
                      h.column.getCanSort()
                        ? "cursor-pointer hover:text-slate-700"
                        : ""
                    }`}
                  >
                    <span className="flex items-center gap-1">
                      {flexRender(h.column.columnDef.header, h.getContext())}
                      {h.column.getIsSorted() === "asc" && " ↑"}
                      {h.column.getIsSorted() === "desc" && " ↓"}
                    </span>
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody className="divide-y divide-slate-100 bg-white">
            {table.getRowModel().rows.length === 0 ? (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-4 py-10 text-center text-slate-400"
                >
                  No records found.
                </td>
              </tr>
            ) : (
              table.getRowModel().rows.map((row) => (
                <tr
                  key={row.id}
                  className="transition-colors hover:bg-slate-50"
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-4 py-3 text-slate-700">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <p className="text-xs text-slate-400">
        {filtered.length} of {data.length} records
      </p>
    </div>
  );
}
