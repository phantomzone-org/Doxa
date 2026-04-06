import { useState } from "react";
import { FreshAccPage } from "./pages/FreshAccPage";
import { AccountsPage } from "./pages/AccountsPage";
import { DepositsPage } from "./pages/DepositsPage";
import { DepositsUnderReviewPage } from "./pages/DepositsUnderReviewPage";
import { OutputNotesUnderReviewPage } from "./pages/OutputNotesUnderReviewPage";
import { OutputNotesPage } from "./pages/OutputNotesPage";
import { InputNotesUnderReviewPage } from "./pages/InputNotesUnderReviewPage";
import { InputNotesPage } from "./pages/InputNotesPage";

type Page =
  | "freshacc"
  | "accounts"
  | "deposits"
  | "deposits-underreview"
  | "output-notes-underreview"
  | "output-notes"
  | "input-notes-underreview"
  | "input-notes";

const NAV_MAIN: { id: Page; label: string; icon: string }[] = [
  { id: "accounts", label: "All Accounts", icon: "👤" },
  { id: "freshacc", label: "New Account Requests", icon: "🪪" },
  { id: "deposits", label: "All Public to Private transfers", icon: "⬇️" },
  { id: "output-notes", label: "All Outgoing transfers", icon: "📄" },
  { id: "input-notes", label: "All Incoming transfers", icon: "📩" },
];

const NAV_UNDER_REVIEW: { id: Page; label: string; icon: string }[] = [
  {
    id: "deposits-underreview",
    label: "Public to Private transfers",
    icon: "⬇️",
  },
  { id: "output-notes-underreview", label: "Outgoing transfers", icon: "📄" },
  { id: "input-notes-underreview", label: "Input transfers", icon: "📩" },
];

export default function App() {
  const [page, setPage] = useState<Page>("freshacc");

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 border-r border-slate-200 bg-white">
        <div className="px-5 py-6">
          <span className="text-base font-bold tracking-tight text-slate-800">
            Tessera Admin
          </span>
        </div>
        <nav className="flex flex-col gap-1 px-3">
          {NAV_MAIN.map((item) => (
            <button
              key={item.id}
              onClick={() => setPage(item.id)}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                page === item.id
                  ? "bg-slate-100 text-slate-900"
                  : "text-slate-500 hover:bg-slate-50 hover:text-slate-800"
              }`}
            >
              <span>{item.icon}</span>
              {item.label}
            </button>
          ))}

          <div className="mx-3 my-3 border-t border-slate-200" />
          <p className="px-3 pb-1 text-xs font-semibold uppercase tracking-wider text-slate-400">
            Under Review
          </p>

          {NAV_UNDER_REVIEW.map((item) => (
            <button
              key={item.id}
              onClick={() => setPage(item.id)}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                page === item.id
                  ? "bg-slate-100 text-slate-900"
                  : "text-slate-500 hover:bg-slate-50 hover:text-slate-800"
              }`}
            >
              <span>{item.icon}</span>
              {item.label}
            </button>
          ))}
        </nav>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-auto bg-slate-50">
        <div className="mx-auto max-w-7xl px-8 py-8">
          {page === "freshacc" && <FreshAccPage />}
          {page === "accounts" && <AccountsPage />}
          {page === "deposits" && <DepositsPage />}
          {page === "deposits-underreview" && <DepositsUnderReviewPage />}
          {page === "output-notes-underreview" && (
            <OutputNotesUnderReviewPage />
          )}
          {page === "output-notes" && <OutputNotesPage />}
          {page === "input-notes-underreview" && <InputNotesUnderReviewPage />}
          {page === "input-notes" && <InputNotesPage />}
        </div>
      </main>
    </div>
  );
}
