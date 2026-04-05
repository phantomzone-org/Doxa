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

const NAV: { id: Page; label: string; icon: string }[] = [
  { id: "freshacc", label: "FreshAcc", icon: "🪪" },
  { id: "accounts", label: "Accounts", icon: "👤" },
  { id: "deposits", label: "Deposits", icon: "💰" },
  { id: "deposits-underreview", label: "Deposits Under Review", icon: "🔍" },
  { id: "output-notes-underreview", label: "Output Notes Review", icon: "📋" },
  { id: "output-notes", label: "All Output Notes", icon: "📄" },
  { id: "input-notes-underreview", label: "Input Notes Review", icon: "📥" },
  { id: "input-notes", label: "All Input Notes", icon: "📩" },
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
          {NAV.map((item) => (
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
          {page === "output-notes-underreview" && <OutputNotesUnderReviewPage />}
          {page === "output-notes" && <OutputNotesPage />}
          {page === "input-notes-underreview" && <InputNotesUnderReviewPage />}
          {page === "input-notes" && <InputNotesPage />}
        </div>
      </main>
    </div>
  );
}
