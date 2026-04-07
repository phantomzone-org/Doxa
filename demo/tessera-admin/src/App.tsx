import { useState } from "react";
import institutions from "../../institutions.json";
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

interface InstitutionConfig {
  name: string;
  "background-color": string;
  "logo-file": string;
  "partner-logo-file": string;
}

const SUBPOOL_ID_HEX =
  (import.meta.env.VITE_SUBPOOL_ID_HEX as string | undefined) ??
  "0100000000000000";

const institution = (institutions as Record<string, InstitutionConfig>)[
  SUBPOOL_ID_HEX
];

function hexToRgba(hex: string, alpha: number): string {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

export default function App() {
  const [page, setPage] = useState<Page>("freshacc");

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside
        className="w-56 flex-shrink-0 flex flex-col border-r border-slate-200"
        style={{
          backgroundColor: institution
            ? hexToRgba(institution["background-color"], 0.5)
            : undefined,
        }}
      >
        <div className="px-5 py-6 flex items-center gap-3">
          {institution && (
            <img
              src={`/images/${institution["logo-file"]}`}
              alt={institution.name}
              className="h-7 w-auto"
              onError={(e) => {
                (e.currentTarget as HTMLImageElement).style.display = "none";
              }}
            />
          )}
          <span className="text-base font-bold tracking-tight text-white">
            {institution?.name ?? ""} - Admin Dashboard
          </span>
        </div>
        <nav className="flex flex-col gap-1 px-3">
          {NAV_MAIN.map((item) => (
            <button
              key={item.id}
              onClick={() => setPage(item.id)}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                page === item.id
                  ? "bg-white/20 text-white"
                  : "text-white/70 hover:bg-white/10 hover:text-white"
              }`}
            >
              <span>{item.icon}</span>
              {item.label}
            </button>
          ))}

          <div className="mx-3 my-3 border-t border-white/20" />
          <p className="px-3 pb-1 text-xs font-semibold uppercase tracking-wider text-white/50">
            Under Review
          </p>

          {NAV_UNDER_REVIEW.map((item) => (
            <button
              key={item.id}
              onClick={() => setPage(item.id)}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                page === item.id
                  ? "bg-white/20 text-white"
                  : "text-white/70 hover:bg-white/10 hover:text-white"
              }`}
            >
              <span>{item.icon}</span>
              {item.label}
            </button>
          ))}
        </nav>

        {/* Powered by */}
        <div className="mt-auto px-5 py-4 flex items-center gap-2">
          <span className="text-sm text-white/40">powered by</span>
          <img
            src="/images/logo-tessera.avif"
            alt="Tessera"
            className="h-6 w-auto"
            onError={(e) => {
              (e.currentTarget as HTMLImageElement).style.display = "none";
            }}
          />
        </div>
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
