import { FreshAccPage } from "./pages/FreshAccPage";

export default function App() {
  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 border-r border-slate-200 bg-white">
        <div className="px-5 py-6">
          <span className="text-base font-bold tracking-tight text-slate-800">
            Tessera Admin
          </span>
        </div>
        <nav className="px-3">
          <button className="flex w-full items-center gap-2.5 rounded-lg bg-slate-100 px-3 py-2 text-sm font-medium text-slate-800">
            <span>🪪</span> FreshAcc
          </button>
        </nav>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-auto bg-slate-50">
        <div className="mx-auto max-w-7xl px-8 py-8">
          <FreshAccPage />
        </div>
      </main>
    </div>
  );
}
