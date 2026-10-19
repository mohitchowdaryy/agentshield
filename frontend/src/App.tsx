import { Activity, Cloud, FileCode2, FileWarning, GitBranch, History, LayoutDashboard, Menu, Settings, ShieldCheck, Swords, X } from "lucide-react";
import { useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { cn } from "./components/ui";
import AttackPaths from "./pages/AttackPaths";
import CloudPosture from "./pages/CloudPosture";
import Findings from "./pages/Findings";
import HistoryPage from "./pages/History";
import IacSecurity from "./pages/IacSecurity";
import Overview from "./pages/Overview";
import RedTeam from "./pages/RedTeam";
import RunDetail from "./pages/RunDetail";
import SettingsPage from "./pages/Settings";
import ToolTraces from "./pages/ToolTraces";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/cloud", label: "Cloud Posture", icon: Cloud },
  { to: "/iac", label: "IaC Security Scanning", icon: FileCode2 },
  { to: "/redteam", label: "AI Red Team", icon: Swords },
  { to: "/traces", label: "Agent Tool Traces", icon: Activity },
  { to: "/paths", label: "Attack Path Explorer", icon: GitBranch },
  { to: "/findings", label: "Findings & Remediation", icon: FileWarning },
  { to: "/history", label: "Test History & Evidence", icon: History },
  { to: "/settings", label: "Settings & Integrations", icon: Settings },
];

function Nav({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav className="flex flex-col gap-0.5 p-3" aria-label="Main">
      {NAV.map(({ to, label, icon: Icon, end }) => (
        <NavLink
          key={to}
          to={to}
          end={end}
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              "flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors",
              isActive ? "bg-accent-500/15 text-ink-100 ring-1 ring-inset ring-accent-500/30" : "text-ink-400 hover:bg-ink-800 hover:text-ink-100",
            )
          }
        >
          <Icon className="size-4 shrink-0" aria-hidden />
          {label}
        </NavLink>
      ))}
    </nav>
  );
}

function Brand() {
  return (
    <div className="flex items-center gap-2.5 px-5 py-5">
      <div className="grid size-8 place-items-center rounded-lg bg-gradient-to-br from-accent-500 to-violet-accent">
        <ShieldCheck className="size-4.5 text-white" aria-hidden />
      </div>
      <div>
        <div className="text-sm font-semibold tracking-tight">AgentShield</div>
        <div className="text-[11px] text-ink-400">Agent security research</div>
      </div>
    </div>
  );
}

export default function App() {
  const [open, setOpen] = useState(false);
  return (
    <div className="min-h-screen bg-ink-950 bg-[radial-gradient(ellipse_at_top_right,rgba(91,124,250,0.08),transparent_50%)]">
      <aside className="fixed inset-y-0 left-0 hidden w-64 border-r border-ink-700/60 bg-ink-900/90 lg:block">
        <Brand />
        <Nav />
        <div className="absolute inset-x-0 bottom-0 border-t border-ink-700/60 px-5 py-3 text-[11px] leading-relaxed text-ink-400">
          Local research build. Simulated and demo results are always labeled.
        </div>
      </aside>

      <header className="sticky top-0 z-20 flex items-center justify-between border-b border-ink-700/60 bg-ink-900/95 px-4 py-2 backdrop-blur lg:hidden">
        <Brand />
        <button className="rounded-lg p-2 text-ink-300 hover:bg-ink-800" onClick={() => setOpen((o) => !o)} aria-label="Toggle navigation" aria-expanded={open}>
          {open ? <X className="size-5" /> : <Menu className="size-5" />}
        </button>
      </header>
      {open && (
        <div className="sticky top-[73px] z-10 border-b border-ink-700/60 bg-ink-900 lg:hidden">
          <Nav onNavigate={() => setOpen(false)} />
        </div>
      )}

      <main className="px-4 py-6 sm:px-6 lg:ml-64 lg:px-8 lg:py-8">
        <div className="mx-auto max-w-[1400px]">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/cloud" element={<CloudPosture />} />
            <Route path="/iac" element={<IacSecurity />} />
            <Route path="/redteam" element={<RedTeam />} />
            <Route path="/traces" element={<ToolTraces />} />
            <Route path="/paths" element={<AttackPaths />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/runs/:runId" element={<RunDetail />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
      </main>
    </div>
  );
}
