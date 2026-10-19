// shadcn-style primitives built with Tailwind (hand-written; no shadcn CLI dependency).
import clsx from "clsx";
import { AlertTriangle, ChevronDown, ChevronRight, Inbox, Loader2 } from "lucide-react";
import { useState, type ButtonHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type InputHTMLAttributes } from "react";
import type { Outcome, Severity } from "../lib/api";

export function cn(...args: Parameters<typeof clsx>) {
  return clsx(...args);
}

export function Card({ className, children }: { className?: string; children: ReactNode }) {
  return <section className={cn("rounded-xl border border-ink-700/70 bg-ink-900/80 shadow-sm", className)}>{children}</section>;
}

export function CardHeader({ title, subtitle, actions }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 border-b border-ink-700/60 px-5 py-4">
      <div className="min-w-0">
        <h2 className="text-sm font-semibold tracking-wide text-ink-100">{title}</h2>
        {subtitle && <p className="mt-0.5 text-xs text-ink-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function CardBody({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("px-5 py-4", className)}>{children}</div>;
}

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";
export function Button({
  variant = "secondary",
  size = "md",
  loading,
  className,
  children,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; size?: "sm" | "md"; loading?: boolean }) {
  return (
    <button
      {...props}
      disabled={props.disabled || loading}
      className={cn(
        "inline-flex items-center justify-center gap-1.5 rounded-lg font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        size === "sm" ? "h-7 px-2.5 text-xs" : "h-9 px-3.5 text-sm",
        variant === "primary" && "bg-accent-500 text-white hover:bg-accent-400",
        variant === "secondary" && "border border-ink-700 bg-ink-800 text-ink-100 hover:border-ink-600 hover:bg-ink-700",
        variant === "ghost" && "text-ink-300 hover:bg-ink-800 hover:text-ink-100",
        variant === "danger" && "bg-sev-critical/90 text-white hover:bg-sev-critical",
        className,
      )}
    >
      {loading && <Loader2 className="size-3.5 animate-spin" aria-hidden />}
      {children}
    </button>
  );
}

export function LinkButton({ href, children, className }: { href: string; children: ReactNode; className?: string }) {
  return (
    <a
      href={href}
      className={cn(
        "inline-flex h-7 items-center gap-1.5 rounded-lg border border-ink-700 bg-ink-800 px-2.5 text-xs font-medium text-ink-100 hover:border-ink-600 hover:bg-ink-700",
        className,
      )}
    >
      {children}
    </a>
  );
}

export function Select({ className, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      {...props}
      className={cn(
        "h-8 rounded-lg border border-ink-700 bg-ink-850 px-2 text-xs text-ink-100 focus:border-accent-500 focus:outline-none",
        className,
      )}
    />
  );
}

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={cn(
        "h-8 rounded-lg border border-ink-700 bg-ink-850 px-2.5 text-xs text-ink-100 placeholder:text-ink-400 focus:border-accent-500 focus:outline-none",
        className,
      )}
    />
  );
}

export function Label({ children }: { children: ReactNode }) {
  return <span className="text-[11px] font-medium uppercase tracking-wider text-ink-400">{children}</span>;
}

const SEV: Record<Severity, string> = {
  critical: "bg-sev-critical/15 text-sev-critical ring-sev-critical/40",
  high: "bg-sev-high/15 text-sev-high ring-sev-high/40",
  medium: "bg-sev-medium/15 text-sev-medium ring-sev-medium/40",
  low: "bg-sev-low/15 text-sev-low ring-sev-low/40",
  info: "bg-sev-info/15 text-sev-info ring-sev-info/40",
};
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const SEV_COLOR: Record<Severity, string> = {
  critical: "#f0506e",
  high: "#f28b45",
  medium: "#e7c14d",
  low: "#4fb3e8",
  info: "#8b95ad",
};

export function Pill({ className, children, title }: { className?: string; children: ReactNode; title?: string }) {
  return (
    <span title={title} className={cn("inline-flex items-center gap-1 whitespace-nowrap rounded-md px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset", className)}>
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Pill className={SEV[severity]}>
      <span className="size-1.5 rounded-full bg-current" aria-hidden />
      {severity}
    </Pill>
  );
}

const OUTCOME: Record<Outcome, { cls: string; label: string; title: string }> = {
  succeeded: { cls: "bg-sev-critical/15 text-sev-critical ring-sev-critical/40", label: "attack succeeded", title: "A violation condition was observed in executed actions or outputs" },
  failed: { cls: "bg-emerald-500/15 text-emerald-400 ring-emerald-500/40", label: "attack failed", title: "No violation executed; defenses held" },
  inconclusive: { cls: "bg-sev-medium/15 text-sev-medium ring-sev-medium/40", label: "inconclusive", title: "The attack was not fully exercised" },
  errored: { cls: "bg-fuchsia-500/15 text-fuchsia-400 ring-fuchsia-500/40", label: "errored", title: "The run errored" },
};
export const OUTCOME_COLOR: Record<string, string> = { succeeded: "#f0506e", failed: "#34d399", inconclusive: "#e7c14d", errored: "#e879f9" };

export function OutcomeBadge({ outcome }: { outcome: Outcome }) {
  const o = OUTCOME[outcome] ?? OUTCOME.errored;
  return <Pill className={o.cls} title={o.title}>{o.label}</Pill>;
}

export function SourceBadge({ simulated, source }: { simulated?: boolean; source?: string }) {
  if (simulated) return <Pill className="bg-violet-accent/15 text-violet-accent ring-violet-accent/40" title="Produced by the deterministic offline simulator, not a real model">SIMULATED</Pill>;
  if (source === "demo") return <Pill className="bg-ink-700/50 text-ink-300 ring-ink-600" title="Synthetic demo dataset">DEMO DATA</Pill>;
  if (source === "live") return <Pill className="bg-accent-500/15 text-accent-400 ring-accent-500/40" title="Collected from a real AWS account">LIVE</Pill>;
  return <Pill className="bg-accent-500/15 text-accent-400 ring-accent-500/40" title="Real model provider">LIVE MODEL</Pill>;
}

export function ModeBadge({ mode }: { mode: string }) {
  return mode === "protected" ? (
    <Pill className="bg-emerald-500/10 text-emerald-300 ring-emerald-500/30">protected policy</Pill>
  ) : (
    <Pill className="bg-sev-high/10 text-sev-high ring-sev-high/30" title="Permissive policy inside the synthetic sandbox">vulnerable policy</Pill>
  );
}

export function DecisionBadge({ decision }: { decision: string | null | undefined }) {
  if (decision === "allow") return <Pill className="bg-emerald-500/10 text-emerald-300 ring-emerald-500/30">allowed</Pill>;
  if (decision === "deny") return <Pill className="bg-sev-critical/15 text-sev-critical ring-sev-critical/40">denied</Pill>;
  return <Pill className="bg-ink-700 text-ink-300 ring-ink-600">-</Pill>;
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 px-5 py-10 text-sm text-ink-400" role="status">
      <Loader2 className="size-4 animate-spin" aria-hidden /> {label}...
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div className="m-4 flex flex-wrap items-center gap-3 rounded-lg border border-sev-critical/40 bg-sev-critical/10 px-4 py-3 text-sm text-sev-critical" role="alert">
      <AlertTriangle className="size-4 shrink-0" aria-hidden />
      <span className="min-w-0 flex-1 break-words">{error}</span>
      {onRetry && (
        <Button size="sm" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      <Inbox className="size-8 text-ink-600" aria-hidden />
      <p className="text-sm font-medium text-ink-300">{title}</p>
      {children && <div className="max-w-md text-xs text-ink-400">{children}</div>}
    </div>
  );
}

export function Stat({ label, value, hint, accent }: { label: string; value: ReactNode; hint?: ReactNode; accent?: string }) {
  return (
    <Card className="p-4">
      <Label>{label}</Label>
      <div className="mt-1.5 text-2xl font-semibold tabular-nums" style={accent ? { color: accent } : undefined}>
        {value}
      </div>
      {hint && <div className="mt-1 text-xs text-ink-400">{hint}</div>}
    </Card>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <code className={cn("break-all font-mono text-[12px] text-ink-300", className)}>{children}</code>;
}

export function JsonView({ value, maxHeight = "24rem" }: { value: unknown; maxHeight?: string }) {
  return (
    <pre className="overflow-auto rounded-lg border border-ink-700/70 bg-ink-950 p-3 font-mono text-[11.5px] leading-relaxed text-ink-300" style={{ maxHeight }}>
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function Collapsible({ title, children, defaultOpen = false }: { title: ReactNode; children: ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-lg border border-ink-700/60">
      <button
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-xs font-medium text-ink-300 hover:text-ink-100"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        {open ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}
        {title}
      </button>
      {open && <div className="border-t border-ink-700/60 p-3">{children}</div>}
    </div>
  );
}

export function Th({ children, className, onClick, sorted }: { children?: ReactNode; className?: string; onClick?: () => void; sorted?: "asc" | "desc" | null }) {
  return (
    <th
      scope="col"
      className={cn("whitespace-nowrap px-3 py-2 text-left text-[11px] font-medium uppercase tracking-wider text-ink-400", onClick && "cursor-pointer select-none hover:text-ink-100", className)}
      onClick={onClick}
      aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined}
    >
      {children}
      {sorted && <span className="ml-1">{sorted === "asc" ? "▲" : "▼"}</span>}
    </th>
  );
}

export function Td({ children, className, colSpan }: { children?: ReactNode; className?: string; colSpan?: number }) {
  return (
    <td colSpan={colSpan} className={cn("px-3 py-2.5 align-top text-[13px] text-ink-100", className)}>
      {children}
    </td>
  );
}

export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse [&_tbody_tr]:border-t [&_tbody_tr]:border-ink-700/50">{children}</table>
    </div>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink-100">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-sm text-ink-400">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
