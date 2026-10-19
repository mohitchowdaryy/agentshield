import { Play } from "lucide-react";
import { Link } from "react-router-dom";
import { CountBars, OutcomeByMode, SeverityBars } from "../components/charts";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  Loading,
  Mono,
  PageHeader,
  SEVERITIES,
  SEV_COLOR,
  SourceBadge,
  Stat,
  fmtTime,
} from "../components/ui";
import { api, type Overview as OverviewData } from "../lib/api";
import { useAction, useApi } from "../lib/hooks";

const GW_RULES: Record<string, string> = {
  "GW-001": "tool not allowlisted",
  "GW-002": "invalid arguments",
  "GW-003": "unsafe identifier",
  "GW-004": "out of scope",
  "GW-005": "destination",
  "GW-006": "DLP marker",
  "GW-007": "approval",
  "GW-008": "call budget",
};

export default function Overview() {
  const q = useApi<OverviewData>("/api/overview");
  const demo = useAction(() => api.post("/api/demo"));

  const runDemo = async () => {
    if (await demo.run()) q.reload();
  };

  if (q.loading && !q.data) return <Loading label="Loading overview" />;
  if (q.error) return <ErrorState error={q.error} onRetry={q.reload} />;
  const o = q.data!;
  const empty = o.findings.open + o.findings.resolved === 0 && o.redteam.runs === 0;

  const demoButton = (
    <Button variant="primary" onClick={runDemo} loading={demo.pending}>
      <Play className="size-3.5" /> Run offline demo
    </Button>
  );

  if (empty) {
    return (
      <>
        <PageHeader title="Overview" description="Cloud posture, agent red-team evidence and gateway decisions, derived from persisted results." />
        <Card>
          <EmptyState title="No evidence yet">
            Run the offline demo to scan the synthetic AWS inventory and execute the red-team scenarios against the simulated agent.
            No credentials are needed. Or use <Mono>agentshield demo</Mono> from the CLI.
            <div className="mt-4">{demoButton}</div>
            {demo.error && <p className="mt-2 text-sev-critical">{demo.error}</p>}
          </EmptyState>
        </Card>
      </>
    );
  }

  const sev = SEVERITIES.map((s) => ({ severity: s, count: o.findings.by_severity[s] ?? 0 }));
  const modes = Object.entries(o.redteam.by_mode_outcome).map(([mode, counts]) => ({ mode, ...counts }));
  const denials = Object.entries(o.gateway.denials_by_rule)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => ({ key: k, count: v }));
  const last = o.scans.last;

  return (
    <>
      <PageHeader
        title="Overview"
        description="Every number below is a count over persisted scan and run evidence. There is no composite risk score."
        actions={demoButton}
      />
      {demo.error && <ErrorState error={demo.error} />}

      <div className="mb-5 flex flex-wrap items-center gap-2 rounded-lg border border-ink-700/60 bg-ink-900/60 px-4 py-2.5 text-xs text-ink-300">
        <span className="font-medium text-ink-100">Data provenance:</span>
        {Object.entries(o.findings.by_source).map(([src, n]) => (
          <span key={src} className="flex items-center gap-1.5">
            <SourceBadge source={src} /> {n} open findings
          </span>
        ))}
        <span className="flex items-center gap-1.5">
          <SourceBadge simulated /> {o.redteam.simulated_runs} runs
        </span>
        <span className="flex items-center gap-1.5">
          <SourceBadge /> {o.redteam.live_model_runs} runs
        </span>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat
          label="Open findings"
          value={o.findings.open}
          accent={o.findings.by_severity.critical ? SEV_COLOR.critical : undefined}
          hint={`${o.findings.by_severity.critical ?? 0} critical · ${o.findings.by_severity.high ?? 0} high · ${o.findings.resolved} resolved`}
        />
        <Stat
          label="Red-team runs"
          value={o.redteam.runs}
          hint={`${o.redteam.by_outcome.succeeded ?? 0} attacks succeeded · ${o.redteam.by_outcome.failed ?? 0} failed`}
        />
        <Stat label="Gateway decisions" value={o.gateway.tool_call_attempts} hint={`${o.gateway.allowed} allowed · ${o.gateway.denied} denied · ${o.gateway.executed} executed`} />
        <Stat
          label="Cloud-agent correlations"
          value={o.correlations.total}
          hint={`${o.correlations.by_status.agent_step_observed_in_simulation ?? 0} with agent step observed · ${o.correlations.by_status.modeled ?? 0} modeled`}
        />
      </div>

      <div className="mt-5 grid gap-5 lg:grid-cols-3">
        <Card>
          <CardHeader title="Open findings by severity" subtitle="Configuration risk; exploitability not validated" actions={<Link className="text-xs text-accent-400 hover:underline" to="/findings">View all</Link>} />
          <CardBody>
            <SeverityBars data={sev} />
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Attack outcomes by policy mode" subtitle="Same scenarios; vulnerable vs protected gateway policy" actions={<Link className="text-xs text-accent-400 hover:underline" to="/history">History</Link>} />
          <CardBody>{modes.length ? <OutcomeByMode data={modes} /> : <EmptyState title="No runs yet" />}</CardBody>
        </Card>
        <Card>
          <CardHeader title="Gateway denials by rule" subtitle={denials.map((d) => `${d.key} ${GW_RULES[d.key] ?? ""}`).join(" · ") || "No denials recorded"} actions={<Link className="text-xs text-accent-400 hover:underline" to="/traces">Traces</Link>} />
          <CardBody>{denials.length ? <CountBars data={denials} label="denied calls" /> : <EmptyState title="No denials yet" />}</CardBody>
        </Card>
      </div>

      {last && (
        <Card className="mt-5">
          <CardHeader title="Latest cloud scan" subtitle={fmtTime(last.started_at)} actions={<SourceBadge source={last.source} />} />
          <CardBody className="grid gap-4 text-sm sm:grid-cols-4">
            <div>
              <div className="text-xs text-ink-400">Account</div>
              <Mono>{last.account_id}</Mono>
            </div>
            <div>
              <div className="text-xs text-ink-400">Status</div>
              {last.status}
            </div>
            <div>
              <div className="text-xs text-ink-400">Findings / resources</div>
              {last.summary.findings ?? 0} / {last.summary.resources ?? 0}
            </div>
            <div>
              <div className="text-xs text-ink-400">Collection gaps</div>
              {last.collection_gaps.length ? (
                <Link to="/cloud" className="text-sev-medium hover:underline">
                  {last.collection_gaps.length} (partial results)
                </Link>
              ) : (
                "none"
              )}
            </div>
          </CardBody>
        </Card>
      )}
    </>
  );
}
