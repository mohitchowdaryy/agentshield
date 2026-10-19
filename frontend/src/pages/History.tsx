import { Download } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import {
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  LinkButton,
  Loading,
  ModeBadge,
  Mono,
  OutcomeBadge,
  PageHeader,
  Select,
  SourceBadge,
  Table,
  Td,
  Th,
  fmtTime,
} from "../components/ui";
import { qs, type RunSummary, type Scenario, type TrialSet } from "../lib/api";
import { useApi } from "../lib/hooks";

function Check({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span title={label} className={ok ? "text-ink-100" : "text-ink-400"}>
      {ok ? "yes" : "no"}
    </span>
  );
}

export default function HistoryPage() {
  const [scenario, setScenario] = useState("");
  const [mode, setMode] = useState("");
  const [outcome, setOutcome] = useState("");
  const [provider, setProvider] = useState("");
  const scenarios = useApi<Scenario[]>("/api/redteam/scenarios");
  const runs = useApi<RunSummary[]>(`/api/redteam/runs${qs({ scenario, mode, outcome, provider })}`);
  const trials = useApi<TrialSet[]>(`/api/redteam/trials${qs({ scenario })}`);

  return (
    <>
      <PageHeader
        title="Test History & Evidence"
        description="Every persisted red-team run with its evaluated outcome. Open a run for the full evidence trace."
        actions={
          <>
            <LinkButton href="/api/redteam/runs/export?format=json">
              <Download className="size-3.5" /> JSON (full evidence)
            </LinkButton>
            <LinkButton href="/api/redteam/runs/export?format=csv">
              <Download className="size-3.5" /> CSV
            </LinkButton>
          </>
        }
      />
      <Card>
        <CardHeader
          title={`${runs.data?.length ?? 0} runs`}
          actions={
            <>
              <Select value={scenario} onChange={(e) => setScenario(e.target.value)} aria-label="Scenario">
                <option value="">all scenarios</option>
                {scenarios.data?.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.id}
                  </option>
                ))}
              </Select>
              <Select value={mode} onChange={(e) => setMode(e.target.value)} aria-label="Policy mode">
                <option value="">all modes</option>
                <option value="protected">protected</option>
                <option value="vulnerable">vulnerable</option>
              </Select>
              <Select value={outcome} onChange={(e) => setOutcome(e.target.value)} aria-label="Outcome">
                <option value="">all outcomes</option>
                <option value="succeeded">attack succeeded</option>
                <option value="failed">attack failed</option>
                <option value="inconclusive">inconclusive</option>
                <option value="errored">errored</option>
              </Select>
              <Select value={provider} onChange={(e) => setProvider(e.target.value)} aria-label="Provider">
                <option value="">all providers</option>
                <option value="simulator">simulator</option>
                <option value="anthropic">anthropic</option>
                <option value="ollama">ollama</option>
              </Select>
            </>
          }
        />
        {runs.loading && !runs.data ? (
          <Loading />
        ) : runs.error ? (
          <ErrorState error={runs.error} onRetry={runs.reload} />
        ) : !runs.data?.length ? (
          <EmptyState title="No runs match">Run scenarios from the AI Red Team page or the CLI.</EmptyState>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Started</Th>
                <Th>Scenario</Th>
                <Th>Model</Th>
                <Th>Policy</Th>
                <Th>Outcome</Th>
                <Th>Saw payload</Th>
                <Th>Unsafe proposal</Th>
                <Th>Gateway denied</Th>
                <Th>Violation executed</Th>
                <Th>Task done</Th>
              </tr>
            </thead>
            <tbody>
              {runs.data.map((r) => (
                <tr key={r.id} className="hover:bg-ink-800/50">
                  <Td className="whitespace-nowrap text-xs">
                    <Link to={`/runs/${r.id}`} className="text-accent-400 hover:underline">
                      {fmtTime(r.started_at)}
                    </Link>
                  </Td>
                  <Td>
                    <Mono>{r.scenario_id}</Mono>
                  </Td>
                  <Td>
                    <div className="flex flex-wrap items-center gap-1.5 text-xs">
                      {r.model} <SourceBadge simulated={r.is_simulated} />
                    </div>
                  </Td>
                  <Td>
                    <ModeBadge mode={r.policy_mode} />
                  </Td>
                  <Td>
                    <OutcomeBadge outcome={r.outcome} />
                  </Td>
                  <Td>
                    <Check ok={r.checks.saw_malicious_content} label="Model received the malicious content" />
                  </Td>
                  <Td>
                    <Check ok={r.checks.unsafe_tool_call_proposed} label="Model proposed an unsafe tool call" />
                  </Td>
                  <Td>{r.checks.unsafe_calls_denied_by_gateway}</Td>
                  <Td className={r.checks.simulated_violation_executed ? "text-sev-critical" : ""}>
                    {r.checks.simulated_violation_executed ? "yes (sandbox)" : "no"}
                  </Td>
                  <Td>
                    <Check ok={r.checks.legitimate_task_completed} label="Legitimate task completed" />
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <Card className="mt-5">
        <CardHeader
          title="Repeated trials"
          subtitle="Outcome counts across N identical runs (agentshield redteam run --trials N). Simulator trials are deterministic, so their counts are not a rate."
        />
        {trials.loading && !trials.data ? (
          <Loading />
        ) : trials.error ? (
          <ErrorState error={trials.error} onRetry={trials.reload} />
        ) : !trials.data?.length ? (
          <EmptyState title="No trial sets yet">Run a scenario with --trials N from the CLI to record outcome counts.</EmptyState>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Started</Th>
                <Th>Scenario</Th>
                <Th>Model</Th>
                <Th>Policy</Th>
                <Th>Trials</Th>
                <Th>Attack succeeded</Th>
                <Th>Attack failed</Th>
                <Th>Inconclusive</Th>
                <Th>Errored</Th>
                <Th>Unsafe proposal</Th>
                <Th>Task done</Th>
              </tr>
            </thead>
            <tbody>
              {trials.data.map((t) => (
                <tr key={t.id} className="hover:bg-ink-800/50">
                  <Td className="whitespace-nowrap text-xs">
                    {t.run_ids.length ? (
                      <Link to={`/runs/${t.run_ids[0]}`} className="text-accent-400 hover:underline">
                        {fmtTime(t.created_at)}
                      </Link>
                    ) : (
                      fmtTime(t.created_at)
                    )}
                  </Td>
                  <Td>
                    <Mono>{t.scenario_id}</Mono>
                  </Td>
                  <Td>
                    <div className="flex flex-wrap items-center gap-1.5 text-xs">
                      {t.model} <SourceBadge simulated={t.is_simulated} />
                    </div>
                  </Td>
                  <Td>
                    <ModeBadge mode={t.policy_mode} />
                  </Td>
                  <Td className="tabular-nums">{t.trials}</Td>
                  <Td className={(t.outcome_counts.succeeded ?? 0) > 0 ? "tabular-nums text-sev-critical" : "tabular-nums"}>
                    {t.outcome_counts.succeeded ?? 0} / {t.trials}
                  </Td>
                  <Td className="tabular-nums">
                    {t.outcome_counts.failed ?? 0} / {t.trials}
                  </Td>
                  <Td className="tabular-nums">
                    {t.outcome_counts.inconclusive ?? 0} / {t.trials}
                  </Td>
                  <Td className="tabular-nums">
                    {t.outcome_counts.errored ?? 0} / {t.trials}
                  </Td>
                  <Td className="tabular-nums">
                    {t.check_counts.unsafe_tool_call_proposed ?? 0} / {t.trials}
                  </Td>
                  <Td className="tabular-nums">
                    {t.check_counts.legitimate_task_completed ?? 0} / {t.trials}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
