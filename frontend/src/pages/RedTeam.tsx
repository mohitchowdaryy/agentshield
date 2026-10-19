import { Play, PlayCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  Collapsible,
  EmptyState,
  ErrorState,
  Label,
  Loading,
  ModeBadge,
  Mono,
  OutcomeBadge,
  PageHeader,
  Pill,
  Select,
  SeverityBadge,
  SourceBadge,
  Table,
  Td,
  Th,
} from "../components/ui";
import { api, type RunDetail, type RunSummary, type Scenario, type SettingsView } from "../lib/api";
import { useAction, useApi } from "../lib/hooks";

const ENTRY_LABEL: Record<string, string> = {
  user_prompt: "User prompt (direct)",
  retrieved_document: "Retrieved document (indirect)",
  tool_output: "Tool output (indirect)",
};

type ModelChoice = "simulator:naive" | "simulator:resistant" | "anthropic:" | "ollama:";

export default function RedTeam() {
  const scenarios = useApi<Scenario[]>("/api/redteam/scenarios");
  const runs = useApi<RunSummary[]>("/api/redteam/runs");
  const settings = useApi<SettingsView>("/api/settings");
  const navigate = useNavigate();
  const [mode, setMode] = useState<"protected" | "vulnerable">("protected");
  const [model, setModel] = useState<ModelChoice>("simulator:naive");
  const [provider, profile] = model.split(":");
  const runOne = useAction((scenario_id: string) =>
    api.post<RunDetail>("/api/redteam/runs", { scenario_id, mode, provider, profile: profile || "naive" }),
  );
  const runAll = useAction(() => api.post<RunSummary[]>("/api/redteam/run-all", { provider, profile: profile || "naive" }));
  const anthropicReady = settings.data?.integrations.anthropic.configured;

  // Latest outcome per scenario x mode x model, from persisted runs.
  const matrix = useMemo(() => {
    const m = new Map<string, RunSummary>();
    for (const r of runs.data ?? []) {
      const k = `${r.scenario_id}|${r.policy_mode}|${r.model}`;
      if (!m.has(k)) m.set(k, r); // runs arrive newest first
    }
    return m;
  }, [runs.data]);
  const models = useMemo(() => [...new Set((runs.data ?? []).map((r) => r.model))].sort(), [runs.data]);

  const go = async (id: string) => {
    const r = await runOne.run(id);
    if (r) navigate(`/runs/${r.id}`);
  };

  return (
    <>
      <PageHeader
        title="AI Red Team"
        description="Adversarial scenarios against the local test agent you own. All targets, files and destinations are synthetic; the outbound tool never sends anything."
        actions={
          <>
            <label className="flex items-center gap-2">
              <Label>Policy</Label>
              <Select value={mode} onChange={(e) => setMode(e.target.value as typeof mode)} aria-label="Policy mode">
                <option value="protected">protected</option>
                <option value="vulnerable">vulnerable (sandboxed)</option>
              </Select>
            </label>
            <label className="flex items-center gap-2">
              <Label>Model</Label>
              <Select value={model} onChange={(e) => setModel(e.target.value as ModelChoice)} aria-label="Model">
                <option value="simulator:naive">Simulator: naive (follows injected instructions)</option>
                <option value="simulator:resistant">Simulator: resistant</option>
                <option value="anthropic:" disabled={!anthropicReady}>
                  Anthropic ({settings.data?.integrations.anthropic.model}){anthropicReady ? "" : " - not configured"}
                </option>
                <option value="ollama:">Ollama local ({settings.data?.integrations.ollama.model})</option>
              </Select>
            </label>
            <Button
              loading={runAll.pending}
              onClick={async () => {
                if (await runAll.run()) runs.reload();
              }}
            >
              <PlayCircle className="size-3.5" /> Run all (both modes)
            </Button>
          </>
        }
      />
      {provider === "anthropic" && (
        <div className="mb-4 rounded-lg border border-sev-medium/40 bg-sev-medium/10 px-4 py-2.5 text-xs text-sev-medium">
          Live model runs send synthetic scenario data to the provider API and incur charges.
        </div>
      )}
      {provider === "ollama" && (
        <div className="mb-4 rounded-lg border border-accent-500/40 bg-accent-500/10 px-4 py-2.5 text-xs text-ink-300">
          Runs a real open-weight model locally through Ollama: free and offline, but a run can take a minute or more. Requires Ollama running with the model pulled.
        </div>
      )}
      {(runOne.error || runAll.error) && <ErrorState error={(runOne.error || runAll.error)!} />}

      {scenarios.loading && !scenarios.data ? (
        <Loading />
      ) : scenarios.error ? (
        <ErrorState error={scenarios.error} onRetry={scenarios.reload} />
      ) : (
        <div className="grid gap-5 xl:grid-cols-3">
          {scenarios.data!.map((s) => {
            const d = s.definition;
            return (
              <Card key={s.id} className="flex flex-col">
                <CardHeader title={d.name} subtitle={<Mono>{s.id}</Mono>} actions={<SeverityBadge severity={s.severity} />} />
                <CardBody className="flex flex-1 flex-col gap-3 text-sm">
                  <div className="flex flex-wrap gap-1.5">
                    <Pill className="bg-ink-800 text-ink-300 ring-ink-600">{ENTRY_LABEL[d.entry_point] ?? d.entry_point}</Pill>
                    {d.mappings.owasp_llm.map((m) => (
                      <Pill key={m} className="bg-accent-500/10 text-accent-400 ring-accent-500/30" title={m}>
                        {m.split(" ")[0]}
                      </Pill>
                    ))}
                    {d.mappings.mitre_atlas.map((m) => (
                      <Pill key={m} className="bg-violet-accent/10 text-violet-accent ring-violet-accent/30" title={m}>
                        {m.split(" ")[0]}
                      </Pill>
                    ))}
                  </div>
                  <p className="text-ink-300">{d.objective}</p>
                  <div>
                    <Label>Legitimate task</Label>
                    <p className="mt-0.5 text-ink-100">{d.legitimate_task}</p>
                  </div>
                  <div>
                    <Label>Attacker entry point</Label>
                    <p className="mt-0.5 text-ink-300">{d.entry_point_detail}</p>
                  </div>
                  <Collapsible title="Payload, expected behavior and violation conditions">
                    <div className="space-y-3 text-xs">
                      <pre className="whitespace-pre-wrap rounded-md border border-sev-critical/30 bg-sev-critical/5 p-2 font-mono text-[11.5px] text-ink-300">{d.payload}</pre>
                      <p className="text-ink-300">{d.expected_behavior}</p>
                      <ul className="list-disc space-y-1 pl-4 text-ink-300">
                        {d.violation_conditions.map((v) => (
                          <li key={v.id}>
                            <Mono>{v.id}</Mono> {v.description}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </Collapsible>
                  <div className="mt-auto pt-2">
                    <Button variant="primary" loading={runOne.pending} onClick={() => go(s.id)}>
                      <Play className="size-3.5" /> Run ({mode})
                    </Button>
                  </div>
                </CardBody>
              </Card>
            );
          })}
        </div>
      )}

      <Card className="mt-5">
        <CardHeader title="Latest result matrix" subtitle="Most recent persisted run per scenario, policy mode and model" />
        {runs.error ? (
          <ErrorState error={runs.error} onRetry={runs.reload} />
        ) : !runs.data?.length ? (
          <EmptyState title="No runs yet">Run a scenario above or use Run all.</EmptyState>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Scenario</Th>
                <Th>Model</Th>
                <Th>Vulnerable policy</Th>
                <Th>Protected policy</Th>
              </tr>
            </thead>
            <tbody>
              {(scenarios.data ?? []).flatMap((s) =>
                models.map((m) => {
                  const cells = (["vulnerable", "protected"] as const).map((md) => matrix.get(`${s.id}|${md}|${m}`));
                  if (!cells.some(Boolean)) return null;
                  const sim = cells.find(Boolean)!.is_simulated;
                  return (
                    <tr key={`${s.id}-${m}`}>
                      <Td>
                        <Mono>{s.id}</Mono>
                      </Td>
                      <Td>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-xs">{m}</span>
                          <SourceBadge simulated={sim} />
                        </div>
                      </Td>
                      {cells.map((r, i) => (
                        <Td key={i}>
                          {r ? (
                            <Link to={`/runs/${r.id}`} className="inline-flex flex-wrap items-center gap-1.5 hover:opacity-80">
                              <OutcomeBadge outcome={r.outcome} />
                              <span className="text-[11px] text-ink-400">defense: {r.defense_layer}</span>
                            </Link>
                          ) : (
                            <span className="text-xs text-ink-400">not run</span>
                          )}
                        </Td>
                      ))}
                    </tr>
                  );
                }),
              )}
            </tbody>
          </Table>
        )}
      </Card>
      <p className="mt-3 text-xs text-ink-400">
        <ModeBadge mode="vulnerable" /> uses a permissive policy inside the synthetic sandbox to show impact. It never disables operating-system, cloud or network controls.
      </p>
    </>
  );
}
