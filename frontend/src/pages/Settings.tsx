import { useState } from "react";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  ErrorState,
  Input,
  JsonView,
  Label,
  Loading,
  Mono,
  PageHeader,
  Pill,
} from "../components/ui";
import { getToken, setToken, type Agent, type SettingsView } from "../lib/api";
import { useApi } from "../lib/hooks";

function Status({ ok, children }: { ok: boolean; children: string }) {
  return <Pill className={ok ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30" : "bg-sev-medium/10 text-sev-medium ring-sev-medium/30"}>{children}</Pill>;
}

const CLI = [
  ["agentshield doctor", "Check environment, database and integrations"],
  ["agentshield demo", "Offline demo: demo scan + simulated red-team matrix + correlation"],
  ["agentshield scan aws --profile <name> -r us-east-1", "Read-only AWS posture scan"],
  ["agentshield redteam list", "List scenarios with OWASP / ATLAS mappings"],
  ["agentshield redteam run --scenario indirect-injection --mode protected", "Run one scenario"],
  ["agentshield redteam run-all --provider anthropic", "Run all scenarios against a live model (incurs charges)"],
  ["agentshield evaluate --run-id <id>", "Re-evaluate a run from stored evidence"],
  ["agentshield report --format json --output report.json", "Export evidence"],
];

export default function SettingsPage() {
  const s = useApi<SettingsView>("/api/settings");
  const agents = useApi<Agent[]>("/api/agents");
  const [token, setTok] = useState(getToken());
  const [saved, setSaved] = useState(false);

  return (
    <>
      <PageHeader title="Settings & Integrations" description="Read-only view of server configuration. Secrets are never returned by the API." />
      {s.loading && !s.data ? (
        <Loading />
      ) : s.error ? (
        <ErrorState error={s.error} onRetry={s.reload} />
      ) : (
        <div className="grid gap-5 lg:grid-cols-2">
          <Card>
            <CardHeader title="Integrations" />
            <CardBody className="space-y-4 text-sm">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="font-medium">Offline simulator</div>
                  <div className="text-xs text-ink-400">{s.data!.integrations.simulator.note}</div>
                </div>
                <Status ok>available</Status>
              </div>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="font-medium">Anthropic (live model)</div>
                  <div className="text-xs text-ink-400">
                    Model <Mono>{s.data!.integrations.anthropic.model}</Mono>. Set <Mono>ANTHROPIC_API_KEY</Mono> in the API server environment.
                  </div>
                </div>
                <Status ok={s.data!.integrations.anthropic.configured}>{s.data!.integrations.anthropic.configured ? "configured" : "not configured"}</Status>
              </div>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="font-medium">AWS (read-only)</div>
                  <div className="text-xs text-ink-400">
                    Profile: <Mono>{s.data!.integrations.aws.profile ?? "default chain"}</Mono>. {s.data!.integrations.aws.note}
                  </div>
                </div>
                <Status ok={!!s.data!.integrations.aws.profile}>{s.data!.integrations.aws.profile ? "profile set" : "default chain"}</Status>
              </div>
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="Server security posture" />
            <CardBody className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <Label>Bind</Label>
                <div>
                  <Mono>{s.data!.bind}</Mono>
                </div>
              </div>
              <div>
                <Label>Database</Label>
                <div>{s.data!.database}</div>
              </div>
              <div>
                <Label>CORS origins</Label>
                <div className="space-y-0.5">
                  {s.data!.cors_origins.map((o) => (
                    <div key={o}>
                      <Mono>{o}</Mono>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <Label>Mutation token</Label>
                <div>{s.data!.api_token_required ? "required" : "not required (local default)"}</div>
              </div>
              <div>
                <Label>Max request body</Label>
                <div>{(s.data!.max_request_bytes / 1024).toFixed(0)} KiB</div>
              </div>
              <div>
                <Label>Agent limits</Label>
                <div>
                  {s.data!.agent.max_turns} turns · {s.data!.agent.timeout_s}s timeout · {s.data!.agent.max_retries} retries
                </div>
              </div>
            </CardBody>
          </Card>

          {s.data!.api_token_required && (
            <Card>
              <CardHeader title="API token" subtitle="Stored only in this browser tab's session storage" />
              <CardBody className="flex flex-wrap items-end gap-2">
                <Input type="password" value={token} onChange={(e) => setTok(e.target.value)} placeholder="AGENTSHIELD_API_TOKEN" aria-label="API token" />
                <Button
                  onClick={() => {
                    setToken(token);
                    setSaved(true);
                  }}
                >
                  Save
                </Button>
                {saved && <span className="text-xs text-emerald-400">saved for this session</span>}
              </CardBody>
            </Card>
          )}

          <Card>
            <CardHeader title="CLI reference" />
            <CardBody className="space-y-2">
              {CLI.map(([cmd, desc]) => (
                <div key={cmd}>
                  <Mono className="text-ink-100">{cmd}</Mono>
                  <div className="text-xs text-ink-400">{desc}</div>
                </div>
              ))}
            </CardBody>
          </Card>

          <Card className="lg:col-span-2">
            <CardHeader title="Agent profiles & gateway policies" subtitle="Policies are configuration files, separate from model prompts" />
            <CardBody className="space-y-3">
              {agents.error && <ErrorState error={agents.error} />}
              {agents.data?.map((a) => (
                <div key={a.id}>
                  <div className="text-sm font-medium">{a.name}</div>
                  <div className="mb-2 text-xs text-ink-400">
                    {a.description} Identity: <Mono>{a.cloud_identity_arn ?? "none"}</Mono>
                  </div>
                  <JsonView value={a.profile} maxHeight="20rem" />
                </div>
              ))}
            </CardBody>
          </Card>
        </div>
      )}
    </>
  );
}
