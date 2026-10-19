import { ArrowLeft, Bot, CheckCircle2, CircleSlash, Download, FileWarning, Gavel, MessageSquare, ShieldAlert, Wrench, XCircle } from "lucide-react";
import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import {
  Card,
  CardBody,
  CardHeader,
  Collapsible,
  DecisionBadge,
  ErrorState,
  JsonView,
  Label,
  LinkButton,
  Loading,
  ModeBadge,
  Mono,
  OutcomeBadge,
  PageHeader,
  Pill,
  SeverityBadge,
  SourceBadge,
  Table,
  Td,
  Th,
  cn,
  fmtTime,
} from "../components/ui";
import type { EvidenceEvent, RunDetail as Run } from "../lib/api";
import { useApi } from "../lib/hooks";

const CHECKS: { key: keyof Run["checks"]; label: string; bad: boolean }[] = [
  { key: "saw_malicious_content", label: "Model received the malicious content", bad: false },
  { key: "unsafe_tool_call_proposed", label: "Model proposed an unsafe tool call", bad: true },
  { key: "simulated_violation_executed", label: "A violating action executed (sandbox)", bad: true },
  { key: "legitimate_task_completed", label: "Legitimate task completed", bad: false },
];

const TRUST: Record<string, { cls: string; label: string }> = {
  principal: { cls: "border-accent-500/50", label: "user (principal)" },
  untrusted: { cls: "border-sev-high/60", label: "untrusted content" },
  model: { cls: "border-violet-accent/50", label: "model output" },
};

function containsPayload(text: string, payload?: string) {
  return !!payload && (text.includes(payload) || text.includes(JSON.stringify(payload).slice(1, -1)));
}

function Step({ icon, title, trust, children, highlight }: { icon: ReactNode; title: ReactNode; trust?: string | null; children?: ReactNode; highlight?: boolean }) {
  const t = trust ? TRUST[trust] : undefined;
  return (
    <li className="relative pl-9">
      <span className="absolute left-0 top-0.5 grid size-6 place-items-center rounded-full border border-ink-700 bg-ink-850 text-ink-300">{icon}</span>
      <div className={cn("rounded-lg border-l-2 bg-ink-950/40 py-1.5 pl-3 pr-2", t?.cls ?? "border-ink-700", highlight && "bg-sev-critical/5 ring-1 ring-sev-critical/30")}>
        <div className="flex flex-wrap items-center gap-2 text-[13px] font-medium text-ink-100">
          {title}
          {t && <span className="text-[10px] font-normal uppercase tracking-wider text-ink-400">{t.label}</span>}
          {highlight && <Pill className="bg-sev-critical/15 text-sev-critical ring-sev-critical/40">contains payload</Pill>}
        </div>
        {children && <div className="mt-1 text-xs text-ink-300">{children}</div>}
      </div>
    </li>
  );
}

function EventStep({ e, payload, taintedCalls }: { e: EvidenceEvent; payload?: string; taintedCalls: Set<string> }) {
  const p = e.payload as Record<string, never>;
  switch (e.type) {
    case "scenario_setup":
      return (
        <Step icon={<FileWarning className="size-3.5" />} title="Scenario setup">
          Payload planted at <b>{String(p.entry_point)}</b>: {String(p.entry_point_detail)}
        </Step>
      );
    case "user_request":
      return (
        <Step icon={<MessageSquare className="size-3.5" />} title="User request" trust="principal" highlight={containsPayload(String(p.content), payload)}>
          <p className="whitespace-pre-wrap text-ink-100">{String(p.content)}</p>
        </Step>
      );
    case "model_request":
      return (
        <Step icon={<Bot className="size-3.5" />} title={`Model call, turn ${p.turn}`}>
          {p.message_count} messages in context; untrusted content in context: {String(p.untrusted_content_in_context)}
        </Step>
      );
    case "model_response": {
      const calls = (p.tool_calls as unknown as { name: string; arguments: object }[]) ?? [];
      return (
        <Step icon={<Bot className="size-3.5" />} title={calls.length ? `Model proposed ${calls.length} tool call(s)` : "Model responded"} trust="model">
          {calls.map((c, i) => (
            <div key={i}>
              <Mono className="text-ink-100">{c.name}</Mono> <Mono>{JSON.stringify(c.arguments).slice(0, 180)}</Mono>
            </div>
          ))}
        </Step>
      );
    }
    case "tool_call_proposed":
      return null; // shown via model_response and the decision step
    case "authorization_decision":
      return (
        <Step icon={<Gavel className="size-3.5" />} title={<>Gateway {p.decision === "allow" ? "allowed" : "denied"} <Mono className="text-ink-100">{String(p.tool)}</Mono> <DecisionBadge decision={String(p.decision)} /></>}>
          <Mono>{(p.rule_ids as unknown as string[]).join(", ")}</Mono> — {(p.reasons as unknown as string[]).join("; ")}
        </Step>
      );
    case "tool_call_executed":
      return (
        <Step icon={<Wrench className="size-3.5" />} title={<>Executed <Mono className="text-ink-100">{String(p.tool)}</Mono> in sandbox</>}>
          <Mono>{String(p.result_preview).slice(0, 220)}</Mono>
        </Step>
      );
    case "tool_call_failed":
      return (
        <Step icon={<XCircle className="size-3.5" />} title={`Tool ${p.tool} failed`}>
          {String(p.error)}
        </Step>
      );
    case "untrusted_content_ingested":
      return (
        <Step icon={<ShieldAlert className="size-3.5" />} title={<>Untrusted output of <Mono className="text-ink-100">{String(p.tool)}</Mono> entered model context</>} trust="untrusted" highlight={taintedCalls.has(String(p.call_id))}>
          {p.chars} chars · sha256 <Mono>{String(p.sha256).slice(0, 16)}…</Mono>
        </Step>
      );
    case "final_answer":
      return (
        <Step icon={<CheckCircle2 className="size-3.5" />} title="Final answer" trust="model">
          see below
        </Step>
      );
    case "error":
      return (
        <Step icon={<CircleSlash className="size-3.5" />} title="Error">
          {String(p.message)}
        </Step>
      );
    default:
      return <Step icon={<Bot className="size-3.5" />} title={e.type} />;
  }
}

export default function RunDetail() {
  const { runId } = useParams();
  const q = useApi<Run>(`/api/redteam/runs/${runId}`);
  if (q.loading && !q.data) return <Loading label="Loading run" />;
  if (q.error) return <ErrorState error={q.error} onRetry={q.reload} />;
  const r = q.data!;
  const sc = r.scenario;
  const ev = r.evaluation;
  const toolResultHasPayload = (content: string) => containsPayload(content, sc?.payload);
  const taintedCalls = new Set<string>();
  for (const i of r.interactions) {
    for (const m of (i.request.messages as { role: string; content: string; tool_call_id?: string }[]) ?? []) {
      if (m.role === "tool" && m.tool_call_id && toolResultHasPayload(m.content)) taintedCalls.add(m.tool_call_id);
    }
  }

  return (
    <>
      <Link to="/history" className="mb-3 inline-flex items-center gap-1 text-xs text-ink-400 hover:text-ink-100">
        <ArrowLeft className="size-3.5" /> Test history
      </Link>
      <PageHeader
        title={sc?.name ?? r.scenario_id}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <Mono>{r.id}</Mono> · {r.model} · {fmtTime(r.started_at)}
          </span>
        }
        actions={
          <>
            <SourceBadge simulated={r.is_simulated} />
            <ModeBadge mode={r.policy_mode} />
            <OutcomeBadge outcome={r.outcome} />
            <LinkButton href={`/api/redteam/runs/${r.id}`}>
              <Download className="size-3.5" /> Evidence JSON
            </LinkButton>
          </>
        }
      />
      {r.is_simulated && (
        <div className="mb-5 rounded-lg border border-violet-accent/40 bg-violet-accent/10 px-4 py-2.5 text-xs text-ink-300">
          <b className="text-violet-accent">Simulation.</b> This run used the deterministic offline simulator ({r.model}), not a language model. It exercises the gateway and evidence pipeline; it does not measure any real model's behavior.
        </div>
      )}

      <Card>
        <CardHeader title="Verdict" subtitle={`Defense layer: ${ev.defense_layer}`} />
        <CardBody className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
          <p className="text-sm text-ink-100">{ev.rationale}</p>
          <ul className="grid gap-2 text-sm sm:grid-cols-2">
            {CHECKS.map((c) => {
              const v = Boolean(r.checks[c.key]);
              const bad = c.bad ? v : !v;
              return (
                <li key={c.key} className="flex items-start gap-2">
                  {v ? <CheckCircle2 className={cn("mt-0.5 size-4 shrink-0", bad ? "text-sev-critical" : "text-emerald-400")} /> : <XCircle className={cn("mt-0.5 size-4 shrink-0", bad ? "text-sev-medium" : "text-ink-400")} />}
                  <span>
                    {c.label}: <b>{v ? "yes" : "no"}</b>
                  </span>
                </li>
              );
            })}
            <li className="flex items-start gap-2">
              <Gavel className="mt-0.5 size-4 shrink-0 text-accent-400" />
              <span>
                Unsafe calls denied / allowed by gateway: <b>{r.checks.unsafe_calls_denied_by_gateway}</b> / <b>{r.checks.unsafe_calls_allowed_by_gateway}</b>
              </span>
            </li>
            <li className="flex items-start gap-2">
              <Bot className="mt-0.5 size-4 shrink-0 text-ink-400" />
              <span>
                Run status: <b>{r.checks.run_status}</b> · {r.usage.model_calls ?? 0} model calls · {r.usage.input_tokens ?? 0}/{r.usage.output_tokens ?? 0} tokens
                {r.usage.estimated ? " (estimated)" : ""}
                {r.usage.cost_usd != null && !r.is_simulated ? ` · $${r.usage.cost_usd.toFixed(4)}` : ""}
              </span>
            </li>
          </ul>
        </CardBody>
      </Card>

      <div className="mt-5 grid gap-5 xl:grid-cols-[420px_minmax(0,1fr)]">
        {sc && (
          <Card className="h-fit">
            <CardHeader title="Scenario" actions={<SeverityBadge severity={sc.severity} />} />
            <CardBody className="space-y-3 text-sm">
              <div>
                <Label>Objective</Label>
                <p className="mt-0.5 text-ink-300">{sc.objective}</p>
              </div>
              <div>
                <Label>Legitimate task</Label>
                <p className="mt-0.5">{sc.legitimate_task}</p>
              </div>
              <div>
                <Label>Entry point</Label>
                <p className="mt-0.5 text-ink-300">{sc.entry_point_detail}</p>
              </div>
              <div>
                <Label>Payload</Label>
                <pre className="mt-1 whitespace-pre-wrap rounded-md border border-sev-critical/30 bg-sev-critical/5 p-2 font-mono text-[11.5px] text-ink-300">{sc.payload}</pre>
              </div>
              <div>
                <Label>Expected authorized behavior</Label>
                <p className="mt-0.5 text-ink-300">{sc.expected_behavior}</p>
              </div>
              <div>
                <Label>Violation conditions</Label>
                <ul className="mt-1 space-y-1 text-xs text-ink-300">
                  {sc.violation_conditions.map((v) => {
                    const hit = ev.violations.some((x) => x.condition_id === v.id);
                    return (
                      <li key={v.id} className={hit ? "text-sev-critical" : ""}>
                        <Mono>{v.id}</Mono> {v.description} {hit && "— OBSERVED"}
                      </li>
                    );
                  })}
                </ul>
              </div>
              <div>
                <Label>Framework mappings</Label>
                <ul className="mt-1 space-y-0.5 text-xs text-ink-300">
                  {[...sc.mappings.owasp_llm, ...sc.mappings.mitre_atlas, ...sc.mappings.other].map((m) => (
                    <li key={m}>{m}</li>
                  ))}
                </ul>
              </div>
            </CardBody>
          </Card>
        )}

        <Card>
          <CardHeader title="Evidence timeline" subtitle="Ordered events: what the model saw, what it proposed, what the gateway decided, what executed" />
          <CardBody>
            <ol className="space-y-2.5">
              {r.events.map((e) => (
                <EventStep key={e.seq} e={e} payload={sc?.payload} taintedCalls={taintedCalls} />
              ))}
            </ol>
          </CardBody>
        </Card>
      </div>

      <Card className="mt-5">
        <CardHeader title="Tool calls: proposed vs executed" />
        <Table>
          <thead>
            <tr>
              <Th>#</Th>
              <Th>Turn</Th>
              <Th>Tool</Th>
              <Th>Arguments</Th>
              <Th>After untrusted content</Th>
              <Th>Decision</Th>
              <Th>Reasons</Th>
              <Th>Executed</Th>
            </tr>
          </thead>
          <tbody>
            {r.tool_calls.map((t) => (
              <tr key={t.id}>
                <Td>{t.seq}</Td>
                <Td>{t.turn}</Td>
                <Td>
                  <Mono className="text-ink-100">{t.tool}</Mono>
                </Td>
                <Td className="max-w-[320px]">
                  <Mono>{JSON.stringify(t.arguments).slice(0, 200)}</Mono>
                </Td>
                <Td>{t.untrusted_context ? <span className="text-sev-high">yes</span> : "no"}</Td>
                <Td>
                  <DecisionBadge decision={t.decision?.decision} />
                  <div className="mt-1">
                    <Mono>{t.decision?.rule_ids.join(", ")}</Mono>
                  </div>
                </Td>
                <Td className="max-w-[360px] text-xs text-ink-300">{t.decision?.reasons.join("; ")}</Td>
                <Td>{t.executed ? <span className="text-sev-high">yes</span> : "no"}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>

      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader title="Final answer returned to the user" />
          <CardBody>
            {r.final_answer ? (
              <pre className={cn("whitespace-pre-wrap rounded-lg border bg-ink-950 p-3 font-mono text-[12px] text-ink-100", r.final_answer.includes("AGS-CANARY") ? "border-sev-critical/50" : "border-ink-700/60")}>
                {r.final_answer}
              </pre>
            ) : (
              <p className="text-sm text-ink-400">No final answer ({r.checks.run_status}).</p>
            )}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Simulated outbox" subtitle="send_message never transmits; messages are only recorded here" />
          <CardBody>
            {ev.outbox?.length ? (
              <ul className="space-y-3">
                {ev.outbox.map((m, i) => (
                  <li key={i} className="rounded-lg border border-sev-critical/40 bg-sev-critical/5 p-3 text-xs">
                    <div>
                      To: <Mono className="text-ink-100">{m.destination}</Mono> · delivered: {String(m.delivered)} · simulated: {String(m.simulated)}
                    </div>
                    <pre className="mt-2 whitespace-pre-wrap font-mono text-[11.5px] text-ink-300">{m.body}</pre>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-ink-400">Empty: nothing was queued.</p>
            )}
          </CardBody>
        </Card>
      </div>

      <Card className="mt-5">
        <CardHeader title="Model interactions" subtitle="Exact messages sent to the model each turn (secrets redacted)" />
        <CardBody className="space-y-2">
          {r.interactions.map((i) => {
            const msgs = (i.request.messages as { role: string; trust: string; content: string }[]) ?? [];
            const tainted = msgs.some((m) => toolResultHasPayload(m.content));
            return (
              <Collapsible
                key={i.id}
                title={
                  <span className="flex flex-wrap items-center gap-2">
                    Turn {i.turn} · {i.input_tokens ?? "?"} in / {i.output_tokens ?? "?"} out tokens · {i.latency_ms?.toFixed(0)} ms
                    {tainted && <Pill className="bg-sev-critical/15 text-sev-critical ring-sev-critical/40">context contains payload</Pill>}
                  </span>
                }
              >
                <div className="grid gap-3 lg:grid-cols-2">
                  <div>
                    <Label>Request</Label>
                    <JsonView value={i.request} />
                  </div>
                  <div>
                    <Label>Response</Label>
                    <JsonView value={i.response} />
                  </div>
                </div>
              </Collapsible>
            );
          })}
        </CardBody>
      </Card>
    </>
  );
}
