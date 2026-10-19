import { Fragment, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Card,
  CardHeader,
  DecisionBadge,
  EmptyState,
  ErrorState,
  Input,
  JsonView,
  Label,
  Loading,
  ModeBadge,
  Mono,
  PageHeader,
  Pill,
  Select,
  SourceBadge,
  Table,
  Td,
  Th,
  fmtTime,
} from "../components/ui";
import { qs, type ToolCallRow } from "../lib/api";
import { useApi } from "../lib/hooks";

export default function ToolTraces() {
  const [decision, setDecision] = useState("");
  const [tool, setTool] = useState("");
  const [untrusted, setUntrusted] = useState("");
  const [search, setSearch] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const q = useApi<ToolCallRow[]>(`/api/tool-calls${qs({ decision, tool })}`);

  const rows = useMemo(() => {
    const s = search.toLowerCase();
    return (q.data ?? []).filter(
      (r) =>
        (untrusted === "" || String(r.untrusted_context) === untrusted) &&
        (!s || JSON.stringify(r.arguments).toLowerCase().includes(s) || r.rule_ids.join(" ").toLowerCase().includes(s) || r.scenario_id.includes(s)),
    );
  }, [q.data, untrusted, search]);

  return (
    <>
      <PageHeader
        title="Agent Tool Traces"
        description="Every tool call the model proposed, the gateway's decision, and whether it executed. Proposed and executed calls are recorded separately."
      />
      <Card>
        <CardHeader
          title={`${rows.length} tool-call attempts`}
          actions={
            <>
              <label className="flex items-center gap-1.5">
                <Label>Decision</Label>
                <Select value={decision} onChange={(e) => setDecision(e.target.value)}>
                  <option value="">all</option>
                  <option value="allow">allowed</option>
                  <option value="deny">denied</option>
                </Select>
              </label>
              <label className="flex items-center gap-1.5">
                <Label>Tool</Label>
                <Select value={tool} onChange={(e) => setTool(e.target.value)}>
                  <option value="">all</option>
                  <option>search_documents</option>
                  <option>read_file</option>
                  <option>send_message</option>
                  <option>lookup_cloud_config</option>
                </Select>
              </label>
              <label className="flex items-center gap-1.5">
                <Label>Context</Label>
                <Select value={untrusted} onChange={(e) => setUntrusted(e.target.value)}>
                  <option value="">all</option>
                  <option value="true">after untrusted content</option>
                  <option value="false">clean context</option>
                </Select>
              </label>
              <Input placeholder="Search args, rules, scenario" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search" />
            </>
          }
        />
        {q.loading && !q.data ? (
          <Loading />
        ) : q.error ? (
          <ErrorState error={q.error} onRetry={q.reload} />
        ) : !rows.length ? (
          <EmptyState title="No tool calls match">Run red-team scenarios to generate traces.</EmptyState>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Proposed</Th>
                <Th>Run</Th>
                <Th>Tool</Th>
                <Th>Arguments</Th>
                <Th>Context</Th>
                <Th>Decision</Th>
                <Th>Rules</Th>
                <Th>Executed</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <Fragment key={r.id}>
                  <tr className="cursor-pointer hover:bg-ink-800/50" onClick={() => setOpen(open === r.id ? null : r.id)}>
                    <Td className="whitespace-nowrap text-xs text-ink-300">{fmtTime(r.proposed_at)}</Td>
                    <Td>
                      <Link to={`/runs/${r.run_id}`} onClick={(e) => e.stopPropagation()} className="text-xs text-accent-400 hover:underline">
                        {r.scenario_id}
                      </Link>
                      <div className="mt-1 flex flex-wrap gap-1">
                        <ModeBadge mode={r.policy_mode} />
                        {r.is_simulated && <SourceBadge simulated />}
                      </div>
                    </Td>
                    <Td>
                      <Mono className="text-ink-100">{r.tool}</Mono>
                    </Td>
                    <Td className="max-w-[340px]">
                      <Mono>{JSON.stringify(r.arguments).slice(0, 140)}</Mono>
                    </Td>
                    <Td>
                      {r.untrusted_context ? (
                        <Pill className="bg-sev-high/10 text-sev-high ring-sev-high/30" title="Proposed after untrusted content entered the model context">
                          untrusted
                        </Pill>
                      ) : (
                        <Pill className="bg-ink-800 text-ink-300 ring-ink-600">clean</Pill>
                      )}
                    </Td>
                    <Td>
                      <DecisionBadge decision={r.decision} />
                    </Td>
                    <Td>
                      <Mono>{r.rule_ids.join(", ")}</Mono>
                    </Td>
                    <Td>{r.executed ? <span className="text-sev-high">yes</span> : <span className="text-ink-400">no</span>}</Td>
                  </tr>
                  {open === r.id && (
                    <tr>
                      <Td colSpan={8} className="bg-ink-950/60">
                        <div className="grid gap-3 md:grid-cols-2">
                          <div>
                            <Label>Gateway reasons</Label>
                            <ul className="mt-1 list-disc space-y-1 pl-4 text-xs text-ink-300">
                              {r.reasons.map((x, i) => (
                                <li key={i}>{x}</li>
                              ))}
                            </ul>
                            <p className="mt-2 text-xs text-ink-400">Approval: {r.approval}</p>
                          </div>
                          <div>
                            <Label>Arguments</Label>
                            <JsonView value={r.arguments} maxHeight="14rem" />
                          </div>
                        </div>
                      </Td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
