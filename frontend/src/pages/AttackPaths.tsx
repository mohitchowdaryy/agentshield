import { Background, Controls, MarkerType, ReactFlow, type Edge, type Node } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { RefreshCw } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  JsonView,
  Label,
  Loading,
  PageHeader,
  Pill,
  SeverityBadge,
  cn,
} from "../components/ui";
import { api, type Correlation, type PathEdge, type PathNode } from "../lib/api";
import { useAction, useApi } from "../lib/hooks";

const NODE_STYLE: Record<PathNode["type"], { border: string; tag: string }> = {
  entry: { border: "#f0506e", tag: "attacker-controlled" },
  agent: { border: "#9b7bff", tag: "AI agent" },
  identity: { border: "#5b7cfa", tag: "cloud identity" },
  resource: { border: "#e7c14d", tag: "cloud resource" },
};

const EDGE_STYLE: Record<PathEdge["status"], { stroke: string; dash?: string; label: string }> = {
  observed_in_simulation: { stroke: "#f28b45", label: "observed in sandboxed simulation" },
  modeled: { stroke: "#7d8bad", dash: "6 5", label: "modeled (not exercised)" },
  configured: { stroke: "#4fb3e8", dash: "2 4", label: "configuration fact" },
};

const STATUS_TEXT: Record<Correlation["status"], string> = {
  modeled: "Modeled risk: preconditions exist in configuration; no step was exercised.",
  agent_step_observed_in_simulation:
    "Agent-side step observed in a sandboxed simulation. The cloud step was not exercised; this is not a proven attack path.",
};

function toFlow(c: Correlation): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = c.path.nodes.map((n, i) => ({
    id: n.id,
    position: { x: i * 250, y: i % 2 === 0 ? 40 : 140 },
    data: {
      label: (
        <div className="text-left">
          <div className="text-[10px] uppercase tracking-wider" style={{ color: NODE_STYLE[n.type].border }}>
            {NODE_STYLE[n.type].tag}
          </div>
          <div className="mt-0.5 text-[12px] font-medium leading-snug text-ink-100">{n.label}</div>
        </div>
      ),
    },
    style: {
      background: "#0e1526",
      border: `1.5px solid ${NODE_STYLE[n.type].border}`,
      borderRadius: 10,
      width: 200,
      padding: 10,
    },
    sourcePosition: "right" as never,
    targetPosition: "left" as never,
  }));
  const edges: Edge[] = c.path.edges.map((e, i) => {
    const s = EDGE_STYLE[e.status];
    return {
      id: `e${i}`,
      source: e.source,
      target: e.target,
      label: e.label,
      animated: e.status === "observed_in_simulation",
      style: { stroke: s.stroke, strokeWidth: 2, strokeDasharray: s.dash },
      labelStyle: { fill: "#e4e9f5", fontSize: 11 },
      labelBgStyle: { fill: "#0a0f1c" },
      labelBgPadding: [4, 2] as [number, number],
      markerEnd: { type: MarkerType.ArrowClosed, color: s.stroke },
    };
  });
  return { nodes, edges };
}

export default function AttackPaths() {
  const q = useApi<Correlation[]>("/api/correlations");
  const [selected, setSelected] = useState<string | null>(null);
  const recompute = useAction(() => api.post("/api/correlations/recompute"));

  useEffect(() => {
    if (q.data?.length && !q.data.some((c) => c.id === selected)) setSelected(q.data[0].id);
  }, [q.data, selected]);

  const current = q.data?.find((c) => c.id === selected);
  const flow = useMemo(() => (current ? toFlow(current) : null), [current]);

  return (
    <>
      <PageHeader
        title="Attack Path Explorer"
        description="Transparent correlation of cloud findings with agent identities, tools and red-team evidence. Paths are modeled risks unless a step is marked as observed."
        actions={
          <Button
            loading={recompute.pending}
            onClick={async () => {
              if (await recompute.run()) q.reload();
            }}
          >
            <RefreshCw className="size-3.5" /> Recompute
          </Button>
        }
      />
      {recompute.error && <ErrorState error={recompute.error} />}
      {q.loading && !q.data ? (
        <Loading />
      ) : q.error ? (
        <ErrorState error={q.error} onRetry={q.reload} />
      ) : !q.data?.length ? (
        <Card>
          <EmptyState title="No correlations">
            Correlations appear when a cloud scan has findings that touch an agent's identity or data sources. Run the demo or a scan.
          </EmptyState>
        </Card>
      ) : (
        <div className="grid gap-5 xl:grid-cols-[340px_minmax(0,1fr)]">
          <Card className="h-fit">
            <CardHeader title={`${q.data.length} correlations`} />
            <ul className="divide-y divide-ink-700/50">
              {q.data.map((c) => (
                <li key={c.id}>
                  <button
                    onClick={() => setSelected(c.id)}
                    className={cn("w-full px-5 py-3 text-left hover:bg-ink-800/50", selected === c.id && "bg-accent-500/10")}
                  >
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={c.severity} />
                      <span className="font-mono text-[11px] text-ink-400">{c.rule_id}</span>
                    </div>
                    <div className="mt-1 text-sm text-ink-100">{c.title}</div>
                    <div className="mt-1 text-[11px] text-ink-400">{c.status === "modeled" ? "modeled" : "agent step observed (sandbox)"}</div>
                  </button>
                </li>
              ))}
            </ul>
          </Card>

          {current && flow && (
            <div className="space-y-5">
              <Card>
                <CardHeader title={current.title} subtitle={STATUS_TEXT[current.status]} actions={<SeverityBadge severity={current.severity} />} />
                <div className="h-[340px] border-b border-ink-700/60">
                  <ReactFlow
                    nodes={flow.nodes}
                    edges={flow.edges}
                    fitView
                    fitViewOptions={{ padding: 0.2 }}
                    nodesConnectable={false}
                    proOptions={{ hideAttribution: false }}
                    colorMode="dark"
                    style={{ background: "transparent" }}
                  >
                    <Background color="#1d2943" gap={22} />
                    <Controls showInteractive={false} />
                  </ReactFlow>
                </div>
                <CardBody className="flex flex-wrap gap-4 text-[11px] text-ink-300">
                  {Object.entries(EDGE_STYLE).map(([k, s]) => (
                    <span key={k} className="flex items-center gap-2">
                      <svg width="28" height="6" aria-hidden>
                        <line x1="0" y1="3" x2="28" y2="3" stroke={s.stroke} strokeWidth="2" strokeDasharray={s.dash} />
                      </svg>
                      {s.label}
                    </span>
                  ))}
                </CardBody>
              </Card>
              <Card>
                <CardHeader title="Why this correlation exists" />
                <CardBody className="space-y-4 text-sm">
                  <p className="text-ink-100">{current.explanation}</p>
                  <div className="flex flex-wrap gap-6">
                    <div>
                      <Label>Cloud findings used</Label>
                      <div className="mt-1 flex flex-wrap gap-1.5">
                        {current.finding_ids.length ? (
                          current.finding_ids.map((id) => (
                            <Link key={id} to={`/findings?id=${id}`}>
                              <Pill className="bg-ink-800 text-accent-400 ring-ink-600 hover:ring-accent-500/50">{id}</Pill>
                            </Link>
                          ))
                        ) : (
                          <span className="text-xs text-ink-400">none</span>
                        )}
                      </div>
                    </div>
                    <div>
                      <Label>Red-team runs used</Label>
                      <div className="mt-1 flex flex-wrap gap-1.5">
                        {current.run_ids.length ? (
                          current.run_ids.map((id) => (
                            <Link key={id} to={`/runs/${id}`}>
                              <Pill className="bg-ink-800 text-accent-400 ring-ink-600 hover:ring-accent-500/50">{id}</Pill>
                            </Link>
                          ))
                        ) : (
                          <span className="text-xs text-ink-400">none</span>
                        )}
                      </div>
                    </div>
                  </div>
                  <div>
                    <Label>Evidence record</Label>
                    <JsonView value={current.evidence} maxHeight="20rem" />
                  </div>
                </CardBody>
              </Card>
            </div>
          )}
        </div>
      )}
    </>
  );
}
