import { Download, X } from "lucide-react";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  Input,
  JsonView,
  Label,
  LinkButton,
  Loading,
  Mono,
  PageHeader,
  Pill,
  SEVERITIES,
  Select,
  SeverityBadge,
  SourceBadge,
  Table,
  Td,
  Th,
  cn,
  fmtTime,
} from "../components/ui";
import { qs, type Finding, type Severity } from "../lib/api";
import { useApi } from "../lib/hooks";

type SortKey = "severity" | "rule_id" | "resource" | "last_seen" | "first_seen";

export default function Findings() {
  const [params, setParams] = useSearchParams();
  const [sev, setSev] = useState<Severity[]>([]);
  const [status, setStatus] = useState("open");
  const [source, setSource] = useState("");
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<SortKey>("severity");
  const [order, setOrder] = useState<"asc" | "desc">("asc");
  const selectedId = params.get("id");

  const filter = { severity: sev, status, source, q: search, sort, order };
  const list = useApi<Finding[]>(`/api/findings${qs(filter)}`);
  const detail = useApi<Finding>(selectedId ? `/api/findings/${selectedId}` : null);

  const toggleSort = (k: SortKey) => {
    if (sort === k) setOrder(order === "asc" ? "desc" : "asc");
    else {
      setSort(k);
      setOrder(k === "last_seen" || k === "first_seen" ? "desc" : "asc");
    }
  };
  const sorted = (k: SortKey) => (sort === k ? order : null);
  const exportQs = (format: string) => `/api/findings/export${qs({ format, severity: sev, status, source })}`;

  return (
    <>
      <PageHeader
        title="Findings & Remediation"
        description="Deduplicated cloud findings with evidence and remediation. Each describes configuration risk; exploitability is not validated."
        actions={
          <>
            <LinkButton href={exportQs("json")}>
              <Download className="size-3.5" /> JSON
            </LinkButton>
            <LinkButton href={exportQs("csv")}>
              <Download className="size-3.5" /> CSV
            </LinkButton>
          </>
        }
      />
      <div className={cn("grid gap-5", selectedId && "xl:grid-cols-[minmax(0,1fr)_480px]")}>
        <Card>
          <CardHeader
            title={`${list.data?.length ?? 0} findings`}
            actions={
              <>
                <div className="flex flex-wrap items-center gap-1" role="group" aria-label="Severity filter">
                  {SEVERITIES.map((s) => (
                    <button
                      key={s}
                      onClick={() => setSev(sev.includes(s) ? sev.filter((x) => x !== s) : [...sev, s])}
                      aria-pressed={sev.includes(s)}
                      className={cn("rounded-md opacity-50 transition-opacity hover:opacity-90", sev.includes(s) && "opacity-100")}
                    >
                      <SeverityBadge severity={s} />
                    </button>
                  ))}
                </div>
                <Select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
                  <option value="open">open</option>
                  <option value="resolved">resolved</option>
                  <option value="">any status</option>
                </Select>
                <Select value={source} onChange={(e) => setSource(e.target.value)} aria-label="Source">
                  <option value="">all sources</option>
                  <option value="live">live</option>
                  <option value="demo">demo</option>
                </Select>
                <Input placeholder="Search title, ARN, rule" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search findings" />
              </>
            }
          />
          {list.loading && !list.data ? (
            <Loading />
          ) : list.error ? (
            <ErrorState error={list.error} onRetry={list.reload} />
          ) : !list.data?.length ? (
            <EmptyState title="No findings match these filters" />
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th onClick={() => toggleSort("severity")} sorted={sorted("severity")}>
                    Severity
                  </Th>
                  <Th onClick={() => toggleSort("rule_id")} sorted={sorted("rule_id")}>
                    Rule
                  </Th>
                  <Th>Title</Th>
                  <Th onClick={() => toggleSort("resource")} sorted={sorted("resource")}>
                    Resource
                  </Th>
                  <Th>Source</Th>
                  <Th onClick={() => toggleSort("last_seen")} sorted={sorted("last_seen")}>
                    Last seen
                  </Th>
                </tr>
              </thead>
              <tbody>
                {list.data.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => setParams({ id: f.id })}
                    className={cn("cursor-pointer hover:bg-ink-800/50", selectedId === f.id && "bg-accent-500/10")}
                  >
                    <Td>
                      <SeverityBadge severity={f.severity} />
                    </Td>
                    <Td className="whitespace-nowrap">
                      <Mono className="break-normal">{f.rule_id}</Mono>
                    </Td>
                    <Td>{f.title}</Td>
                    <Td className="min-w-[200px] max-w-[300px]">
                      <Mono>{f.resource_arn}</Mono>
                      <div className="text-[11px] text-ink-400">
                        {f.account_id} · {f.region}
                      </div>
                    </Td>
                    <Td>
                      <SourceBadge source={f.source} />
                    </Td>
                    <Td className="whitespace-nowrap text-xs">{fmtTime(f.last_seen_at)}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>

        {selectedId && (
          <Card className="h-fit xl:sticky xl:top-6">
            <CardHeader
              title={detail.data?.title ?? "Finding"}
              subtitle={detail.data && <Mono>{detail.data.rule_id}</Mono>}
              actions={
                <Button variant="ghost" size="sm" onClick={() => setParams({})} aria-label="Close detail">
                  <X className="size-4" />
                </Button>
              }
            />
            {detail.loading && !detail.data ? (
              <Loading />
            ) : detail.error ? (
              <ErrorState error={detail.error} onRetry={detail.reload} />
            ) : detail.data ? (
              <CardBody className="space-y-4 text-sm">
                <div className="flex flex-wrap gap-1.5">
                  <SeverityBadge severity={detail.data.severity} />
                  <SourceBadge source={detail.data.source} />
                  <Pill className="bg-ink-800 text-ink-300 ring-ink-600">{detail.data.status}</Pill>
                  <Pill className="bg-ink-800 text-ink-300 ring-ink-600" title="Static configuration analysis; no exploitation attempted">
                    exploitability: {detail.data.exploitability.replace("_", " ")}
                  </Pill>
                </div>
                <div>
                  <Label>Resource</Label>
                  <div className="mt-0.5">
                    <Mono>{detail.data.resource_arn}</Mono>
                  </div>
                  <div className="text-xs text-ink-400">
                    {detail.data.resource_type} · account {detail.data.account_id} · {detail.data.region}
                  </div>
                </div>
                <div>
                  <Label>Remediation</Label>
                  <p className="mt-0.5 text-ink-100">{detail.data.remediation}</p>
                </div>
                <div>
                  <Label>Evidence</Label>
                  <JsonView value={detail.data.evidence} maxHeight="18rem" />
                </div>
                {!!detail.data.references?.length && (
                  <div>
                    <Label>References</Label>
                    <ul className="mt-1 space-y-1 text-xs">
                      {detail.data.references.map((r) => (
                        <li key={r}>
                          <a href={r} target="_blank" rel="noreferrer noopener" className="break-all text-accent-400 hover:underline">
                            {r}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <Label>First seen</Label>
                    <div>{fmtTime(detail.data.first_seen_at)}</div>
                  </div>
                  <div>
                    <Label>Observed in scans</Label>
                    <div>{detail.data.observations?.length ?? 0}</div>
                  </div>
                </div>
                {!!detail.data.correlations?.length && (
                  <Link to="/paths" className="block text-xs text-accent-400 hover:underline">
                    Used by {detail.data.correlations.length} cloud-agent correlation(s) →
                  </Link>
                )}
                <div className="text-[11px] text-ink-400">
                  Fingerprint <Mono>{detail.data.fingerprint.slice(0, 16)}…</Mono>
                </div>
              </CardBody>
            ) : null}
          </Card>
        )}
      </div>
    </>
  );
}
