import { Download, FileCode2, Play } from "lucide-react";
import { Fragment, useEffect, useMemo, useState } from "react";
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
  Select,
  Stat,
  Table,
  Td,
  Th,
  cn,
  fmtTime,
} from "../components/ui";
import { api, qs, type IacComparison, type IacFinding, type IacScan, type IacScannerInfo } from "../lib/api";
import { useAction, useApi } from "../lib/hooks";

const RESULT_PILL: Record<string, string> = {
  failed: "bg-sev-critical/15 text-sev-critical ring-sev-critical/40",
  passed: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30",
  skipped: "bg-ink-800 text-ink-300 ring-ink-600",
};

function ResultBadge({ result }: { result: string }) {
  return <Pill className={RESULT_PILL[result] ?? RESULT_PILL.skipped}>{result}</Pill>;
}

function SeverityCell({ severity }: { severity: string | null }) {
  return severity ? (
    <span>{severity}</span>
  ) : (
    <span className="text-ink-400" title="Checkov's open-source checks do not report severity; AgentShield does not invent one">
      not provided
    </span>
  );
}

function ComparisonTable({ title, rows, tone }: { title: string; rows: IacFinding[]; tone: string }) {
  if (!rows.length) return null;
  return (
    <div>
      <h3 className={cn("mb-2 text-xs font-semibold uppercase tracking-wider", tone)}>
        {title} ({rows.length})
      </h3>
      <Table>
        <thead>
          <tr>
            <Th>Check</Th>
            <Th>Resource</Th>
            <Th>Title</Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((f) => (
            <tr key={f.id}>
              <Td className="whitespace-nowrap">
                <Mono className="break-normal">{f.check_id}</Mono>
              </Td>
              <Td>
                <Mono>{f.resource}</Mono>
              </Td>
              <Td>{f.check_name}</Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

export default function IacSecurity() {
  const scanner = useApi<IacScannerInfo>("/api/iac/scanner");
  const scans = useApi<IacScan[]>("/api/iac/scans");
  const comparison = useApi<IacComparison>("/api/iac/compare");
  const [scanId, setScanId] = useState<string>("");
  const [result, setResult] = useState<string>("failed");
  const [resource, setResource] = useState<string>("");
  const [search, setSearch] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const findings = useApi<IacFinding[]>(scanId ? `/api/iac/findings${qs({ scan_id: scanId, result, q: search })}` : null);
  const allForScan = useApi<IacFinding[]>(scanId ? `/api/iac/findings${qs({ scan_id: scanId })}` : null);

  const refresh = () => {
    setScanId(""); // jump to the newest completed scan once the list reloads
    scans.reload();
    comparison.reload();
  };
  const demo = useAction(() => api.post<IacComparison>("/api/iac/demo"));
  const scanOne = useAction((target: "insecure" | "secure") => api.post<IacScan>("/api/iac/scans", { target }));

  useEffect(() => {
    const completed = scans.data?.filter((s) => s.status === "completed") ?? [];
    if (completed.length && !completed.some((s) => s.id === scanId)) setScanId(completed[0].id);
  }, [scans.data, scanId]);

  const resources = useMemo(() => [...new Set((allForScan.data ?? []).map((f) => f.resource))].sort(), [allForScan.data]);
  const rows = useMemo(() => (findings.data ?? []).filter((f) => !resource || f.resource === resource), [findings.data, resource]);
  const selected = scans.data?.find((s) => s.id === scanId);
  const cmp = comparison.data;

  return (
    <>
      <PageHeader
        title="Infrastructure-as-Code Security Scanning"
        description="Static analysis of Terraform files with the open-source Checkov scanner. Nothing is deployed and no cloud credentials are used. This is not live cloud posture management (see Cloud Posture for that)."
        actions={
          <>
            <Button
              variant="primary"
              loading={demo.pending}
              disabled={scanner.data?.available === false}
              onClick={async () => {
                if (await demo.run()) refresh();
              }}
            >
              <Play className="size-3.5" /> Run lab demo (scan, fix, rescan)
            </Button>
            <Button
              loading={scanOne.pending}
              disabled={scanner.data?.available === false}
              onClick={async () => {
                if (await scanOne.run("insecure")) refresh();
              }}
            >
              <FileCode2 className="size-3.5" /> Scan insecure
            </Button>
            <Button
              loading={scanOne.pending}
              disabled={scanner.data?.available === false}
              onClick={async () => {
                if (await scanOne.run("secure")) refresh();
              }}
            >
              <FileCode2 className="size-3.5" /> Scan secure
            </Button>
          </>
        }
      />

      <div className="mb-5 flex flex-wrap items-center gap-2 rounded-lg border border-ink-700/60 bg-ink-900/60 px-4 py-2.5 text-xs text-ink-300">
        <span className="font-medium text-ink-100">Scanner:</span>
        {scanner.loading && !scanner.data ? (
          "checking..."
        ) : scanner.data?.available ? (
          <>
            <Pill className="bg-emerald-500/10 text-emerald-300 ring-emerald-500/30">Checkov {scanner.data.version}</Pill>
            <span>runs offline (--skip-download); severity is shown only when Checkov reports it</span>
          </>
        ) : (
          <span className="text-sev-medium">{scanner.data?.error ?? scanner.error}</span>
        )}
      </div>
      {(demo.error || scanOne.error) && <ErrorState error={(demo.error || scanOne.error)!} />}

      <Card>
        <CardHeader
          title="Before and after"
          subtitle={cmp ? `${cmp.before.label} (${fmtTime(cmp.before.started_at)}) vs ${cmp.after.label} (${fmtTime(cmp.after.started_at)}). ${cmp.method}` : "Latest insecure scan vs latest secure scan"}
        />
        {comparison.loading && !comparison.data ? (
          <Loading />
        ) : !cmp ? (
          <EmptyState title="No comparison yet">Run the lab demo to scan the insecure files, the fixed files, and compare the real results.</EmptyState>
        ) : (
          <CardBody className="space-y-5">
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
              <Stat label="Failed before" value={cmp.counts.failed_before} accent="#f0506e" />
              <Stat label="Failed after" value={cmp.counts.failed_after} />
              <Stat label="Fixed" value={cmp.counts.fixed} accent="#34d399" />
              <Stat label="Still failing" value={cmp.counts.still_failing} hint="Same check, same resource" />
              <Stat label="New failures" value={cmp.counts.new_failures} hint="Introduced by the fix" />
            </div>
            <ComparisonTable title="New failures" rows={cmp.new_failures} tone="text-sev-critical" />
            <ComparisonTable title="Still failing" rows={cmp.still_failing} tone="text-sev-medium" />
            <ComparisonTable title="Fixed" rows={cmp.fixed} tone="text-emerald-400" />
            <ComparisonTable title="Not evaluated in the later scan" rows={cmp.not_evaluated_after} tone="text-ink-400" />
          </CardBody>
        )}
      </Card>

      <Card className="mt-5">
        <CardHeader
          title="Findings"
          subtitle={selected ? `${selected.label} · ${selected.target} · Checkov ${selected.scanner_version} · ${selected.summary.resource_count ?? 0} resources` : undefined}
          actions={
            <>
              <Select value={scanId} onChange={(e) => setScanId(e.target.value)} aria-label="Scan">
                {(scans.data ?? []).map((s) => (
                  <option key={s.id} value={s.id} disabled={s.status !== "completed"}>
                    {s.label} · {fmtTime(s.started_at)} {s.status !== "completed" ? "(failed)" : ""}
                  </option>
                ))}
              </Select>
              <label className="flex items-center gap-1.5">
                <Label>Status</Label>
                <Select value={result} onChange={(e) => setResult(e.target.value)} aria-label="Status">
                  <option value="failed">failed</option>
                  <option value="passed">passed</option>
                  <option value="skipped">skipped</option>
                  <option value="">all</option>
                </Select>
              </label>
              <label className="flex items-center gap-1.5">
                <Label>Resource</Label>
                <Select value={resource} onChange={(e) => setResource(e.target.value)} aria-label="Resource">
                  <option value="">all resources</option>
                  {resources.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </Select>
              </label>
              <Input placeholder="Search check or resource" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search" />
              {scanId && (
                <>
                  <LinkButton href={`/api/iac/findings/export${qs({ format: "json", scan_id: scanId })}`}>
                    <Download className="size-3.5" /> JSON
                  </LinkButton>
                  <LinkButton href={`/api/iac/findings/export${qs({ format: "csv", scan_id: scanId })}`}>
                    <Download className="size-3.5" /> CSV
                  </LinkButton>
                </>
              )}
            </>
          }
        />
        {scans.error ? (
          <ErrorState error={scans.error} onRetry={scans.reload} />
        ) : !scans.data?.length ? (
          <EmptyState title="No IaC scans yet">Run the lab demo, or `agentshield iac scan &lt;dir&gt;` from the CLI.</EmptyState>
        ) : findings.loading && !findings.data ? (
          <Loading />
        ) : findings.error ? (
          <ErrorState error={findings.error} onRetry={findings.reload} />
        ) : !rows.length ? (
          <EmptyState title="No findings match these filters" />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Status</Th>
                <Th>Check</Th>
                <Th>Resource</Th>
                <Th>Location</Th>
                <Th>Severity</Th>
                <Th>Title</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <Fragment key={f.id}>
                  <tr className="cursor-pointer hover:bg-ink-800/50" onClick={() => setOpen(open === f.id ? null : f.id)}>
                    <Td>
                      <ResultBadge result={f.result} />
                    </Td>
                    <Td className="whitespace-nowrap">
                      <Mono className="break-normal">{f.check_id}</Mono>
                    </Td>
                    <Td>
                      <Mono>{f.resource}</Mono>
                    </Td>
                    <Td className="whitespace-nowrap">
                      <Mono>
                        {f.file_path}
                        {f.line_start ? `:${f.line_start}-${f.line_end}` : ""}
                      </Mono>
                    </Td>
                    <Td>
                      <SeverityCell severity={f.severity} />
                    </Td>
                    <Td>{f.check_name}</Td>
                  </tr>
                  {open === f.id && (
                    <tr>
                      <Td colSpan={6} className="bg-ink-950/60">
                        <div className="grid gap-4 lg:grid-cols-2">
                          <div className="space-y-3 text-sm">
                            <div>
                              <Label>Remediation</Label>
                              <p className="mt-0.5">{f.remediation}</p>
                            </div>
                            <div>
                              <Label>Checkov guideline</Label>
                              <p className="mt-0.5 text-ink-300">
                                {f.guideline ? (
                                  <a href={f.guideline} target="_blank" rel="noreferrer noopener" className="text-accent-400 hover:underline">
                                    {f.guideline}
                                  </a>
                                ) : (
                                  "Not provided by Checkov in offline mode."
                                )}
                              </p>
                            </div>
                            {!!f.evidence?.evaluated_keys?.length && (
                              <div>
                                <Label>Evaluated keys</Label>
                                <p className="mt-0.5">
                                  <Mono>{f.evidence.evaluated_keys.join(", ")}</Mono>
                                </p>
                              </div>
                            )}
                          </div>
                          <div>
                            <Label>Code ({f.file_path})</Label>
                            {f.evidence?.code?.length ? (
                              <pre className="mt-1 overflow-auto rounded-lg border border-ink-700/70 bg-ink-950 p-3 font-mono text-[11.5px] leading-relaxed text-ink-300">
                                {f.evidence.code.map(([n, line]) => `${String(n).padStart(4, " ")}  ${line}`).join("\n")}
                              </pre>
                            ) : (
                              <JsonView value={f.evidence} maxHeight="12rem" />
                            )}
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
