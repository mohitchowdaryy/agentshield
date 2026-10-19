import { CloudCog, Database } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ErrorState,
  Input,
  Label,
  Loading,
  Mono,
  PageHeader,
  SeverityBadge,
  SourceBadge,
  Table,
  Td,
  Th,
  cn,
  fmtTime,
} from "../components/ui";
import { api, type Resource, type Scan } from "../lib/api";
import { useAction, useApi } from "../lib/hooks";

export default function CloudPosture() {
  const scans = useApi<Scan[]>("/api/scans");
  const resources = useApi<Resource[]>("/api/resources");
  const [selected, setSelected] = useState<string | null>(null);
  const detail = useApi<Scan>(selected ? `/api/scans/${selected}` : null);
  const [profile, setProfile] = useState("");
  const [regions, setRegions] = useState("");
  const scan = useAction((body: object) => api.post<Scan>("/api/scans", body));

  useEffect(() => {
    if (!selected && scans.data?.length) setSelected(scans.data[0].id);
  }, [scans.data, selected]);

  const start = async (body: object) => {
    const s = await scan.run(body);
    if (s) {
      scans.reload();
      resources.reload();
      setSelected(s.id);
    }
  };

  const regionList = regions.split(/[\s,]+/).filter(Boolean);

  return (
    <>
      <PageHeader
        title="Cloud Posture"
        description="Read-only AWS posture scanning. Findings describe configuration risk; none of them claims a resource was exploited."
      />

      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader title="Scan a live AWS account" subtitle="Uses the standard AWS credential chain on the API host. Only Get/List/Describe calls are made." />
          <CardBody className="flex flex-wrap items-end gap-3">
            <label className="flex flex-col gap-1">
              <Label>Profile (optional)</Label>
              <Input value={profile} onChange={(e) => setProfile(e.target.value)} placeholder="default chain" />
            </label>
            <label className="flex flex-col gap-1">
              <Label>Regions (optional)</Label>
              <Input value={regions} onChange={(e) => setRegions(e.target.value)} placeholder="us-east-1, eu-west-1" />
            </label>
            <Button variant="primary" loading={scan.pending} onClick={() => start({ source: "aws", profile: profile || null, regions: regionList })}>
              <CloudCog className="size-3.5" /> Run AWS scan
            </Button>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Demo inventory" subtitle="Synthetic account 111122223333 evaluated by the same rules. Results are labeled DEMO DATA." />
          <CardBody>
            <Button loading={scan.pending} onClick={() => start({ source: "demo" })}>
              <Database className="size-3.5" /> Run demo scan
            </Button>
          </CardBody>
        </Card>
      </div>
      {scan.error && <ErrorState error={scan.error} />}

      <Card className="mt-5">
        <CardHeader title="Scan history" subtitle="Repeated scans deduplicate findings by stable fingerprint" />
        {scans.loading && !scans.data ? (
          <Loading />
        ) : scans.error ? (
          <ErrorState error={scans.error} onRetry={scans.reload} />
        ) : !scans.data?.length ? (
          <EmptyState title="No scans yet">Run a demo or AWS scan above.</EmptyState>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Started</Th>
                <Th>Source</Th>
                <Th>Account</Th>
                <Th>Regions</Th>
                <Th>Status</Th>
                <Th>Findings</Th>
                <Th>Gaps</Th>
              </tr>
            </thead>
            <tbody>
              {scans.data.map((s) => (
                <tr key={s.id} onClick={() => setSelected(s.id)} className={cn("cursor-pointer hover:bg-ink-800/50", selected === s.id && "bg-accent-500/10")}>
                  <Td>{fmtTime(s.started_at)}</Td>
                  <Td>
                    <SourceBadge source={s.source} />
                  </Td>
                  <Td>
                    <Mono>{s.account_id}</Mono>
                  </Td>
                  <Td>{s.regions.join(", ")}</Td>
                  <Td>{s.status}</Td>
                  <Td>{s.summary.findings ?? 0}</Td>
                  <Td className={s.collection_gaps.length ? "text-sev-medium" : ""}>{s.collection_gaps.length}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      {detail.data && (
        <Card className="mt-5">
          <CardHeader
            title={`Scan ${detail.data.id}`}
            subtitle={<>Caller: <Mono>{detail.data.caller_arn ?? "-"}</Mono></>}
            actions={<SourceBadge source={detail.data.source} />}
          />
          <CardBody className="space-y-5">
            {detail.data.collection_gaps.length > 0 && (
              <div>
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-sev-medium">Collection gaps (partial results)</h3>
                <p className="mb-2 text-xs text-ink-400">Rules skip evidence that could not be collected, so these resources may have unreported issues.</p>
                <Table>
                  <thead>
                    <tr>
                      <Th>Service</Th>
                      <Th>Operation</Th>
                      <Th>Resource</Th>
                      <Th>Error</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {detail.data.collection_gaps.map((g, i) => (
                      <tr key={i}>
                        <Td>{g.service}</Td>
                        <Td>{g.operation}</Td>
                        <Td>
                          <Mono>{g.resource ?? "-"}</Mono>
                        </Td>
                        <Td>
                          <span className="text-sev-medium">{g.error_code}</span>
                          <div className="text-xs text-ink-400">{g.message}</div>
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            )}
            <div>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-ink-400">Findings observed in this scan</h3>
              {detail.data.findings?.length ? (
                <Table>
                  <thead>
                    <tr>
                      <Th>Severity</Th>
                      <Th>Rule</Th>
                      <Th>Resource</Th>
                      <Th>Title</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {[...detail.data.findings]
                      .sort((a, b) => ["critical", "high", "medium", "low", "info"].indexOf(a.severity) - ["critical", "high", "medium", "low", "info"].indexOf(b.severity))
                      .map((f) => (
                        <tr key={f.id} className="hover:bg-ink-800/50">
                          <Td>
                            <SeverityBadge severity={f.severity} />
                          </Td>
                          <Td>
                            <Mono>{f.rule_id}</Mono>
                          </Td>
                          <Td>
                            <Mono>{f.resource_arn}</Mono>
                          </Td>
                          <Td>
                            <Link to={`/findings?id=${f.id}`} className="hover:text-accent-400 hover:underline">
                              {f.title}
                            </Link>
                          </Td>
                        </tr>
                      ))}
                  </tbody>
                </Table>
              ) : (
                <EmptyState title="No findings in this scan" />
              )}
            </div>
          </CardBody>
        </Card>
      )}

      <Card className="mt-5">
        <CardHeader title="Resource inventory" subtitle={`${resources.data?.length ?? 0} resources across all scans`} />
        {resources.error ? (
          <ErrorState error={resources.error} onRetry={resources.reload} />
        ) : !resources.data?.length ? (
          <EmptyState title="No resources collected yet" />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Type</Th>
                <Th>Name</Th>
                <Th>Region</Th>
                <Th>ARN</Th>
                <Th>Last seen</Th>
              </tr>
            </thead>
            <tbody>
              {resources.data.map((r) => (
                <tr key={r.id}>
                  <Td className="whitespace-nowrap text-ink-300">{r.type}</Td>
                  <Td>{r.name}</Td>
                  <Td>{r.region}</Td>
                  <Td>
                    <Mono>{r.arn}</Mono>
                  </Td>
                  <Td className="whitespace-nowrap">{fmtTime(r.last_seen_at)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
