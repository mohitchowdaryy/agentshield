"""Persist cloud scans: accounts, resources, deduplicated findings and per-scan observations."""

from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentshield.cloud.base import CloudInventory, Collector
from agentshield.cloud.rules import evaluate_inventory
from agentshield.models import CloudAccount, Finding, FindingObservation, Resource, Scan, utcnow
from agentshield.redaction import redact


def _resources(inv: CloudInventory) -> list[dict[str, Any]]:
    out = []
    for b in inv.s3_buckets or []:
        out.append(
            {"arn": b.arn, "type": "AWS::S3::Bucket", "name": b.name, "region": b.region, "attributes": b.model_dump()}
        )
    for r in inv.iam_roles or []:
        out.append(
            {"arn": r.arn, "type": "AWS::IAM::Role", "name": r.name, "region": "global", "attributes": r.model_dump()}
        )
    for t in inv.cloudtrail_trails or []:
        out.append(
            {
                "arn": t.arn,
                "type": "AWS::CloudTrail::Trail",
                "name": t.name,
                "region": t.home_region,
                "attributes": t.model_dump(),
            }
        )
    out.append(
        {
            "arn": inv.account_arn,
            "type": "AWS::Account",
            "name": inv.account_id,
            "region": "global",
            "attributes": {
                "root_account": inv.root_account.model_dump(),
                "account_public_access_block": inv.account_public_access_block,
                "account_public_access_block_status": inv.account_public_access_block_status,
            },
        }
    )
    return out


def persist_inventory(session: Session, inv: CloudInventory) -> Scan:
    account = session.scalar(
        select(CloudAccount).where(
            CloudAccount.provider == inv.provider,
            CloudAccount.account_id == inv.account_id,
            CloudAccount.source == inv.source,
        )
    )
    if account is None:
        account = CloudAccount(provider=inv.provider, account_id=inv.account_id, source=inv.source)
        session.add(account)
    account.caller_arn = inv.caller_arn

    scan = Scan(
        account=account,
        source=inv.source,
        status="running",
        regions=inv.regions,
        collection_gaps=[g.model_dump() for g in inv.gaps],
        started_at=inv.collected_at,
    )
    session.add(scan)
    session.flush()

    now = utcnow()
    res_by_arn: dict[str, Resource] = {}
    for r in _resources(inv):
        row = session.scalar(select(Resource).where(Resource.account_fk == account.id, Resource.arn == r["arn"]))
        if row is None:
            row = Resource(account_fk=account.id, arn=r["arn"], first_seen_at=now)
            session.add(row)
        row.resource_type, row.name, row.region = r["type"], r["name"], r["region"]
        row.attributes = redact(r["attributes"])
        row.last_scan_fk, row.last_seen_at = scan.id, now
        res_by_arn[r["arn"]] = row
    session.flush()

    results = evaluate_inventory(inv)
    seen: set[str] = set()
    for f in results:
        fp = f.fingerprint
        if fp in seen:
            continue
        seen.add(fp)
        frow = session.scalar(select(Finding).where(Finding.fingerprint == fp))
        if frow is None:
            frow = Finding(fingerprint=fp, first_seen_at=now)
            session.add(frow)
        frow.rule_id, frow.title, frow.severity = f.rule_id, f.title, f.severity
        frow.status, frow.source = "open", f.source
        frow.account_id, frow.region, frow.resource_arn, frow.resource_type = (
            f.account_id,
            f.region,
            f.resource_arn,
            f.resource_type,
        )
        res = res_by_arn.get(f.resource_arn)
        frow.resource_fk = res.id if res else None
        frow.evidence = redact(f.evidence)
        frow.remediation, frow.references = f.remediation, f.references
        frow.risk_type, frow.exploitability = f.risk_type, f.exploitability
        frow.last_seen_at, frow.last_scan_fk = now, scan.id
        session.flush()
        session.add(FindingObservation(finding_fk=frow.id, scan_fk=scan.id, observed_at=now))

    # Resolve previously open findings that a gap-free scan of the same account no longer observes.
    resolved = 0
    if not inv.gaps:
        stale = session.scalars(
            select(Finding).where(
                Finding.account_id == inv.account_id,
                Finding.source == inv.source,
                Finding.status == "open",
                Finding.fingerprint.not_in(seen) if seen else Finding.id.is_not(None),
            )
        ).all()
        for stale_row in stale:
            stale_row.status = "resolved"
            resolved += 1

    sev = Counter(f.severity for f in results)
    scan.status = "partial" if inv.gaps else "completed"
    scan.finished_at = utcnow()
    scan.summary = {
        "findings": len(seen),
        "by_severity": dict(sev),
        "resources": len(res_by_arn),
        "collection_gaps": len(inv.gaps),
        "resolved": resolved,
    }
    session.flush()
    return scan


def run_scan(session: Session, collector: Collector) -> Scan:
    return persist_inventory(session, collector.collect())
