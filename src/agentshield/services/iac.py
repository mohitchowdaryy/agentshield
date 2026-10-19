"""Infrastructure-as-Code security scanning: persist Checkov results, compare scans, run the lab demo.

Clearly separate from live CSPM: IaC scans read files on disk and never touch a cloud account.
"""

from __future__ import annotations

import time
from collections import Counter
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agentshield.config import get_settings
from agentshield.iac.checkov import CheckovError, CheckovReport, checkov_version, find_checkov, scan_directory
from agentshield.models import IacFinding, IacScan, utcnow
from agentshield.redaction import redact
from agentshield.services.queries import _iso

LAB_TARGETS = ("insecure", "secure")


def lab_dir() -> Path:
    return Path(get_settings().iac_lab_dir).resolve()


def lab_target(name: str) -> Path:
    if name not in LAB_TARGETS:
        raise ValueError(f"unknown lab target '{name}'; expected one of {', '.join(LAB_TARGETS)}")
    path = lab_dir() / name
    if not path.is_dir():
        raise CheckovError(
            f"lab directory not found: {path} (run from the project root or set AGENTSHIELD_IAC_LAB_DIR)"
        )
    return path


def scanner_info() -> dict[str, Any]:
    s = get_settings()
    try:
        cmd = find_checkov(s.checkov_path)
        return {"available": True, "scanner": "checkov", "version": checkov_version(cmd), "error": None}
    except CheckovError as exc:
        return {"available": False, "scanner": "checkov", "version": None, "error": str(exc)}


def _display_target(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def persist_report(session: Session, report: CheckovReport, label: str, target: Path, duration_ms: float) -> IacScan:
    scan = IacScan(
        label=label,
        target=_display_target(target),
        scanner="checkov",
        scanner_version=report.scanner_version,
        framework="terraform",
        status="completed",
        summary=report.summary,
        command=report.command,
        parsing_errors=report.parsing_errors[:50],
        duration_ms=round(duration_ms, 1),
        finished_at=utcnow(),
    )
    session.add(scan)
    session.flush()
    for r in report.results:
        session.add(
            IacFinding(
                scan_fk=scan.id,
                fingerprint=r.fingerprint,
                check_id=r.check_id,
                check_name=r.check_name,
                result=r.result,
                resource=r.resource,
                resource_type=r.resource_type,
                file_path=r.file_path,
                line_start=r.line_start,
                line_end=r.line_end,
                severity=r.severity,
                guideline=r.guideline,
                remediation=r.remediation,
                evidence=redact(r.evidence),
            )
        )
    session.flush()
    return scan


def run_iac_scan(session: Session, target: Path, label: str | None = None) -> IacScan:
    """Run Checkov on `target` and store the results.

    A failed run (Checkov missing, timeout, unparseable output) is stored with status "failed" and its
    error, and returned rather than raised, so the record survives the caller's transaction.
    """
    s = get_settings()
    label = label or target.name
    started = time.perf_counter()
    try:
        cmd = find_checkov(s.checkov_path)
        report = scan_directory(target, cmd, timeout=s.checkov_timeout_seconds)
    except CheckovError as exc:
        failed = IacScan(
            label=label,
            target=_display_target(target),
            scanner="checkov",
            framework="terraform",
            status="failed",
            error=str(exc)[:2000],
            duration_ms=round((time.perf_counter() - started) * 1000, 1),
            finished_at=utcnow(),
        )
        session.add(failed)
        session.flush()
        return failed
    return persist_report(session, report, label, target, (time.perf_counter() - started) * 1000)


def compare_scans(session: Session, before_id: str, after_id: str) -> dict[str, Any]:
    """Compare two scans check by check, keyed on (check_id, resource address)."""
    before = session.get(IacScan, before_id)
    after = session.get(IacScan, after_id)
    if before is None or after is None:
        raise KeyError("scan not found")

    def index(scan: IacScan) -> dict[tuple[str, str], IacFinding]:
        return {(f.check_id, f.resource): f for f in scan.findings}

    b, a = index(before), index(after)
    fixed, still_failing, new_failures, not_evaluated = [], [], [], []
    for key, fb in b.items():
        if fb.result != "failed":
            continue
        fa = a.get(key)
        if fa is None:
            not_evaluated.append(_finding_dict(fb))
        elif fa.result == "passed":
            fixed.append(_finding_dict(fa))
        elif fa.result == "failed":
            still_failing.append(_finding_dict(fa))
    for key, fa in a.items():
        if fa.result == "failed" and (key not in b or b[key].result != "failed"):
            new_failures.append(_finding_dict(fa))
    return {
        "before": scan_dict(before),
        "after": scan_dict(after),
        "fixed": fixed,
        "still_failing": still_failing,
        "new_failures": new_failures,
        "not_evaluated_after": not_evaluated,
        "counts": {
            "failed_before": sum(1 for f in b.values() if f.result == "failed"),
            "failed_after": sum(1 for f in a.values() if f.result == "failed"),
            "fixed": len(fixed),
            "still_failing": len(still_failing),
            "new_failures": len(new_failures),
            "not_evaluated_after": len(not_evaluated),
        },
        "method": "Matched on (check_id, resource address). 'Fixed' means the same check on the same "
        "resource changed from FAILED to PASSED in the later scan.",
    }


def run_lab_demo(session: Session) -> dict[str, Any]:
    """Scan the insecure lab, scan the fixed lab, and compare the two real results."""
    before = run_iac_scan(session, lab_target("insecure"), "insecure")
    after = run_iac_scan(session, lab_target("secure"), "secure")
    failed = [s for s in (before, after) if s.status != "completed"]
    if failed:
        return {"error": failed[0].error, "before": scan_dict(before), "after": scan_dict(after)}
    return compare_scans(session, before.id, after.id)


def latest_lab_pair(session: Session) -> tuple[IacScan | None, IacScan | None]:
    def latest(label: str) -> IacScan | None:
        return session.scalar(
            select(IacScan)
            .where(IacScan.label == label, IacScan.status == "completed")
            .order_by(IacScan.started_at.desc())
            .limit(1)
        )

    return latest("insecure"), latest("secure")


def scan_dict(s: IacScan) -> dict[str, Any]:
    counts = Counter(f.result for f in s.findings)
    return {
        "id": s.id,
        "label": s.label,
        "target": s.target,
        "scanner": s.scanner,
        "scanner_version": s.scanner_version,
        "framework": s.framework,
        "status": s.status,
        "summary": s.summary,
        "stored_counts": {k: counts.get(k, 0) for k in ("failed", "passed", "skipped")},
        "command": s.command,
        "parsing_errors": s.parsing_errors,
        "error": s.error,
        "duration_ms": s.duration_ms,
        "started_at": _iso(s.started_at),
        "finished_at": _iso(s.finished_at),
        "kind": "iac_static_analysis",
    }


def _finding_dict(f: IacFinding) -> dict[str, Any]:
    return {
        "id": f.id,
        "scan_id": f.scan_fk,
        "fingerprint": f.fingerprint,
        "check_id": f.check_id,
        "check_name": f.check_name,
        "result": f.result,
        "resource": f.resource,
        "resource_type": f.resource_type,
        "file_path": f.file_path,
        "line_start": f.line_start,
        "line_end": f.line_end,
        "severity": f.severity,
        "guideline": f.guideline,
        "remediation": f.remediation,
    }


def finding_dict(f: IacFinding, detail: bool = False) -> dict[str, Any]:
    d = _finding_dict(f)
    if detail:
        d["evidence"] = f.evidence
    return d
