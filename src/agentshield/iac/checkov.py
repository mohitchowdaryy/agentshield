"""Checkov runner and result normalizer for Infrastructure-as-Code security scanning.

This is static analysis of IaC files, not live cloud posture management: nothing is deployed and no
cloud API is called.

Subprocess safety:
- The executable is resolved to an absolute path and invoked with an argument list (no shell).
- The scan target must be an existing directory; it is passed as a single argument.
- Every call has a timeout; stdout is parsed as JSON and errors carry only a bounded stderr excerpt.

Severity: Checkov's open-source checks usually report `severity: null` (severities come from the
Prisma Cloud platform). The normalizer keeps whatever Checkov reports and never invents a value.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess  # noqa: S404 - invoked with argument lists only, never a shell
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

RESULTS = ("failed", "passed", "skipped")
_STDERR_LIMIT = 2000
_CODE_LINES_LIMIT = 25


class CheckovError(RuntimeError):
    """Checkov is missing, timed out, or produced output that could not be parsed."""


def _python_beside(script: Path) -> Path | None:
    for name in ("python.exe", "python3", "python"):
        candidate = script.parent / name
        if candidate.is_file():
            return candidate
    return None


def _command_for(path: Path) -> list[str]:
    """Turn a resolved path into an argv prefix, never routing through a shell (.cmd/.bat)."""
    name = path.name.lower()
    if name.startswith("python"):
        return [str(path), "-m", "checkov.main"]
    if name.endswith((".cmd", ".bat")) or (os.name == "nt" and not name.endswith(".exe")):
        py = _python_beside(path)
        if py is None:
            raise CheckovError(f"cannot run {path.name} without a shell and no Python interpreter beside it")
        return [str(py), "-m", "checkov.main"]
    return [str(path)]


def find_checkov(configured: str | None = None) -> list[str]:
    """Resolve how to invoke Checkov: configured path, then PATH, then a ~/.checkov-venv install.

    Returns an argv prefix such as ["/usr/local/bin/checkov"] or [".../python.exe", "-m", "checkov.main"].
    """
    if configured:
        p = Path(configured).expanduser()
        if p.is_file():
            return _command_for(p.resolve())
        raise CheckovError(f"configured Checkov path does not exist: {configured}")
    on_path = shutil.which("checkov")
    if on_path:
        return _command_for(Path(on_path).resolve())
    home = Path.home()
    for p in (home / ".checkov-venv" / "Scripts" / "python.exe", home / ".checkov-venv" / "bin" / "checkov"):
        if p.is_file():
            return _command_for(p.resolve())
    raise CheckovError(
        "Checkov not found. Install it (pip install checkov, ideally in its own virtualenv) and put it on "
        "PATH or set AGENTSHIELD_CHECKOV_PATH."
    )


def _env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    # Keep Checkov offline and quiet: no platform API key is used, no update checks.
    env.pop("BC_API_KEY", None)
    env.pop("PRISMA_API_URL", None)
    env["CHECKOV_RUN_SCA_PACKAGE_SCAN_V2"] = "false"
    return env


def _run(args: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(  # noqa: S603 - fixed executable path + argument list, shell=False
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            env=_env(),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CheckovError(f"Checkov timed out after {timeout:.0f}s") from exc
    except OSError as exc:
        raise CheckovError(f"could not start Checkov: {exc}") from exc


def checkov_version(command: list[str], timeout: float = 60.0) -> str:
    proc = _run([*command, "--version"], timeout)
    out = (proc.stdout or "").strip().splitlines()
    if proc.returncode != 0 or not out:
        raise CheckovError(f"`checkov --version` failed: {(proc.stderr or '')[-_STDERR_LIMIT:]}")
    return out[-1].strip()


@dataclass
class CheckResult:
    check_id: str
    check_name: str
    result: str  # failed | passed | skipped
    resource: str
    resource_type: str
    file_path: str
    line_start: int | None
    line_end: int | None
    severity: str | None
    guideline: str | None
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.check_id}|{self.resource}|{self.file_path}".encode()).hexdigest()

    @property
    def remediation(self) -> str:
        text = f"Change the configuration of {self.resource} so that the check passes: {self.check_name}."
        if self.guideline:
            text += f" Checkov guideline: {self.guideline}"
        return text


@dataclass
class CheckovReport:
    scanner_version: str
    target: str
    results: list[CheckResult]
    summary: dict[str, Any]
    parsing_errors: list[str]
    command: list[str]


def _relative(path: str) -> str:
    return path.replace("\\", "/").lstrip("/")


def _normalize_check(raw: dict[str, Any], result: str) -> CheckResult:
    resource = str(raw.get("resource") or "")
    lines = raw.get("file_line_range") or []
    code_block = raw.get("code_block") or []
    severity = raw.get("severity")
    evidence: dict[str, Any] = {
        "evaluated_keys": (raw.get("check_result") or {}).get("evaluated_keys") or [],
        "code": [[ln, txt.rstrip("\n")] for ln, txt in code_block[:_CODE_LINES_LIMIT]],
        "check_class": raw.get("check_class"),
    }
    if raw.get("bc_check_id"):
        evidence["bc_check_id"] = raw["bc_check_id"]
    if raw.get("suppress_comment"):
        evidence["suppress_comment"] = raw["suppress_comment"]
    return CheckResult(
        check_id=str(raw.get("check_id") or ""),
        check_name=str(raw.get("check_name") or ""),
        result=result,
        resource=resource,
        resource_type=resource.split(".", 1)[0] if "." in resource else resource,
        file_path=_relative(str(raw.get("file_path") or raw.get("repo_file_path") or "")),
        line_start=int(lines[0]) if len(lines) >= 1 else None,
        line_end=int(lines[1]) if len(lines) >= 2 else None,
        severity=str(severity) if severity else None,
        guideline=str(raw["guideline"]) if raw.get("guideline") else None,
        evidence=evidence,
    )


def parse_report(data: Any) -> tuple[list[CheckResult], dict[str, Any], list[str]]:
    """Normalize Checkov's JSON output (one report object, or a list of them for several frameworks)."""
    reports = data if isinstance(data, list) else [data]
    results: list[CheckResult] = []
    summary: dict[str, Any] = {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0, "resource_count": 0}
    parsing_errors: list[str] = []
    for rep in reports:
        if not isinstance(rep, dict):
            raise CheckovError("unexpected Checkov JSON: report is not an object")
        res = rep.get("results")
        if res is None and set(rep) <= {
            "passed",
            "failed",
            "skipped",
            "parsing_errors",
            "resource_count",
            "checkov_version",
        }:
            # Checkov emits a bare summary object when nothing was scanned.
            for k in summary:
                summary[k] += int(rep.get(k) or 0)
            continue
        if not isinstance(res, dict):
            raise CheckovError("unexpected Checkov JSON: missing 'results'")
        for key, result in (("failed_checks", "failed"), ("passed_checks", "passed"), ("skipped_checks", "skipped")):
            for raw in res.get(key) or []:
                results.append(_normalize_check(raw, result))
        parsing_errors += [str(p) for p in res.get("parsing_errors") or []]
        s = rep.get("summary") or {}
        for k in summary:
            summary[k] += int(s.get(k) or 0)
    return results, summary, parsing_errors


def scan_directory(directory: Path, command: list[str], timeout: float = 300.0) -> CheckovReport:
    """Run Checkov on a directory of Terraform files and return normalized results."""
    target = directory.resolve()
    if not target.is_dir():
        raise CheckovError(f"scan target is not a directory: {directory}")
    version = checkov_version(command)
    args = [
        *command,
        "--directory",
        str(target),
        "--framework",
        "terraform",
        "--output",
        "json",
        "--soft-fail",  # exit 0 even when checks fail; a non-zero exit then means a real error
        "--skip-download",  # offline: no guideline/check downloads from the Prisma platform
    ]
    proc = _run(args, timeout)
    stdout = (proc.stdout or "").strip()
    if proc.returncode != 0:
        raise CheckovError(f"Checkov exited with {proc.returncode}: {(proc.stderr or stdout)[-_STDERR_LIMIT:]}")
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise CheckovError(
            f"Checkov output was not valid JSON: {stdout[:300]!r} stderr: {(proc.stderr or '')[-500:]!r}"
        ) from exc
    results, summary, parsing_errors = parse_report(data)
    if parsing_errors:
        summary["parsing_errors"] = max(int(summary.get("parsing_errors") or 0), len(parsing_errors))
    return CheckovReport(
        scanner_version=version,
        target=str(target),
        results=results,
        summary=summary,
        parsing_errors=parsing_errors,
        command=["checkov", *(a if a != str(target) else "<target>" for a in args[len(command) :])],
    )
