"""Tool authorization gateway: deterministic policy enforcement between proposed and executed tool calls.

The gateway never asks a model whether a call is safe. Every decision is reproducible from the
policy file, the call arguments and the run context, and carries the rule IDs that produced it.

Rule IDs
  GW-000 allowed by policy             GW-005 destination not allowlisted / malformed
  GW-001 tool not allowlisted          GW-006 DLP marker in outbound content
  GW-002 argument validation failed    GW-007 human approval required and not granted
  GW-003 unsafe resource identifier    GW-008 per-run call budget exceeded
  GW-004 resource outside scope
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

from pydantic import ValidationError

from agentshield.agent.policy import AgentPolicy
from agentshield.agent.tools import TOOLS
from agentshield.agent.workspace import UnsafeIdentifierError, strict_validate_path

_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})+$")


@lru_cache(maxsize=256)
def _glob_regex(pattern: str) -> re.Pattern[str]:
    """`**` matches across `/`, `*` matches within one segment, `?` one non-`/` character."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def glob_match(pattern: str, value: str) -> bool:
    return bool(_glob_regex(pattern).match(value))


def destination_allowed(destination: str, patterns: list[str]) -> tuple[bool, str]:
    """Validate the destination format, then match it against the allowlist."""
    if "*" in patterns:
        return True, "all destinations allowed by policy"
    if _EMAIL.match(destination):
        local, domain = destination.lower().rsplit("@", 1)
        for p in patterns:
            if "@" in p and not p.startswith("http"):
                p_local, p_domain = p.lower().rsplit("@", 1)
                if glob_match(p_local, local) and p_domain == domain:
                    return True, f"matches {p}"
        return False, f"email destination '{destination}' is not on the allowlist"
    parts = urlsplit(destination)
    if parts.scheme in ("http", "https"):
        if parts.scheme != "https":
            return False, "only https destinations are permitted"
        if "@" in parts.netloc or parts.port not in (None, 443) or not parts.hostname:
            return False, "URL contains userinfo, a non-standard port, or no host"
        for p in patterns:
            pp = urlsplit(p)
            if pp.scheme != "https":
                continue
            if (pp.hostname or "").lower() == parts.hostname.lower() and glob_match(pp.path or "/", parts.path or "/"):
                return True, f"matches {p}"
        return False, f"URL host '{parts.hostname}' is not on the allowlist"
    return False, "destination is neither an email address nor an https URL"


@dataclass
class ApprovalRequest:
    tool: str
    arguments: dict[str, Any]
    reason: str


class Approver(Protocol):
    def review(self, request: ApprovalRequest) -> bool: ...


class DenyAllApprover:
    """Default for non-interactive runs: no human is present, so approval is never granted."""

    name = "deny-all (no human approver attached)"

    def review(self, request: ApprovalRequest) -> bool:
        return False


class AllowAllApprover:
    """Test helper that approves everything. Never used by default."""

    name = "allow-all (test only)"

    def review(self, request: ApprovalRequest) -> bool:
        return True


@dataclass
class CallContext:
    untrusted_context: bool
    call_counts: dict[str, int] = field(default_factory=dict)


@dataclass
class AuthorizationResult:
    decision: Literal["allow", "deny"]
    rule_ids: list[str]
    reasons: list[str]
    approval: Literal["not_required", "approved", "denied"] = "not_required"
    validated_args: Any = None

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


class Gateway:
    def __init__(self, policy: AgentPolicy, approver: Approver | None = None) -> None:
        self.policy = policy
        self.approver: Approver = approver or DenyAllApprover()

    def _deny(self, rule_id: str, reason: str, approval: str = "not_required") -> AuthorizationResult:
        return AuthorizationResult("deny", [rule_id], [reason], approval)  # type: ignore[arg-type]

    def authorize(self, tool_name: str, arguments: dict[str, Any], ctx: CallContext) -> AuthorizationResult:
        p = self.policy
        spec = TOOLS.get(tool_name)
        if spec is None or not ("*" in p.allowed_tools or tool_name in p.allowed_tools):
            return self._deny("GW-001", f"tool '{tool_name}' is not on this agent's allowlist")

        rule = p.tool_rules.get(tool_name)

        if rule and rule.max_calls is not None and ctx.call_counts.get(tool_name, 0) >= rule.max_calls:
            return self._deny("GW-008", f"per-run budget of {rule.max_calls} calls to '{tool_name}' exhausted")

        try:
            args = spec.args_model.model_validate(arguments)
        except ValidationError as exc:
            errs = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()[:5])
            return self._deny("GW-002", f"argument validation failed: {errs}")

        if spec.resource_arg:
            resource = getattr(args, spec.resource_arg)
            if spec.resource_arg == "path" and not p.skip_identifier_validation:
                try:
                    strict_validate_path(resource)
                except UnsafeIdentifierError as exc:
                    return self._deny("GW-003", f"unsafe resource identifier '{resource[:80]}': {exc}")
            scopes = rule.resource_scopes if rule else None
            if not scopes or not any(glob_match(s, resource) for s in scopes):
                return self._deny("GW-004", f"resource '{resource[:80]}' is outside the agent's allowed scopes")

        if spec.destination_arg:
            dest = getattr(args, spec.destination_arg)
            ok, why = destination_allowed(dest, (rule.destinations if rule else None) or [])
            if not ok:
                return self._deny("GW-005", why)

        if spec.egress and p.dlp_block_markers:
            text = " ".join(str(v) for v in args.model_dump().values())
            hits = [m for m in p.dlp_block_markers if m.lower() in text.lower()]
            if hits:
                return self._deny("GW-006", f"outbound content contains protected data markers: {hits}")

        needs_approval_reasons = []
        if rule and rule.requires_approval:
            needs_approval_reasons.append(f"'{tool_name}' always requires approval")
        if ctx.untrusted_context and tool_name in p.approval_when_untrusted_context:
            needs_approval_reasons.append(
                f"'{tool_name}' was proposed after untrusted content entered the model context"
            )
        if needs_approval_reasons:
            reason = "; ".join(needs_approval_reasons)
            granted = self.approver.review(ApprovalRequest(tool_name, args.model_dump(), reason))
            if not granted:
                approver_name = getattr(self.approver, "name", type(self.approver).__name__)
                return self._deny("GW-007", f"human approval required ({reason}); denied by {approver_name}", "denied")
            return AuthorizationResult(
                "allow", ["GW-000", "GW-007"], [f"approved by human reviewer: {reason}"], "approved", args
            )

        return AuthorizationResult("allow", ["GW-000"], ["allowed by policy"], "not_required", args)
