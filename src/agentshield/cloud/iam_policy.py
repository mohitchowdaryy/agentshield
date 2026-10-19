"""IAM policy document parsing and conservative static analysis.

This is intentionally a *static* analyzer of identity and resource policies. It does not model
SCPs, permission boundaries, session policies, or most condition keys, so its results describe
configured permissions, not effective, proven access.
"""

from __future__ import annotations

import fnmatch
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

# Condition keys that constrain *who* can use a public-principal statement. When present we
# treat the statement as not unconditionally public (it may still be risky).
RESTRICTIVE_CONDITION_KEYS = {
    "aws:sourcearn",
    "aws:sourceaccount",
    "aws:sourceowner",
    "aws:principalorgid",
    "aws:principalorgpaths",
    "aws:principalaccount",
    "aws:principalarn",
    "aws:sourcevpc",
    "aws:sourcevpce",
    "aws:sourceip",
    "aws:userid",
    "sts:externalid",
}


@dataclass(frozen=True)
class Statement:
    effect: str
    actions: tuple[str, ...]
    not_actions: tuple[str, ...]
    resources: tuple[str, ...]
    not_resources: tuple[str, ...]
    principal: Any
    condition: dict[str, Any]
    sid: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


def load_document(doc: dict[str, Any] | str | None) -> dict[str, Any]:
    if doc is None:
        return {}
    if isinstance(doc, str):
        from urllib.parse import unquote

        text = doc if doc.lstrip().startswith("{") else unquote(doc)
        loaded: dict[str, Any] = json.loads(text)
        return loaded
    return doc


def statements(doc: dict[str, Any] | str | None) -> list[Statement]:
    data = load_document(doc)
    raw = data.get("Statement", [])
    if isinstance(raw, dict):
        raw = [raw]
    out = []
    for s in raw:
        if not isinstance(s, dict):
            continue
        out.append(
            Statement(
                effect=str(s.get("Effect", "")),
                actions=_as_tuple(s.get("Action")),
                not_actions=_as_tuple(s.get("NotAction")),
                resources=_as_tuple(s.get("Resource")),
                not_resources=_as_tuple(s.get("NotResource")),
                principal=s.get("Principal"),
                condition=s.get("Condition") or {},
                sid=s.get("Sid"),
                raw=s,
            )
        )
    return out


def _match(pattern: str, value: str) -> bool:
    return fnmatch.fnmatchcase(value.lower(), pattern.lower())


def action_matches(patterns: Iterable[str], action: str) -> bool:
    return any(_match(p, action) for p in patterns)


def resource_matches(patterns: Iterable[str], resource: str) -> bool:
    return any(p == "*" or fnmatch.fnmatchcase(resource, p) for p in patterns)


def is_full_admin(stmt: Statement) -> bool:
    """Allow on every action and every resource (e.g. AdministratorAccess)."""
    if stmt.effect != "Allow" or stmt.condition:
        return False
    all_resources = "*" in stmt.resources or (not stmt.resources and stmt.not_resources)
    if stmt.actions and any(a in ("*", "*:*") for a in stmt.actions) and all_resources:
        return True
    # "Allow NotAction X on *" grants everything except X — treated as admin-equivalent.
    return bool(stmt.not_actions) and not stmt.actions and "*" in stmt.resources


def service_wildcards(stmt: Statement) -> list[str]:
    """Service-wide wildcards like `s3:*` or `iam:*` granted on all resources."""
    if stmt.effect != "Allow" or "*" not in stmt.resources:
        return []
    return sorted({a for a in stmt.actions if a.endswith(":*") and a not in ("*:*",)})


def principal_is_public(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for key in ("AWS", "CanonicalUser"):
            vals = _as_tuple(principal.get(key))
            if "*" in vals:
                return True
    return False


def condition_keys(stmt: Statement) -> set[str]:
    keys: set[str] = set()
    for _op, kv in stmt.condition.items():
        if isinstance(kv, dict):
            keys.update(k.lower() for k in kv)
    return keys


def is_unconditionally_public(stmt: Statement) -> bool:
    return (
        stmt.effect == "Allow"
        and principal_is_public(stmt.principal)
        and not (condition_keys(stmt) & RESTRICTIVE_CONDITION_KEYS)
    )


def allows(documents: Iterable[dict[str, Any]], action: str, resource: str) -> tuple[bool, list[str]]:
    """Does any Allow statement grant `action` on `resource` without an explicit Deny?

    Conditions are ignored (treated as satisfiable), which over-approximates access. Returns
    (allowed, matched statement Sids/indices) for use as evidence.
    """
    allowed_by: list[str] = []
    denied = False
    for d_index, doc in enumerate(documents):
        for s_index, stmt in enumerate(statements(doc)):
            label = stmt.sid or f"doc{d_index}.stmt{s_index}"
            if stmt.actions:
                act_ok = action_matches(stmt.actions, action)
            else:
                act_ok = bool(stmt.not_actions) and not action_matches(stmt.not_actions, action)
            if stmt.resources:
                res_ok = resource_matches(stmt.resources, resource)
            else:
                res_ok = bool(stmt.not_resources) and not resource_matches(stmt.not_resources, resource)
            if act_ok and res_ok:
                if stmt.effect == "Deny":
                    denied = True
                elif stmt.effect == "Allow":
                    allowed_by.append(label)
    return (bool(allowed_by) and not denied, allowed_by)
