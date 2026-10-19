"""Secret redaction applied to every piece of evidence before it is persisted or exported.

Synthetic canary tokens (AGS-CANARY-*) are deliberately NOT redacted: they are the
observable signal used to prove whether synthetic confidential data moved.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b")),
    (
        "aws_secret_access_key",
        re.compile(r"(?i)(aws_secret_access_key|secretaccesskey)(\s*[=:]\s*|\"\s*:\s*\")([A-Za-z0-9/+=]{40})"),
    ),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{16,}=*")),
    (
        "private_key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    ),
    ("aws_session_token", re.compile(r"(?i)(aws_session_token)(\s*[=:]\s*)(\S{100,})")),
]

_SENSITIVE_KEYS = re.compile(
    r"(?i)^(password|passwd|secret|secret_access_key|api[_-]?key|access[_-]?token|session[_-]?token|authorization)$"
)


def redact_text(text: str) -> str:
    for name, pattern in _PATTERNS:
        if pattern.groups >= 3:
            text = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
        else:
            text = pattern.sub(f"{REDACTED}:{name}", text)
    return text


def redact(value: Any) -> Any:
    """Recursively redact strings in JSON-like structures; values under sensitive keys are dropped."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if isinstance(k, str) and _SENSITIVE_KEYS.match(k) and v not in (None, ""):
                out[k] = REDACTED
            else:
                out[k] = redact(v)
        return out
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    return value
