"""In-memory synthetic workspace used by every agent tool.

Security invariants (enforced here, independent of policy mode):
- Tools never touch the real filesystem: files live in a dict loaded from packaged synthetic data.
- Paths that escape the workspace root resolve to nothing.
- The outbox is a Python list. Nothing is ever transmitted over a network.
"""

from __future__ import annotations

import copy
import json
import posixpath
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import resources
from typing import Any

MAX_IDENTIFIER_LEN = 256
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class UnsafeIdentifierError(ValueError):
    """A resource identifier failed strict validation."""


def strict_validate_path(path: str) -> str:
    """Strict validation used by the gateway: reject anything that is not a plain relative path."""
    if not path or len(path) > MAX_IDENTIFIER_LEN:
        raise UnsafeIdentifierError("path is empty or too long")
    if _CONTROL_CHARS.search(path):
        raise UnsafeIdentifierError("path contains control characters")
    if "\\" in path:
        raise UnsafeIdentifierError("path contains a backslash")
    if path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        raise UnsafeIdentifierError("absolute paths are not allowed")
    if "%" in path:
        raise UnsafeIdentifierError("percent-encoded paths are not allowed")
    parts = path.split("/")
    if any(p in ("..", ".", "") for p in parts):
        raise UnsafeIdentifierError("path traversal or empty segments are not allowed")
    return path


def lenient_normalize_path(path: str) -> str | None:
    """Normalization used by the sandboxed tool layer: resolve `.`/`..` but never escape the root."""
    if not path or len(path) > 4 * MAX_IDENTIFIER_LEN or _CONTROL_CHARS.search(path):
        return None
    path = path.replace("\\", "/")
    norm = posixpath.normpath("/" + path.lstrip("/"))
    # normpath of an absolute path clamps ".." at "/", so detect escapes on the raw segments instead.
    depth = 0
    for seg in path.lstrip("/").split("/"):
        if seg == "..":
            depth -= 1
            if depth < 0:
                return None
        elif seg not in ("", "."):
            depth += 1
    return norm.lstrip("/")


@dataclass
class OutboxMessage:
    destination: str
    subject: str
    body: str
    queued_at: str
    delivered: bool = False  # always False: delivery is simulated
    simulated: bool = True


@dataclass
class SyntheticWorkspace:
    files: dict[str, str]
    cloud_configs: dict[str, dict[str, Any]]
    outbox: list[OutboxMessage] = field(default_factory=list)

    @classmethod
    def load_default(cls) -> SyntheticWorkspace:
        root = resources.files("agentshield.data") / "workspace"
        files: dict[str, str] = {}

        def walk(node: Any, prefix: str) -> None:
            for child in node.iterdir():
                rel = f"{prefix}{child.name}"
                if child.is_dir():
                    walk(child, rel + "/")
                else:
                    files[rel] = child.read_text(encoding="utf-8")

        walk(root, "")
        inventory = json.loads((resources.files("agentshield.data") / "demo_cloud_inventory.json").read_text())
        configs = {}
        for b in inventory["s3_buckets"]:
            configs[f"s3:{b['name']}"] = {
                "resource_id": f"s3:{b['name']}",
                "arn": b["arn"],
                "region": b["region"],
                "encryption": b["encryption_rules"],
                "versioning": b["versioning"],
                "public_access_block": b["public_access_block"],
                "tags": dict(b["tags"]),
            }
        return cls(files=files, cloud_configs=configs)

    def clone(self) -> SyntheticWorkspace:
        return SyntheticWorkspace(files=dict(self.files), cloud_configs=copy.deepcopy(self.cloud_configs))

    def read(self, path: str) -> str | None:
        norm = lenient_normalize_path(path)
        if norm is None:
            return None
        return self.files.get(norm)

    def send(self, destination: str, subject: str, body: str) -> OutboxMessage:
        msg = OutboxMessage(destination, subject, body, datetime.now(UTC).isoformat())
        self.outbox.append(msg)
        return msg
