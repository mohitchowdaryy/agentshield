"""Demo collector: loads a synthetic inventory with the same schema the AWS collector produces."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from importlib import resources

from agentshield.cloud.base import CloudInventory


class DemoCollector:
    source = "demo"

    def collect(self) -> CloudInventory:
        raw = json.loads((resources.files("agentshield.data") / "demo_cloud_inventory.json").read_text())
        raw.pop("_comment", None)
        raw["collected_at"] = datetime.now(UTC).isoformat()
        return CloudInventory.model_validate(raw)
