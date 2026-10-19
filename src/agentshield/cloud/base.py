"""Cloud posture contracts: the normalized inventory, findings and the Rule / Collector interfaces.

A collector turns a cloud account into a `CloudInventory`; rules turn an inventory into
`FindingResult`s. Rules never call cloud APIs, so live and demo scans share identical logic.
Values that could not be collected are `None` and rules skip them (no finding without evidence).
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
SEVERITY_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
ScanSource = Literal["live", "demo"]


class CollectionGap(BaseModel):
    """A piece of inventory that could not be collected (AccessDenied, throttling, API error)."""

    service: str
    operation: str
    resource: str | None = None
    region: str | None = None
    error_code: str
    message: str


class S3Bucket(BaseModel):
    name: str
    arn: str
    region: str
    public_access_block: dict[str, bool] | None = None
    public_access_block_status: Literal["configured", "not_configured", "unknown"] = "unknown"
    policy: dict[str, Any] | None = None
    policy_status: Literal["present", "absent", "unknown"] = "unknown"
    encryption_rules: list[dict[str, Any]] | None = None
    encryption_status: Literal["configured", "not_configured", "unknown"] = "unknown"
    versioning: Literal["Enabled", "Suspended", "Disabled"] | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class AttachedPolicy(BaseModel):
    arn: str
    name: str
    document: dict[str, Any] | None = None  # None when GetPolicyVersion was denied


class IamRole(BaseModel):
    name: str
    arn: str
    path: str = "/"
    trust_policy: dict[str, Any] | None = None
    inline_policies: dict[str, dict[str, Any]] | None = None
    attached_policies: list[AttachedPolicy] | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class RootAccountSummary(BaseModel):
    mfa_enabled: bool | None = None
    access_keys_present: bool | None = None


class CloudTrailTrail(BaseModel):
    name: str
    arn: str
    home_region: str
    is_multi_region: bool
    log_file_validation: bool | None = None
    is_logging: bool | None = None


class CloudInventory(BaseModel):
    provider: Literal["aws"] = "aws"
    partition: str = "aws"
    account_id: str
    caller_arn: str | None = None
    source: ScanSource
    regions: list[str]
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    account_public_access_block: dict[str, bool] | None = None
    account_public_access_block_status: Literal["configured", "not_configured", "unknown"] = "unknown"
    s3_buckets: list[S3Bucket] | None = None
    iam_roles: list[IamRole] | None = None
    root_account: RootAccountSummary = Field(default_factory=RootAccountSummary)
    cloudtrail_trails: list[CloudTrailTrail] | None = None
    gaps: list[CollectionGap] = Field(default_factory=list)

    @property
    def account_arn(self) -> str:
        return f"arn:{self.partition}:iam::{self.account_id}:root"


class FindingResult(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    resource_arn: str
    resource_type: str
    account_id: str
    region: str
    evidence: dict[str, Any]
    remediation: str
    references: list[str] = Field(default_factory=list)
    risk_type: Literal["configuration"] = "configuration"
    exploitability: Literal["not_validated"] = "not_validated"
    source: ScanSource
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def fingerprint(self) -> str:
        return finding_fingerprint(self.rule_id, self.account_id, self.region, self.resource_arn)


def finding_fingerprint(rule_id: str, account_id: str, region: str, resource_arn: str) -> str:
    """Stable identity of a finding across scans; evidence changes do not create duplicates."""
    key = "|".join([rule_id, account_id, region, resource_arn])
    return hashlib.sha256(key.encode()).hexdigest()


class Rule(ABC):
    rule_id: str
    title: str
    service: str
    references: list[str] = []

    @abstractmethod
    def evaluate(self, inv: CloudInventory) -> list[FindingResult]: ...

    def finding(
        self,
        inv: CloudInventory,
        *,
        severity: Severity,
        resource_arn: str,
        resource_type: str,
        region: str,
        evidence: dict[str, Any],
        remediation: str,
        title: str | None = None,
    ) -> FindingResult:
        return FindingResult(
            rule_id=self.rule_id,
            title=title or self.title,
            severity=severity,
            resource_arn=resource_arn,
            resource_type=resource_type,
            account_id=inv.account_id,
            region=region,
            evidence=evidence,
            remediation=remediation,
            references=list(self.references),
            source=inv.source,
        )


class Collector(Protocol):
    def collect(self) -> CloudInventory: ...
