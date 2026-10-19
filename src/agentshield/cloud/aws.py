"""Read-only AWS collector.

- Credentials come from the standard boto3 chain (env, profile, SSO, instance/role). Nothing is stored.
- Every API call goes through `_call`, which refuses any operation that is not Get*/List*/Describe*.
- Throttling is handled by botocore's adaptive retry mode with a bounded attempt count.
- AccessDenied and other per-resource errors become `CollectionGap`s; the scan continues and the
  affected inventory fields stay `None`/`unknown`, so rules do not report on missing evidence.
"""

from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    PartialCredentialsError,
    ProfileNotFound,
)

from agentshield.cloud.base import (
    AttachedPolicy,
    CloudInventory,
    CloudTrailTrail,
    CollectionGap,
    IamRole,
    RootAccountSummary,
    S3Bucket,
)
from agentshield.cloud.iam_policy import load_document

log = logging.getLogger(__name__)

READ_ONLY_PREFIXES = ("get_", "list_", "describe_")
ACCESS_DENIED = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthorizationError",
    "UnauthorizedAccess",
}


class AwsScanError(RuntimeError):
    """The scan could not start (no credentials, unknown profile, STS failure)."""


class _Gap(Exception):
    pass


class AwsCollector:
    source = "live"

    def __init__(
        self,
        profile: str | None = None,
        regions: list[str] | None = None,
        max_attempts: int = 5,
        session: boto3.Session | None = None,
    ) -> None:
        try:
            self.session = session if session is not None else boto3.Session(profile_name=profile)
        except ProfileNotFound as exc:
            raise AwsScanError(f"AWS profile not found: {profile}") from exc
        self.regions = regions or [self.session.region_name or "us-east-1"]
        self.config = Config(
            retries={"mode": "adaptive", "max_attempts": max_attempts},
            connect_timeout=5,
            read_timeout=30,
            user_agent_extra="agentshield-readonly-scanner",
        )
        self.gaps: list[CollectionGap] = []
        self._clients: dict[tuple[str, str], Any] = {}
        self._policy_cache: dict[str, dict[str, Any] | None] = {}

    # -- plumbing --------------------------------------------------------------------------------
    def _client(self, service: str, region: str | None = None) -> Any:
        key = (service, region or self.regions[0])
        if key not in self._clients:
            self._clients[key] = self.session.client(service, region_name=key[1], config=self.config)
        return self._clients[key]

    def _call(
        self, client: Any, operation: str, *, resource: str | None = None, tolerate: tuple[str, ...] = (), **kwargs: Any
    ) -> dict[str, Any] | None:
        """Invoke a read-only operation. Returns None when the error code is in `tolerate`."""
        if not operation.startswith(READ_ONLY_PREFIXES):
            raise PermissionError(f"refusing non read-only AWS operation: {operation}")
        try:
            result: dict[str, Any] = getattr(client, operation)(**kwargs)
            return result
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code in tolerate:
                return None
            self._gap(client, operation, resource, code, exc.response.get("Error", {}).get("Message", str(exc)))
            raise _Gap from exc
        except BotoCoreError as exc:
            self._gap(client, operation, resource, type(exc).__name__, str(exc))
            raise _Gap from exc

    def _paginate(
        self, client: Any, operation: str, key: str, *, resource: str | None = None, **kwargs: Any
    ) -> list[Any]:
        if not operation.startswith(READ_ONLY_PREFIXES):
            raise PermissionError(f"refusing non read-only AWS operation: {operation}")
        items: list[Any] = []
        try:
            for page in client.get_paginator(operation).paginate(**kwargs):
                items.extend(page.get(key, []))
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            self._gap(client, operation, resource, code, exc.response.get("Error", {}).get("Message", str(exc)))
            raise _Gap from exc
        except BotoCoreError as exc:
            self._gap(client, operation, resource, type(exc).__name__, str(exc))
            raise _Gap from exc
        return items

    def _gap(self, client: Any, operation: str, resource: str | None, code: str, message: str) -> None:
        service = client.meta.service_model.service_name
        op_name = "".join(p.capitalize() for p in operation.split("_"))
        self.gaps.append(
            CollectionGap(
                service=service,
                operation=op_name,
                resource=resource,
                region=client.meta.region_name,
                error_code=code,
                message=message[:500],
            )
        )
        log.warning("collection gap: %s:%s %s %s", service, op_name, resource or "", code)

    # -- collection -------------------------------------------------------------------------------
    def collect(self) -> CloudInventory:
        try:
            ident = self._client("sts").get_caller_identity()
        except (NoCredentialsError, PartialCredentialsError) as exc:
            raise AwsScanError("No AWS credentials found. Configure a profile or role (see README).") from exc
        except (ClientError, BotoCoreError) as exc:
            raise AwsScanError(f"STS GetCallerIdentity failed: {exc}") from exc
        account_id, arn = ident["Account"], ident["Arn"]
        partition = arn.split(":")[1] if arn.count(":") >= 2 else "aws"

        inv = CloudInventory(
            account_id=account_id, caller_arn=arn, partition=partition, source="live", regions=self.regions
        )
        self._account_pab(inv)
        inv.s3_buckets = self._buckets(partition)
        inv.iam_roles = self._roles()
        inv.root_account = self._root()
        inv.cloudtrail_trails = self._trails()
        inv.gaps = self.gaps
        return inv

    def _account_pab(self, inv: CloudInventory) -> None:
        try:
            resp = self._call(
                self._client("s3control"),
                "get_public_access_block",
                AccountId=inv.account_id,
                resource=inv.account_arn,
                tolerate=("NoSuchPublicAccessBlockConfiguration",),
            )
        except _Gap:
            return
        if resp is None:
            inv.account_public_access_block_status = "not_configured"
        else:
            inv.account_public_access_block = resp["PublicAccessBlockConfiguration"]
            inv.account_public_access_block_status = "configured"

    def _buckets(self, partition: str) -> list[S3Bucket] | None:
        s3 = self._client("s3")
        try:
            raw = self._paginate(s3, "list_buckets", "Buckets")
        except _Gap:
            return None
        out = []
        for b in raw:
            name = b["Name"]
            arn = f"arn:{partition}:s3:::{name}"
            bucket = S3Bucket(name=name, arn=arn, region="unknown")
            try:
                loc = self._call(s3, "get_bucket_location", Bucket=name, resource=arn)
                bucket.region = (loc or {}).get("LocationConstraint") or "us-east-1"
            except _Gap:
                pass
            rc = self._client("s3", bucket.region if bucket.region != "unknown" else None)
            try:
                pab = self._call(
                    rc,
                    "get_public_access_block",
                    Bucket=name,
                    resource=arn,
                    tolerate=("NoSuchPublicAccessBlockConfiguration",),
                )
                bucket.public_access_block = pab["PublicAccessBlockConfiguration"] if pab else None
                bucket.public_access_block_status = "configured" if pab else "not_configured"
            except _Gap:
                pass
            try:
                pol = self._call(rc, "get_bucket_policy", Bucket=name, resource=arn, tolerate=("NoSuchBucketPolicy",))
                bucket.policy = load_document(pol["Policy"]) if pol else None
                bucket.policy_status = "present" if pol else "absent"
            except _Gap:
                pass
            try:
                enc = self._call(
                    rc,
                    "get_bucket_encryption",
                    Bucket=name,
                    resource=arn,
                    tolerate=("ServerSideEncryptionConfigurationNotFoundError",),
                )
                bucket.encryption_rules = enc["ServerSideEncryptionConfiguration"]["Rules"] if enc else None
                bucket.encryption_status = "configured" if enc else "not_configured"
            except _Gap:
                pass
            try:
                ver = self._call(rc, "get_bucket_versioning", Bucket=name, resource=arn)
                bucket.versioning = (ver or {}).get("Status") or "Disabled"
            except _Gap:
                pass
            try:
                tags = self._call(rc, "get_bucket_tagging", Bucket=name, resource=arn, tolerate=("NoSuchTagSet",))
                bucket.tags = {t["Key"]: t["Value"] for t in (tags or {}).get("TagSet", [])}
            except _Gap:
                pass
            out.append(bucket)
        return out

    def _managed_policy_document(self, iam: Any, arn: str) -> dict[str, Any] | None:
        if arn not in self._policy_cache:
            doc = None
            try:
                pol = self._call(iam, "get_policy", PolicyArn=arn, resource=arn)
                if pol:
                    ver = self._call(
                        iam,
                        "get_policy_version",
                        PolicyArn=arn,
                        VersionId=pol["Policy"]["DefaultVersionId"],
                        resource=arn,
                    )
                    doc = load_document(ver["PolicyVersion"]["Document"]) if ver else None
            except _Gap:
                doc = None
            self._policy_cache[arn] = doc
        return self._policy_cache[arn]

    def _roles(self) -> list[IamRole] | None:
        iam = self._client("iam")
        try:
            raw = self._paginate(iam, "list_roles", "Roles")
        except _Gap:
            return None
        roles = []
        for r in raw:
            role = IamRole(
                name=r["RoleName"],
                arn=r["Arn"],
                path=r.get("Path", "/"),
                trust_policy=load_document(r.get("AssumeRolePolicyDocument")),
            )
            try:
                names = self._paginate(iam, "list_role_policies", "PolicyNames", RoleName=role.name, resource=role.arn)
                inline: dict[str, dict[str, Any]] = {}
                for n in names:
                    p = self._call(iam, "get_role_policy", RoleName=role.name, PolicyName=n, resource=role.arn)
                    if p:
                        inline[n] = load_document(p["PolicyDocument"])
                role.inline_policies = inline
            except _Gap:
                pass
            try:
                attached = self._paginate(
                    iam, "list_attached_role_policies", "AttachedPolicies", RoleName=role.name, resource=role.arn
                )
                role.attached_policies = [
                    AttachedPolicy(
                        arn=a["PolicyArn"],
                        name=a["PolicyName"],
                        document=self._managed_policy_document(iam, a["PolicyArn"]),
                    )
                    for a in attached
                ]
            except _Gap:
                pass
            try:
                tags = self._paginate(iam, "list_role_tags", "Tags", RoleName=role.name, resource=role.arn)
                role.tags = {t["Key"]: t["Value"] for t in tags}
            except _Gap:
                pass
            roles.append(role)
        return roles

    def _root(self) -> RootAccountSummary:
        try:
            resp = self._call(self._client("iam"), "get_account_summary")
        except _Gap:
            return RootAccountSummary()
        sm = (resp or {}).get("SummaryMap", {})
        return RootAccountSummary(
            mfa_enabled=bool(sm["AccountMFAEnabled"]) if "AccountMFAEnabled" in sm else None,
            access_keys_present=bool(sm["AccountAccessKeysPresent"]) if "AccountAccessKeysPresent" in sm else None,
        )

    def _trails(self) -> list[CloudTrailTrail] | None:
        trails: dict[str, CloudTrailTrail] = {}
        any_ok = False
        for region in self.regions:
            ct = self._client("cloudtrail", region)
            try:
                resp = self._call(ct, "describe_trails", includeShadowTrails=True)
            except _Gap:
                continue
            any_ok = True
            for t in (resp or {}).get("trailList", []):
                arn = t["TrailARN"]
                if arn in trails:
                    continue
                trail = CloudTrailTrail(
                    name=t["Name"],
                    arn=arn,
                    home_region=t.get("HomeRegion", region),
                    is_multi_region=bool(t.get("IsMultiRegionTrail")),
                    log_file_validation=t.get("LogFileValidationEnabled"),
                )
                try:
                    st = self._call(
                        self._client("cloudtrail", trail.home_region), "get_trail_status", Name=arn, resource=arn
                    )
                    trail.is_logging = bool((st or {}).get("IsLogging"))
                except _Gap:
                    pass
                trails[arn] = trail
        return list(trails.values()) if any_ok else None
