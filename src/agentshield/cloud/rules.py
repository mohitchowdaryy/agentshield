"""AWS posture rules. Each rule reads only the normalized inventory and emits evidence-backed findings.

Findings describe configuration risk. None of them claims that a resource was exploited or is
exploitable; `exploitability` is always `not_validated`.
"""

from __future__ import annotations

from typing import Any

from agentshield.cloud import iam_policy
from agentshield.cloud.base import CloudInventory, FindingResult, IamRole, Rule, Severity

PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")

S3_BPA_DOC = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
S3_ENC_DOC = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html"
S3_VER_DOC = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"
IAM_BP_DOC = "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"
ROOT_DOC = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"
CT_DOC = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html"
CT_VALIDATION_DOC = (
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html"
)
WA_SEC = "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html"


def _missing_pab(pab: dict[str, bool] | None) -> list[str]:
    if pab is None:
        return list(PAB_KEYS)
    return [k for k in PAB_KEYS if not pab.get(k, False)]


class AccountPublicAccessBlock(Rule):
    rule_id = "AWS-S3-001"
    title = "Account-level S3 Block Public Access is not fully enabled"
    service = "s3"
    references = [S3_BPA_DOC, WA_SEC]

    def evaluate(self, inv: CloudInventory) -> list[FindingResult]:
        if inv.account_public_access_block_status == "unknown":
            return []
        missing = _missing_pab(inv.account_public_access_block)
        if not missing:
            return []
        return [
            self.finding(
                inv,
                severity="medium",
                resource_arn=inv.account_arn,
                resource_type="AWS::S3::AccountPublicAccessBlock",
                region="global",
                evidence={
                    "configuration": inv.account_public_access_block,
                    "status": inv.account_public_access_block_status,
                    "settings_not_enabled": missing,
                },
                remediation=(
                    "Enable all four S3 Block Public Access settings at the account level "
                    "(s3control put-public-access-block) unless a documented exception requires public buckets."
                ),
            )
        ]


class BucketPublicAccessBlock(Rule):
    rule_id = "AWS-S3-002"
    title = "S3 bucket Block Public Access is not fully enabled"
    service = "s3"
    references = [S3_BPA_DOC]

    def evaluate(self, inv: CloudInventory) -> list[FindingResult]:
        out = []
        account_missing = (
            _missing_pab(inv.account_public_access_block)
            if inv.account_public_access_block_status != "unknown"
            else None
        )
        for b in inv.s3_buckets or []:
            if b.public_access_block_status == "unknown":
                continue
            missing = _missing_pab(b.public_access_block)
            # A setting is effectively on if enabled at either bucket or account level.
            effective_missing = [k for k in missing if account_missing is None or k in account_missing]
            if not effective_missing:
                continue
            out.append(
                self.finding(
                    inv,
                    severity="medium" if account_missing else "low",
                    resource_arn=b.arn,
                    resource_type="AWS::S3::Bucket",
                    region=b.region,
                    evidence={
                        "bucket_configuration": b.public_access_block,
                        "bucket_status": b.public_access_block_status,
                        "account_settings_not_enabled": account_missing,
                        "effective_settings_not_enabled": effective_missing,
                    },
                    remediation=f"Enable S3 Block Public Access on bucket '{b.name}' (s3api put-public-access-block).",
                )
            )
        return out


class BucketPolicyPublic(Rule):
    rule_id = "AWS-S3-003"
    title = "S3 bucket policy grants access to any principal"
    service = "s3"
    references = [S3_BPA_DOC, WA_SEC]

    def evaluate(self, inv: CloudInventory) -> list[FindingResult]:
        out = []
        acct_pab = inv.account_public_access_block or {}
        for b in inv.s3_buckets or []:
            if b.policy_status != "present" or not b.policy:
                continue
            public = [s for s in iam_policy.statements(b.policy) if iam_policy.is_unconditionally_public(s)]
            if not public:
                continue
            bucket_pab = b.public_access_block or {}
            restricted = bool(bucket_pab.get("RestrictPublicBuckets") or acct_pab.get("RestrictPublicBuckets"))
            severity: Severity = "low" if restricted else "critical"
            actions = sorted({a for s in public for a in s.actions})
            out.append(
                self.finding(
                    inv,
                    severity=severity,
                    resource_arn=b.arn,
                    resource_type="AWS::S3::Bucket",
                    region=b.region,
                    evidence={
                        "public_statements": [s.raw for s in public],
                        "public_actions": actions,
                        "restrict_public_buckets_effective": restricted,
                        "note": (
                            "RestrictPublicBuckets limits access to AWS service principals and the bucket "
                            "owner's account, which mitigates this policy."
                            if restricted
                            else "No RestrictPublicBuckets setting mitigates this policy."
                        ),
                    },
                    remediation=(
                        f"Remove or scope the Principal \"*\" statements in the policy of '{b.name}' "
                        "(add aws:PrincipalOrgID / aws:SourceVpce conditions or name specific principals), "
                        "and enable Block Public Access."
                    ),
                )
            )
        return out


class BucketEncryption(Rule):
    rule_id = "AWS-S3-004"
    title = "S3 bucket has no default encryption configuration"
    service = "s3"
    references = [S3_ENC_DOC]

    def evaluate(self, inv: CloudInventory) -> list[FindingResult]:
        return [
            self.finding(
                inv,
                severity="medium",
                resource_arn=b.arn,
                resource_type="AWS::S3::Bucket",
                region=b.region,
                evidence={"encryption_status": b.encryption_status, "encryption_rules": b.encryption_rules},
                remediation=(
                    f"Configure default encryption on '{b.name}' (SSE-KMS with a customer managed key for "
                    "sensitive data). Note: since January 2023 S3 applies SSE-S3 to new objects by default; "
                    "a missing configuration usually indicates an API gap or a legacy/non-standard partition."
                ),
            )
            for b in inv.s3_buckets or []
            if b.encryption_status == "not_configured"
        ]


class BucketVersioning(Rule):
    rule_id = "AWS-S3-005"
    title = "S3 bucket versioning is not enabled"
    service = "s3"
    references = [S3_VER_DOC]

    def evaluate(self, inv: CloudInventory) -> list[FindingResult]:
        return [
            self.finding(
                inv,
                severity="low",
                resource_arn=b.arn,
                resource_type="AWS::S3::Bucket",
                region=b.region,
                evidence={"versioning_status": b.versioning},
                remediation=f"Enable versioning on '{b.name}' to protect against accidental or malicious overwrite.",
            )
            for b in inv.s3_buckets or []
            if b.versioning in ("Disabled", "Suspended")
        ]


def _role_documents(role: IamRole) -> list[tuple[str, dict[str, Any]]]:
    docs: list[tuple[str, dict[str, Any]]] = []
    for name, doc in (role.inline_policies or {}).items():
        docs.append((f"inline:{name}", doc))
    for ap in role.attached_policies or []:
        if ap.document is not None:
            docs.append((f"attached:{ap.arn}", ap.document))
    return docs


class RoleFullAdmin(Rule):
    rule_id = "AWS-IAM-001"
    title = "IAM role grants full administrative access (Action * on Resource *)"
    service = "iam"
    references = [IAM_BP_DOC, WA_SEC]

    def evaluate(self, inv: CloudInventory) -> list[FindingResult]:
        out = []
        for role in inv.iam_roles or []:
            if role.path.startswith("/aws-service-role/"):
                continue  # service-linked roles are AWS-managed
            sources = []
            for label, doc in _role_documents(role):
                stmts = [s.raw for s in iam_policy.statements(doc) if iam_policy.is_full_admin(s)]
                if stmts:
                    sources.append({"policy": label, "statements": stmts})
            if sources:
                out.append(
                    self.finding(
                        inv,
                        severity="critical",
                        resource_arn=role.arn,
                        resource_type="AWS::IAM::Role",
                        region="global",
                        evidence={"role": role.name, "admin_grants": sources},
                        remediation=(
                            f"Replace administrative grants on role '{role.name}' with least-privilege policies "
                            "scoped to the actions and resources the workload needs (use IAM Access Analyzer "
                            "policy generation from CloudTrail activity)."
                        ),
                    )
                )
        return out


class RoleServiceWildcard(Rule):
    rule_id = "AWS-IAM-002"
    title = "IAM role grants service-wide wildcard actions on all resources"
    service = "iam"
    references = [IAM_BP_DOC]

    def evaluate(self, inv: CloudInventory) -> list[FindingResult]:
        out = []
        for role in inv.iam_roles or []:
            if role.path.startswith("/aws-service-role/"):
                continue
            grants = []
            for label, doc in _role_documents(role):
                for s in iam_policy.statements(doc):
                    if iam_policy.is_full_admin(s):
                        continue  # reported by AWS-IAM-001
                    wildcards = iam_policy.service_wildcards(s)
                    if wildcards:
                        grants.append({"policy": label, "actions": wildcards, "statement": s.raw})
            if grants:
                sensitive = any(
                    a.split(":")[0] in {"iam", "s3", "kms", "sts", "secretsmanager"}
                    for g in grants
                    for a in g["actions"]
                )
                out.append(
                    self.finding(
                        inv,
                        severity="high" if sensitive else "medium",
                        resource_arn=role.arn,
                        resource_type="AWS::IAM::Role",
                        region="global",
                        evidence={"role": role.name, "wildcard_grants": grants},
                        remediation=(
                            f"Scope the wildcard actions on role '{role.name}' to specific actions and resource ARNs."
                        ),
                    )
                )
        return out


class RoleTrustPublic(Rule):
    rule_id = "AWS-IAM-003"
    title = "IAM role trust policy allows any AWS principal to assume it"
    service = "iam"
    references = [IAM_BP_DOC]

    def evaluate(self, inv: CloudInventory) -> list[FindingResult]:
        out = []
        for role in inv.iam_roles or []:
            if role.trust_policy is None:
                continue
            stmts = [
                s
                for s in iam_policy.statements(role.trust_policy)
                if s.effect == "Allow" and iam_policy.principal_is_public(s.principal)
            ]
            if not stmts:
                continue
            unconditional = [s for s in stmts if iam_policy.is_unconditionally_public(s)]
            out.append(
                self.finding(
                    inv,
                    severity="critical" if unconditional else "medium",
                    resource_arn=role.arn,
                    resource_type="AWS::IAM::Role",
                    region="global",
                    evidence={
                        "role": role.name,
                        "statements": [s.raw for s in stmts],
                        "has_restrictive_conditions": not unconditional,
                    },
                    remediation=(
                        f"Restrict the trust policy of '{role.name}' to specific principals and add "
                        "sts:ExternalId / aws:PrincipalOrgID conditions where cross-account access is required."
                    ),
                )
            )
        return out


class RootMfa(Rule):
    rule_id = "AWS-ROOT-001"
    title = "Root user does not have MFA enabled"
    service = "iam"
    references = [ROOT_DOC]

    def evaluate(self, inv: CloudInventory) -> list[FindingResult]:
        if inv.root_account.mfa_enabled is not False:
            return []
        return [
            self.finding(
                inv,
                severity="critical",
                resource_arn=inv.account_arn,
                resource_type="AWS::IAM::RootUser",
                region="global",
                evidence={"AccountMFAEnabled": 0, "api": "iam:GetAccountSummary"},
                remediation="Enable MFA (preferably a FIDO2 security key) on the root user.",
            )
        ]


class RootAccessKeys(Rule):
    rule_id = "AWS-ROOT-002"
    title = "Root user has active access keys"
    service = "iam"
    references = [ROOT_DOC]

    def evaluate(self, inv: CloudInventory) -> list[FindingResult]:
        if inv.root_account.access_keys_present is not True:
            return []
        return [
            self.finding(
                inv,
                severity="critical",
                resource_arn=inv.account_arn,
                resource_type="AWS::IAM::RootUser",
                region="global",
                evidence={"AccountAccessKeysPresent": 1, "api": "iam:GetAccountSummary"},
                remediation="Delete root user access keys and use IAM roles for programmatic access.",
            )
        ]


class CloudTrailMultiRegion(Rule):
    rule_id = "AWS-CT-001"
    title = "No multi-region CloudTrail trail is actively logging"
    service = "cloudtrail"
    references = [CT_DOC, WA_SEC]

    def evaluate(self, inv: CloudInventory) -> list[FindingResult]:
        trails = inv.cloudtrail_trails
        if trails is None:
            return []
        if any(t.is_multi_region and t.is_logging for t in trails):
            return []
        # If logging state is unknown for every multi-region trail we cannot conclude.
        if any(t.is_multi_region and t.is_logging is None for t in trails):
            return []
        return [
            self.finding(
                inv,
                severity="high",
                resource_arn=inv.account_arn,
                resource_type="AWS::CloudTrail::Trail",
                region="global",
                evidence={
                    "trails": [t.model_dump() for t in trails],
                    "multi_region_logging_trails": 0,
                },
                remediation=(
                    "Create a multi-region CloudTrail trail (or an organization trail) with logging enabled, "
                    "delivering to a dedicated, access-restricted S3 bucket."
                ),
            )
        ]


class CloudTrailLogValidation(Rule):
    rule_id = "AWS-CT-002"
    title = "CloudTrail log file validation is disabled"
    service = "cloudtrail"
    references = [CT_VALIDATION_DOC]

    def evaluate(self, inv: CloudInventory) -> list[FindingResult]:
        return [
            self.finding(
                inv,
                severity="low",
                resource_arn=t.arn,
                resource_type="AWS::CloudTrail::Trail",
                region=t.home_region,
                evidence={"trail": t.name, "LogFileValidationEnabled": False},
                remediation=f"Enable log file integrity validation on trail '{t.name}'.",
            )
            for t in inv.cloudtrail_trails or []
            if t.log_file_validation is False
        ]


ALL_RULES: list[Rule] = [
    AccountPublicAccessBlock(),
    BucketPublicAccessBlock(),
    BucketPolicyPublic(),
    BucketEncryption(),
    BucketVersioning(),
    RoleFullAdmin(),
    RoleServiceWildcard(),
    RoleTrustPublic(),
    RootMfa(),
    RootAccessKeys(),
    CloudTrailMultiRegion(),
    CloudTrailLogValidation(),
]


def evaluate_inventory(inv: CloudInventory, rules: list[Rule] | None = None) -> list[FindingResult]:
    findings: list[FindingResult] = []
    for rule in rules or ALL_RULES:
        findings.extend(rule.evaluate(inv))
    return findings
