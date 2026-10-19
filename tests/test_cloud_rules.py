from agentshield.cloud.base import (
    AttachedPolicy,
    CloudInventory,
    CloudTrailTrail,
    IamRole,
    RootAccountSummary,
    S3Bucket,
    finding_fingerprint,
)
from agentshield.cloud.demo import DemoCollector
from agentshield.cloud.rules import evaluate_inventory

FULL_PAB = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
PUBLIC_POLICY = {
    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]
}


def inv(**kw):
    base = dict(account_id="123456789012", source="live", regions=["us-east-1"])
    base.update(kw)
    return CloudInventory(**base)


def rules(findings):
    return sorted(f.rule_id for f in findings)


def bucket(**kw):
    b = dict(name="b", arn="arn:aws:s3:::b", region="us-east-1")
    b.update(kw)
    return S3Bucket(**b)


def test_clean_inventory_has_no_findings():
    i = inv(
        account_public_access_block=FULL_PAB,
        account_public_access_block_status="configured",
        s3_buckets=[
            bucket(
                public_access_block=FULL_PAB,
                public_access_block_status="configured",
                policy_status="absent",
                encryption_status="configured",
                encryption_rules=[{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}],
                versioning="Enabled",
            )
        ],
        iam_roles=[],
        root_account=RootAccountSummary(mfa_enabled=True, access_keys_present=False),
        cloudtrail_trails=[
            CloudTrailTrail(
                name="t",
                arn="arn:t",
                home_region="us-east-1",
                is_multi_region=True,
                log_file_validation=True,
                is_logging=True,
            )
        ],
    )
    assert evaluate_inventory(i) == []


def test_unknown_values_produce_no_findings():
    """AccessDenied leaves fields unknown; rules must not invent findings without evidence."""
    i = inv(s3_buckets=[bucket()], iam_roles=None, cloudtrail_trails=None)
    assert evaluate_inventory(i) == []


def test_public_bucket_policy_critical_without_mitigation():
    i = inv(
        account_public_access_block_status="not_configured",
        s3_buckets=[bucket(policy=PUBLIC_POLICY, policy_status="present", public_access_block_status="not_configured")],
    )
    fs = {f.rule_id: f for f in evaluate_inventory(i)}
    assert fs["AWS-S3-003"].severity == "critical"
    assert fs["AWS-S3-003"].evidence["public_actions"] == ["s3:GetObject"]
    assert fs["AWS-S3-003"].exploitability == "not_validated"
    assert "AWS-S3-001" in fs and "AWS-S3-002" in fs


def test_public_policy_downgraded_when_restrict_public_buckets_enabled():
    i = inv(
        account_public_access_block=FULL_PAB,
        account_public_access_block_status="configured",
        s3_buckets=[bucket(policy=PUBLIC_POLICY, policy_status="present")],
    )
    f = [x for x in evaluate_inventory(i) if x.rule_id == "AWS-S3-003"][0]
    assert f.severity == "low"
    assert f.evidence["restrict_public_buckets_effective"] is True


def test_bucket_pab_effective_with_account_level_settings():
    partial = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    }
    i = inv(
        account_public_access_block=FULL_PAB,
        account_public_access_block_status="configured",
        s3_buckets=[bucket(public_access_block=partial, public_access_block_status="configured")],
    )
    assert "AWS-S3-002" not in rules(evaluate_inventory(i))


def test_encryption_and_versioning():
    i = inv(s3_buckets=[bucket(encryption_status="not_configured", versioning="Suspended")])
    assert rules(evaluate_inventory(i)) == ["AWS-S3-004", "AWS-S3-005"]


def test_iam_admin_wildcard_and_public_trust():
    role = IamRole(
        name="r",
        arn="arn:aws:iam::123456789012:role/r",
        trust_policy={"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]},
        inline_policies={"p": {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}},
        attached_policies=[
            AttachedPolicy(
                arn="arn:aws:iam::aws:policy/AdministratorAccess",
                name="AdministratorAccess",
                document={"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            )
        ],
    )
    fs = {f.rule_id: f for f in evaluate_inventory(inv(iam_roles=[role]))}
    assert fs["AWS-IAM-001"].severity == "critical"
    assert fs["AWS-IAM-002"].severity == "high"
    assert fs["AWS-IAM-002"].evidence["wildcard_grants"][0]["actions"] == ["iam:*"]
    assert fs["AWS-IAM-003"].severity == "critical"


def test_conditional_public_trust_is_medium():
    role = IamRole(
        name="r",
        arn="arn:aws:iam::1:role/r",
        trust_policy={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"sts:ExternalId": "x"}},
                }
            ]
        },
    )
    f = [x for x in evaluate_inventory(inv(iam_roles=[role])) if x.rule_id == "AWS-IAM-003"][0]
    assert f.severity == "medium"


def test_service_linked_roles_are_skipped():
    role = IamRole(
        name="slr",
        arn="arn:aws:iam::1:role/aws-service-role/x/slr",
        path="/aws-service-role/x/",
        inline_policies={"p": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}},
    )
    assert evaluate_inventory(inv(iam_roles=[role])) == []


def test_root_and_cloudtrail_rules():
    i = inv(
        root_account=RootAccountSummary(mfa_enabled=False, access_keys_present=True),
        cloudtrail_trails=[
            CloudTrailTrail(
                name="t",
                arn="arn:t",
                home_region="us-east-1",
                is_multi_region=False,
                log_file_validation=False,
                is_logging=True,
            )
        ],
    )
    assert rules(evaluate_inventory(i)) == ["AWS-CT-001", "AWS-CT-002", "AWS-ROOT-001", "AWS-ROOT-002"]


def test_cloudtrail_unknown_logging_state_is_not_reported():
    i = inv(
        cloudtrail_trails=[
            CloudTrailTrail(name="t", arn="arn:t", home_region="us-east-1", is_multi_region=True, is_logging=None)
        ]
    )
    assert "AWS-CT-001" not in rules(evaluate_inventory(i))


def test_no_trails_at_all_is_reported():
    assert rules(evaluate_inventory(inv(cloudtrail_trails=[]))) == ["AWS-CT-001"]


def test_finding_fields_and_fingerprint_stability():
    i = inv(root_account=RootAccountSummary(mfa_enabled=False))
    f1 = evaluate_inventory(i)[0]
    f2 = evaluate_inventory(i)[0]
    assert (
        f1.fingerprint
        == f2.fingerprint
        == finding_fingerprint("AWS-ROOT-001", "123456789012", "global", "arn:aws:iam::123456789012:root")
    )
    for field in (
        "rule_id",
        "title",
        "severity",
        "resource_arn",
        "account_id",
        "region",
        "evidence",
        "remediation",
        "observed_at",
        "source",
    ):
        assert getattr(f1, field) not in (None, "")


def test_demo_inventory_findings():
    found = rules(evaluate_inventory(DemoCollector().collect()))
    assert found == sorted(
        [
            "AWS-S3-001",
            "AWS-S3-002",
            "AWS-S3-002",
            "AWS-S3-003",
            "AWS-S3-004",
            "AWS-S3-005",
            "AWS-S3-005",
            "AWS-IAM-001",
            "AWS-IAM-002",
            "AWS-IAM-003",
            "AWS-ROOT-001",
            "AWS-CT-001",
            "AWS-CT-002",
        ]
    )
