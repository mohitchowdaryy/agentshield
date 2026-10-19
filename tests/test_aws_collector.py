"""AWS collector tests. Moto and botocore Stubber only: the suite never calls real AWS."""

import json

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from agentshield.cloud.aws import READ_ONLY_PREFIXES, AwsCollector, AwsScanError
from agentshield.cloud.rules import evaluate_inventory


def _seed():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="public-kb")
    s3.put_bucket_policy(
        Bucket="public-kb",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::public-kb/*",
                    }
                ],
            }
        ),
    )
    s3.put_bucket_tagging(Bucket="public-kb", Tagging={"TagSet": [{"Key": "owner", "Value": "support"}]})
    s3.create_bucket(Bucket="locked-down")
    s3.put_public_access_block(
        Bucket="locked-down",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_versioning(Bucket="locked-down", VersioningConfiguration={"Status": "Enabled"})
    s3.create_bucket(Bucket="trail-logs")

    iam = boto3.client("iam", region_name="us-east-1")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName="ci-admin", AssumeRolePolicyDocument=json.dumps(trust))
    admin = iam.create_policy(
        PolicyName="Admin",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        ),
    )
    iam.attach_role_policy(RoleName="ci-admin", PolicyArn=admin["Policy"]["Arn"])
    svc_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName="agent", AssumeRolePolicyDocument=json.dumps(svc_trust))
    iam.put_role_policy(
        RoleName="agent",
        PolicyName="s3",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        ),
    )

    ct = boto3.client("cloudtrail", region_name="us-east-1")
    ct.create_trail(Name="single-region", S3BucketName="trail-logs", IsMultiRegionTrail=False)
    ct.start_logging(Name="single-region")


@mock_aws
def test_collects_inventory_and_evaluates_rules():
    _seed()
    inv = AwsCollector(regions=["us-east-1"]).collect()
    assert inv.source == "live" and inv.account_id
    names = {b.name: b for b in inv.s3_buckets}
    assert names["public-kb"].policy_status == "present"
    assert names["public-kb"].tags == {"owner": "support"}
    assert names["locked-down"].public_access_block_status == "configured"
    assert names["locked-down"].versioning == "Enabled"
    roles = {r.name: r for r in inv.iam_roles}
    assert roles["ci-admin"].attached_policies[0].document["Statement"][0]["Action"] == "*"
    assert roles["agent"].inline_policies["s3"]["Statement"][0]["Action"] == "s3:*"
    assert inv.cloudtrail_trails[0].is_logging is True

    findings = evaluate_inventory(inv)
    by_rule = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, []).append(f.resource_arn)
    assert "arn:aws:s3:::public-kb" in by_rule["AWS-S3-003"]
    assert any(a.endswith("role/ci-admin") for a in by_rule["AWS-IAM-001"])
    assert any(a.endswith("role/ci-admin") for a in by_rule["AWS-IAM-003"])
    assert any(a.endswith("role/agent") for a in by_rule["AWS-IAM-002"])
    assert "AWS-CT-001" in by_rule  # only a single-region trail exists
    assert all(f.source == "live" and f.exploitability == "not_validated" for f in findings)


@mock_aws
def test_access_denied_becomes_collection_gap_and_scan_continues(monkeypatch):
    _seed()
    collector = AwsCollector(regions=["us-east-1"])
    s3 = collector._client("s3")
    real = s3.get_bucket_policy

    def denied(**kwargs):
        if kwargs["Bucket"] == "public-kb":
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetBucketPolicy")
        return real(**kwargs)

    monkeypatch.setattr(s3, "get_bucket_policy", denied)
    inv = collector.collect()
    assert any(g.operation == "GetBucketPolicy" and g.error_code == "AccessDenied" for g in inv.gaps)
    kb = [b for b in inv.s3_buckets if b.name == "public-kb"][0]
    assert kb.policy_status == "unknown"
    # No public-policy finding without the evidence, but other rules still ran.
    findings = evaluate_inventory(inv)
    assert not any(f.rule_id == "AWS-S3-003" for f in findings)
    assert any(f.rule_id == "AWS-IAM-001" for f in findings)


@mock_aws
def test_iam_list_denied_marks_roles_unknown():
    collector = AwsCollector(regions=["us-east-1"])
    iam = collector._client("iam")

    class DeniedPaginator:
        def paginate(self, **kw):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListRoles")

    orig = iam.get_paginator
    iam.get_paginator = lambda op: DeniedPaginator() if op == "list_roles" else orig(op)
    inv = collector.collect()
    assert inv.iam_roles is None
    assert any(g.service == "iam" and g.operation == "ListRoles" for g in inv.gaps)


def test_refuses_mutating_operations():
    collector = AwsCollector(regions=["us-east-1"], session=boto3.Session(region_name="us-east-1"))
    with pytest.raises(PermissionError):
        collector._call(collector._client("s3"), "put_bucket_policy", Bucket="x", Policy="{}")
    with pytest.raises(PermissionError):
        collector._paginate(collector._client("s3"), "delete_objects", "Deleted")


def test_collector_source_only_uses_read_only_operations():
    """Static guard: every boto3 operation named in the collector is Get*/List*/Describe*."""
    import inspect
    import re

    import agentshield.cloud.aws as mod

    src = inspect.getsource(mod)
    ops = set(re.findall(r'_(?:call|paginate)\([^,]+,\s*"([a-z_]+)"', src))
    assert ops, "expected to find operations"
    assert all(op.startswith(READ_ONLY_PREFIXES) for op in ops), ops


def test_missing_credentials_raise_clear_error(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    session = boto3.Session(region_name="us-east-1")
    monkeypatch.setattr(session, "client", _no_creds_client(session.client))
    with pytest.raises(AwsScanError, match="No AWS credentials"):
        AwsCollector(regions=["us-east-1"], session=session).collect()


def _no_creds_client(real_client):
    from botocore.exceptions import NoCredentialsError

    def make(service, **kw):
        c = real_client(service, **kw)
        if service == "sts":

            def boom(**_):
                raise NoCredentialsError()

            c.get_caller_identity = boom
        return c

    return make


def test_unknown_profile_raises():
    with pytest.raises(AwsScanError, match="profile not found"):
        AwsCollector(profile="definitely-not-a-profile-xyz")
