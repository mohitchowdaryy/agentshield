import json
from urllib.parse import quote

from agentshield.cloud import iam_policy as ip


def test_single_statement_dict_and_string_values_are_normalized():
    stmts = ip.statements({"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}})
    assert len(stmts) == 1
    assert stmts[0].actions == ("s3:GetObject",)
    assert stmts[0].resources == ("*",)


def test_url_encoded_document_is_decoded():
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    assert ip.is_full_admin(ip.statements(quote(json.dumps(doc)))[0])


def test_full_admin_detection():
    admin = ip.statements({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})[0]
    assert ip.is_full_admin(admin)
    scoped = ip.statements({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b/*"}]})[0]
    assert not ip.is_full_admin(scoped)
    deny = ip.statements({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})[0]
    assert not ip.is_full_admin(deny)


def test_allow_notaction_on_all_resources_is_admin_equivalent():
    s = ip.statements({"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]})[0]
    assert ip.is_full_admin(s)


def test_service_wildcards_only_on_all_resources():
    s = ip.statements({"Statement": [{"Effect": "Allow", "Action": ["s3:*", "ec2:Describe*"], "Resource": "*"}]})[0]
    assert ip.service_wildcards(s) == ["s3:*"]
    scoped = ip.statements({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::b"}]})[0]
    assert ip.service_wildcards(scoped) == []


def test_public_principal_forms():
    assert ip.principal_is_public("*")
    assert ip.principal_is_public({"AWS": "*"})
    assert ip.principal_is_public({"AWS": ["arn:aws:iam::1:root", "*"]})
    assert not ip.principal_is_public({"AWS": "arn:aws:iam::111122223333:root"})
    assert not ip.principal_is_public({"Service": "lambda.amazonaws.com"})


def test_restrictive_conditions_make_public_statement_conditional():
    s = ip.statements(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1"}},
                }
            ]
        }
    )[0]
    assert not ip.is_unconditionally_public(s)
    s2 = ip.statements(
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                }
            ]
        }
    )[0]
    assert ip.is_unconditionally_public(s2)


def test_allows_with_explicit_deny_and_wildcards():
    docs = [
        {"Statement": [{"Sid": "Broad", "Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
        {"Statement": [{"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::secret/*"}]},
    ]
    ok, by = ip.allows(docs, "s3:GetObject", "arn:aws:s3:::public/key")
    assert ok and by == ["Broad"]
    ok, _ = ip.allows(docs, "s3:GetObject", "arn:aws:s3:::secret/key")
    assert not ok
    ok, _ = ip.allows(docs, "iam:CreateUser", "*")
    assert not ok


def test_action_matching_is_case_insensitive():
    assert ip.action_matches(["S3:get*"], "s3:GetObject")
    assert not ip.action_matches(["s3:List*"], "s3:GetObject")
