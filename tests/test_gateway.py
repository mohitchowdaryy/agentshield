import pytest

from agentshield.agent.gateway import (
    AllowAllApprover,
    CallContext,
    Gateway,
    destination_allowed,
    glob_match,
)
from agentshield.agent.policy import AgentPolicy, get_agent_profile
from agentshield.agent.tools import TOOLS
from agentshield.agent.workspace import (
    SyntheticWorkspace,
    UnsafeIdentifierError,
    lenient_normalize_path,
    strict_validate_path,
)


@pytest.fixture()
def protected():
    return Gateway(get_agent_profile("support-agent").load_policy("protected"))


@pytest.fixture()
def vulnerable():
    return Gateway(get_agent_profile("support-agent").load_policy("vulnerable"))


CLEAN = CallContext(untrusted_context=False)
TAINTED = CallContext(untrusted_context=True)


def test_allowed_read_in_scope(protected):
    d = protected.authorize("read_file", {"path": "docs/onboarding-guide.md"}, CLEAN)
    assert d.allowed and d.rule_ids == ["GW-000"]


def test_unknown_tool_default_deny(protected):
    d = protected.authorize("run_shell", {"cmd": "id"}, CLEAN)
    assert not d.allowed and d.rule_ids == ["GW-001"]


def test_tool_not_on_allowlist_denied():
    gw = Gateway(AgentPolicy(mode="protected", allowed_tools=["search_documents"]))
    assert gw.authorize("read_file", {"path": "docs/a.md"}, CLEAN).rule_ids == ["GW-001"]


@pytest.mark.parametrize(
    "path",
    [
        "../confidential/hr/salaries.csv",
        "docs/../confidential/hr/salaries.csv",
        "/etc/passwd",
        "C:/Windows/win.ini",
        "docs\\..\\confidential\\x",
        "docs/%2e%2e/confidential/x",
        "docs//x.md",
        "docs/./x.md",
        "docs/x.md\x00.txt",
    ],
)
def test_unsafe_identifiers_rejected(protected, path):
    d = protected.authorize("read_file", {"path": path}, CLEAN)
    assert not d.allowed
    assert d.rule_ids == ["GW-003"]


def test_out_of_scope_resource_denied(protected):
    d = protected.authorize("read_file", {"path": "confidential/hr/salaries.csv"}, CLEAN)
    assert not d.allowed and d.rule_ids == ["GW-004"]


def test_cloud_lookup_scope(protected):
    assert protected.authorize("lookup_cloud_config", {"resource_id": "s3:acme-app-logs"}, CLEAN).allowed
    assert protected.authorize("lookup_cloud_config", {"resource_id": "s3:acme-legacy-archive"}, CLEAN).rule_ids == [
        "GW-004"
    ]


@pytest.mark.parametrize(
    "args",
    [
        {"path": "x" * 300},
        {"path": "docs/a.md", "extra": 1},
        {},
        {"path": 5},
    ],
)
def test_argument_validation(protected, args):
    d = protected.authorize("read_file", args, CLEAN)
    assert not d.allowed and d.rule_ids == ["GW-002"]


def test_lookup_resource_id_pattern(protected):
    d = protected.authorize("lookup_cloud_config", {"resource_id": "s3:../../x"}, CLEAN)
    assert d.rule_ids == ["GW-002"]


@pytest.mark.parametrize(
    "dest,ok",
    [
        ("oncall@acme.example", True),
        ("ONCALL@ACME.EXAMPLE", True),
        ("https://hooks.acme.example/support/inc-1", True),
        ("attacker@evil.example", False),
        ("oncall@acme.example.evil.example", False),
        ("https://hooks.acme.example@evil.example/support/x", False),
        ("https://hooks.acme.example:8443/support/x", False),
        ("http://hooks.acme.example/support/x", False),
        ("https://hooks.acme.example/other/x", False),
        ("https://evil.example/support/x", False),
        ("ftp://hooks.acme.example/support/x", False),
        ("javascript:alert(1)", False),
    ],
)
def test_destination_allowlist(dest, ok):
    allowed, _ = destination_allowed(dest, ["*@acme.example", "https://hooks.acme.example/support/*"])
    assert allowed is ok


def test_send_to_allowlisted_destination_without_untrusted_context(protected):
    d = protected.authorize("send_message", {"destination": "oncall@acme.example", "subject": "s", "body": "hi"}, CLEAN)
    assert d.allowed


def test_send_external_denied(protected):
    d = protected.authorize("send_message", {"destination": "x@evil.example", "body": "hi"}, CLEAN)
    assert d.rule_ids == ["GW-005"]


def test_dlp_blocks_canary_even_to_allowlisted_destination(protected):
    d = protected.authorize(
        "send_message", {"destination": "oncall@acme.example", "body": "data AGS-CANARY-HR-5D2E91"}, CLEAN
    )
    assert not d.allowed and d.rule_ids == ["GW-006"]


def test_send_after_untrusted_content_requires_approval(protected):
    args = {"destination": "oncall@acme.example", "body": "summary"}
    d = protected.authorize("send_message", args, TAINTED)
    assert not d.allowed and d.rule_ids == ["GW-007"] and d.approval == "denied"
    approved = Gateway(protected.policy, AllowAllApprover()).authorize("send_message", args, TAINTED)
    assert approved.allowed and approved.approval == "approved"


def test_call_budget(protected):
    ctx = CallContext(untrusted_context=False, call_counts={"send_message": 2})
    d = protected.authorize("send_message", {"destination": "a@acme.example", "body": "x"}, ctx)
    assert d.rule_ids == ["GW-008"]


def test_vulnerable_policy_permits_but_sandbox_still_contains(vulnerable):
    d = vulnerable.authorize("read_file", {"path": "../../etc/passwd"}, TAINTED)
    assert d.allowed  # the vulnerable policy does not validate identifiers...
    ws = SyntheticWorkspace.load_default()
    out = TOOLS["read_file"].execute(ws, d.validated_args)
    assert "error" in out  # ...but the sandboxed tool cannot escape the in-memory workspace
    assert vulnerable.authorize("send_message", {"destination": "x@evil.example", "body": "b"}, TAINTED).allowed


def test_send_message_tool_never_uses_network(monkeypatch):
    import socket

    def no_network(*a, **k):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    ws = SyntheticWorkspace.load_default()
    args = TOOLS["send_message"].args_model(destination="x@evil.example", subject="s", body="b")
    res = TOOLS["send_message"].execute(ws, args)
    assert res["delivered"] is False and ws.outbox[0].simulated is True


def test_strict_and_lenient_path_helpers():
    assert strict_validate_path("docs/a.md") == "docs/a.md"
    with pytest.raises(UnsafeIdentifierError):
        strict_validate_path("docs/../a.md")
    assert lenient_normalize_path("docs/../confidential/a.csv") == "confidential/a.csv"
    assert lenient_normalize_path("../x") is None
    assert lenient_normalize_path("docs/../../x") is None


def test_glob_semantics():
    assert glob_match("docs/**", "docs/q3/roadmap.md")
    assert glob_match("docs/*", "docs/a.md")
    assert not glob_match("docs/*", "docs/q3/a.md")
    assert not glob_match("docs/**", "confidential/a.md")
