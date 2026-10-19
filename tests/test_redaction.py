from agentshield.redaction import REDACTED, redact, redact_text


def test_redacts_common_secret_formats():
    text = (
        "key AKIAIOSFODNN7EXAMPLE secret aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY "
        "anthropic sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345 auth Bearer abcdefghijklmnopqrstuvwxyz"
    )
    out = redact_text(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in out
    assert "sk-ant-api03" not in out
    assert "abcdefghijklmnopqrstuvwxyz" not in out


def test_private_key_block():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    assert "MIIEowIBAAKCAQEA" not in redact_text(pem)


def test_nested_structures_and_sensitive_keys():
    data = {"headers": {"Authorization": "Bearer x", "x": ["AKIAIOSFODNN7EXAMPLE"]}, "api_key": "k", "n": 3}
    out = redact(data)
    assert out["headers"]["Authorization"] == REDACTED
    assert out["api_key"] == REDACTED
    assert "AKIA" not in out["headers"]["x"][0]
    assert out["n"] == 3


def test_canary_tokens_are_preserved_as_evidence():
    assert redact_text("canary AGS-CANARY-HR-5D2E91") == "canary AGS-CANARY-HR-5D2E91"
