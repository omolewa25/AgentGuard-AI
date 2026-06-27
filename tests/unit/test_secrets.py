import pytest

from agentguard.security.scanner import HeuristicScanner
from agentguard.security.secrets import redact_secrets, scan_secrets

pytestmark = pytest.mark.unit


def test_scan_and_redact_secrets(secret):
    assert "openai_api_key" in scan_secrets(f"token {secret}")
    sanitized, matches = redact_secrets(f"token {secret}")
    assert "openai_api_key" in matches and secret not in sanitized


def test_scan_tool_input_flags_outbound_secret(secret):
    result = HeuristicScanner().scan_tool_input({"body": f"here is the key {secret}"})
    assert result.detected is True


def test_scan_tool_input_allows_clean_args():
    result = HeuristicScanner().scan_tool_input({"to": "alice@example.com", "subject": "hi"})
    assert result.detected is False
