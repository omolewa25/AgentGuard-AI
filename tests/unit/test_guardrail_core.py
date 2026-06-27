import pytest

from agentguard.guardrails.base import OnFail, more_severe

pytestmark = pytest.mark.unit


def test_more_severe_ordering():
    assert more_severe(OnFail.REDACT, OnFail.BLOCK) == OnFail.BLOCK
    assert more_severe(OnFail.REASK, OnFail.REDACT) == OnFail.REASK
    assert more_severe(None, OnFail.LOG) == OnFail.LOG
