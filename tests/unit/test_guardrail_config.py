import json

import pytest

from agentguard.guardrails.config import GuardrailsConfig, load_guardrails_config
from agentguard.guardrails.factory import build_guardrails

pytestmark = pytest.mark.unit


def test_load_guardrails_config(tmp_path):
    path = tmp_path / "g.json"
    path.write_text(json.dumps({"output": [{"type": "pii"}], "max_reasks": 3}))
    config = load_guardrails_config(str(path))
    assert config.max_reasks == 3 and config.output[0]["type"] == "pii"


def test_build_guardrails_assembles_pipelines():
    config = GuardrailsConfig(
        input=[{"type": "topic", "deny": ["x"]}],
        output=[{"type": "pii"}, {"type": "toxicity"}, {"type": "grounding"}],
        max_reasks=2,
    )
    input_pipe, output_pipe, max_reasks = build_guardrails(config)
    assert max_reasks == 2
    assert [g.name for g in input_pipe.guardrails] == ["topic"]
    assert [g.name for g in output_pipe.guardrails] == ["pii", "toxicity", "grounding"]


def test_build_guardrail_unknown_type_raises():
    with pytest.raises(ValueError):
        build_guardrails(GuardrailsConfig(output=[{"type": "nope"}]))
