import pytest

from agentguard.providers.cicd.jenkins import JenkinsClient
from tests._helpers.fakes import FakeResponse, FakeSession

pytestmark = pytest.mark.unit


def _client(session):
    return JenkinsClient(base_url="http://j", user="u", token="t", session=session)


def test_client_requires_configuration(monkeypatch):
    for var in ("JENKINS_URL", "JENKINS_USER", "JENKINS_API_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(RuntimeError):
        JenkinsClient()


def test_trigger_build_with_parameters_uses_build_with_parameters():
    session = FakeSession()
    result = _client(session).trigger_build("deploy-api", {"ENV": "staging"})
    post_calls = [c for c in session.calls if c[0] == "POST"]
    assert post_calls[0][1].endswith("/job/deploy-api/buildWithParameters")
    assert post_calls[0][2]["params"] == {"ENV": "staging"}
    assert result["status"] == "queued"
    assert result["queue_url"] == "http://j/queue/item/42/"


def test_trigger_build_without_parameters_uses_build():
    session = FakeSession()
    _client(session).trigger_build("deploy-api")
    post_calls = [c for c in session.calls if c[0] == "POST"]
    assert post_calls[0][1].endswith("/job/deploy-api/build")


def test_crumb_header_attached_when_available():
    session = FakeSession(get_responses={"crumbIssuer": FakeResponse(200, {"crumbRequestField": "Jenkins-Crumb", "crumb": "abc"})})
    _client(session).trigger_build("job", {"X": "1"})
    post = next(c for c in session.calls if c[0] == "POST")
    assert post[2]["headers"].get("Jenkins-Crumb") == "abc"


def test_get_build_status_parses_result():
    session = FakeSession(get_responses={"/job/api/3/api/json": FakeResponse(200, {"building": False, "result": "SUCCESS", "url": "http://j/job/api/3/"})})
    status = _client(session).get_build_status("api", 3)
    assert status["result"] == "SUCCESS"
    assert status["building"] is False
