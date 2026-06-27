from __future__ import annotations

import os
from typing import Any


class JenkinsClient:
    """Minimal Jenkins REST client (trigger a job, read build status).

    Talks to a real Jenkins server using API-token auth and CSRF crumb handling.
    Construction fails fast if the server/credentials are not configured. A
    `session` can be injected for testing."""

    def __init__(
        self,
        base_url: str | None = None,
        user: str | None = None,
        token: str | None = None,
        *,
        session: Any | None = None,
        timeout: int = 30,
    ) -> None:
        self.base_url = (base_url or os.getenv("JENKINS_URL") or "").rstrip("/")
        self.user = user or os.getenv("JENKINS_USER")
        self.token = token or os.getenv("JENKINS_API_TOKEN")
        if not (self.base_url and self.user and self.token):
            raise RuntimeError(
                "Jenkins is not configured. Set JENKINS_URL, JENKINS_USER, and "
                "JENKINS_API_TOKEN to use the Jenkins tools."
            )
        self.timeout = timeout
        self._session = session

    def _sess(self):
        if self._session is None:
            import requests

            session = requests.Session()
            session.auth = (self.user, self.token)
            self._session = session
        return self._session

    def _crumb_headers(self) -> dict[str, str]:
        try:
            resp = self._sess().get(f"{self.base_url}/crumbIssuer/api/json", timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                return {data["crumbRequestField"]: data["crumb"]}
        except Exception:
            pass  # crumb issuer disabled or unreachable; proceed without it
        return {}

    def trigger_build(self, job: str, parameters: dict | None = None) -> dict:
        headers = self._crumb_headers()
        if parameters:
            url = f"{self.base_url}/job/{job}/buildWithParameters"
            resp = self._sess().post(url, params=parameters, headers=headers, timeout=self.timeout)
        else:
            url = f"{self.base_url}/job/{job}/build"
            resp = self._sess().post(url, headers=headers, timeout=self.timeout)
        resp.raise_for_status()
        return {
            "job": job,
            "status": "queued",
            "http_status": resp.status_code,
            "queue_url": resp.headers.get("Location"),
        }

    def get_build_status(self, job: str, build_number: int) -> dict:
        url = f"{self.base_url}/job/{job}/{build_number}/api/json"
        resp = self._sess().get(url, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        return {
            "job": job,
            "build_number": build_number,
            "building": data.get("building"),
            "result": data.get("result"),
            "url": data.get("url"),
        }


def build_jenkins_client() -> JenkinsClient:
    """Factory used by the tools; reads configuration from the environment."""
    return JenkinsClient()
