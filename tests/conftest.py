"""Shared fixtures for the AgentGuard test suite."""

import pytest

from agentguard.providers.storage.memory import MemoryStore
from tests._helpers.constants import SECRET


@pytest.fixture
def secret() -> str:
    return SECRET


@pytest.fixture
def store() -> MemoryStore:
    """A fresh in-memory store; pass to build_runtime(store=...) to inspect audit logs."""
    return MemoryStore()
