from __future__ import annotations

import os

from agentguard.providers.storage.base import Store
from agentguard.providers.storage.memory import MemoryStore


def build_store() -> Store:
    """Select a store via AGENTGUARD_STORE (memory|sqlite). SQLite persists
    approvals and audit history across restarts (AGENTGUARD_DB_PATH)."""
    backend = os.getenv("AGENTGUARD_STORE", "memory").lower()
    if backend == "sqlite":
        from agentguard.providers.storage.sqlite import SQLiteStore

        return SQLiteStore(os.getenv("AGENTGUARD_DB_PATH", "agentguard.db"))
    return MemoryStore()
