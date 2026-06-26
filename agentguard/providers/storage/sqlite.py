from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, UTC


class SQLiteStore:
    """Durable store backed by SQLite (stdlib). Audit history and approvals
    survive restarts, which is required for compliance evidence."""

    def __init__(self, db_path: str = "agentguard.db") -> None:
        self.db_path = db_path
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT UNIQUE NOT NULL,
                    tool_name TEXT NOT NULL,
                    tool_args TEXT NOT NULL,
                    user_role TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT
                );
                CREATE TABLE IF NOT EXISTS audit_logs (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT UNIQUE NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            self._conn.commit()

    @staticmethod
    def _approval_from_row(row: sqlite3.Row) -> dict:
        approval = {
            "id": row["id"],
            "tool_name": row["tool_name"],
            "tool_args": json.loads(row["tool_args"]),
            "user_role": row["user_role"],
            "status": row["status"],
            "created_at": row["created_at"],
        }
        if row["updated_at"]:
            approval["updated_at"] = row["updated_at"]
        return approval

    def create_approval(self, tool_name: str, tool_args: dict, user_role: str) -> str:
        approval_id = str(uuid.uuid4())
        with self._lock:
            self._conn.execute(
                "INSERT INTO approvals (id, tool_name, tool_args, user_role, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (approval_id, tool_name, json.dumps(tool_args), user_role, "pending", datetime.now(UTC).isoformat()),
            )
            self._conn.commit()
        return approval_id

    def get_approval(self, approval_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        return self._approval_from_row(row) if row else None

    def update_approval_status(self, approval_id: str, status: str) -> dict | None:
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE approvals SET status = ?, updated_at = ? WHERE id = ?",
                (status, datetime.now(UTC).isoformat(), approval_id),
            )
            self._conn.commit()
            if cursor.rowcount == 0:
                return None
            row = self._conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        return self._approval_from_row(row) if row else None

    def list_approvals(self, status: str | None = None, limit: int | None = 100) -> list[dict]:
        query = "SELECT * FROM approvals"
        params: list = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY seq DESC"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._approval_from_row(row) for row in rows]

    def log_event(self, event_type: str, payload: dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_logs (id, event_type, payload, created_at) VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), event_type, json.dumps(payload, default=str), datetime.now(UTC).isoformat()),
            )
            self._conn.commit()

    def list_audit_logs(self, limit: int | None = 50) -> list[dict]:
        query = "SELECT * FROM audit_logs ORDER BY seq DESC"
        params: list = []
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [
            {
                "id": row["id"],
                "event_type": row["event_type"],
                "payload": json.loads(row["payload"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]
