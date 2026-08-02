from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class QueueItem:
    sequence: int
    kind: str
    payload: dict[str, Any]
    created_at: datetime
    byte_size: int
    accepted: bool = True
    drop_reason: str | None = None


class BoundedUplinkQueue:
    def __init__(
        self,
        path: Path,
        *,
        max_bytes: int,
        max_age_seconds: int,
    ) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self.max_age_seconds = max_age_seconds
        path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def enqueue(self, *, kind: str, payload: dict[str, Any]) -> QueueItem:
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        created_at = datetime.now(timezone.utc)
        byte_size = len(encoded.encode("utf-8"))
        with self._connect() as connection:
            self._expire_stale_queue(connection, now=created_at)
            sequence = self._metadata_int(connection, "next_sequence", 1)
            total = int(
                connection.execute(
                    "SELECT COALESCE(SUM(byte_size), 0) FROM uplink_queue"
                ).fetchone()[0]
            )
            if byte_size > self.max_bytes or total + byte_size > self.max_bytes:
                self._record_drop(connection, count=1)
                return QueueItem(
                    sequence=sequence,
                    kind=kind,
                    payload=dict(payload),
                    created_at=created_at,
                    byte_size=byte_size,
                    accepted=False,
                    drop_reason="queue_capacity_exceeded",
                )
            self._set_metadata(connection, "next_sequence", sequence + 1)
            connection.execute(
                """
                INSERT INTO uplink_queue(
                    sequence, kind, payload_json, byte_size, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    sequence,
                    kind,
                    encoded,
                    byte_size,
                    created_at.isoformat(),
                ),
            )
        return QueueItem(
            sequence=sequence,
            kind=kind,
            payload=dict(payload),
            created_at=created_at,
            byte_size=byte_size,
        )

    def peek(self, *, kind: str, limit: int) -> list[QueueItem]:
        with self._connect() as connection:
            self._expire_stale_queue(
                connection,
                now=datetime.now(timezone.utc),
            )
            rows = connection.execute(
                """
                SELECT sequence, kind, payload_json, byte_size, created_at
                FROM uplink_queue
                WHERE kind = ?
                ORDER BY sequence
                LIMIT ?
                """,
                (kind, limit),
            ).fetchall()
        return [
            QueueItem(
                sequence=int(row[0]),
                kind=str(row[1]),
                payload=json.loads(row[2]),
                byte_size=int(row[3]),
                created_at=datetime.fromisoformat(row[4]),
            )
            for row in rows
        ]

    def peek_all(self, *, limit: int) -> list[QueueItem]:
        with self._connect() as connection:
            self._expire_stale_queue(
                connection,
                now=datetime.now(timezone.utc),
            )
            rows = connection.execute(
                """
                SELECT sequence, kind, payload_json, byte_size, created_at
                FROM uplink_queue
                ORDER BY sequence
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            QueueItem(
                sequence=int(row[0]),
                kind=str(row[1]),
                payload=json.loads(row[2]),
                byte_size=int(row[3]),
                created_at=datetime.fromisoformat(row[4]),
            )
            for row in rows
        ]

    def acknowledge_through(self, sequence: int) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM uplink_queue WHERE sequence <= ?",
                (sequence,),
            )
            acknowledged = self._metadata_int(
                connection,
                "acknowledged_sequence",
                0,
            )
            if sequence > acknowledged:
                self._set_metadata(
                    connection,
                    "acknowledged_sequence",
                    sequence,
                )
            next_sequence = self._metadata_int(
                connection,
                "next_sequence",
                1,
            )
            if next_sequence <= sequence:
                self._set_metadata(connection, "next_sequence", sequence + 1)

    def ensure_next_sequence_at_least(self, sequence: int) -> None:
        with self._connect() as connection:
            current = self._metadata_int(connection, "next_sequence", 1)
            if sequence > current:
                self._set_metadata(connection, "next_sequence", sequence)

    def summary(self) -> dict[str, int]:
        with self._connect() as connection:
            self._expire_stale_queue(
                connection,
                now=datetime.now(timezone.utc),
            )
            row = connection.execute(
                """
                SELECT COUNT(*), COALESCE(SUM(byte_size), 0),
                       COALESCE(MIN(sequence), 0), COALESCE(MAX(sequence), 0)
                FROM uplink_queue
                """
            ).fetchone()
        return {
            "queue_depth": int(row[0]),
            "queue_bytes": int(row[1]),
            "oldest_sequence": int(row[2]),
            "latest_sequence": int(row[3]),
            "dropped_count": self._read_metadata_int("dropped_count", 0),
            "reconciliation_required": self._read_metadata_int(
                "reconciliation_required",
                0,
            ),
        }

    def needs_reconciliation(self) -> bool:
        return bool(
            self._read_metadata_int("reconciliation_required", 0)
        )

    def mark_reconciliation_queued(self) -> None:
        with self._connect() as connection:
            self._set_metadata(connection, "reconciliation_required", 0)

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS uplink_queue (
                    sequence INTEGER PRIMARY KEY,
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    byte_size INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS queue_metadata (
                    key TEXT PRIMARY KEY,
                    value INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO queue_metadata(key, value) VALUES ('next_sequence', 1)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO queue_metadata(key, value) VALUES ('dropped_count', 0)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO queue_metadata(key, value) VALUES ('acknowledged_sequence', 0)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO queue_metadata(key, value) VALUES ('reconciliation_required', 0)"
            )

    def _expire_stale_queue(
        self,
        connection: sqlite3.Connection,
        *,
        now: datetime,
    ) -> None:
        cutoff = now - timedelta(seconds=self.max_age_seconds)
        expired = int(
            connection.execute(
                "SELECT COUNT(*) FROM uplink_queue WHERE created_at < ?",
                (cutoff.isoformat(),),
            ).fetchone()[0]
        )
        if not expired:
            return
        queued = int(
            connection.execute("SELECT COUNT(*) FROM uplink_queue").fetchone()[0]
        )
        connection.execute("DELETE FROM uplink_queue")
        acknowledged = self._metadata_int(
            connection,
            "acknowledged_sequence",
            0,
        )
        self._set_metadata(
            connection,
            "next_sequence",
            acknowledged + 1,
        )
        self._record_drop(connection, count=queued)

    def _record_drop(
        self,
        connection: sqlite3.Connection,
        *,
        count: int,
    ) -> None:
        if count <= 0:
            return
        current = self._metadata_int(connection, "dropped_count", 0)
        self._set_metadata(connection, "dropped_count", current + count)
        self._set_metadata(connection, "reconciliation_required", 1)

    def _read_metadata_int(self, key: str, default: int) -> int:
        with self._connect() as connection:
            return self._metadata_int(connection, key, default)

    @staticmethod
    def _metadata_int(
        connection: sqlite3.Connection,
        key: str,
        default: int,
    ) -> int:
        row = connection.execute(
            "SELECT value FROM queue_metadata WHERE key = ?",
            (key,),
        ).fetchone()
        return int(row[0]) if row else default

    @staticmethod
    def _set_metadata(
        connection: sqlite3.Connection,
        key: str,
        value: int,
    ) -> None:
        connection.execute(
            """
            INSERT INTO queue_metadata(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)
