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
        with self._connect() as connection:
            sequence = self._metadata_int(connection, "next_sequence", 1)
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
                    len(encoded.encode("utf-8")),
                    created_at.isoformat(),
                ),
            )
            self._prune(connection, now=created_at)
        return QueueItem(
            sequence=sequence,
            kind=kind,
            payload=dict(payload),
            created_at=created_at,
            byte_size=len(encoded.encode("utf-8")),
        )

    def peek(self, *, kind: str, limit: int) -> list[QueueItem]:
        with self._connect() as connection:
            self._prune(connection, now=datetime.now(timezone.utc))
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
            self._prune(connection, now=datetime.now(timezone.utc))
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

    def ensure_next_sequence_at_least(self, sequence: int) -> None:
        with self._connect() as connection:
            current = self._metadata_int(connection, "next_sequence", 1)
            if sequence > current:
                self._set_metadata(connection, "next_sequence", sequence)

    def summary(self) -> dict[str, int]:
        with self._connect() as connection:
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
        }

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

    def _prune(self, connection: sqlite3.Connection, *, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.max_age_seconds)
        expired = connection.execute(
            "DELETE FROM uplink_queue WHERE created_at < ?",
            (cutoff.isoformat(),),
        ).rowcount
        dropped = max(int(expired or 0), 0)
        total = int(
            connection.execute(
                "SELECT COALESCE(SUM(byte_size), 0) FROM uplink_queue"
            ).fetchone()[0]
        )
        while total > self.max_bytes:
            oldest = connection.execute(
                "SELECT sequence, byte_size FROM uplink_queue ORDER BY sequence LIMIT 1"
            ).fetchone()
            if oldest is None:
                break
            connection.execute(
                "DELETE FROM uplink_queue WHERE sequence = ?",
                (oldest[0],),
            )
            total -= int(oldest[1])
            dropped += 1
        if dropped:
            current = self._metadata_int(connection, "dropped_count", 0)
            self._set_metadata(connection, "dropped_count", current + dropped)

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
