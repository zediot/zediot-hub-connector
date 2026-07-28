from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class CommandReceiptStore:
    def __init__(self, path: Path, *, retention_seconds: int = 86400) -> None:
        self.path = path
        self.retention_seconds = retention_seconds
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS command_receipt (
                    command_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL,
                    envelope_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reason_code TEXT NULL,
                    evidence_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def get(self, *, command_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            self._prune(connection)
            row = connection.execute(
                """
                SELECT command_id, idempotency_key, envelope_digest, status,
                       reason_code, evidence_json, updated_at
                FROM command_receipt
                WHERE command_id = ?
                """,
                (command_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "command_id": row[0],
            "idempotency_key": row[1],
            "envelope_digest": row[2],
            "status": row[3],
            "reason_code": row[4],
            "evidence": json.loads(row[5]),
            "updated_at": row[6],
        }

    def save(
        self,
        *,
        command_id: str,
        idempotency_key: str,
        envelope: dict[str, Any],
        status: str,
        reason_code: str | None,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        digest = command_envelope_digest(envelope)
        existing = self.get(command_id=command_id)
        if existing and (
            existing["idempotency_key"] != idempotency_key
            or existing["envelope_digest"] != digest
        ):
            raise RuntimeError("HUB_COMMAND_IDEMPOTENCY_CONFLICT")
        updated_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO command_receipt(
                    command_id, idempotency_key, envelope_digest, status,
                    reason_code, evidence_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(command_id) DO UPDATE SET
                    status = excluded.status,
                    reason_code = excluded.reason_code,
                    evidence_json = excluded.evidence_json,
                    updated_at = excluded.updated_at
                """,
                (
                    command_id,
                    idempotency_key,
                    digest,
                    status,
                    reason_code,
                    json.dumps(evidence, sort_keys=True, separators=(",", ":")),
                    updated_at,
                ),
            )
        return self.get(command_id=command_id) or {}

    def _prune(self, connection: sqlite3.Connection) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(
            seconds=self.retention_seconds
        )
        connection.execute(
            "DELETE FROM command_receipt WHERE updated_at < ?",
            (cutoff.isoformat(),),
        )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)


def command_envelope_digest(envelope: dict[str, Any]) -> str:
    encoded = json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
