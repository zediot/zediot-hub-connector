from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from zediot_ha_hub_connector.rule_package import VerifiedRulePackage


class LocalRuleStore:
    def __init__(
        self,
        path: Path,
        *,
        evidence_max_rows: int,
        evidence_retention_seconds: int,
    ) -> None:
        self.path = path
        self.evidence_max_rows = evidence_max_rows
        self.evidence_retention_seconds = evidence_retention_seconds
        path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def apply_package(self, package: VerifiedRulePackage) -> None:
        payload = package.payload
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM active_rule_package WHERE rule_id = ?",
                (str(payload["rule_id"]),),
            )
            connection.execute(
                """
                INSERT INTO active_rule_package(
                    package_id, rule_id, package_hash, document_json,
                    valid_until, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    package.package_id,
                    str(payload["rule_id"]),
                    package.package_hash,
                    json.dumps(
                        package.as_document(),
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    package.valid_until.isoformat(),
                    now,
                ),
            )

    def apply_control(self, control: dict[str, Any]) -> bool:
        if control.get("status") not in {"revoked", "expired"}:
            raise RuntimeError("RULE_PACKAGE_CONTROL_INVALID")
        with self._connect() as connection:
            deleted = connection.execute(
                "DELETE FROM active_rule_package WHERE package_id = ?",
                (str(control.get("package_id") or ""),),
            ).rowcount
        return bool(deleted)

    def active_documents(self, *, now: datetime | None = None) -> list[dict]:
        current = (now or datetime.now(UTC)).isoformat()
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM active_rule_package WHERE valid_until <= ?",
                (current,),
            )
            rows = connection.execute(
                """
                SELECT document_json FROM active_rule_package
                ORDER BY rule_id
                """
            ).fetchall()
        return [dict(json.loads(row[0])) for row in rows]

    def reserve_execution(
        self,
        *,
        idempotency_key: str,
        execution_id: str,
        evidence: dict[str, Any],
    ) -> tuple[dict[str, Any], bool]:
        encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            existing = connection.execute(
                """
                SELECT evidence_json, upload_status
                FROM local_rule_execution
                WHERE idempotency_key = ?
                """,
                (idempotency_key,),
            ).fetchone()
            if existing:
                return {
                    **dict(json.loads(existing[0])),
                    "_upload_status": str(existing[1]),
                }, False
            connection.execute(
                """
                INSERT INTO local_rule_execution(
                    idempotency_key, execution_id, evidence_json,
                    execution_status, upload_status, created_at, updated_at
                ) VALUES (?, ?, ?, 'processing', 'held', ?, ?)
                """,
                (idempotency_key, execution_id, encoded, now, now),
            )
            self._prune(connection, now=datetime.now(UTC))
        return dict(evidence), True

    def finalize_execution(self, evidence: dict[str, Any]) -> None:
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            updated = connection.execute(
                """
                UPDATE local_rule_execution
                SET evidence_json = ?, execution_status = 'complete',
                    upload_status = 'pending', updated_at = ?
                WHERE idempotency_key = ?
                """,
                (
                    json.dumps(
                        evidence,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    now,
                    str(evidence["idempotency_key"]),
                ),
            )
            if updated.rowcount != 1:
                raise RuntimeError("LOCAL_RULE_EXECUTION_RESERVATION_MISSING")
            self._prune(connection, now=datetime.now(UTC))

    def pending_evidence(self, *, limit: int) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT evidence_json FROM local_rule_execution
                WHERE execution_status = 'complete'
                  AND upload_status = 'pending'
                ORDER BY created_at
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(json.loads(row[0])) for row in rows]

    def mark_uploaded(self, *, execution_ids: list[str]) -> None:
        if not execution_ids:
            return
        placeholders = ",".join("?" for _ in execution_ids)
        with self._connect() as connection:
            connection.execute(
                f"""
                UPDATE local_rule_execution
                SET upload_status = 'uploaded', updated_at = ?
                WHERE execution_id IN ({placeholders})
                """,
                (datetime.now(UTC).isoformat(), *execution_ids),
            )
            self._prune(connection, now=datetime.now(UTC))

    def summary(self) -> dict[str, int]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                  COUNT(*),
                  SUM(CASE WHEN upload_status = 'pending' THEN 1 ELSE 0 END),
                  SUM(CASE WHEN upload_status = 'uploaded' THEN 1 ELSE 0 END),
                  SUM(CASE WHEN execution_status = 'processing' THEN 1 ELSE 0 END)
                FROM local_rule_execution
                """
            ).fetchone()
            package_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM active_rule_package"
                ).fetchone()[0]
            )
        return {
            "active_package_count": package_count,
            "execution_count": int(row[0] or 0),
            "pending_evidence_count": int(row[1] or 0),
            "uploaded_evidence_count": int(row[2] or 0),
            "processing_count": int(row[3] or 0),
        }

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS active_rule_package (
                    package_id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL UNIQUE,
                    package_hash TEXT NOT NULL,
                    document_json TEXT NOT NULL,
                    valid_until TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS local_rule_execution (
                    idempotency_key TEXT PRIMARY KEY,
                    execution_id TEXT NOT NULL UNIQUE,
                    evidence_json TEXT NOT NULL,
                    execution_status TEXT NOT NULL,
                    upload_status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def _prune(
        self,
        connection: sqlite3.Connection,
        *,
        now: datetime,
    ) -> None:
        cutoff = now - timedelta(seconds=self.evidence_retention_seconds)
        connection.execute(
            """
            DELETE FROM local_rule_execution
            WHERE upload_status = 'uploaded' AND updated_at < ?
            """,
            (cutoff.isoformat(),),
        )
        row_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM local_rule_execution"
            ).fetchone()[0]
        )
        excess = max(row_count - self.evidence_max_rows, 0)
        if excess:
            connection.execute(
                """
                DELETE FROM local_rule_execution
                WHERE idempotency_key IN (
                    SELECT idempotency_key FROM local_rule_execution
                    ORDER BY
                      CASE upload_status WHEN 'uploaded' THEN 0 ELSE 1 END,
                      created_at
                    LIMIT ?
                )
                """,
                (excess,),
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)
