from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from zediot_ha_hub_connector.identity import ConnectorIdentity


@dataclass(frozen=True)
class HubSession:
    session_id: str
    integration_instance_id: str
    lease_generation: int
    lease_expires_at: datetime
    resume_cursor: dict[str, Any] | None


class IoTCoreHubClient:
    def __init__(
        self,
        *,
        base_url: str,
        timeout_seconds: float = 20,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(timeout=timeout_seconds)
        self._token: str | None = None
        self._token_expires_at: datetime | None = None

    def exchange(
        self,
        *,
        pairing_code: str,
        installation_id: str,
        display_name: str,
        public_key_pem: str,
    ) -> dict[str, Any]:
        enrollment_id = pairing_code.split(".", 1)[0]
        return self._request(
            "POST",
            "/api/hub/v1/enrollments/exchange",
            json={
                "enrollment_id": enrollment_id,
                "pairing_code": pairing_code,
                "installation_id": installation_id,
                "display_name": display_name,
                "public_key_pem": public_key_pem,
                "contract_version": "1.0",
                "manifest": {
                    "runtime": "home_assistant_addon",
                    "contract_version": "1.0",
                },
            },
            authenticated=False,
        )

    def enrollment_status(
        self,
        *,
        enrollment_id: str,
        exchange_receipt: str,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/api/hub/v1/enrollments/{enrollment_id}",
            headers={"X-Hub-Exchange-Receipt": exchange_receipt},
            authenticated=False,
        )

    def authenticate(self, identity: ConnectorIdentity) -> None:
        if not identity.connector_id or not identity.credential_id:
            raise RuntimeError("HUB_IDENTITY_NOT_ENROLLED")
        challenge = self._request(
            "POST",
            "/api/hub/v1/auth/challenges",
            json={
                "connector_id": identity.connector_id,
                "credential_id": identity.credential_id,
                "contract_version": "1.0",
            },
            authenticated=False,
        )
        signature = identity.private_key.sign(
            challenge["canonical_message"].encode("utf-8")
        )
        token = self._request(
            "POST",
            "/api/hub/v1/auth/token",
            json={
                "challenge_id": challenge["challenge_id"],
                "nonce": challenge["nonce"],
                "signature": base64.urlsafe_b64encode(signature)
                .decode("ascii")
                .rstrip("="),
                "contract_version": "1.0",
                "ttl_seconds": 900,
            },
            authenticated=False,
        )
        self._token = token["access_token"]
        self._token_expires_at = _parse_time(token["expires_at"])

    def connect_session(
        self,
        *,
        identity: ConnectorIdentity,
        resume_cursor: dict[str, Any] | None,
    ) -> HubSession:
        self._ensure_token(identity)
        row = self._request(
            "POST",
            "/api/hub/v1/sessions",
            json={
                "contract_version": "1.0",
                "lease_owner": "zediot-hub-connector",
                "resume_cursor": resume_cursor,
            },
        )
        return HubSession(
            session_id=row["session_id"],
            integration_instance_id=row["integration_instance_id"],
            lease_generation=int(row["lease_generation"]),
            lease_expires_at=_parse_time(row["lease_expires_at"]),
            resume_cursor=(
                dict(row["resume_cursor"]) if row.get("resume_cursor") else None
            ),
        )

    def heartbeat(
        self,
        *,
        identity: ConnectorIdentity,
        session: HubSession,
        cursor: dict[str, Any],
        queue_summary: dict[str, int],
        circuit_state: str,
    ) -> dict[str, Any]:
        self._ensure_token(identity)
        return self._request(
            "POST",
            f"/api/hub/v1/sessions/{session.session_id}/heartbeat",
            json={
                "lease_generation": session.lease_generation,
                "cursor": cursor,
                "queue_depth": queue_summary["queue_depth"],
                "queue_bytes": queue_summary["queue_bytes"],
                "dropped_count": queue_summary["dropped_count"],
                "local_platform_health": (
                    "healthy" if circuit_state == "closed" else "degraded"
                ),
                "reason_code": (
                    None
                    if circuit_state == "closed"
                    else f"core_circuit_{circuit_state}"
                ),
            },
        )

    def upload_snapshot(
        self,
        *,
        identity: ConnectorIdentity,
        session: HubSession,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        self._ensure_token(identity)
        return self._request(
            "POST",
            f"/api/hub/v1/sessions/{session.session_id}/snapshots",
            json={
                "lease_generation": session.lease_generation,
                **payload,
            },
        )

    def upload_events(
        self,
        *,
        identity: ConnectorIdentity,
        session: HubSession,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        self._ensure_token(identity)
        return self._request(
            "POST",
            f"/api/hub/v1/sessions/{session.session_id}/events",
            json={
                "lease_generation": session.lease_generation,
                **payload,
            },
        )

    def claim_commands(
        self,
        *,
        identity: ConnectorIdentity,
        session: HubSession,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        self._ensure_token(identity)
        row = self._request(
            "POST",
            f"/api/hub/v1/sessions/{session.session_id}/commands/claim",
            json={
                "lease_generation": session.lease_generation,
                "limit": limit,
            },
        )
        return [dict(item) for item in row.get("items") or []]

    def acknowledge_command(
        self,
        *,
        identity: ConnectorIdentity,
        session: HubSession,
        delivery_id: str,
        status: str,
        reason_code: str | None,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        self._ensure_token(identity)
        return self._request(
            "POST",
            (
                f"/api/hub/v1/sessions/{session.session_id}/commands/"
                f"{delivery_id}/ack"
            ),
            json={
                "lease_generation": session.lease_generation,
                "status": status,
                "reason_code": reason_code,
                "evidence": evidence,
            },
        )

    def claim_rule_packages(
        self,
        *,
        identity: ConnectorIdentity,
        session: HubSession,
        limit: int = 10,
    ) -> dict[str, Any]:
        self._ensure_token(identity)
        return self._request(
            "POST",
            (
                f"/api/hub/v1/sessions/{session.session_id}/"
                "rule-packages/claim"
            ),
            json={
                "lease_generation": session.lease_generation,
                "limit": limit,
            },
        )

    def acknowledge_rule_package(
        self,
        *,
        identity: ConnectorIdentity,
        session: HubSession,
        package_id: str,
        receipt_id: str,
        package_hash: str,
        status: str,
        reason_code: str | None,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        self._ensure_token(identity)
        return self._request(
            "POST",
            (
                f"/api/hub/v1/sessions/{session.session_id}/"
                f"rule-packages/{package_id}/receipt"
            ),
            json={
                "lease_generation": session.lease_generation,
                "receipt_id": receipt_id,
                "package_hash": package_hash,
                "status": status,
                "reason_code": reason_code,
                "evidence": evidence,
                "reported_at": datetime.now(timezone.utc).isoformat(),
            },
        )

    def upload_rule_evidence(
        self,
        *,
        identity: ConnectorIdentity,
        session: HubSession,
        items: list[dict[str, Any]],
    ) -> dict[str, Any]:
        self._ensure_token(identity)
        return self._request(
            "POST",
            (
                f"/api/hub/v1/sessions/{session.session_id}/"
                "rule-executions/evidence"
            ),
            json={
                "lease_generation": session.lease_generation,
                "items": items,
            },
        )

    def _ensure_token(self, identity: ConnectorIdentity) -> None:
        if (
            self._token is None
            or self._token_expires_at is None
            or (self._token_expires_at - datetime.now(timezone.utc)).total_seconds()
            < 60
        ):
            self.authenticate(identity)

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        authenticated: bool = True,
    ) -> dict[str, Any]:
        request_headers = dict(headers or {})
        if authenticated:
            if not self._token:
                raise RuntimeError("HUB_TOKEN_MISSING")
            request_headers["Authorization"] = f"Bearer {self._token}"
        response = self._client.request(
            method,
            f"{self.base_url}{path}",
            json=json,
            headers=request_headers,
        )
        response.raise_for_status()
        body = response.json()
        return dict(body.get("data") or {})


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )
