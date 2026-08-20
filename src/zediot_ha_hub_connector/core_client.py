from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from zediot_ha_hub_connector.identity import (
    SIGNATURE_ALGORITHM_ED25519,
    ConnectorIdentity,
)


class HubActivationError(RuntimeError):
    """激活被服务端拒绝。

    `terminal` 区分两类拒绝，这是 A.5 优雅等待的关键：

      * terminal=True  —— 密钥错误、身份/批次被撤销、clone 可疑。重试没有
        任何意义，必须停下来并把原因显示出来，否则设备会永远刷同一个错误。
      * terminal=False —— 限流、5xx、时钟偏移。退避后重试是对的。

    把两者混为一谈是这条改造最容易犯的错：要么该停的一直重试（日志噪音、
    还会撞限流），要么该等的直接退出（用户明明只是还没输绑定码）。
    """

    def __init__(self, *, detail: str, status_code: int, terminal: bool) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code
        self.terminal = terminal


class HubSessionInvalidError(RuntimeError):
    """The server rejected a session that must be re-established."""

    def __init__(self, *, session_id: str, detail: str) -> None:
        self.session_id = session_id
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True)
class HubSession:
    session_id: str
    integration_instance_id: str
    lease_generation: int
    lease_expires_at: datetime
    resume_cursor: dict[str, Any] | None
    effective_grants: frozenset[str] = frozenset()

    def allows(self, grant: str) -> bool:
        return grant in self.effective_grants


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
        runtime_kind: str,
        signature_algorithm: str = SIGNATURE_ALGORITHM_ED25519,
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
                "signature_algorithm": signature_algorithm,
                "contract_version": "1.0",
                "manifest": {
                    "runtime": runtime_kind,
                    "contract_version": "1.0",
                },
            },
            authenticated=False,
        )

    def activate(
        self,
        *,
        tenant_id: str,
        product_key: str,
        device_name: str,
        device_secret: str,
        public_key_pem: str,
        installation_id: str,
        signature_algorithm: str = SIGNATURE_ALGORITHM_ED25519,
        health: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """预发放设备激活（43 第 4.3 节 / 附录 A.4）。

        密钥在 TLS 内直接出示，**不做 HMAC 签名**：验证 HMAC 需要服务端持有
        明文密钥，与"只存哈希"冲突（第 4.3 节偏差 1）。

        这个调用同时兼作待绑定期的存活信标（GW-09）：同一把公钥重放是幂等的，
        设备在等待绑定期间按退避周期重复调用即可，服务端据此记录 last_seen
        并回当前 binding_state。
        """
        payload: dict[str, Any] = {
            "tenant_id": tenant_id,
            "product_key": product_key,
            "device_name": device_name,
            "device_secret": device_secret,
            "public_key_pem": public_key_pem,
            "signature_algorithm": signature_algorithm,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nonce": uuid.uuid4().hex,
            "installation_id": installation_id,
        }
        if health:
            payload["health"] = health
        try:
            return self._request(
                "POST",
                "/api/hub/v1/gateways/activate",
                json=payload,
                authenticated=False,
            )
        except httpx.HTTPStatusError as error:
            raise _activation_error(error) from error

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
        # A legacy Core may omit this additive field. That omission is compatible
        # only with an existing Ed25519 identity; any explicit mismatch fails
        # closed before proof generation.
        challenge_algorithm = (
            challenge.get("signature_algorithm") or SIGNATURE_ALGORITHM_ED25519
        )
        if challenge_algorithm != identity.signature_algorithm:
            raise RuntimeError("HUB_SIGNATURE_ALGORITHM_MISMATCH")
        signature = identity.sign_challenge(
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
            effective_grants=frozenset(
                str(item) for item in row.get("effective_grants") or []
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

    def disconnect_session(
        self,
        *,
        identity: ConnectorIdentity,
        session: HubSession,
        reason_code: str,
    ) -> dict[str, Any]:
        # Shutdown must stay inside the container stop window. Re-authentication
        # can require two network round trips and would extend credential life
        # during teardown, so use only the token that owns this session.
        if not self._token:
            raise RuntimeError("HUB_TOKEN_MISSING")
        return self._request(
            "POST",
            f"/api/hub/v1/sessions/{session.session_id}/disconnect",
            json={
                "lease_generation": session.lease_generation,
                "reason_code": reason_code,
            },
            timeout_seconds=5,
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
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        request_headers = dict(headers or {})
        if authenticated:
            if not self._token:
                raise RuntimeError("HUB_TOKEN_MISSING")
            request_headers["Authorization"] = f"Bearer {self._token}"
        request_kwargs: dict[str, Any] = {
            "json": json,
            "headers": request_headers,
        }
        if timeout_seconds is not None:
            request_kwargs["timeout"] = timeout_seconds
        response = self._client.request(
            method,
            f"{self.base_url}{path}",
            **request_kwargs,
        )
        invalid_session = _invalid_session_detail(response, path=path)
        if invalid_session is not None:
            raise HubSessionInvalidError(
                session_id=_session_id_from_path(path),
                detail=invalid_session,
            )
        response.raise_for_status()
        body = response.json()
        return dict(body.get("data") or {})


def _parse_time(value: str | int | float) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def _invalid_session_detail(
    response: httpx.Response,
    *,
    path: str,
) -> str | None:
    if response.status_code != 409 or "/api/hub/v1/sessions/" not in path:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    detail = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(detail, str):
        return None
    if detail in {
        "Hub session is not active",
        "stale Hub session lease generation",
        "Hub session lease expired",
    }:
        return detail
    return None


def _session_id_from_path(path: str) -> str:
    return path.split("/sessions/", 1)[1].split("/", 1)[0]


# 服务端把"这台设备再也不该激活"和"现在不行、待会再来"用不同状态码表达：
#   403 = 凭据无效或身份被锁（GW-12 的锁定也是 403，但它会自己到期）
#   409 = 身份/批次被撤销、clone 可疑、产品停售——都要人介入
#   429 = 限流，退避后重试
#   4xx 其他 = 请求本身有问题（时钟偏移是 400），重试同样无意义
_TERMINAL_ACTIVATION_STATUSES = frozenset({400, 403, 404, 409, 422})


def _activation_error(error: httpx.HTTPStatusError) -> HubActivationError:
    response = error.response
    status_code = response.status_code
    detail = ""
    try:
        body = response.json()
        detail = str(body.get("data") or body.get("message") or "")
    except ValueError:
        detail = response.text[:200]
    # 锁定是有期限的（GW-12 默认 900s），归为可重试——把它当终态会让一次
    # 装机人员输错密钥就要求返厂
    locked_out = "too many failed" in detail
    terminal = status_code in _TERMINAL_ACTIVATION_STATUSES and not locked_out
    return HubActivationError(
        detail=detail or f"activation rejected with HTTP {status_code}",
        status_code=status_code,
        terminal=terminal,
    )
