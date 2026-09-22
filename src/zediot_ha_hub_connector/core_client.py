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


class HubLeaseConflictError(RuntimeError):
    """建会话时，上一份会话的租约还没过期（Core 409 `active_lease_conflict`）。

    这不是故障，是「上一个进程的会话还活着」—— 重启、容器重建、异常退出之后
    重连，撞上的都是它。它也不是终态：租约一到期就能接管。

    Core 在响应里给出租约到期时刻与 `retry_after_seconds`，照着等就行。原先这里
    只有 `raise_for_status()`，异常一路冒出 `run_forever`，进程退出、容器重启、
    再撞一次：现网 09-19 08:16–08:19 被拒 7 次，间隔约 30 秒，正是一次次冷启动的
    节奏，而 Core 从第一次拒绝起就知道答案。

    旧版 Core 只回一句字符串，没有秒数；那时 `retry_after_seconds` 为 None，
    由调用方用保守的固定间隔。
    """

    def __init__(
        self,
        *,
        retry_after_seconds: float | None,
        lease_expires_at: datetime | None,
    ) -> None:
        super().__init__("HUB_ACTIVE_LEASE_CONFLICT")
        self.retry_after_seconds = retry_after_seconds
        self.lease_expires_at = lease_expires_at


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
        self._ensure_token(identity, session=session)
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
        self._ensure_token(identity, session=session)
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
        self._ensure_token(identity, session=session)
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
        self._ensure_token(identity, session=session)
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
        self._ensure_token(identity, session=session)
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
        self._ensure_token(identity, session=session)
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
        self._ensure_token(identity, session=session)
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
        self._ensure_token(identity, session=session)
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

    def _ensure_token(
        self,
        identity: ConnectorIdentity,
        *,
        session: HubSession | None = None,
    ) -> None:
        """确保 bearer 可用；若在会话存续期间换了令牌，必须把会话一并换绑。

        Core 把会话绑在签发它的那个令牌的 jti 上（_ensure_session_token_binding）。
        换了令牌却不换绑，之后每一次心跳都会被判 403
        "Hub session token binding mismatch"。而 403 不在「需重建会话」的判据里，
        客户端只会一直空转，直到 90 秒租约自然过期才收到 409。

        实测表现为每 ~16 分钟丢一次会话：令牌 900 秒、提前 60 秒续签 ⇒ 每 ~14 分钟
        换一次令牌，换完 403 空转 ~2 分钟。现网 6 小时 22 个会话（同期正常网关 2 个），
        审计里 13 次 hub.auth.token.issue 对 0 次 hub.session.token_rebind。

        connect_session 建会话时还没有会话可换绑，因此那一处不传 session。
        断开会话同样不传：拆除必须用拥有该会话的那个令牌，不能因为到了续签窗口
        就重新签发（见 test_session_parses_effective_grants_and_disconnects_the_same_lease）。
        """
        if (
            self._token is not None
            and self._token_expires_at is not None
            and (self._token_expires_at - datetime.now(timezone.utc)).total_seconds()
            >= 60
        ):
            return
        self.authenticate(identity)
        if session is not None:
            self._rebind_session_token(session)

    def _rebind_session_token(self, session: HubSession) -> None:
        """把运行中的会话换绑到刚签发的令牌上。

        换绑不改变 lease_generation：请求体带当前代次做乐观并发，Core 校验通过后
        只更新会话的 token_binding_hash。
        """
        self._request(
            "POST",
            f"/api/hub/v1/sessions/{session.session_id}/token",
            json={"lease_generation": session.lease_generation},
        )

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
        lease_conflict = _lease_conflict(response, path=path)
        if lease_conflict is not None:
            raise lease_conflict
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
    if "/api/hub/v1/sessions/" not in path:
        return None
    if response.status_code not in {403, 409}:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    data = payload.get("data") if isinstance(payload, dict) else None
    # 409 的 data 是一个字符串；403 的 data 可能是 {"reason_code":..., "detail":...}。
    detail: str | None = None
    if isinstance(data, str):
        detail = data
    elif isinstance(data, dict) and isinstance(data.get("detail"), str):
        detail = data["detail"]
    if detail is None:
        return None
    if detail in {
        "Hub session is not active",
        "stale Hub session lease generation",
        "Hub session lease expired",
        # 403：令牌换了而会话没换绑。没有这两条，客户端会拿新令牌反复打旧会话，
        # 直到租约过期才收到 409 —— 中间那 90 秒全是必然失败的心跳。
        "Hub session token binding mismatch",
        "Hub session has no token binding",
    }:
        return detail
    return None


_LEGACY_LEASE_CONFLICT_DETAIL = "Hub connector already has an active session lease"


def _lease_conflict(
    response: httpx.Response,
    *,
    path: str,
) -> HubLeaseConflictError | None:
    """建会话的 409 里，只认「租约冲突」这一种。

    同一个端点的 409 还有别的含义（契约版本不符、集成实例未激活），那些不是等
    一会就能好的，照旧交给 raise_for_status。所以按 reason_code / 原文精确匹配，
    不按状态码一概而论。
    """
    if path != "/api/hub/v1/sessions" or response.status_code != 409:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    data = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(data, str):
        # 旧版 Core：只有一句话，没有秒数。
        if data == _LEGACY_LEASE_CONFLICT_DETAIL:
            return HubLeaseConflictError(
                retry_after_seconds=None, lease_expires_at=None
            )
        return None
    if not isinstance(data, dict) or data.get("reason_code") != "active_lease_conflict":
        return None
    retry_after = data.get("retry_after_seconds")
    retry_after_seconds = (
        float(retry_after)
        if isinstance(retry_after, (int, float)) and not isinstance(retry_after, bool)
        and retry_after >= 0
        else None
    )
    expires_raw = data.get("active_lease_expires_at")
    lease_expires_at: datetime | None = None
    if isinstance(expires_raw, str):
        try:
            lease_expires_at = _parse_time(expires_raw)
        except ValueError:
            lease_expires_at = None
    return HubLeaseConflictError(
        retry_after_seconds=retry_after_seconds,
        lease_expires_at=lease_expires_at,
    )


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
