from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterator

import websocket


@dataclass(frozen=True)
class HomeAssistantSnapshot:
    areas: list[dict[str, Any]]
    devices: list[dict[str, Any]]
    entities: list[dict[str, Any]]
    states: list[dict[str, Any]]
    observed_at: datetime


class HomeAssistantClient:
    # 采一次快照的总时限。必须显著小于 Hub 会话租约（默认 90s），否则采集一慢就会
    # 拖过租约、把会话拖死——这正是现网每 13 分钟丢一次会话的根因之一。
    # 单次 recv 的 30s 超时不足以封顶：_receive_non_ping 是循环，遇到持续 ping 流
    # 耗时无上界，所以这里按"整次采集"设硬时限。
    DEFAULT_SNAPSHOT_DEADLINE_SECONDS = 20.0

    def __init__(
        self,
        *,
        access_token: str,
        websocket_url: str,
        create_connection: Callable[..., Any] = websocket.create_connection,
        snapshot_deadline_seconds: float | None = None,
    ) -> None:
        self._token = access_token
        self._websocket_url = websocket_url
        self._create_connection = create_connection
        self._snapshot_deadline_seconds = (
            self.DEFAULT_SNAPSHOT_DEADLINE_SECONDS
            if snapshot_deadline_seconds is None
            else float(snapshot_deadline_seconds)
        )

    def collect_snapshot(self) -> HomeAssistantSnapshot:
        """采集全量清单。整次调用受 snapshot_deadline_seconds 封顶。

        超时抛 TimeoutError 由调用方处理：宁可这轮对账失败下轮重来，也不能让采集
        无限期占住调用线程。
        """
        deadline = time.monotonic() + self._snapshot_deadline_seconds
        socket = self._open(deadline=deadline)
        try:
            areas = self._command(socket, 1, "config/area_registry/list", deadline)
            devices = self._command(socket, 2, "config/device_registry/list", deadline)
            entities = self._command(socket, 3, "config/entity_registry/list", deadline)
            states = self._command(socket, 4, "get_states", deadline)
            return HomeAssistantSnapshot(
                areas=list(areas or []),
                devices=list(devices or []),
                entities=list(entities or []),
                states=list(states or []),
                observed_at=datetime.now(timezone.utc),
            )
        finally:
            socket.close()

    def subscribe_state_events(self) -> Iterator[dict[str, Any]]:
        socket = self._open()
        socket.send(
            json.dumps(
                {"id": 100, "type": "subscribe_events", "event_type": "state_changed"}
            )
        )
        confirmation = self._receive_non_ping(socket)
        if not confirmation.get("success"):
            socket.close()
            raise RuntimeError("HA_SUBSCRIPTION_FAILED")
        try:
            while True:
                message = self._receive_non_ping(socket)
                if message.get("type") == "event":
                    yield dict(message.get("event") or {})
        finally:
            socket.close()

    def call_service(
        self,
        *,
        domain: str,
        service: str,
        entity_id: str,
        service_data: dict[str, Any],
    ) -> dict[str, Any]:
        socket = self._open()
        try:
            socket.send(
                json.dumps(
                    {
                        "id": 200,
                        "type": "call_service",
                        "domain": domain,
                        "service": service,
                        "service_data": {
                            **service_data,
                            "entity_id": entity_id,
                        },
                        "return_response": False,
                    }
                )
            )
            response = self._receive_non_ping(socket)
            if response.get("id") != 200 or not response.get("success"):
                raise RuntimeError("HA_SERVICE_CALL_FAILED")
            return {
                "request_id": str(response.get("id")),
                "result": response.get("result"),
            }
        finally:
            socket.close()

    def read_entity_state(self, *, entity_id: str) -> dict[str, Any] | None:
        socket = self._open()
        try:
            states = self._command(socket, 201, "get_states")
            for state in states or []:
                if state.get("entity_id") == entity_id:
                    return {
                        "entity_id": entity_id,
                        "state": str(state.get("state") or ""),
                        "last_changed": state.get("last_changed"),
                        "last_updated": state.get("last_updated"),
                    }
            return None
        finally:
            socket.close()

    def _open(self, *, deadline: float | None = None) -> Any:
        # 连接超时同样收敛到剩余时限内，避免"连接就用掉整个预算"。
        connect_timeout = 30 if deadline is None else max(1.0, min(30.0, deadline - time.monotonic()))
        socket = self._create_connection(
            self._websocket_url,
            timeout=connect_timeout,
        )
        required = self._receive_non_ping(socket, deadline)
        if required.get("type") != "auth_required":
            socket.close()
            raise RuntimeError("HA_AUTH_PROTOCOL_ERROR")
        socket.send(json.dumps({"type": "auth", "access_token": self._token}))
        authenticated = self._receive_non_ping(socket, deadline)
        if authenticated.get("type") != "auth_ok":
            socket.close()
            raise RuntimeError("HA_AUTH_FAILED")
        return socket

    def _command(
        self,
        socket: Any,
        request_id: int,
        command_type: str,
        deadline: float | None = None,
    ) -> Any:
        socket.send(json.dumps({"id": request_id, "type": command_type}))
        response = self._receive_non_ping(socket, deadline)
        if response.get("id") != request_id or not response.get("success"):
            raise RuntimeError(f"HA_COMMAND_FAILED:{command_type}")
        return response.get("result")

    @staticmethod
    def _receive_non_ping(socket: Any, deadline: float | None = None) -> dict[str, Any]:
        """读到第一条非 ping 消息。

        ping 要回 pong，但不能因此无限等下去：这个循环本身没有上界，单次 recv 的
        超时封不住它。带 deadline 时，到点即抛 TimeoutError。
        """
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("HA_SNAPSHOT_DEADLINE_EXCEEDED")
            message = json.loads(socket.recv())
            if message.get("type") == "ping":
                socket.send(json.dumps({"id": message.get("id"), "type": "pong"}))
                continue
            return message


# Compatibility alias for existing integrations importing the original class.
HomeAssistantSupervisorClient = HomeAssistantClient
