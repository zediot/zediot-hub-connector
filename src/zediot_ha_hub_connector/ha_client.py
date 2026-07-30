from __future__ import annotations

import json
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
    def __init__(
        self,
        *,
        access_token: str,
        websocket_url: str,
        create_connection: Callable[..., Any] = websocket.create_connection,
    ) -> None:
        self._token = access_token
        self._websocket_url = websocket_url
        self._create_connection = create_connection

    def collect_snapshot(self) -> HomeAssistantSnapshot:
        socket = self._open()
        try:
            areas = self._command(socket, 1, "config/area_registry/list")
            devices = self._command(socket, 2, "config/device_registry/list")
            entities = self._command(socket, 3, "config/entity_registry/list")
            states = self._command(socket, 4, "get_states")
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
                        "return_response": True,
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

    def _open(self) -> Any:
        socket = self._create_connection(
            self._websocket_url,
            timeout=30,
        )
        required = self._receive_non_ping(socket)
        if required.get("type") != "auth_required":
            socket.close()
            raise RuntimeError("HA_AUTH_PROTOCOL_ERROR")
        socket.send(json.dumps({"type": "auth", "access_token": self._token}))
        authenticated = self._receive_non_ping(socket)
        if authenticated.get("type") != "auth_ok":
            socket.close()
            raise RuntimeError("HA_AUTH_FAILED")
        return socket

    def _command(
        self,
        socket: Any,
        request_id: int,
        command_type: str,
    ) -> Any:
        socket.send(json.dumps({"id": request_id, "type": command_type}))
        response = self._receive_non_ping(socket)
        if response.get("id") != request_id or not response.get("success"):
            raise RuntimeError(f"HA_COMMAND_FAILED:{command_type}")
        return response.get("result")

    @staticmethod
    def _receive_non_ping(socket: Any) -> dict[str, Any]:
        while True:
            message = json.loads(socket.recv())
            if message.get("type") == "ping":
                socket.send(json.dumps({"id": message.get("id"), "type": "pong"}))
                continue
            return message


# Compatibility alias for existing integrations importing the original class.
HomeAssistantSupervisorClient = HomeAssistantClient
