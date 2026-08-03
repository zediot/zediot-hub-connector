import json

from zediot_ha_hub_connector.ha_client import HomeAssistantClient


class FakeSocket:
    def __init__(self):
        self.sent = []
        self.responses = [
            {"type": "auth_required"},
            {"type": "auth_ok"},
            {"id": 100, "type": "result", "success": True},
            {
                "id": 100,
                "type": "event",
                "event": {
                    "event_type": "state_changed",
                    "data": {
                        "new_state": {
                            "entity_id": "sensor.temperature",
                            "state": "22.5",
                        }
                    },
                },
            },
        ]

    def send(self, value):
        self.sent.append(json.loads(value))

    def recv(self):
        return json.dumps(self.responses.pop(0))

    def close(self):
        return None


def test_ha_event_subscription_uses_configured_websocket_without_exposing_token():
    socket = FakeSocket()
    requested_urls = []
    client = HomeAssistantClient(
        access_token="must-not-leak",
        websocket_url="ws://home-assistant.local:8123/api/websocket",
        create_connection=lambda url, **_kwargs: (
            requested_urls.append(url) or socket
        ),
    )
    events = client.subscribe_state_events()
    event = next(events)
    events.close()

    assert event["event_type"] == "state_changed"
    assert {
        "id": 100,
        "type": "subscribe_events",
        "event_type": "state_changed",
    } in socket.sent
    assert requested_urls == [
        "ws://home-assistant.local:8123/api/websocket"
    ]
    assert "must-not-leak" not in str(event)


def test_ha_service_call_does_not_request_unsupported_response_data():
    socket = FakeSocket()
    socket.responses = [
        {"type": "auth_required"},
        {"type": "auth_ok"},
        {"id": 200, "type": "result", "success": True, "result": None},
    ]
    client = HomeAssistantClient(
        access_token="must-not-leak",
        websocket_url="ws://home-assistant.local:8123/api/websocket",
        create_connection=lambda _url, **_kwargs: socket,
    )

    result = client.call_service(
        domain="light",
        service="turn_on",
        entity_id="light.command_smoke",
        service_data={"entity_id": "light.command_smoke"},
    )

    assert result == {"request_id": "200", "result": None}
    assert socket.sent[-1] == {
        "id": 200,
        "type": "call_service",
        "domain": "light",
        "service": "turn_on",
        "service_data": {"entity_id": "light.command_smoke"},
        "return_response": False,
    }
    assert "must-not-leak" not in str(result)
