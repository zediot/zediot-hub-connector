import json

from zediot_ha_hub_connector.ha_client import HomeAssistantSupervisorClient


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


def test_ha_event_subscription_uses_supervisor_websocket_without_exposing_token():
    socket = FakeSocket()
    client = HomeAssistantSupervisorClient(
        supervisor_token="must-not-leak",
        create_connection=lambda *_args, **_kwargs: socket,
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
    assert "must-not-leak" not in str(event)
