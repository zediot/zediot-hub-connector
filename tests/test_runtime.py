from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zediot_ha_hub_connector.config import ConnectorConfig
from zediot_ha_hub_connector.core_client import HubSession
from zediot_ha_hub_connector.identity import ConnectorIdentity
from zediot_ha_hub_connector.runtime import HubConnectorRuntime


class FakeCore:
    def __init__(self):
        self.events = []

    def upload_events(self, *, identity, session, payload):
        self.events.append(payload)
        return {"cursor_after": payload["sequence_end"]}


class FakeHomeAssistant:
    pass


def test_runtime_flushes_contiguous_events_and_removes_acknowledged_rows(
    tmp_path: Path,
):
    config = ConnectorConfig(
        core_url="https://core.example",
        display_name="Test",
        installation_id="install-1",
        pairing_code=None,
        ha_websocket_url="ws://supervisor/core/websocket",
        ha_access_token="supervisor",
        ha_auth_mode="supervisor",
        runtime_kind="home_assistant_addon",
        state_dir=tmp_path,
        queue_max_bytes=1024 * 1024,
        queue_max_age_seconds=3600,
        retry_base_seconds=0,
    )
    core = FakeCore()
    runtime = HubConnectorRuntime(
        config,
        core=core,
        home_assistant=FakeHomeAssistant(),
        sleep=lambda _seconds: None,
    )
    runtime.identity = ConnectorIdentity(
        private_key=Ed25519PrivateKey.generate(),
        enrollment_id="henr_1",
        connector_id="hub_1",
        credential_id="hcred_1",
        exchange_receipt="receipt",
    )
    runtime.session = HubSession(
        session_id="hsess_1",
        integration_instance_id="int_test",
        lease_generation=1,
        lease_expires_at=datetime.now(timezone.utc) + timedelta(seconds=90),
        resume_cursor=None,
    )
    runtime.enqueue_event(
        {
            "time_fired": "2026-07-29T01:00:00Z",
            "context": {"id": "ctx-1"},
            "data": {
                "new_state": {
                    "entity_id": "sensor.temperature",
                    "state": "22.5",
                    "last_updated": "2026-07-29T01:00:00Z",
                }
            },
        }
    )
    runtime.enqueue_event(
        {
            "time_fired": "2026-07-29T01:00:01Z",
            "context": {"id": "ctx-2"},
            "data": {
                "new_state": {
                    "entity_id": "sensor.temperature",
                    "state": "22.6",
                    "last_updated": "2026-07-29T01:00:01Z",
                }
            },
        }
    )

    assert runtime.flush_once() is True
    assert core.events[0]["sequence_start"] == 1
    assert core.events[0]["sequence_end"] == 2
    assert runtime.queue.summary()["queue_depth"] == 0
