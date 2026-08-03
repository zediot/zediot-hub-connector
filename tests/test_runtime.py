import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zediot_ha_hub_connector.config import ConnectorConfig
from zediot_ha_hub_connector.core_client import (
    HubSession,
    HubSessionInvalidError,
)
from zediot_ha_hub_connector.ha_client import HomeAssistantSnapshot
from zediot_ha_hub_connector.identity import ConnectorIdentity
from zediot_ha_hub_connector.runtime import HubConnectorRuntime


class FakeCore:
    def __init__(self, *, resume_cursor=None):
        self.events = []
        self.resume_cursor = resume_cursor

    def enrollment_status(self, *, enrollment_id, exchange_receipt):
        return {"status": "approved"}

    def authenticate(self, identity):
        return None

    def connect_session(self, *, identity, resume_cursor):
        return HubSession(
            session_id="hsess_prepare",
            integration_instance_id="int_test",
            lease_generation=1,
            lease_expires_at=(
                datetime.now(timezone.utc) + timedelta(seconds=90)
            ),
            resume_cursor=self.resume_cursor,
        )

    def upload_events(self, *, identity, session, payload):
        self.events.append(payload)
        return {"cursor_after": payload["sequence_end"]}


class RecoveringFakeCore(FakeCore):
    def __init__(self):
        super().__init__()
        self.connect_count = 0

    def connect_session(self, *, identity, resume_cursor):
        self.connect_count += 1
        return HubSession(
            session_id=f"hsess_recovered_{self.connect_count}",
            integration_instance_id="int_test",
            lease_generation=self.connect_count,
            lease_expires_at=(
                datetime.now(timezone.utc) + timedelta(seconds=90)
            ),
            resume_cursor=resume_cursor,
        )


class FakeHomeAssistant:
    def collect_snapshot(self):
        return HomeAssistantSnapshot(
            observed_at=datetime.now(timezone.utc),
            areas=[],
            devices=[],
            entities=[],
            states=[],
        )


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


def test_runtime_queues_reconciliation_after_capacity_drop(tmp_path: Path):
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
        queue_max_bytes=100,
        queue_max_age_seconds=3600,
        retry_base_seconds=0,
    )
    runtime = HubConnectorRuntime(
        config,
        core=FakeCore(),
        home_assistant=FakeHomeAssistant(),
        sleep=lambda _seconds: None,
    )

    dropped = runtime.enqueue_event(
        {
            "time_fired": "2026-07-29T01:00:00Z",
            "context": {"id": "ctx-overflow"},
            "data": {
                "new_state": {
                    "entity_id": "sensor.large",
                    "state": "x" * 500,
                    "last_updated": "2026-07-29T01:00:00Z",
                }
            },
        }
    )

    assert dropped.accepted is False
    assert runtime.queue.needs_reconciliation() is True

    runtime.queue.max_bytes = 1024 * 1024
    assert runtime.enqueue_reconciliation_if_needed() is True
    assert runtime.queue.needs_reconciliation() is False
    queued = runtime.queue.peek_all(limit=10)
    assert len(queued) == 1
    assert queued[0].kind == "snapshot"
    assert queued[0].payload["run_type"] == "reconciliation"


def test_unenrolled_runtime_requires_pairing_code(tmp_path: Path):
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
        retry_base_seconds=0,
    )
    runtime = HubConnectorRuntime(
        config,
        core=FakeCore(),
        home_assistant=FakeHomeAssistant(),
        sleep=lambda _seconds: None,
    )

    with pytest.raises(RuntimeError, match="HUB_PAIRING_REQUIRED"):
        runtime.prepare()


def test_enrolled_runtime_restarts_without_pairing_and_repairs_queue_gap(
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
        retry_base_seconds=0,
    )
    runtime = HubConnectorRuntime(
        config,
        core=FakeCore(resume_cursor={"uplink_sequence": 1}),
        home_assistant=FakeHomeAssistant(),
        sleep=lambda _seconds: None,
    )
    runtime.identity_store.load_or_create()
    runtime.identity_store.save_exchange(
        enrollment_id="henr_1",
        connector_id="hub_1",
        credential_id="hcred_1",
        exchange_receipt="receipt",
    )
    runtime.queue.enqueue(kind="event", payload={"value": "first"})
    runtime.queue.enqueue(kind="event", payload={"value": "second"})
    with sqlite3.connect(runtime.queue.path) as connection:
        connection.execute("UPDATE uplink_queue SET sequence = sequence + 9")

    runtime.prepare()

    assert runtime.identity is not None
    assert runtime.identity.connector_id == "hub_1"
    assert runtime.queue.summary()["queue_depth"] == 0
    assert runtime.queue.needs_reconciliation() is True


def test_runtime_replaces_only_the_stale_session_once(tmp_path: Path):
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
        retry_base_seconds=0,
    )
    core = RecoveringFakeCore()
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
        session_id="hsess_stale",
        integration_instance_id="int_test",
        lease_generation=1,
        lease_expires_at=datetime.now(timezone.utc) + timedelta(seconds=90),
        resume_cursor=None,
    )

    error = HubSessionInvalidError(
        session_id="hsess_stale",
        detail="Hub session is not active",
    )
    runtime._recover_after_session_error(error)
    runtime._recover_after_session_error(error)

    assert runtime.session.session_id == "hsess_recovered_1"
    assert core.connect_count == 1


def test_runtime_limits_event_batches_to_request_budget(tmp_path: Path):
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
        event_batch_size=2,
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
    for index in range(3):
        runtime.enqueue_event(
            {
                "time_fired": f"2026-08-03T08:00:0{index}Z",
                "context": {"id": f"ctx-{index}"},
                "data": {
                    "new_state": {
                        "entity_id": "sensor.batch",
                        "state": str(index),
                        "last_updated": f"2026-08-03T08:00:0{index}Z",
                    }
                },
            }
        )

    assert runtime.flush_once() is True
    assert core.events[0]["sequence_start"] == 1
    assert core.events[0]["sequence_end"] == 2
    assert runtime.queue.summary()["queue_depth"] == 1
