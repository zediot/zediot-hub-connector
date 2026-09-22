import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zediot_ha_hub_connector.config import ConnectorConfig
from zediot_ha_hub_connector.core_client import (
    HubLeaseConflictError,
    HubSession,
    HubSessionInvalidError,
)
from zediot_ha_hub_connector.ha_client import HomeAssistantSnapshot
from zediot_ha_hub_connector.identity import BINDING_READY, ConnectorIdentity
from zediot_ha_hub_connector.runtime import HubConnectorRuntime
from zediot_ha_hub_connector.snapshot import build_snapshot_uplink


class FakeCore:
    def __init__(self, *, resume_cursor=None, grants=None):
        self.events = []
        self.snapshots = []
        self.resume_cursor = resume_cursor
        self.grants = frozenset(
            grants
            or {"inventory_read", "state_uplink", "presence_uplink"}
        )
        self.disconnects = []
        self.heartbeats = []

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
            effective_grants=self.grants,
        )

    def upload_events(self, *, identity, session, payload):
        self.events.append(payload)
        return {"cursor_after": payload["sequence_end"]}

    def upload_snapshot(self, *, identity, session, payload):
        self.snapshots.append(payload)
        return {"cursor_after": payload["sequence"]}

    def disconnect_session(self, **kwargs):
        self.disconnects.append(kwargs)
        return {"status": "disconnected"}

    def heartbeat(self, **kwargs):
        self.heartbeats.append(kwargs)
        return {"status": "active"}


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
            effective_grants=self.grants,
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


def test_snapshot_includes_bounded_device_identity_evidence():
    payload = build_snapshot_uplink(
        HomeAssistantSnapshot(
            observed_at=datetime.now(timezone.utc),
            areas=[],
            devices=[
                {
                    "id": "ha-device-1",
                    "name": "QA Light",
                    "manufacturer": "ZedIoT",
                    "model": "Virtual Light",
                    "identifiers": [["mqtt", "qa-light"]],
                    "connections": [
                        ["mac", "00:11:22:33:44:55"],
                        ["serial", "qa-1"],
                    ],
                }
            ],
            entities=[],
            states=[],
        ),
        run_type="bootstrap",
    )

    device = next(
        item for item in payload["objects"] if item["object_type"] == "device"
    )
    assert device["metadata"]["identifier_count"] == 1
    assert device["metadata"]["connection_count"] == 2


def test_snapshot_carries_bounded_current_state_and_changes_its_version():
    observed_at = datetime(2026, 8, 22, 8, 0, tzinfo=timezone.utc)

    def build(state: str):
        return build_snapshot_uplink(
            HomeAssistantSnapshot(
                observed_at=observed_at,
                areas=[],
                devices=[],
                entities=[
                    {"entity_id": "light.qa", "disabled_by": None},
                    {"entity_id": "sensor.disabled", "disabled_by": "user"},
                ],
                states=[
                    {
                        "entity_id": "light.qa",
                        "state": state,
                        "last_changed": "2026-08-22T07:59:00Z",
                        "last_updated": "2026-08-22T08:00:00Z",
                        "attributes": {"access_token": "must-not-leave-ha"},
                    },
                    {
                        "entity_id": "sensor.disabled",
                        "state": "42",
                        "last_updated": "2026-08-22T08:00:00Z",
                    },
                ],
            ),
            run_type="bootstrap",
        )

    online = build("on")
    offline = build("off")

    assert online["current_states"] == [
        {
            "entity_id": "light.qa",
            "state": "on",
            "last_changed": "2026-08-22T07:59:00Z",
            "last_updated": "2026-08-22T08:00:00Z",
        }
    ]
    assert online["source_version"] != offline["source_version"]
    assert "access_token" not in str(online)


def test_runtime_scopes_shared_ha_context_event_ids_by_entity(tmp_path: Path):
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
        effective_grants=frozenset({"inventory_read", "state_uplink"}),
    )
    for entity_id in (
        "input_boolean.qa_light_power",
        "light.qa_light",
    ):
        runtime.enqueue_event(
            {
                "time_fired": "2026-08-19T13:25:15Z",
                "context": {"id": "shared-context"},
                "data": {
                    "new_state": {
                        "entity_id": entity_id,
                        "state": "on",
                        "last_updated": "2026-08-19T13:25:15Z",
                    }
                },
            }
        )

    queued = runtime.queue.peek_all(limit=10)
    assert len({item.payload["source_event_id"] for item in queued}) == 2
    assert runtime.flush_once() is True
    assert len({item["source_event_id"] for item in core.events[0]["events"]}) == 2


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
        effective_grants=frozenset(
            {"inventory_read", "state_uplink", "presence_uplink"}
        ),
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


def test_runtime_retries_failed_event_batch_as_offline_replay(tmp_path: Path):
    class FlakyCore(FakeCore):
        def upload_events(self, *, identity, session, payload):
            self.events.append(payload)
            if len(self.events) == 1:
                raise httpx.ConnectError("offline")
            return {"cursor_after": payload["sequence_end"]}

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
        retry_max_attempts=2,
        retry_base_seconds=0,
    )
    core = FlakyCore()
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
        effective_grants=frozenset({"state_uplink"}),
    )
    runtime.enqueue_event(
        {
            "time_fired": "2026-08-22T08:00:00Z",
            "context": {"id": "ctx-offline-replay"},
            "data": {
                "new_state": {
                    "entity_id": "light.qa",
                    "state": "on",
                    "last_updated": "2026-08-22T08:00:00Z",
                }
            },
        }
    )

    assert runtime.flush_once() is True
    assert len(core.events) == 2
    first = core.events[0]["events"][0]
    replayed = core.events[1]["events"][0]
    assert first["delivery_mode"] == "realtime"
    assert first["is_replay"] is False
    assert replayed["delivery_mode"] == "replay"
    assert replayed["is_replay"] is True
    assert replayed["source_event_id"] == first["source_event_id"]
    assert replayed["observed_at"] == first["observed_at"]
    assert replayed["sequence"] == first["sequence"]
    assert runtime.queue.summary()["queue_depth"] == 0


def test_runtime_fences_event_queued_behind_failed_batch_as_replay(
    tmp_path: Path,
):
    runtime_holder = {}

    class FlakyCore(FakeCore):
        def upload_events(self, *, identity, session, payload):
            self.events.append(payload)
            if len(self.events) == 1:
                runtime_holder["runtime"].enqueue_event(
                    {
                        "time_fired": "2026-08-22T08:00:01Z",
                        "context": {"id": "ctx-queued-behind"},
                        "data": {
                            "new_state": {
                                "entity_id": "light.queued_behind",
                                "state": "on",
                                "last_updated": "2026-08-22T08:00:01Z",
                            }
                        },
                    }
                )
                raise httpx.ConnectError("offline")
            return {"cursor_after": payload["sequence_end"]}

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
        event_batch_size=1,
        retry_max_attempts=2,
        retry_base_seconds=0,
    )
    core = FlakyCore()
    runtime = HubConnectorRuntime(
        config,
        core=core,
        home_assistant=FakeHomeAssistant(),
        sleep=lambda _seconds: None,
    )
    runtime_holder["runtime"] = runtime
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
        effective_grants=frozenset({"state_uplink"}),
    )
    runtime.enqueue_event(
        {
            "time_fired": "2026-08-22T08:00:00Z",
            "context": {"id": "ctx-attempted"},
            "data": {
                "new_state": {
                    "entity_id": "light.attempted",
                    "state": "on",
                    "last_updated": "2026-08-22T08:00:00Z",
                }
            },
        }
    )

    assert runtime.flush_once() is True
    assert runtime.flush_once() is True
    queued_behind = core.events[-1]["events"][0]
    assert queued_behind["payload"]["new_state"]["entity_id"] == (
        "light.queued_behind"
    )
    assert queued_behind["delivery_mode"] == "replay"
    assert queued_behind["is_replay"] is True


def test_runtime_retries_failed_snapshot_as_offline_replay(tmp_path: Path):
    class FlakySnapshotCore(FakeCore):
        def upload_snapshot(self, *, identity, session, payload):
            self.snapshots.append(payload)
            if len(self.snapshots) == 1:
                raise httpx.ConnectError("offline")
            return {"cursor_after": payload["sequence"]}

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
        retry_max_attempts=2,
        retry_base_seconds=0,
    )
    core = FlakySnapshotCore()
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
        effective_grants=frozenset({"inventory_read"}),
    )
    runtime.enqueue_snapshot(run_type="bootstrap")

    assert runtime.flush_once() is True
    assert len(core.snapshots) == 2
    assert core.snapshots[0]["delivery_mode"] == "realtime"
    assert core.snapshots[1]["delivery_mode"] == "replay"
    assert core.snapshots[1]["sequence"] == core.snapshots[0]["sequence"]
    assert runtime.queue.summary()["queue_depth"] == 0


def test_runtime_preserves_offline_classification_from_enqueue_to_upload(
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
        effective_grants=frozenset({"state_uplink"}),
    )
    runtime.breaker.state = "open"
    runtime.breaker.opened_at = 0
    runtime.enqueue_event(
        {
            "time_fired": "2026-08-22T08:00:00Z",
            "context": {"id": "ctx-collected-offline"},
            "data": {
                "new_state": {
                    "entity_id": "light.qa",
                    "state": "off",
                    "last_updated": "2026-08-22T08:00:00Z",
                }
            },
        }
    )

    runtime.breaker.state = "closed"
    runtime.breaker.opened_at = None
    assert runtime.flush_once() is True
    uploaded = core.events[0]["events"][0]
    assert uploaded["delivery_mode"] == "replay"
    assert uploaded["is_replay"] is True


def test_runtime_replays_unattempted_event_after_process_restart(tmp_path: Path):
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
    first_runtime = HubConnectorRuntime(
        config,
        core=FakeCore(),
        home_assistant=FakeHomeAssistant(),
        sleep=lambda _seconds: None,
    )
    first_runtime.enqueue_event(
        {
            "time_fired": "2026-08-22T08:00:00Z",
            "context": {"id": "ctx-before-restart"},
            "data": {
                "new_state": {
                    "entity_id": "light.qa",
                    "state": "on",
                    "last_updated": "2026-08-22T08:00:00Z",
                }
            },
        }
    )

    core = FakeCore()
    restarted = HubConnectorRuntime(
        config,
        core=core,
        home_assistant=FakeHomeAssistant(),
        sleep=lambda _seconds: None,
    )
    restarted.identity = ConnectorIdentity(
        private_key=Ed25519PrivateKey.generate(),
        enrollment_id="henr_1",
        connector_id="hub_1",
        credential_id="hcred_1",
        exchange_receipt="receipt",
    )
    restarted.session = HubSession(
        session_id="hsess_restarted",
        integration_instance_id="int_test",
        lease_generation=2,
        lease_expires_at=datetime.now(timezone.utc) + timedelta(seconds=90),
        resume_cursor=None,
        effective_grants=frozenset({"state_uplink"}),
    )

    assert restarted.flush_once() is True
    uploaded = core.events[0]["events"][0]
    assert uploaded["delivery_mode"] == "replay"
    assert uploaded["is_replay"] is True


def test_successful_heartbeat_closes_half_open_circuit_with_empty_queue(
    tmp_path: Path,
):
    core = FakeCore(grants={"state_uplink"})
    runtime = HubConnectorRuntime(
        ConnectorConfig(
            core_url="https://core.example",
            display_name="Test",
            installation_id="install-1",
            pairing_code=None,
            ha_websocket_url="ws://supervisor/core/websocket",
            ha_access_token="supervisor",
            ha_auth_mode="supervisor",
            runtime_kind="home_assistant_addon",
            state_dir=tmp_path,
            circuit_recovery_seconds=0,
        ),
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
    runtime.session = core.connect_session(
        identity=runtime.identity,
        resume_cursor=None,
    )
    runtime.breaker.state = "open"
    runtime.breaker.opened_at = 0

    assert runtime.flush_once() is False
    assert core.heartbeats[-1]["circuit_state"] == "half_open"
    assert runtime.breaker.state == "closed"


def test_maintenance_heartbeat_does_not_own_half_open_transition(
    tmp_path: Path,
):
    core = FakeCore(grants={"state_uplink"})
    runtime = HubConnectorRuntime(
        ConnectorConfig(
            core_url="https://core.example",
            display_name="Test",
            installation_id="install-1",
            pairing_code=None,
            ha_websocket_url="ws://supervisor/core/websocket",
            ha_access_token="supervisor",
            ha_auth_mode="supervisor",
            runtime_kind="home_assistant_addon",
            state_dir=tmp_path,
        ),
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
    runtime.session = core.connect_session(
        identity=runtime.identity,
        resume_cursor=None,
    )
    runtime.breaker.state = "half_open"

    assert runtime.heartbeat() == {"status": "active"}
    assert runtime.breaker.state == "half_open"


@pytest.mark.parametrize(
    ("queue_kind", "grants"),
    (
        ("snapshot", {"state_uplink"}),
        ("event", {"command_downlink"}),
    ),
)
def test_half_open_probe_recovers_with_ineligible_persisted_queue_head(
    tmp_path: Path,
    queue_kind: str,
    grants: set[str],
):
    core = FakeCore(grants=grants)
    runtime = HubConnectorRuntime(
        ConnectorConfig(
            core_url="https://core.example",
            display_name="Test",
            installation_id="install-1",
            pairing_code=None,
            ha_websocket_url="ws://supervisor/core/websocket",
            ha_access_token="supervisor",
            ha_auth_mode="supervisor",
            runtime_kind="home_assistant_addon",
            state_dir=tmp_path,
            circuit_recovery_seconds=0,
        ),
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
    runtime.session = core.connect_session(
        identity=runtime.identity,
        resume_cursor=None,
    )
    runtime.queue.enqueue(kind=queue_kind, payload={"persisted": True})
    runtime.breaker.state = "open"
    runtime.breaker.opened_at = 0

    assert runtime.flush_once() is False
    assert core.heartbeats[-1]["circuit_state"] == "half_open"
    assert runtime.breaker.current_state() == "closed"
    assert runtime.queue.summary()["queue_depth"] == 1


def test_stale_upload_success_does_not_close_after_newer_failure(
    tmp_path: Path,
):
    core = FakeCore(grants={"state_uplink"})
    runtime = HubConnectorRuntime(
        ConnectorConfig(
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
            circuit_failure_threshold=1,
        ),
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
    runtime.session = core.connect_session(
        identity=runtime.identity,
        resume_cursor=None,
    )
    original_upload = core.upload_events

    def upload_after_newer_failure(**kwargs):
        runtime.breaker.failure()
        return original_upload(**kwargs)

    core.upload_events = upload_after_newer_failure  # type: ignore[method-assign]
    runtime.enqueue_event(
        {
            "time_fired": "2026-08-26T18:00:00Z",
            "context": {"id": "ctx-stale-success"},
            "data": {
                "new_state": {
                    "entity_id": "light.stale_success",
                    "state": "on",
                    "last_updated": "2026-08-26T18:00:00Z",
                }
            },
        }
    )

    assert runtime.flush_once() is True
    assert runtime.breaker.current_state() == "open"
    assert runtime.queue.summary()["queue_depth"] == 0


def test_stale_session_recovery_success_does_not_close_after_newer_failure(
    tmp_path: Path,
):
    core = RecoveringFakeCore()
    runtime = HubConnectorRuntime(
        ConnectorConfig(
            core_url="https://core.example",
            display_name="Test",
            installation_id="install-1",
            pairing_code=None,
            ha_websocket_url="ws://supervisor/core/websocket",
            ha_access_token="supervisor",
            ha_auth_mode="supervisor",
            runtime_kind="home_assistant_addon",
            state_dir=tmp_path,
            circuit_failure_threshold=1,
        ),
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
        effective_grants=core.grants,
    )
    original_connect = core.connect_session

    def connect_after_newer_failure(**kwargs):
        session = original_connect(**kwargs)
        runtime.breaker.failure()
        return session

    core.connect_session = connect_after_newer_failure  # type: ignore[method-assign]

    runtime._recover_after_session_error(
        HubSessionInvalidError(
            session_id="hsess_stale",
            detail="Hub session is not active",
        )
    )

    assert runtime.session.session_id == "hsess_recovered_1"
    assert runtime.breaker.current_state() == "open"


def test_upload_loop_logs_bounded_failure_evidence_without_error_text(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
):
    runtime = HubConnectorRuntime(
        ConnectorConfig(
            core_url="https://core.example",
            display_name="Test",
            installation_id="install-1",
            pairing_code=None,
            ha_websocket_url="ws://supervisor/core/websocket",
            ha_access_token="supervisor",
            ha_auth_mode="supervisor",
            runtime_kind="home_assistant_addon",
            state_dir=tmp_path,
        ),
        core=FakeCore(),
        home_assistant=FakeHomeAssistant(),
        sleep=lambda _seconds: runtime.request_stop(),
    )

    def fail_flush() -> bool:
        raise RuntimeError("sensitive-upstream-detail")

    runtime.flush_once = fail_flush  # type: ignore[method-assign]
    with caplog.at_level(logging.WARNING):
        runtime._upload_loop()

    assert "exception_type=RuntimeError" in caplog.text
    assert "circuit_state=closed" in caplog.text
    assert "queue_depth=0" in caplog.text
    assert "sensitive-upstream-detail" not in caplog.text


def test_upload_loop_survives_queue_summary_failure_while_logging(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
):
    runtime = HubConnectorRuntime(
        ConnectorConfig(
            core_url="https://core.example",
            display_name="Test",
            installation_id="install-1",
            pairing_code=None,
            ha_websocket_url="ws://supervisor/core/websocket",
            ha_access_token="supervisor",
            ha_auth_mode="supervisor",
            runtime_kind="home_assistant_addon",
            state_dir=tmp_path,
        ),
        core=FakeCore(),
        home_assistant=FakeHomeAssistant(),
        sleep=lambda _seconds: runtime.request_stop(),
    )

    def fail_flush() -> bool:
        raise RuntimeError("sensitive-upstream-detail")

    def fail_summary() -> dict[str, int]:
        raise sqlite3.OperationalError("database is locked")

    runtime.flush_once = fail_flush  # type: ignore[method-assign]
    runtime.queue.summary = fail_summary  # type: ignore[method-assign]
    with caplog.at_level(logging.WARNING):
        runtime._upload_loop()

    assert "exception_type=RuntimeError" in caplog.text
    assert "queue_depth=unavailable" in caplog.text
    assert "database is locked" not in caplog.text
    assert "sensitive-upstream-detail" not in caplog.text


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
        effective_grants=frozenset(
            {"inventory_read", "state_uplink", "presence_uplink"}
        ),
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
        effective_grants=frozenset(
            {"inventory_read", "state_uplink", "presence_uplink"}
        ),
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


def test_runtime_starts_only_loops_allowed_by_effective_grants(tmp_path: Path):
    core = FakeCore(grants={"inventory_read", "state_uplink", "presence_uplink"})
    runtime = HubConnectorRuntime(
        ConnectorConfig(
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
        ),
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
    runtime.session = core.connect_session(
        identity=runtime.identity,
        resume_cursor=None,
    )

    assert runtime.process_commands_once() == 0
    assert runtime.process_rule_packages_once() == 0
    assert runtime.flush_rule_evidence_once() == 0
    assert {thread.name for thread in runtime._runtime_threads()} == {
        "hub-subscription",
        "hub-upload",
        # 对账独立成线程：采 HA 全量快照是同步且可能很慢的活，留在心跳线程里会
        # 拖过租约把会话拖死。仅在有 inventory_read 授权时启动。
        "hub-inventory",
        "hub-maintenance",
    }


def test_presence_only_grant_does_not_enable_http_state_uplink(tmp_path: Path):
    core = FakeCore(grants={"presence_uplink"})
    runtime = HubConnectorRuntime(
        ConnectorConfig(
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
        ),
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
    runtime.session = core.connect_session(
        identity=runtime.identity,
        resume_cursor=None,
    )

    assert {thread.name for thread in runtime._runtime_threads()} == {
        "hub-maintenance"
    }


def test_runtime_clean_shutdown_disconnects_the_active_lease(tmp_path: Path):
    core = FakeCore(grants={"inventory_read"})
    runtime = HubConnectorRuntime(
        ConnectorConfig(
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
        ),
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
    runtime.session = core.connect_session(
        identity=runtime.identity,
        resume_cursor=None,
    )
    runtime.binding_state = "ready"
    runtime.prepare = lambda: None
    runtime.request_stop(reason_code="connector_sigterm")

    runtime.run_forever()

    assert runtime.session is None
    assert len(core.disconnects) == 1
    assert core.disconnects[0]["reason_code"] == "connector_sigterm"


class LeaseHeldFakeCore(FakeCore):
    """第一次建会话撞上旧租约，之后成功。"""

    def __init__(self, *, retry_after_seconds):
        super().__init__()
        self.retry_after_seconds = retry_after_seconds
        self.connect_attempts = 0

    def connect_session(self, *, identity, resume_cursor):
        self.connect_attempts += 1
        if self.connect_attempts == 1:
            raise HubLeaseConflictError(
                retry_after_seconds=self.retry_after_seconds,
                lease_expires_at=None,
            )
        return super().connect_session(identity=identity, resume_cursor=resume_cursor)


class RecordingStopEvent:
    def __init__(self, *, stop_during_wait=False):
        self.waits = []
        self.stop_during_wait = stop_during_wait

    def wait(self, seconds):
        self.waits.append(seconds)
        return self.stop_during_wait

    def is_set(self):
        return self.stop_during_wait and bool(self.waits)


def _lease_runtime(tmp_path: Path, core) -> HubConnectorRuntime:
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
    return HubConnectorRuntime(
        config,
        core=core,
        home_assistant=FakeHomeAssistant(),
        sleep=lambda _seconds: None,
    )


def _lease_identity() -> ConnectorIdentity:
    return ConnectorIdentity(
        private_key=Ed25519PrivateKey.generate(),
        enrollment_id="henr_1",
        connector_id="hub_1",
        credential_id="hcred_1",
        exchange_receipt="receipt",
    )


def test_held_lease_is_waited_out_instead_of_crashing_the_process(tmp_path: Path):
    """撞上旧租约时按 Core 给的秒数原地等，然后接管 —— 不能让异常冒出 run_forever。

    现网：异常冒出去、进程退出、容器重启再撞，09-19 被拒 7 次，每次冷启动都在
    Core 审计里多一条 connector_clone_suspected。
    """
    core = LeaseHeldFakeCore(retry_after_seconds=187)
    runtime = _lease_runtime(tmp_path, core)
    runtime.stop_event = RecordingStopEvent()

    runtime._establish_session(_lease_identity())

    assert core.connect_attempts == 2, "等完之后应当再试一次并成功"
    assert runtime.stop_event.waits == [188.0], "按 retry_after_seconds 等，多留 1 秒余量"
    assert runtime.session is not None


def test_held_lease_without_a_hint_falls_back_to_a_bounded_wait(tmp_path: Path):
    """旧版 Core 不给秒数：用固定间隔，而不是立刻重试。"""
    core = LeaseHeldFakeCore(retry_after_seconds=None)
    runtime = _lease_runtime(tmp_path, core)
    runtime.stop_event = RecordingStopEvent()

    runtime._establish_session(_lease_identity())

    assert runtime.stop_event.waits == [30.0]
    assert runtime.session is not None


def test_absurd_wait_hint_is_capped(tmp_path: Path):
    """一个异常的大值不该让连接器静默挂上几个小时。"""
    core = LeaseHeldFakeCore(retry_after_seconds=86_400)
    runtime = _lease_runtime(tmp_path, core)
    runtime.stop_event = RecordingStopEvent()

    runtime._establish_session(_lease_identity())

    assert runtime.stop_event.waits == [600.0]


def test_stop_during_lease_wait_exits_without_another_attempt(tmp_path: Path):
    """等待期间收到 SIGTERM：立刻停，不再建会话，也不能卡到租约到期。"""
    core = LeaseHeldFakeCore(retry_after_seconds=187)
    runtime = _lease_runtime(tmp_path, core)
    runtime.stop_event = RecordingStopEvent(stop_during_wait=True)

    runtime._establish_session(_lease_identity())

    assert core.connect_attempts == 1
    assert runtime.session is None


class HomeAssistantNotUpYet(FakeHomeAssistant):
    """前几次采快照时 HA 还没在监听 —— 整机重启后连接器先于 HA 起来就是这样。"""

    def __init__(self, *, refusals):
        self.refusals = refusals
        self.collect_calls = 0

    def collect_snapshot(self):
        self.collect_calls += 1
        if self.collect_calls <= self.refusals:
            raise ConnectionRefusedError(111, "Connection refused")
        return super().collect_snapshot()


class StopAfterWaits:
    """wait() 前 n 次返回 False（继续循环），之后返回 True（停止）。"""

    def __init__(self, n):
        self.remaining = n
        self.waits = []

    def wait(self, seconds):
        self.waits.append(seconds)
        if self.remaining > 0:
            self.remaining -= 1
            return False
        return True

    def is_set(self):
        return False

    def set(self):
        pass


def _snapshot_runtime(tmp_path: Path, home_assistant) -> HubConnectorRuntime:
    runtime = _lease_runtime(tmp_path, FakeCore())
    runtime.home_assistant = home_assistant
    runtime.session = HubSession(
        session_id="hsess_1",
        integration_instance_id="int_test",
        lease_generation=1,
        lease_expires_at=datetime.now(timezone.utc) + timedelta(seconds=240),
        resume_cursor=None,
        effective_grants=frozenset({"inventory_read", "state_uplink"}),
    )
    return runtime


def test_home_assistant_not_up_at_startup_does_not_crash_the_process(tmp_path: Path):
    """HA 还没起来时，run_forever 不能因为启动快照而抛出去。

    现网 2026-09-22：AIBox 整机重启，连接器先于 HA 起来，启动快照连接被拒，
    异常冒出 run_forever，进程退出、容器重启，连崩 5 次才等到 HA。
    """
    home_assistant = HomeAssistantNotUpYet(refusals=1)
    runtime = _snapshot_runtime(tmp_path, home_assistant)
    runtime.prepare = lambda: None
    runtime.binding_state = BINDING_READY  # prepare() 正常走完后的状态
    runtime._runtime_threads = lambda: []
    runtime.stop_event = StopAfterWaits(0)

    runtime.run_forever()  # 修复前：ConnectionRefusedError 从这里冒出去

    assert home_assistant.collect_calls == 1
    assert runtime._bootstrap_snapshot_pending is True, "没采到的启动快照要留着补"


def test_inventory_loop_backfills_the_missed_startup_snapshot(tmp_path: Path):
    """补采走对账线程，run_type 仍是 bootstrap，补上之后不再重复。"""
    home_assistant = HomeAssistantNotUpYet(refusals=2)
    runtime = _snapshot_runtime(tmp_path, home_assistant)
    run_types = []
    original = runtime.enqueue_snapshot

    def _recording(*, run_type):
        run_types.append(run_type)
        return original(run_type=run_type)

    runtime.enqueue_snapshot = _recording
    runtime._bootstrap_snapshot_pending = True
    assert runtime._try_bootstrap_snapshot() is False  # 启动时：被拒一次

    runtime.stop_event = StopAfterWaits(2)
    runtime._inventory_loop()  # 第一轮再被拒，第二轮补上

    assert run_types == ["bootstrap", "bootstrap", "bootstrap"]
    assert home_assistant.collect_calls == 3
    assert runtime._bootstrap_snapshot_pending is False


class CoreBriefBlackout(FakeCore):
    """Core 暂时不可用：前几次请求失败，之后恢复。现网是数据库连接池耗尽导致读超时。"""

    def __init__(self, *, failing_calls, error_factory, fail_on="authenticate"):
        super().__init__()
        self.failing_calls = failing_calls
        self.error_factory = error_factory
        self.fail_on = fail_on
        self.calls = {"authenticate": 0, "enrollment_status": 0}

    def _maybe_fail(self, name):
        self.calls[name] += 1
        if name == self.fail_on and self.calls[name] <= self.failing_calls:
            raise self.error_factory()

    def authenticate(self, identity):
        self._maybe_fail("authenticate")

    def enrollment_status(self, *, enrollment_id, exchange_receipt):
        self._maybe_fail("enrollment_status")
        return {"status": "approved"}


def _read_timeout():
    return httpx.ReadTimeout("The read operation timed out")


def _http_status(code):
    def _make():
        request = httpx.Request("POST", "https://core.example/api/hub/v1/auth/challenges")
        return httpx.HTTPStatusError(
            f"{code}", request=request, response=httpx.Response(code, request=request)
        )
    return _make


def test_core_read_timeout_while_going_live_is_retried_not_fatal(tmp_path: Path):
    """启动时认证读超时：等一会重试，而不是让异常冒出 run_forever。

    现网 2026-09-22 06:55：Core 数据库连接池耗尽几分钟，AIBox 连接器在认证这一步
    读超时，异常冒出去、进程退出、容器重启，连崩 2 次。
    """
    core = CoreBriefBlackout(failing_calls=2, error_factory=_read_timeout)
    runtime = _lease_runtime(tmp_path, core)
    runtime.stop_event = RecordingStopEvent()

    runtime._go_live(_lease_identity())  # 修复前：ReadTimeout 从这里冒出去

    assert core.calls["authenticate"] == 3
    assert runtime.stop_event.waits == [5.0, 10.0], "5 秒起、翻倍"
    assert runtime.session is not None


def test_core_5xx_and_429_are_retried(tmp_path: Path):
    for code in (503, 429):
        core = CoreBriefBlackout(failing_calls=1, error_factory=_http_status(code))
        runtime = _lease_runtime(tmp_path / str(code), core)
        runtime.stop_event = RecordingStopEvent()

        runtime._go_live(_lease_identity())

        assert core.calls["authenticate"] == 2, code
        assert runtime.session is not None, code


def test_rejected_credentials_still_fail_fast(tmp_path: Path):
    """凭据被拒（403）等多久都不会好：照旧抛出，不能被重试逻辑吞掉。"""
    core = CoreBriefBlackout(failing_calls=99, error_factory=_http_status(403))
    runtime = _lease_runtime(tmp_path, core)
    runtime.stop_event = RecordingStopEvent()

    with pytest.raises(httpx.HTTPStatusError):
        runtime._go_live(_lease_identity())
    assert core.calls["authenticate"] == 1
    assert runtime.stop_event.waits == []


def test_retry_backoff_is_capped(tmp_path: Path):
    core = CoreBriefBlackout(failing_calls=6, error_factory=_read_timeout)
    runtime = _lease_runtime(tmp_path, core)
    runtime.stop_event = RecordingStopEvent()

    runtime._go_live(_lease_identity())

    assert runtime.stop_event.waits == [5.0, 10.0, 20.0, 40.0, 60.0, 60.0]


def test_stop_while_core_is_unavailable_exits_cleanly(tmp_path: Path):
    core = CoreBriefBlackout(failing_calls=99, error_factory=_read_timeout)
    runtime = _lease_runtime(tmp_path, core)
    runtime.stop_event = RecordingStopEvent(stop_during_wait=True)

    runtime._go_live(_lease_identity())

    assert core.calls["authenticate"] == 1
    assert runtime.session is None


def test_enrollment_check_timeout_at_startup_is_retried(tmp_path: Path):
    """配对路径启动时先查注册状态，这一步读超时同样不能把进程带崩。"""
    core = CoreBriefBlackout(
        failing_calls=1, error_factory=_read_timeout, fail_on="enrollment_status"
    )
    runtime = _lease_runtime(tmp_path, core)
    runtime.stop_event = RecordingStopEvent()

    runtime._prepare_existing(_lease_identity())

    assert core.calls["enrollment_status"] == 2
    assert runtime.session is not None

