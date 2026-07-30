from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zediot_ha_hub_connector.config import ConnectorConfig
from zediot_ha_hub_connector.core_client import HubSession
from zediot_ha_hub_connector.identity import ConnectorIdentity
from zediot_ha_hub_connector.runtime import HubConnectorRuntime


class FakeCore:
    def __init__(self, delivery):
        self.delivery = delivery
        self.acks = []

    def claim_commands(self, **_kwargs):
        return [self.delivery]

    def acknowledge_command(self, **kwargs):
        self.acks.append(kwargs)
        return {"status": kwargs["status"]}


class FakeHomeAssistant:
    def __init__(self):
        self.calls = []

    def call_service(self, **kwargs):
        self.calls.append(kwargs)
        return {"request_id": "200"}


def _runtime(tmp_path: Path, core, home_assistant) -> HubConnectorRuntime:
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
        home_assistant=home_assistant,
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
    return runtime


def test_command_redelivery_reuses_terminal_receipt_without_duplicate_side_effect(
    tmp_path: Path,
):
    delivery = {
        "delivery_id": "hcmd_1",
        "command_id": "cmd_1",
        "idempotency_key": "hub-command:cmd_1",
        "deadline_at": (
            datetime.now(timezone.utc) + timedelta(minutes=5)
        ).isoformat(),
        "envelope": {
            "domain": "light",
            "service": "turn_on",
            "entity_id": "light.cold_room",
            "service_data": {"entity_id": "light.cold_room"},
        },
    }
    core = FakeCore(delivery)
    home_assistant = FakeHomeAssistant()
    runtime = _runtime(tmp_path, core, home_assistant)

    assert runtime.process_commands_once() == 1
    assert runtime.process_commands_once() == 1
    assert len(home_assistant.calls) == 1
    assert [item["status"] for item in core.acks] == ["executed", "executed"]


def test_command_allowlist_rejects_arbitrary_home_assistant_service(tmp_path: Path):
    delivery = {
        "delivery_id": "hcmd_2",
        "command_id": "cmd_2",
        "idempotency_key": "hub-command:cmd_2",
        "deadline_at": (
            datetime.now(timezone.utc) + timedelta(minutes=5)
        ).isoformat(),
        "envelope": {
            "domain": "lock",
            "service": "unlock",
            "entity_id": "lock.front_door",
            "service_data": {"entity_id": "lock.front_door"},
        },
    }
    runtime = _runtime(tmp_path, FakeCore(delivery), FakeHomeAssistant())
    try:
        runtime.process_commands_once()
    except RuntimeError as exc:
        assert str(exc) == "HUB_COMMAND_NOT_ALLOWLISTED"
    else:
        raise AssertionError("arbitrary HA service must fail closed")


def test_expired_command_is_recorded_without_home_assistant_side_effect(
    tmp_path: Path,
):
    delivery = {
        "delivery_id": "hcmd_expired",
        "command_id": "cmd_expired",
        "idempotency_key": "hub-command:cmd_expired",
        "deadline_at": (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat(),
        "envelope": {
            "domain": "light",
            "service": "turn_off",
            "entity_id": "light.cold_room",
            "service_data": {"entity_id": "light.cold_room"},
        },
    }
    core = FakeCore(delivery)
    home_assistant = FakeHomeAssistant()
    runtime = _runtime(tmp_path, core, home_assistant)

    assert runtime.process_commands_once() == 1
    assert home_assistant.calls == []
    assert core.acks[0]["status"] == "timeout"
    assert core.acks[0]["reason_code"] == "command_deadline_expired"
