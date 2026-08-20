from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zediot_ha_hub_connector.core_client import (
    HubSessionInvalidError,
    IoTCoreHubClient,
)
from zediot_ha_hub_connector.identity import ConnectorIdentity


def test_exchange_reports_the_selected_runtime_profile():
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["payload"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "data": {
                    "enrollment_id": "henr_test",
                    "status": "pending_approval",
                }
            },
        )

    client = IoTCoreHubClient(
        base_url="https://core.example",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    result = client.exchange(
        pairing_code="henr_test.one-time-pairing-secret",
        installation_id="ha-install-1",
        display_name="Kitchen Home Assistant",
        public_key_pem="public-key",
        runtime_kind="home_assistant_container",
    )

    assert result["status"] == "pending_approval"
    assert captured["path"] == "/api/hub/v1/enrollments/exchange"
    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["manifest"] == {
        "runtime": "home_assistant_container",
        "contract_version": "1.0",
    }
    assert payload["signature_algorithm"] == "Ed25519"
    assert "ha_access_token" not in json.dumps(payload)


def test_activate_reports_the_credential_bound_signature_algorithm():
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(200, json={"data": {"binding_state": "ready"}})

    client = IoTCoreHubClient(
        base_url="https://core.example",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    client.activate(
        tenant_id="tenant-1",
        product_key="gateway-product",
        device_name="Gateway",
        device_secret="device-secret",
        public_key_pem="public-key",
        installation_id="install-1",
    )

    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["signature_algorithm"] == "Ed25519"


def test_authenticate_rejects_a_challenge_algorithm_mismatch():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "challenge_id": "challenge-1",
                    "nonce": "nonce-1",
                    "canonical_message": "message-to-sign",
                    "signature_algorithm": "ES256",
                }
            },
        )

    client = IoTCoreHubClient(
        base_url="https://core.example",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    identity = ConnectorIdentity(
        private_key=Ed25519PrivateKey.generate(),
        enrollment_id="henr-1",
        connector_id="hub-1",
        credential_id="hcred-1",
        exchange_receipt="receipt-1",
    )

    with pytest.raises(RuntimeError, match="HUB_SIGNATURE_ALGORITHM_MISMATCH"):
        client.authenticate(identity)


@pytest.mark.parametrize("challenge_algorithm", ["Ed25519", None])
def test_authenticate_accepts_current_and_legacy_ed25519_challenges(
    challenge_algorithm,
):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/auth/challenges"):
            data = {
                "challenge_id": "challenge-1",
                "nonce": "nonce-1",
                "canonical_message": "message-to-sign",
            }
            if challenge_algorithm is not None:
                data["signature_algorithm"] = challenge_algorithm
            return httpx.Response(200, json={"data": data})
        return httpx.Response(
            200,
            json={
                "data": {
                    "access_token": "hub-token",
                    "expires_at": "2099-01-01T00:00:00Z",
                }
            },
        )

    client = IoTCoreHubClient(
        base_url="https://core.example",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    identity = ConnectorIdentity(
        private_key=Ed25519PrivateKey.generate(),
        enrollment_id="henr-1",
        connector_id="hub-1",
        credential_id="hcred-1",
        exchange_receipt="receipt-1",
    )

    client.authenticate(identity)

    assert len(requests) == 2
    token_payload = json.loads(requests[1].content.decode("utf-8"))
    assert "signature_algorithm" not in token_payload
    assert token_payload["signature"]


def test_parse_time_accepts_core_epoch_and_iso_contracts():
    from datetime import timezone

    from zediot_ha_hub_connector.core_client import _parse_time

    epoch = _parse_time(1785429900)
    iso = _parse_time("2026-07-30T16:45:00Z")

    assert epoch.tzinfo == timezone.utc
    assert int(epoch.timestamp()) == 1785429900
    assert iso.tzinfo == timezone.utc
    assert iso.isoformat() == "2026-07-30T16:45:00+00:00"


def test_session_parses_effective_grants_and_disconnects_the_same_lease():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/hub/v1/sessions":
            return httpx.Response(
                200,
                json={
                    "data": {
                        "session_id": "hsess-1",
                        "integration_instance_id": "int-1",
                        "lease_generation": 7,
                        "lease_expires_at": "2099-01-01T00:00:00Z",
                        "resume_cursor": None,
                        "effective_grants": [
                            "inventory_read",
                            "state_uplink",
                        ],
                    }
                },
            )
        return httpx.Response(200, json={"data": {"status": "disconnected"}})

    client = IoTCoreHubClient(
        base_url="https://core.example",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    client._token = "test-token"
    client._token_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    identity = ConnectorIdentity(
        private_key=Ed25519PrivateKey.generate(),
        enrollment_id="henr-1",
        connector_id="hub-1",
        credential_id="hcred-1",
        exchange_receipt="receipt-1",
    )

    session = client.connect_session(identity=identity, resume_cursor=None)
    assert session.effective_grants == frozenset(
        {"inventory_read", "state_uplink"}
    )
    assert session.allows("inventory_read") is True
    assert session.allows("command_downlink") is False

    # Teardown uses the token that owns the session and must not start a fresh
    # challenge/token exchange merely because the refresh window was reached.
    client._token_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    client.disconnect_session(
        identity=identity,
        session=session,
        reason_code="connector_sigterm",
    )
    disconnect_payload = json.loads(requests[-1].content.decode("utf-8"))
    assert requests[-1].url.path == "/api/hub/v1/sessions/hsess-1/disconnect"
    assert disconnect_payload == {
        "lease_generation": 7,
        "reason_code": "connector_sigterm",
    }


def test_legacy_session_without_grants_is_fail_closed():
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "session_id": "hsess-legacy",
                    "integration_instance_id": "int-1",
                    "lease_generation": 1,
                    "lease_expires_at": "2099-01-01T00:00:00Z",
                    "resume_cursor": None,
                }
            },
        )

    client = IoTCoreHubClient(
        base_url="https://core.example",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    client._token = "test-token"
    client._token_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    identity = ConnectorIdentity(
        private_key=Ed25519PrivateKey.generate(),
        enrollment_id="henr-1",
        connector_id="hub-1",
        credential_id="hcred-1",
        exchange_receipt="receipt-1",
    )

    session = client.connect_session(identity=identity, resume_cursor=None)

    assert session.effective_grants == frozenset()
    assert session.allows("inventory_read") is False


def test_session_conflict_classifies_only_recoverable_session_errors():
    responses = iter(
        (
            httpx.Response(
                409,
                json={"data": "Hub session is not active"},
            ),
            httpx.Response(
                409,
                json={
                    "data": "Hub uplink sequence gap: expected at most 2, got 4"
                },
            ),
        )
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return next(responses)

    client = IoTCoreHubClient(
        base_url="https://core.example",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    client._token = "test-token"

    with pytest.raises(HubSessionInvalidError) as invalid:
        client._request(
            "POST",
            "/api/hub/v1/sessions/hsess_stale/heartbeat",
        )
    assert invalid.value.session_id == "hsess_stale"

    with pytest.raises(httpx.HTTPStatusError):
        client._request(
            "POST",
            "/api/hub/v1/sessions/hsess_active/events",
        )
