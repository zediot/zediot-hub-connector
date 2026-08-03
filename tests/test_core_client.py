from __future__ import annotations

import json

import httpx
import pytest

from zediot_ha_hub_connector.core_client import (
    HubSessionInvalidError,
    IoTCoreHubClient,
)


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
    assert "ha_access_token" not in json.dumps(payload)


def test_parse_time_accepts_core_epoch_and_iso_contracts():
    from datetime import timezone

    from zediot_ha_hub_connector.core_client import _parse_time

    epoch = _parse_time(1785429900)
    iso = _parse_time("2026-07-30T16:45:00Z")

    assert epoch.tzinfo == timezone.utc
    assert int(epoch.timestamp()) == 1785429900
    assert iso.tzinfo == timezone.utc
    assert iso.isoformat() == "2026-07-30T16:45:00+00:00"


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
