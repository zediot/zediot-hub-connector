from __future__ import annotations

import json
from pathlib import Path

import pytest

from zediot_ha_hub_connector.config import ConnectorConfig


def test_supervisor_mode_uses_local_supervisor_websocket(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    monkeypatch.setenv("ZEDIOT_CORE_URL", "https://core.example")
    monkeypatch.setenv("SUPERVISOR_TOKEN", "supervisor-secret")
    monkeypatch.setenv("ZEDIOT_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("ZEDIOT_HA_AUTH_MODE", raising=False)

    config = ConnectorConfig.from_env()

    assert config.ha_auth_mode == "supervisor"
    assert config.ha_access_token == "supervisor-secret"
    assert config.ha_websocket_url == "ws://supervisor/core/websocket"
    assert config.runtime_kind == "home_assistant_addon"
    assert config.installation_id.startswith("ha-")
    assert (tmp_path / "installation_id").read_text().strip() == (
        config.installation_id
    )


def test_container_mode_reads_token_and_pairing_code_from_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    token_path = tmp_path / "ha_token"
    token_path.write_text("ha-secret-token\n", encoding="utf-8")
    pairing_path = tmp_path / "pairing_code"
    pairing_path.write_text("henr_1.one-time-secret\n", encoding="utf-8")
    state_dir = tmp_path / "state"
    monkeypatch.setenv("ZEDIOT_CORE_URL", "https://core.example")
    monkeypatch.setenv("ZEDIOT_HA_AUTH_MODE", "token_file")
    monkeypatch.setenv(
        "ZEDIOT_HA_WEBSOCKET_URL",
        "ws://host.docker.internal:8123/api/websocket",
    )
    monkeypatch.setenv("ZEDIOT_HA_TOKEN_FILE", str(token_path))
    monkeypatch.setenv("ZEDIOT_PAIRING_CODE_FILE", str(pairing_path))
    monkeypatch.setenv("ZEDIOT_STATE_DIR", str(state_dir))
    monkeypatch.setenv("ZEDIOT_INSTALLATION_ID", "nas-ha")

    config = ConnectorConfig.from_env()

    assert config.ha_auth_mode == "token_file"
    assert config.ha_access_token == "ha-secret-token"
    assert config.pairing_code == "henr_1.one-time-secret"
    assert config.runtime_kind == "home_assistant_container"
    assert config.installation_id == "nas-ha"
    assert config.event_batch_size == 50


def test_consumed_pairing_code_file_is_optional_after_enrollment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    token_path = tmp_path / "ha_token"
    token_path.write_text("ha-secret-token", encoding="utf-8")
    pairing_path = tmp_path / "pairing_code"
    pairing_path.write_text("", encoding="utf-8")
    monkeypatch.setenv("ZEDIOT_CORE_URL", "https://core.example")
    monkeypatch.setenv("ZEDIOT_HA_AUTH_MODE", "token_file")
    monkeypatch.setenv("ZEDIOT_HA_TOKEN_FILE", str(token_path))
    monkeypatch.setenv("ZEDIOT_PAIRING_CODE_FILE", str(pairing_path))
    monkeypatch.setenv("ZEDIOT_STATE_DIR", str(tmp_path / "state"))

    config = ConnectorConfig.from_env()

    assert config.pairing_code is None


def test_home_assistant_token_file_remains_required_and_nonempty(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    token_path = tmp_path / "ha_token"
    token_path.write_text("", encoding="utf-8")
    monkeypatch.setenv("ZEDIOT_CORE_URL", "https://core.example")
    monkeypatch.setenv("ZEDIOT_HA_AUTH_MODE", "token_file")
    monkeypatch.setenv("ZEDIOT_HA_TOKEN_FILE", str(token_path))
    monkeypatch.setenv("ZEDIOT_STATE_DIR", str(tmp_path / "state"))

    with pytest.raises(ValueError, match="must not be empty"):
        ConnectorConfig.from_env()


def test_invalid_home_assistant_websocket_url_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    token_path = tmp_path / "ha_token"
    token_path.write_text("ha-secret-token", encoding="utf-8")
    monkeypatch.setenv("ZEDIOT_CORE_URL", "https://core.example")
    monkeypatch.setenv("ZEDIOT_HA_AUTH_MODE", "token_file")
    monkeypatch.setenv("ZEDIOT_HA_TOKEN_FILE", str(token_path))
    monkeypatch.setenv("ZEDIOT_HA_WEBSOCKET_URL", "http://ha:8123")
    monkeypatch.setenv("ZEDIOT_STATE_DIR", str(tmp_path / "state"))

    with pytest.raises(ValueError, match="absolute ws"):
        ConnectorConfig.from_env()


def test_addon_options_remain_backward_compatible(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    options = tmp_path / "options.json"
    options.write_text(
        json.dumps(
            {
                "core_url": "https://core.example",
                "pairing_code": "henr_1.addon-secret",
                "display_name": "Kitchen HA",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("SUPERVISOR_TOKEN", "supervisor-secret")
    monkeypatch.setenv("ZEDIOT_OPTIONS_PATH", str(options))
    monkeypatch.setenv("ZEDIOT_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.delenv("ZEDIOT_CORE_URL", raising=False)

    config = ConnectorConfig.from_env()

    assert config.core_url == "https://core.example"
    assert config.pairing_code == "henr_1.addon-secret"
    assert config.display_name == "Kitchen HA"


def test_runtime_kind_rejects_unknown_installation_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    token_path = tmp_path / "ha_token"
    token_path.write_text("ha-secret-token", encoding="utf-8")
    monkeypatch.setenv("ZEDIOT_CORE_URL", "https://core.example")
    monkeypatch.setenv("ZEDIOT_HA_AUTH_MODE", "token_file")
    monkeypatch.setenv("ZEDIOT_HA_TOKEN_FILE", str(token_path))
    monkeypatch.setenv("ZEDIOT_RUNTIME_KIND", "custom_runtime")
    monkeypatch.setenv("ZEDIOT_STATE_DIR", str(tmp_path / "state"))

    with pytest.raises(ValueError, match="home_assistant_addon"):
        ConnectorConfig.from_env()
