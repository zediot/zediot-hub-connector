from __future__ import annotations

import os
import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class ConnectorConfig:
    core_url: str
    display_name: str
    installation_id: str
    pairing_code: str | None
    ha_websocket_url: str
    ha_access_token: str
    ha_auth_mode: str
    runtime_kind: str
    state_dir: Path
    reconciliation_interval_seconds: int = 21600
    heartbeat_interval_seconds: int = 30
    queue_max_age_seconds: int = 86400
    queue_max_bytes: int = 100 * 1024 * 1024
    retry_max_attempts: int = 5
    retry_base_seconds: float = 1.0
    circuit_failure_threshold: int = 5
    circuit_recovery_seconds: int = 60
    trusted_rule_package_key_ids: frozenset[str] = frozenset(
        {"rule-package-signing-v1"}
    )
    rule_poll_interval_seconds: int = 5
    rule_evidence_max_rows: int = 5000
    rule_evidence_retention_seconds: int = 7 * 24 * 60 * 60

    @classmethod
    def from_env(cls) -> "ConnectorConfig":
        options = _load_options()
        state_dir = Path(os.getenv("ZEDIOT_STATE_DIR", "/data")).resolve()
        state_dir.mkdir(parents=True, exist_ok=True)
        ha_auth_mode = (
            os.getenv("ZEDIOT_HA_AUTH_MODE")
            or ("supervisor" if os.getenv("SUPERVISOR_TOKEN") else "token_file")
        ).strip()
        if ha_auth_mode not in {"supervisor", "token_file"}:
            raise ValueError(
                "ZEDIOT_HA_AUTH_MODE must be supervisor or token_file"
            )
        if ha_auth_mode == "supervisor":
            ha_access_token = _required("SUPERVISOR_TOKEN")
            default_websocket_url = "ws://supervisor/core/websocket"
            default_runtime_kind = "home_assistant_addon"
        else:
            ha_access_token = _required_secret_file("ZEDIOT_HA_TOKEN_FILE")
            default_websocket_url = (
                "ws://host.docker.internal:8123/api/websocket"
            )
            default_runtime_kind = "home_assistant_container"
        ha_websocket_url = (
            os.getenv("ZEDIOT_HA_WEBSOCKET_URL")
            or default_websocket_url
        ).strip()
        _validate_websocket_url(ha_websocket_url)
        reconciliation = _bounded_int(
            "ZEDIOT_RECONCILIATION_INTERVAL_SECONDS",
            default=21600,
            minimum=21600,
            maximum=86400,
            options=options,
            option_key="reconciliation_interval_seconds",
        )
        return cls(
            core_url=_value(
                "ZEDIOT_CORE_URL",
                options=options,
                option_key="core_url",
                required=True,
            ).rstrip("/"),
            display_name=_value(
                "ZEDIOT_CONNECTOR_DISPLAY_NAME",
                options=options,
                option_key="display_name",
                default="ZedIoT Hub Connector",
            ),
            installation_id=_installation_id(
                state_dir=state_dir,
                options=options,
            ),
            pairing_code=_secret_value(
                "ZEDIOT_PAIRING_CODE",
                file_env_name="ZEDIOT_PAIRING_CODE_FILE",
                options=options,
                option_key="pairing_code",
            )
            or None,
            ha_websocket_url=ha_websocket_url,
            ha_access_token=ha_access_token,
            ha_auth_mode=ha_auth_mode,
            runtime_kind=_runtime_kind(default_runtime_kind),
            state_dir=state_dir,
            reconciliation_interval_seconds=reconciliation,
            heartbeat_interval_seconds=_bounded_int(
                "ZEDIOT_HEARTBEAT_INTERVAL_SECONDS",
                default=30,
                minimum=15,
                maximum=60,
                options=options,
                option_key="heartbeat_interval_seconds",
            ),
            queue_max_age_seconds=_bounded_int(
                "ZEDIOT_QUEUE_MAX_AGE_SECONDS",
                default=86400,
                minimum=3600,
                maximum=86400,
                options=options,
                option_key="queue_max_age_seconds",
            ),
            queue_max_bytes=_bounded_int(
                "ZEDIOT_QUEUE_MAX_BYTES",
                default=100 * 1024 * 1024,
                minimum=1024 * 1024,
                maximum=100 * 1024 * 1024,
                options=options,
                option_key="queue_max_bytes",
            ),
            trusted_rule_package_key_ids=_csv_set(
                _value(
                    "ZEDIOT_RULE_PACKAGE_TRUSTED_KEY_IDS",
                    options=options,
                    option_key="rule_package_trusted_key_ids",
                    default="rule-package-signing-v1",
                )
            ),
            rule_poll_interval_seconds=_bounded_int(
                "ZEDIOT_RULE_POLL_INTERVAL_SECONDS",
                default=5,
                minimum=1,
                maximum=60,
                options=options,
                option_key="rule_poll_interval_seconds",
            ),
            rule_evidence_max_rows=_bounded_int(
                "ZEDIOT_RULE_EVIDENCE_MAX_ROWS",
                default=5000,
                minimum=100,
                maximum=50000,
                options=options,
                option_key="rule_evidence_max_rows",
            ),
            rule_evidence_retention_seconds=_bounded_int(
                "ZEDIOT_RULE_EVIDENCE_RETENTION_SECONDS",
                default=7 * 24 * 60 * 60,
                minimum=86400,
                maximum=7 * 24 * 60 * 60,
                options=options,
                option_key="rule_evidence_retention_seconds",
            ),
        )


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


def _required_secret_file(name: str) -> str:
    raw_path = os.getenv(name, "").strip()
    if not raw_path:
        raise ValueError(f"{name} is required")
    path = Path(raw_path)
    if not path.is_file():
        raise ValueError(f"{name} must point to a readable file")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError(f"{name} must not be empty")
    return value


def _secret_value(
    name: str,
    *,
    file_env_name: str,
    options: dict[str, object],
    option_key: str,
) -> str:
    file_path = os.getenv(file_env_name, "").strip()
    if file_path:
        return _required_secret_file(file_env_name)
    return str(os.getenv(name) or options.get(option_key) or "").strip()


def _installation_id(
    *,
    state_dir: Path,
    options: dict[str, object],
) -> str:
    configured = str(
        os.getenv("ZEDIOT_INSTALLATION_ID")
        or options.get("installation_id")
        or ""
    ).strip()
    if configured:
        return configured
    path = state_dir / "installation_id"
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = f"ha-{uuid.uuid4().hex}"
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)
    return value


def _validate_websocket_url(value: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme not in {"ws", "wss"} or not parsed.netloc:
        raise ValueError(
            "ZEDIOT_HA_WEBSOCKET_URL must be an absolute ws:// or wss:// URL"
        )


def _bounded_int(
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
    options: dict[str, object] | None = None,
    option_key: str | None = None,
) -> int:
    raw = os.getenv(name)
    if raw is None and options is not None and option_key:
        raw = str(options.get(option_key, default))
    value = int(raw or default)
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _value(
    name: str,
    *,
    options: dict[str, object],
    option_key: str,
    default: str = "",
    required: bool = False,
) -> str:
    value = str(os.getenv(name) or options.get(option_key) or default).strip()
    if required and not value:
        raise ValueError(f"{name} or option {option_key} is required")
    return value


def _load_options() -> dict[str, object]:
    path = Path(os.getenv("ZEDIOT_OPTIONS_PATH", "/data/options.json"))
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


def _csv_set(value: str) -> frozenset[str]:
    items = frozenset(
        item.strip()
        for item in value.split(",")
        if item.strip()
    )
    if not items:
        raise ValueError(
            "ZEDIOT_RULE_PACKAGE_TRUSTED_KEY_IDS must not be empty"
        )
    return items


def _runtime_kind(default: str) -> str:
    value = (os.getenv("ZEDIOT_RUNTIME_KIND") or default).strip()
    allowed = {"home_assistant_addon", "home_assistant_container"}
    if value not in allowed:
        raise ValueError(
            "ZEDIOT_RUNTIME_KIND must be home_assistant_addon or "
            "home_assistant_container"
        )
    return value
