from __future__ import annotations

import os
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ConnectorConfig:
    core_url: str
    display_name: str
    installation_id: str
    pairing_code: str | None
    supervisor_token: str
    state_dir: Path
    reconciliation_interval_seconds: int = 21600
    heartbeat_interval_seconds: int = 30
    queue_max_age_seconds: int = 86400
    queue_max_bytes: int = 100 * 1024 * 1024
    retry_max_attempts: int = 5
    retry_base_seconds: float = 1.0
    circuit_failure_threshold: int = 5
    circuit_recovery_seconds: int = 60

    @classmethod
    def from_env(cls) -> "ConnectorConfig":
        options = _load_options()
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
            installation_id=_value(
                "ZEDIOT_INSTALLATION_ID",
                options=options,
                option_key="installation_id",
                required=True,
            ),
            pairing_code=_value(
                "ZEDIOT_PAIRING_CODE",
                options=options,
                option_key="pairing_code",
                default="",
            )
            or None,
            supervisor_token=_required("SUPERVISOR_TOKEN"),
            state_dir=Path(os.getenv("ZEDIOT_STATE_DIR", "/data")).resolve(),
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
        )


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


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
