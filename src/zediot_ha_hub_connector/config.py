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
    event_batch_size: int = 50
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
    # 待绑定轮询的退避区间（43 附录 A.5）。起步要快——用户刚输完绑定码
    # 不该干等；上限要大——设备可能在仓库里放几天，固定短间隔会打出上万次
    # 无谓请求并撞上 GW-12 的限流。
    binding_poll_initial_seconds: float = 5.0
    binding_poll_max_seconds: float = 300.0
    # 运行时接收绑定码的文件（43 附录 A.7）。终端用户是在设备**已经在跑**
    # 之后才拿到绑定码的，不能要求他重启容器。
    claim_code_file: Path | None = None
    # 预发放三元组（R6-S5-EDGE-01 / 43 附录 A.2）。与 pairing_code **并存**：
    # 存量实例和模式 C 仍走配对码，出厂预置的设备走三元组。
    #
    # 放在末尾并给默认值，是为了不打断既有的 ConnectorConfig(...) 调用——
    # A.9 要求存量路径不受影响，那也包括调用方的代码。
    tenant_id: str | None = None
    product_key: str | None = None
    device_name: str | None = None
    device_secret: str | None = None

    @classmethod
    def from_env(cls) -> "ConnectorConfig":
        options = _load_options()
        # 预配置包也带 core_url（43 第 4.2 节的导出格式），让装机只需一个文件
        bundle = _load_provisioning_bundle(options=options)
        if bundle.get("core_url") and not os.getenv("ZEDIOT_CORE_URL"):
            options = {**options, "core_url": options.get("core_url") or bundle["core_url"]}
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
            pairing_code=_optional_secret_value(
                "ZEDIOT_PAIRING_CODE",
                file_env_name="ZEDIOT_PAIRING_CODE_FILE",
                options=options,
                option_key="pairing_code",
            )
            or None,
            **_provisioning_triple(options=options),
            claim_code_file=_claim_code_file(state_dir=state_dir, options=options),
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
            event_batch_size=_bounded_int(
                "ZEDIOT_EVENT_BATCH_SIZE",
                default=50,
                minimum=1,
                maximum=100,
                options=options,
                option_key="event_batch_size",
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


def _optional_secret_value(
    name: str,
    *,
    file_env_name: str,
    options: dict[str, object],
    option_key: str,
) -> str:
    file_path = os.getenv(file_env_name, "").strip()
    if file_path:
        path = Path(file_path)
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8").strip()
    return str(os.getenv(name) or options.get(option_key) or "").strip()


def _provisioning_triple(*, options: dict[str, object]) -> dict[str, str | None]:
    """读出预发放三元组（43 附录 A.2）。

    优先读**预配置包**：产线/镜像制作时写入单个 JSON 文件，内含
    core_url + tenant_id + product_key + device_name + device_secret，
    正是第 4.2 节导出的逐台格式。装机时手填四个字段既慢又容易错行，
    而这份文件可以直接由导出结果切分得到。

    密钥只从**文件**读，不接受环境变量明文——env 会出现在 `docker inspect`、
    进程列表和崩溃转储里，而 device_secret 是设备的唯一凭据。
    """
    bundle = _load_provisioning_bundle(options=options)

    def pick(key: str, env_name: str) -> str | None:
        value = (
            str(os.getenv(env_name) or "").strip()
            or str(options.get(key) or "").strip()
            or str(bundle.get(key) or "").strip()
        )
        return value or None

    secret = _secret_from_file("ZEDIOT_DEVICE_SECRET_FILE") or str(
        bundle.get("device_secret") or ""
    ).strip()

    return {
        "tenant_id": pick("tenant_id", "ZEDIOT_TENANT_ID"),
        "product_key": pick("product_key", "ZEDIOT_PRODUCT_KEY"),
        "device_name": pick("device_name", "ZEDIOT_DEVICE_NAME"),
        "device_secret": secret or None,
    }


def _claim_code_file(*, state_dir: Path, options: dict[str, object]) -> Path:
    """绑定码的落点。

    默认放在 state_dir 下：HA Add-on 的选项变更会写进这里，Compose 场景也
    可以直接 `docker cp` 或挂卷写入，两种部署形态共用一条通路，不必各写一套。
    """
    configured = (
        str(os.getenv("ZEDIOT_CLAIM_CODE_FILE") or "").strip()
        or str(options.get("claim_code_file") or "").strip()
    )
    return Path(configured) if configured else state_dir / "claim_code"


def _secret_from_file(file_env_name: str) -> str:
    """只从文件读密钥，**不提供环境变量入口**。

    env 会出现在 `docker inspect`、进程列表与崩溃转储里，而 device_secret
    是这台设备的唯一凭据——它和 HA token 一样只能走 secret file。
    """
    raw_path = os.getenv(file_env_name, "").strip()
    if not raw_path:
        return ""
    path = Path(raw_path)
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8").strip()


def _load_provisioning_bundle(*, options: dict[str, object]) -> dict[str, object]:
    raw_path = (
        str(os.getenv("ZEDIOT_PROVISIONING_BUNDLE_FILE") or "").strip()
        or str(options.get("provisioning_bundle_file") or "").strip()
    )
    if not raw_path:
        return {}
    path = Path(raw_path)
    if not path.is_file():
        # 缺文件不是致命错误：可能这台设备走的是配对码路径，
        # 引导逻辑会在拿不到任何凭据时才报错，那里的信息更完整
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(
            f"ZEDIOT_PROVISIONING_BUNDLE_FILE is not valid JSON: {error}"
        ) from error
    if not isinstance(payload, dict):
        raise ValueError("provisioning bundle must be a JSON object")
    return payload


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
