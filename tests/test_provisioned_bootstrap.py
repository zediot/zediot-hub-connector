"""预发放引导路径（R6-S5-EDGE-01~08 / 43 附录 A）。

最重要的两条断言在本文件里：

* **A.9 双路径兼容**：存量实例升级后第一次启动，不得被要求重新激活或配对。
* **A.5 优雅等待**：已激活未绑定不是错误，不得崩溃退出——那会变成
  崩溃 → 容器重启 → 再崩溃的循环。
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zediot_ha_hub_connector.config import ConnectorConfig
from zediot_ha_hub_connector.core_client import HubActivationError, HubSession
from zediot_ha_hub_connector.identity import (
    BINDING_AWAITING_BINDING,
    BINDING_READY,
    BOOTSTRAP_PAIRING,
    BOOTSTRAP_PROVISIONED,
    ConnectorIdentityStore,
)
from zediot_ha_hub_connector.runtime import HubConnectorRuntime


def _config(tmp_path: Path, **overrides) -> ConnectorConfig:
    base = dict(
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
        binding_poll_initial_seconds=0,
        binding_poll_max_seconds=0,
    )
    base.update(overrides)
    return ConnectorConfig(**base)


class BootstrapCore:
    """按脚本返回激活结果，记录调用轨迹。"""

    def __init__(self, *, activations=None):
        self.activations = list(activations or [])
        self.activate_calls: list[dict] = []
        self.exchange_calls: list[dict] = []
        self.enrollment_calls: list[dict] = []
        self.authenticated = 0

    def activate(self, **kwargs):
        self.activate_calls.append(kwargs)
        if not self.activations:
            raise AssertionError("unexpected extra activate() call")
        outcome = self.activations.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def exchange(self, **kwargs):
        self.exchange_calls.append(kwargs)
        return {
            "enrollment_id": "henr_1",
            "connector_id": "hub_1",
            "credential_id": "hcred_1",
            "exchange_receipt": "receipt-1",
        }

    def enrollment_status(self, *, enrollment_id, exchange_receipt):
        self.enrollment_calls.append({"enrollment_id": enrollment_id})
        return {"status": "approved"}

    def authenticate(self, identity):
        self.authenticated += 1

    def connect_session(self, *, identity, resume_cursor):
        return HubSession(
            session_id="hsess_1",
            integration_instance_id="int_1",
            lease_generation=1,
            lease_expires_at=datetime.now(timezone.utc) + timedelta(seconds=90),
            resume_cursor=resume_cursor,
        )


class FakeHomeAssistant:
    def snapshot(self):  # pragma: no cover - 引导阶段不该被调用
        raise AssertionError("data plane must stay closed before binding")


def _runtime(config, core) -> HubConnectorRuntime:
    return HubConnectorRuntime(
        config, core=core, home_assistant=FakeHomeAssistant(), sleep=lambda _s: None
    )


# --- A.9 双路径兼容（不可退让）-------------------------------------------


def test_existing_paired_instance_boots_without_reactivation(tmp_path):
    """存量实例升级后第一次启动必须原样可用。

    它的 connector_identity.json 里没有 bootstrap_mode 字段——那是本次新增
    的。任何"没有标记就当预发放"的写法都会让它去走激活流程，而它根本没有
    device_secret，等于把现网设备打死。
    """
    store = ConnectorIdentityStore(tmp_path)
    store.load_or_create()
    # 刻意写成升级前的格式：没有 bootstrap_mode
    (tmp_path / "connector_identity.json").write_text(
        json.dumps(
            {
                "enrollment_id": "henr_legacy",
                "connector_id": "hub_legacy",
                "credential_id": "hcred_legacy",
                "exchange_receipt": "receipt-legacy",
            }
        ),
        encoding="utf-8",
    )
    core = BootstrapCore()
    runtime = _runtime(_config(tmp_path), core)

    runtime.prepare()

    assert core.activate_calls == [], "存量实例被要求重新激活了"
    assert core.exchange_calls == [], "存量实例被要求重新配对了"
    assert core.enrollment_calls, "存量实例应走原有的 enrollment 审批检查"
    assert runtime.identity.effective_bootstrap_mode == BOOTSTRAP_PAIRING
    assert runtime.binding_state == BINDING_READY


def test_triple_is_ignored_when_an_identity_already_exists(tmp_path):
    """既有身份优先于三元组：判定顺序不能反。"""
    (tmp_path / "connector_identity.json").write_text(
        json.dumps(
            {
                "enrollment_id": "henr_legacy",
                "connector_id": "hub_legacy",
                "credential_id": "hcred_legacy",
                "exchange_receipt": "receipt-legacy",
            }
        ),
        encoding="utf-8",
    )
    core = BootstrapCore()
    runtime = _runtime(
        _config(
            tmp_path,
            tenant_id="t1",
            product_key="pk",
            device_name="gw-1",
            device_secret="s3cret",
        ),
        core,
    )

    runtime.prepare()
    assert core.activate_calls == []


def test_fresh_install_without_any_credential_keeps_the_original_error(tmp_path):
    """错误码不改名：运维手册与告警规则都在匹配 HUB_PAIRING_REQUIRED。"""
    core = BootstrapCore()
    runtime = _runtime(_config(tmp_path), core)
    with pytest.raises(RuntimeError, match="HUB_PAIRING_REQUIRED"):
        runtime.prepare()


# --- A.5 优雅等待 ---------------------------------------------------------


def test_activation_then_binding_completes_without_crashing(tmp_path):
    """已激活未绑定要等，不要崩。"""
    core = BootstrapCore(
        activations=[
            {
                "identity_id": "gwid_1",
                "binding_state": BINDING_AWAITING_BINDING,
                "data_plane_open": False,
            },
            {
                "identity_id": "gwid_1",
                "binding_state": BINDING_AWAITING_BINDING,
                "data_plane_open": False,
            },
            {
                "identity_id": "gwid_1",
                "binding_state": BINDING_READY,
                "data_plane_open": True,
                "bound_space_node_id": "space_1",
                "connector_id": "hub_new",
                "credential_id": "hcred_new",
            },
        ]
    )
    runtime = _runtime(
        _config(
            tmp_path,
            tenant_id="t1",
            product_key="pk",
            device_name="gw-1",
            device_secret="s3cret",
        ),
        core,
    )

    runtime.prepare()

    # 前两轮不抛异常、不退出，只是继续轮询
    assert len(core.activate_calls) == 3
    assert core.activate_calls[0]["signature_algorithm"] == "Ed25519"
    assert runtime.binding_state == BINDING_READY
    assert runtime.identity.effective_bootstrap_mode == BOOTSTRAP_PROVISIONED
    assert core.authenticated == 1


def test_terminal_activation_error_stops_instead_of_looping(tmp_path):
    """密钥无效/已撤销是终态：继续重试只会刷日志并撞上限流。"""
    core = BootstrapCore(
        activations=[
            HubActivationError(
                detail="invalid device credentials", status_code=403, terminal=True
            )
        ]
    )
    runtime = _runtime(
        _config(
            tmp_path,
            tenant_id="t1",
            product_key="pk",
            device_name="gw-1",
            device_secret="wrong",
        ),
        core,
    )

    with pytest.raises(RuntimeError, match="HUB_ACTIVATION_REJECTED"):
        runtime.prepare()
    assert len(core.activate_calls) == 1
    assert "invalid device credentials" in runtime.binding_failure


def test_lockout_is_retried_not_treated_as_terminal(tmp_path):
    """GW-12 的锁定有期限（默认 900s），当终态会让一次输错就要求返厂。"""
    core = BootstrapCore(
        activations=[
            HubActivationError(
                detail="too many failed activation attempts for this device",
                status_code=403,
                terminal=False,
            ),
            {
                "identity_id": "gwid_1",
                "binding_state": BINDING_READY,
                "connector_id": "hub_new",
                "credential_id": "hcred_new",
                "bound_space_node_id": "space_1",
            },
        ]
    )
    runtime = _runtime(
        _config(
            tmp_path,
            tenant_id="t1",
            product_key="pk",
            device_name="gw-1",
            device_secret="s3cret",
        ),
        core,
    )

    runtime.prepare()
    assert len(core.activate_calls) == 2
    assert runtime.binding_state == BINDING_READY


def test_transient_network_failure_is_retried(tmp_path):
    core = BootstrapCore(
        activations=[
            ConnectionError("core unreachable"),
            {
                "identity_id": "gwid_1",
                "binding_state": BINDING_READY,
                "connector_id": "hub_new",
                "credential_id": "hcred_new",
            },
        ]
    )
    runtime = _runtime(
        _config(
            tmp_path,
            tenant_id="t1",
            product_key="pk",
            device_name="gw-1",
            device_secret="s3cret",
        ),
        core,
    )
    runtime.prepare()
    assert len(core.activate_calls) == 2


def test_self_health_carries_no_home_assistant_data(tmp_path):
    """待绑定期允许上报自身健康，但 HA 侧数据属于数据面，不得外传。"""
    core = BootstrapCore(
        activations=[
            {
                "identity_id": "gwid_1",
                "binding_state": BINDING_READY,
                "connector_id": "hub_new",
                "credential_id": "hcred_new",
            }
        ]
    )
    runtime = _runtime(
        _config(
            tmp_path,
            tenant_id="t1",
            product_key="pk",
            device_name="gw-1",
            device_secret="s3cret",
        ),
        core,
    )
    runtime.prepare()
    health = core.activate_calls[0]["health"]
    assert set(health) == {"runtime_kind", "installation_id", "contract_version"}


# --- A.6 数据面 fail-closed ----------------------------------------------


def test_data_plane_gate_blocks_before_binding(tmp_path):
    core = BootstrapCore()
    runtime = _runtime(_config(tmp_path), core)
    with pytest.raises(RuntimeError, match="HUB_DATA_PLANE_CLOSED"):
        runtime.ensure_data_plane_open()


# --- A.8 本地状态可见性 ---------------------------------------------------


def test_local_status_never_exposes_credentials(tmp_path):
    core = BootstrapCore(
        activations=[
            {
                "identity_id": "gwid_1",
                "binding_state": BINDING_READY,
                "connector_id": "hub_new",
                "credential_id": "hcred_new",
                "bound_space_node_id": "space_1",
            }
        ]
    )
    runtime = _runtime(
        _config(
            tmp_path,
            tenant_id="t1",
            product_key="pk",
            device_name="gw-1",
            device_secret="s3cret-must-not-leak",
        ),
        core,
    )
    runtime.prepare()
    status = runtime.local_status()

    assert status["binding_state"] == BINDING_READY
    assert status["data_plane_open"] is True
    assert status["device_name"] == "gw-1"
    # 这份状态是给现场人员看的，绝不能带凭据
    assert "s3cret-must-not-leak" not in json.dumps(status)


# --- A.7 运行时绑定码通路 -------------------------------------------------


def test_claim_code_file_is_consumed_and_deleted(tmp_path):
    """绑定码是一次性凭证，留在磁盘上等于给人一个能抢走设备的东西。

    直接测这个方法而不是走完整 prepare()：绑定成功后会清掉指引信息（对的，
    那时指引已经过时），而这里要验的正是**等待期间**的行为。
    """
    claim_file = tmp_path / "claim_code"
    claim_file.write_text("ABCD-EFGH-JKMN-PQRS", encoding="utf-8")
    runtime = _runtime(
        _config(
            tmp_path,
            tenant_id="t1",
            product_key="pk",
            device_name="gw-1",
            device_secret="s3cret",
            claim_code_file=claim_file,
        ),
        BootstrapCore(),
    )

    runtime._consume_claim_code_if_present()

    assert not claim_file.exists(), "绑定码没有被删除"
    # 本版本设备侧不提交绑定码（Core 无面向设备的 claim 端点），
    # 但要给出正确指引而不是让装机人员干等
    assert "IoT Core app" in (runtime.binding_failure or "")


def test_missing_claim_code_file_is_not_an_error(tmp_path):
    runtime = _runtime(
        _config(tmp_path, claim_code_file=tmp_path / "absent"), BootstrapCore()
    )
    runtime._consume_claim_code_if_present()
    assert runtime.binding_failure is None
