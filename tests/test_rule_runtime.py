from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from zediot_ha_hub_connector.config import ConnectorConfig
from zediot_ha_hub_connector.core_client import HubSession
from zediot_ha_hub_connector.identity import ConnectorIdentity
from zediot_ha_hub_connector.runtime import HubConnectorRuntime

INSTANCE = "int_ha_rule"


class FakeCore:
    def __init__(self, delivery: dict):
        self.package_response = {
            "items": [delivery],
            "controls": [],
        }
        self.package_receipts: list[dict] = []
        self.evidence_batches: list[list[dict]] = []

    def claim_rule_packages(self, **_kwargs):
        # items 是队列：claim 过一次就不再返回。
        # controls **不是**——Core 侧 list_control_directives 是一句
        # `SELECT ... WHERE status IN ('revoked','expired')`，没有消费语义，
        # 同一条会在每次 claim 里原样带回。
        #
        # 这个假对象原先把 controls 也一并清空，于是所有规则测试都跑在一个
        # "control 会被消费掉"的、不存在的世界里——真实环境下由此产生的忙等
        # 因此从未被任何测试触及。
        response = {
            "items": list(self.package_response.get("items") or []),
            "controls": list(self.package_response.get("controls") or []),
        }
        self.package_response = {
            "items": [],
            "controls": list(self.package_response.get("controls") or []),
        }
        return response

    def acknowledge_rule_package(self, **kwargs):
        self.package_receipts.append(kwargs)
        return {"receipt_status": "accepted"}

    def upload_rule_evidence(self, *, items, **_kwargs):
        self.evidence_batches.append(items)
        return {
            "items": [
                {
                    "execution_id": item["execution_id"],
                    "ingest_status": "accepted",
                }
                for item in items
            ]
        }


class FakeHomeAssistant:
    def __init__(self, *, fail: bool = False):
        self.calls: list[dict] = []
        self.fail = fail

    def call_service(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise RuntimeError("provider failure")
        return {"request_id": "ha-request-1"}


def _runtime(
    tmp_path: Path,
    *,
    delivery: dict,
    home_assistant: FakeHomeAssistant | None = None,
) -> tuple[HubConnectorRuntime, FakeCore, FakeHomeAssistant]:
    core = FakeCore(delivery)
    ha = home_assistant or FakeHomeAssistant()
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
        home_assistant=ha,
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
        integration_instance_id=INSTANCE,
        lease_generation=1,
        lease_expires_at=datetime.now(timezone.utc) + timedelta(seconds=90),
        resume_cursor=None,
    )
    from zediot_ha_hub_connector.rule_runtime import (
        HomeAssistantLocalRuleRuntime,
    )

    runtime.local_rule_runtime = HomeAssistantLocalRuleRuntime(
        store=runtime.rule_store,
        home_assistant=ha,
        integration_instance_id=INSTANCE,
        trusted_key_ids=frozenset({"rule-package-signing-v1"}),
    )
    return runtime, core, ha


def test_local_rule_executes_offline_once_and_replays_evidence(tmp_path: Path):
    delivery = _signed_delivery()
    runtime, core, home_assistant = _runtime(
        tmp_path,
        delivery=delivery,
    )

    assert runtime.process_rule_packages_once() == 1
    assert core.package_receipts[0]["status"] == "applied"
    event = _state_event(context_id="ctx-local-rule-1", state="on")
    runtime.enqueue_event(event)
    runtime.enqueue_event(event)

    assert len(home_assistant.calls) == 1
    assert runtime.rule_store.summary()["pending_evidence_count"] == 1
    assert core.evidence_batches == []
    assert runtime.flush_rule_evidence_once() == 1
    assert core.evidence_batches[0][0]["result"] == "hit"
    assert core.evidence_batches[0][0]["action_results"][0]["status"] == (
        "succeeded"
    )
    assert runtime.rule_store.summary()["pending_evidence_count"] == 0


def test_action_failure_keeps_hit_execution_evidence(tmp_path: Path):
    runtime, core, home_assistant = _runtime(
        tmp_path,
        delivery=_signed_delivery(),
        home_assistant=FakeHomeAssistant(fail=True),
    )
    runtime.process_rule_packages_once()

    runtime.enqueue_event(_state_event(context_id="ctx-failed", state="on"))
    assert len(home_assistant.calls) == 1
    assert runtime.flush_rule_evidence_once() == 1
    evidence = core.evidence_batches[0][0]
    assert evidence["result"] == "hit"
    assert evidence["action_results"][0]["status"] == "failed"


def test_revoke_control_removes_package_and_prevents_new_execution(
    tmp_path: Path,
):
    delivery = _signed_delivery()
    runtime, core, home_assistant = _runtime(
        tmp_path,
        delivery=delivery,
    )
    runtime.process_rule_packages_once()
    core.package_response = {
        "items": [],
        "controls": [
            {
                "package_id": delivery["package_id"],
                "status": "revoked",
            }
        ],
    }

    assert runtime.process_rule_packages_once() == 1
    runtime.enqueue_event(_state_event(context_id="ctx-revoked", state="on"))
    assert home_assistant.calls == []
    assert runtime.rule_store.summary()["active_package_count"] == 0


def test_repeated_revoke_control_is_not_counted_as_progress(tmp_path: Path):
    """同一条 control 反复返回时不得再算作"有进展"。

    Core 的 control 目录是全量列表而非队列：一个包被撤销后，**每次** claim
    都会原样带回这条 control。_rule_loop 只在"没进展"时 sleep，所以只要这里
    还返回非零，轮询就会退化成忙等——NAS 上实测 52 次/秒、连续 6 天。
    """
    delivery = _signed_delivery()
    runtime, core, _ = _runtime(tmp_path, delivery=delivery)
    runtime.process_rule_packages_once()
    core.package_response = {
        "items": [],
        "controls": [
            {"package_id": delivery["package_id"], "status": "revoked"}
        ],
    }

    # 第一次真的删掉了本地包 -> 是进展
    assert runtime.process_rule_packages_once() == 1
    # 之后同一条 control 再来多少次都不该算进展
    for _ in range(3):
        assert runtime.process_rule_packages_once() == 0
    # 删除本身仍然每轮执行，包不会复活
    assert runtime.rule_store.summary()["active_package_count"] == 0


def test_tampered_package_fails_closed(tmp_path: Path):
    delivery = _signed_delivery()
    delivery["payload"]["rule"]["condition"]["right"] = False
    runtime, core, _ = _runtime(tmp_path, delivery=delivery)

    assert runtime.process_rule_packages_once() == 1
    assert core.package_receipts[0]["status"] == "failed"
    assert runtime.rule_store.summary()["active_package_count"] == 0


def _signed_delivery() -> dict:
    now = datetime.now(timezone.utc)
    payload = {
        "package_version": "1.0",
        "compiler_version": "zed-rule-compiler-v1",
        "contract_version": "1.0",
        "profile_key": "home_assistant",
        "profile_version": "1.0",
        "runtime_version": "zediot-ha-rule-runtime-v1",
        "tenant_id": "tenant_ha_rule",
        "rule_id": "rule_ha_local",
        "version_id": "rver_ha_local",
        "version_no": 1,
        "deployment_id": "rdep_ha_local",
        "integration_instance_id": INSTANCE,
        "scope_fingerprint": "f" * 64,
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "valid_until": (now + timedelta(hours=1)).isoformat(),
        "previous_package_id": None,
        "rule": {
            "trigger": {"type": "latest_state.changed"},
            "condition": {
                "op": "eq",
                "left": {"var": "event.value"},
                "right": True,
            },
            "actions": [
                {
                    "type": "device_command",
                    "payload": {
                        "canonical_capability": "light.power",
                        "template_code": "set_light_power",
                        "value": True,
                    },
                }
            ],
        },
        "targeting_policy": {
            "match_scope": {
                "scope_type": "device",
                "scope_value": "dev_ha_light",
            }
        },
        "runtime_plan": {
            "runtime": "home_assistant",
            "runtime_version": "zediot-ha-rule-runtime-v1",
            "event_binding": {
                "provider_event_type": "state_changed",
                "provider_entity_id": "light.local_rule",
                "canonical_event_type": "latest_state.changed",
                "target_id": "dev_ha_light",
            },
            "actions": [
                {
                    "action_index": 0,
                    "action_type": "device_command",
                    "target_id": "dev_ha_light",
                    "provider_entity_id": "light.local_rule",
                    "provider_domain": "light",
                    "provider_service": "turn_on",
                    "canonical_capability": "light.power",
                    "template_code": "set_light_power",
                    "value": True,
                    "mapping_id": "imap_ha_light",
                    "mapping_version": "1",
                    "command_safety_evidence": {
                        "reviewed": True,
                        "risk_class": "non_destructive",
                    },
                }
            ],
        },
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    payload_hash = hashlib.sha256(canonical).hexdigest()
    return {
        "package_id": f"rpkg_{payload_hash[:24]}",
        "payload_hash": payload_hash,
        "signature": base64.urlsafe_b64encode(
            private_key.sign(canonical)
        ).decode("ascii").rstrip("="),
        "signature_key_id": "rule-package-signing-v1",
        "signing_public_key_pem": public_key,
        "deployment_id": payload["deployment_id"],
        "rule_id": payload["rule_id"],
        "version_id": payload["version_id"],
        "version_no": payload["version_no"],
        "integration_instance_id": INSTANCE,
        "payload": payload,
    }


def _state_event(*, context_id: str, state: str) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "time_fired": now,
        "context": {"id": context_id},
        "data": {
            "new_state": {
                "entity_id": "light.local_rule",
                "state": state,
                "last_updated": now,
            }
        },
    }
