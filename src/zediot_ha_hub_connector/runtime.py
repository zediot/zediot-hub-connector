from __future__ import annotations

import hashlib
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

from zediot_ha_hub_connector.config import ConnectorConfig
from zediot_ha_hub_connector.event_identity import build_source_event_id
from zediot_ha_hub_connector.command_executor import HubCommandExecutor
from zediot_ha_hub_connector.command_store import CommandReceiptStore
from zediot_ha_hub_connector.core_client import (
    HubActivationError,
    HubSession,
    HubLeaseConflictError,
    HubSessionInvalidError,
    IoTCoreHubClient,
)
from zediot_ha_hub_connector.ha_client import HomeAssistantClient
from zediot_ha_hub_connector.identity import (
    BINDING_AWAITING_ACTIVATION,
    BINDING_AWAITING_APPROVAL,
    BINDING_AWAITING_BINDING,
    BINDING_READY,
    BOOTSTRAP_PROVISIONED,
    ConnectorIdentity,
    ConnectorIdentityStore,
)
from zediot_ha_hub_connector.queue import BoundedUplinkQueue, QueueItem
from zediot_ha_hub_connector.reliability import (
    CircuitBreaker,
    CircuitPermit,
    retry_bounded,
)
from zediot_ha_hub_connector.rule_package import (
    verify_rule_package_delivery,
)
from zediot_ha_hub_connector.rule_runtime import (
    HomeAssistantLocalRuleRuntime,
)
from zediot_ha_hub_connector.rule_store import LocalRuleStore
from zediot_ha_hub_connector.snapshot import build_snapshot_uplink

# 规则轮询在"有进展"时的最小间隔。见 _rule_loop 的说明。
_RULE_DRAIN_MIN_INTERVAL_SECONDS = 0.2

_GRANT_INVENTORY_READ = "inventory_read"
_GRANT_STATE_UPLINK = "state_uplink"
_GRANT_COMMAND_DOWNLINK = "command_downlink"
_GRANT_LOCAL_RULE_RUNTIME = "local_rule_runtime"
_EVENT_UPLINK_GRANTS = frozenset({_GRANT_STATE_UPLINK})
_SUBSCRIPTION_GRANTS = _EVENT_UPLINK_GRANTS | {
    _GRANT_LOCAL_RULE_RUNTIME,
}

logger = logging.getLogger(__name__)


class HubConnectorRuntime:
    def __init__(
        self,
        config: ConnectorConfig,
        *,
        core: IoTCoreHubClient | None = None,
        home_assistant: HomeAssistantClient | None = None,
        sleep=time.sleep,
    ) -> None:
        self.config = config
        self.core = core or IoTCoreHubClient(base_url=config.core_url)
        self.home_assistant = home_assistant or HomeAssistantClient(
            access_token=config.ha_access_token,
            websocket_url=config.ha_websocket_url,
        )
        self.identity_store = ConnectorIdentityStore(config.state_dir)
        self.queue = BoundedUplinkQueue(
            config.state_dir / "uplink_queue.sqlite3",
            max_bytes=config.queue_max_bytes,
            max_age_seconds=config.queue_max_age_seconds,
        )
        self.command_receipts = CommandReceiptStore(
            config.state_dir / "command_receipts.sqlite3"
        )
        self.command_executor = HubCommandExecutor(
            home_assistant=self.home_assistant,
            receipts=self.command_receipts,
            sleep=sleep,
        )
        self.rule_store = LocalRuleStore(
            config.state_dir / "local_rule_runtime.sqlite3",
            evidence_max_rows=config.rule_evidence_max_rows,
            evidence_retention_seconds=(
                config.rule_evidence_retention_seconds
            ),
        )
        self.breaker = CircuitBreaker(
            failure_threshold=config.circuit_failure_threshold,
            recovery_seconds=config.circuit_recovery_seconds,
        )
        self.sleep = sleep
        self.stop_event = threading.Event()
        self._shutdown_reason_code = "connector_shutdown"
        self._session_lock = threading.Lock()
        self.identity: ConnectorIdentity | None = None
        self.session: HubSession | None = None
        self.local_rule_runtime: HomeAssistantLocalRuleRuntime | None = None
        self.cursor: dict[str, Any] = {"uplink_sequence": 0}
        # 本地状态可见性（43 附录 A.8）：装机与售后靠它判断，而不是翻日志
        self.binding_state: str = BINDING_AWAITING_ACTIVATION
        self.binding_failure: str | None = None

    def prepare(self) -> None:
        """引导。三条路径并存（43 附录 A.9，不可退让）：

        1. 已有 connector_id 的存量实例 —— 原样走 PoP 认证与会话，
           **不因升级要求重新激活或配对**；
        2. 全新安装 + 三元组 —— 走激活路径（A.4），可能需要等待绑定；
        3. 全新安装 + 配对码 —— 走原 exchange 路径。

        判定顺序刻意把存量放第一位：任何"先试新路径"的写法都会在升级后的
        第一次启动上把现网设备打死。
        """
        identity = self.identity_store.load_or_create()

        if identity.connector_id:
            self._prepare_existing(identity)
            return
        if self._has_provisioning_triple():
            self._prepare_provisioned(identity)
            return
        if self.config.pairing_code:
            self._prepare_paired(identity)
            return
        # 沿用原错误码：没有三元组时缺的确实就是配对码，而运维手册与告警
        # 规则都在匹配 HUB_PAIRING_REQUIRED，无谓改名只会制造一次静默失联
        raise RuntimeError("HUB_PAIRING_REQUIRED")

    def _has_provisioning_triple(self) -> bool:
        return all(
            (
                self.config.tenant_id,
                self.config.product_key,
                self.config.device_name,
                self.config.device_secret,
            )
        )

    def _prepare_existing(self, identity: ConnectorIdentity) -> None:
        """已有身份：直接进运行态。

        预发放路径没有 enrollment，所以**不能**再无条件查 enrollment_status
        ——那是原实现里唯一硬绑配对模型的地方。
        """
        if identity.effective_bootstrap_mode == BOOTSTRAP_PROVISIONED:
            self.identity = identity
            self.binding_state = identity.binding_state or BINDING_READY
            self._go_live(identity)
            return
        if not identity.enrollment_id or not identity.exchange_receipt:
            raise RuntimeError("HUB_ENROLLMENT_STATE_INVALID")
        status = self.core.enrollment_status(
            enrollment_id=identity.enrollment_id,
            exchange_receipt=identity.exchange_receipt,
        )
        if status["status"] != "approved":
            raise RuntimeError(f"HUB_APPROVAL_{status['status'].upper()}")
        self.identity = identity
        self.binding_state = BINDING_READY
        self._go_live(identity)

    def _prepare_paired(self, identity: ConnectorIdentity) -> None:
        exchanged = self.core.exchange(
            pairing_code=self.config.pairing_code,
            installation_id=self.config.installation_id,
            display_name=self.config.display_name,
            public_key_pem=self.identity_store.public_key_pem(identity),
            runtime_kind=self.config.runtime_kind,
            signature_algorithm=identity.signature_algorithm,
        )
        identity = self.identity_store.save_exchange(
            enrollment_id=exchanged["enrollment_id"],
            connector_id=exchanged["connector_id"],
            credential_id=exchanged["credential_id"],
            exchange_receipt=exchanged["exchange_receipt"],
        )
        self._prepare_existing(identity)

    def _prepare_provisioned(self, identity: ConnectorIdentity) -> None:
        """预发放路径：激活，然后**优雅等待绑定**（43 附录 A.5）。

        这是本次改造最重要的一条。设备出厂后可能长期停在"已激活未绑定"
        ——货已发出、终端用户还没注册并输入绑定码。原实现在这种情况下
        raise，进程退出、容器重启、再退出，日志被噪音淹没，装机人员也
        分不出"设备坏了"和"等我操作"。

        因此这里不抛异常、不退出，按退避周期轮询，直到绑定完成才进运行态。
        真正的终态错误（密钥无效、身份或批次被撤销）仍然明确失败并停止重试。
        """
        self.binding_state = BINDING_AWAITING_ACTIVATION
        delay = self.config.binding_poll_initial_seconds
        while not self.stop_event.is_set():
            try:
                result = self.core.activate(
                    tenant_id=self.config.tenant_id,
                    product_key=self.config.product_key,
                    device_name=self.config.device_name,
                    device_secret=self.config.device_secret,
                    public_key_pem=self.identity_store.public_key_pem(identity),
                    installation_id=self.config.installation_id,
                    signature_algorithm=identity.signature_algorithm,
                    health=self._self_health(),
                )
            except HubActivationError as error:
                if error.terminal:
                    # 停下来并把原因留在状态里：重试解决不了"密钥不对"或
                    # "这批已被撤销"，只会刷日志并撞上限流
                    self.binding_failure = error.detail
                    raise RuntimeError(f"HUB_ACTIVATION_REJECTED: {error.detail}")
                self.binding_failure = error.detail
                delay = self._wait_before_retry(delay)
                continue
            except Exception as error:  # noqa: BLE001
                # 网络抖动、Core 未就绪：等待是对的
                self.binding_failure = str(error)
                delay = self._wait_before_retry(delay)
                continue

            self.binding_failure = None
            identity = self.identity_store.save_activation(
                tenant_id=self.config.tenant_id,
                product_key=self.config.product_key,
                device_name=self.config.device_name,
                identity_id=result.get("identity_id"),
                binding_state=str(result.get("binding_state") or BINDING_AWAITING_BINDING),
                bound_space_node_id=result.get("bound_space_node_id"),
                connector_id=result.get("connector_id"),
            )
            self.binding_state = identity.binding_state or BINDING_AWAITING_BINDING

            if self.binding_state == BINDING_READY and result.get("connector_id"):
                credential_id = self._resolve_credential_id(result)
                identity = self.identity_store.save_binding_state(
                    binding_state=BINDING_READY,
                    connector_id=result.get("connector_id"),
                    credential_id=credential_id,
                )
                self.identity = identity
                self._go_live(identity)
                return

            # awaiting_binding / awaiting_approval：数据面保持关闭（A.6），
            # 只继续做存活信标；期间检查有没有人投进来绑定码
            self._consume_claim_code_if_present()
            delay = self._wait_before_retry(delay)

    def _consume_claim_code_if_present(self) -> None:
        """运行时绑定码通路（43 附录 A.7 / R6-S5-EDGE-06）。

        **当前只做到"接住并给出正确指引"，没有提交。** 原因是 Core 侧现在
        唯一的 claim 入口 `POST /api/app/v1/gateway-claims` 要求**用户**
        身份令牌，而设备没有用户身份；`/api/hub/v1/` 下没有设备可用的
        claim 端点。附录 A.7 描述的"设备提交绑定码"属于模式 C（动态注册），
        对应 42 第 8 节的阶段 2c，本 Sprint 未实现。

        在已交付的模式 A（一机一密预发放）里，绑定码是终端用户在 IoT Core
        App 里输入的，设备只需轮询 activate 等 binding_state 翻转——这条
        路径已经通了。

        那为什么还要接住这个文件？因为装机人员**会**把码写到设备上（说明书
        上就写着"输入绑定码"），然后对着一台毫无反应的网关发呆。接住它并把
        指引写进本地状态，比让文件躺在那里没人理要好得多。

        读到就立刻删除：绑定码是一次性凭证，留在磁盘上等于给拿到文件系统
        访问权的人一个能把设备抢走的东西。
        """
        path = self.config.claim_code_file
        if path is None or not path.is_file():
            return
        try:
            claim_code = path.read_text(encoding="utf-8").strip()
        except OSError:
            return
        finally:
            try:
                path.unlink()
            except OSError:
                pass
        if not claim_code:
            return
        self.binding_failure = (
            "claim code received locally but this build binds through the "
            "IoT Core app: ask the end user to enter it there. Device-side "
            "claim submission needs a hub-facing endpoint (provisioning "
            "mode C, not in this release)."
        )

    def _resolve_credential_id(self, result: dict[str, Any]) -> str | None:
        """绑定完成时 Core 会建 connector + credential。

        激活响应目前只回 connector_id；credential_id 由 Core 侧在同一次
        绑定事务里生成，边缘需要它来做 PoP 挑战。若响应里没有，
        留给下一轮轮询——绝不猜一个值，猜错会让认证在运行期才失败。
        """
        return result.get("credential_id")

    def _wait_before_retry(self, delay: float) -> float:
        """指数退避，带上限。

        固定短间隔在"用户三天后才输绑定码"的场景下会打出上万次无谓请求，
        还会撞上 GW-12 的限流；固定长间隔又让刚输完码的用户干等。
        """
        self.stop_event.wait(delay)
        return min(delay * 2, self.config.binding_poll_max_seconds)

    def _self_health(self) -> dict[str, Any]:
        """待绑定期允许上报的自身健康（A.5 第 3 点）。

        只报边缘自己的运行信息，**不含任何 HA 侧数据**——那属于数据面，
        绑定完成前不得外传。
        """
        return {
            "runtime_kind": self.config.runtime_kind,
            "installation_id": self.config.installation_id,
            "contract_version": "1.0",
        }

    def ensure_data_plane_open(self) -> None:
        """数据面自我约束（43 附录 A.6 / R6-S5-EDGE-05）。

        Core 侧已经有服务端门禁（GW-09），边缘再挡一层不是重复劳动：未绑定
        时发出去的请求必然被拒，只会在两侧都刷错误日志、消耗限流额度，
        并让真正的故障淹没在噪音里。

        门放在**启动数据面线程之前**，而不是每个上行方法里——那些方法都先
        要求 session，而未绑定时根本没有 session，写在那里是永不触发的死代码。
        真正要防的是"线程起来了、开始轮询命令与规则包"。

        允许的只有身份认证与自身健康上报——两者都不经过这个门。
        """
        if self.binding_state != BINDING_READY:
            raise RuntimeError(f"HUB_DATA_PLANE_CLOSED: {self.binding_state}")

    def local_status(self) -> dict[str, Any]:
        """本地状态（43 附录 A.8 / R6-S5-EDGE-07）。

        装机与售后要能直接看出当前处于哪一步，而不是翻日志。
        刻意**不含任何凭据**：这份状态是给现场人员看的。
        """
        return {
            "binding_state": self.binding_state,
            "failure_reason": self.binding_failure,
            "data_plane_open": self.binding_state == BINDING_READY,
            "bootstrap_mode": (
                self.identity.effective_bootstrap_mode if self.identity else None
            ),
            "device_name": self.config.device_name,
            "installation_id": self.config.installation_id,
            "bound_space_node_id": (
                self.identity.bound_space_node_id if self.identity else None
            ),
            "session_id": self.session.session_id if self.session else None,
            "effective_grants": (
                sorted(self.session.effective_grants) if self.session else []
            ),
        }

    def _go_live(self, identity: ConnectorIdentity) -> None:
        self.binding_state = BINDING_READY
        self.core.authenticate(identity)
        self._establish_session(identity)

    def _establish_session(self, identity: ConnectorIdentity) -> None:
        # 会话建立成功即证明 Core 放行了数据面（GW-09 的服务端门禁在此之前）。
        # 把 READY 设在这里而不是 _go_live，是因为会话恢复路径也走这里——
        # 设在别处会让一次重连之后自己把自己挡在门外。
        self.binding_state = BINDING_READY
        while True:
            try:
                self.session = self.core.connect_session(
                    identity=identity,
                    resume_cursor=self.cursor,
                )
                break
            except HubLeaseConflictError as conflict:
                # 上一个进程的会话还没到期。原地等到期再接管，而不是让异常冒出
                # run_forever：那会退出进程、靠容器重启再撞一次，每次冷启动都在
                # Core 审计里多一条 connector_clone_suspected。
                wait_seconds = _lease_conflict_wait_seconds(
                    conflict.retry_after_seconds
                )
                logger.info(
                    "Hub session lease still held by the previous session; "
                    "reconnecting in %.0fs (lease_expires_at=%s)",
                    wait_seconds,
                    conflict.lease_expires_at.isoformat()
                    if conflict.lease_expires_at
                    else "unknown",
                )
                if self.stop_event.wait(wait_seconds):
                    return  # 等待期间被要求停止：不建会话，run_forever 会自己收尾
        self.local_rule_runtime = None
        if self.session.allows(_GRANT_LOCAL_RULE_RUNTIME):
            self.local_rule_runtime = HomeAssistantLocalRuleRuntime(
                store=self.rule_store,
                home_assistant=self.home_assistant,
                integration_instance_id=self.session.integration_instance_id,
                trusted_key_ids=self.config.trusted_rule_package_key_ids,
            )
        server_cursor = dict(self.session.resume_cursor or {})
        acknowledged = int(server_cursor.get("uplink_sequence") or 0)
        self.cursor = server_cursor or {"uplink_sequence": acknowledged}
        self.queue.synchronize_with_server_cursor(acknowledged)

    def _recover_session(self, *, stale_session_id: str) -> None:
        with self._session_lock:
            if self.session and self.session.session_id != stale_session_id:
                return
            if self.identity is None:
                raise RuntimeError("HUB_IDENTITY_NOT_READY")
            self.core.authenticate(self.identity)
            self._establish_session(self.identity)

    def _recover_after_session_error(
        self,
        error: HubSessionInvalidError,
    ) -> None:
        permit = self.breaker.observe()
        try:
            self._recover_session(stale_session_id=error.session_id)
            self.breaker.success(permit)
        except Exception:
            self.breaker.failure()
            self.sleep(1)

    def enqueue_snapshot(self, *, run_type: str) -> QueueItem:
        snapshot = self.home_assistant.collect_snapshot()
        payload = build_snapshot_uplink(snapshot, run_type=run_type)
        if self.breaker.current_state() != "closed":
            payload["delivery_mode"] = "replay"
        return self.queue.enqueue(
            kind="snapshot",
            payload=payload,
        )

    def enqueue_reconciliation_if_needed(self, *, force: bool = False) -> bool:
        if self.session and not self.session.allows(_GRANT_INVENTORY_READ):
            return False
        required = self.queue.needs_reconciliation()
        if not force and not required:
            return False
        item = self.enqueue_snapshot(run_type="reconciliation")
        if not item.accepted:
            return False
        if required:
            self.queue.mark_reconciliation_queued()
        return True

    def enqueue_event(self, event: dict[str, Any]) -> QueueItem | None:
        data = dict(event.get("data") or {})
        new_state = data.get("new_state")
        if not isinstance(new_state, dict):
            raise ValueError("HA_STATE_EVENT_MISSING_NEW_STATE")
        observed_at = str(
            event.get("time_fired")
            or new_state.get("last_updated")
            or datetime.now(timezone.utc).isoformat()
        )
        source_event_id = _source_event_id(event, new_state)
        if self.local_rule_runtime is not None:
            self.local_rule_runtime.process_event(
                event,
                connectivity_state=(
                    "connected"
                    if self.breaker.current_state() == "closed"
                    else "offline"
                ),
            )
        if self.session and not (
            self.session.effective_grants & _EVENT_UPLINK_GRANTS
        ):
            return None
        is_replay = self.breaker.current_state() != "closed"
        return self.queue.enqueue(
            kind="event",
            payload={
                "source_event_id": source_event_id,
                "event_type": "state_changed",
                "observed_at": observed_at,
                "delivery_mode": "replay" if is_replay else "realtime",
                "is_replay": is_replay,
                "payload": {"new_state": new_state},
            },
        )

    def flush_once(self) -> bool:
        permit = self.breaker.allow()
        if permit is None:
            return False
        try:
            if not self.identity or not self.session:
                raise RuntimeError("HUB_SESSION_NOT_READY")
            items = self.queue.peek_all(limit=self.config.event_batch_size)
        except Exception:
            self.breaker.failure()
            raise
        if not items:
            self._complete_half_open_probe(permit)
            return False
        first = items[0]
        if first.kind == "snapshot" and not self.session.allows(
            _GRANT_INVENTORY_READ
        ):
            self._complete_half_open_probe(permit)
            return False
        if first.kind == "event" and not (
            self.session.effective_grants & _EVENT_UPLINK_GRANTS
        ):
            self._complete_half_open_probe(permit)
            return False
        try:
            if first.kind == "snapshot":
                attempt = first.delivery_attempts
                queued_as_replay = first.payload.get("delivery_mode") == "replay"

                def upload_snapshot() -> dict[str, Any]:
                    nonlocal attempt
                    replay = queued_as_replay or attempt > 0
                    payload = {
                        **first.payload,
                        "sequence": first.sequence,
                        "delivery_mode": "replay" if replay else "realtime",
                    }
                    self.queue.mark_delivery_attempted(sequences=[first.sequence])
                    attempt += 1
                    try:
                        return self.core.upload_snapshot(
                            identity=self.identity,
                            session=self.session,
                            payload=payload,
                        )
                    except Exception:
                        self.queue.mark_pending_delivery_uncertain()
                        raise

                receipt = retry_bounded(
                    upload_snapshot,
                    max_attempts=self.config.retry_max_attempts,
                    base_seconds=self.config.retry_base_seconds,
                    sleep=self.sleep,
                    retryable=_retryable_core_error,
                )
                acknowledged = int(receipt["cursor_after"])
            else:
                event_items = _contiguous_events(items)
                attempt = max(item.delivery_attempts for item in event_items)
                queued_as_replay = any(
                    item.payload.get("delivery_mode") == "replay"
                    or item.payload.get("is_replay") is True
                    for item in event_items
                )

                def upload_events() -> dict[str, Any]:
                    nonlocal attempt
                    replay = queued_as_replay or attempt > 0
                    events = [
                        {
                            **item.payload,
                            "sequence": item.sequence,
                            "delivery_mode": "replay" if replay else "realtime",
                            "is_replay": replay,
                        }
                        for item in event_items
                    ]
                    payload = {
                        "sequence_start": event_items[0].sequence,
                        "sequence_end": event_items[-1].sequence,
                        "source_version": f"ha:event:{event_items[-1].sequence}",
                        "observed_at": events[-1]["observed_at"],
                        "events": events,
                    }
                    self.queue.mark_delivery_attempted(
                        sequences=[item.sequence for item in event_items]
                    )
                    attempt += 1
                    try:
                        return self.core.upload_events(
                            identity=self.identity,
                            session=self.session,
                            payload=payload,
                        )
                    except Exception:
                        self.queue.mark_pending_delivery_uncertain()
                        raise

                receipt = retry_bounded(
                    upload_events,
                    max_attempts=self.config.retry_max_attempts,
                    base_seconds=self.config.retry_base_seconds,
                    sleep=self.sleep,
                    retryable=_retryable_core_error,
                )
                acknowledged = int(receipt["cursor_after"])
            self.queue.acknowledge_through(acknowledged)
            self.cursor["uplink_sequence"] = acknowledged
            self.breaker.success(permit)
            return True
        except Exception:
            self.breaker.failure()
            raise

    def _complete_half_open_probe(self, permit: CircuitPermit) -> None:
        if not permit.half_open_probe:
            return
        try:
            # The upload loop owns half-open probes. When there is no eligible
            # payload, heartbeat is the bounded authenticated Core check.
            self.heartbeat()
            self.breaker.success(permit)
        except Exception:
            self.breaker.failure()
            raise

    def heartbeat(self) -> dict[str, Any]:
        if not self.identity or not self.session:
            raise RuntimeError("HUB_SESSION_NOT_READY")
        return self.core.heartbeat(
            identity=self.identity,
            session=self.session,
            cursor=self.cursor,
            queue_summary=self.queue.summary(),
            circuit_state=self.breaker.current_state(),
        )

    def process_commands_once(self) -> int:
        if not self.identity or not self.session:
            raise RuntimeError("HUB_SESSION_NOT_READY")
        if not self.session.allows(_GRANT_COMMAND_DOWNLINK):
            return 0
        deliveries = retry_bounded(
            lambda: self.core.claim_commands(
                identity=self.identity,
                session=self.session,
                limit=10,
            ),
            max_attempts=self.config.retry_max_attempts,
            base_seconds=self.config.retry_base_seconds,
            sleep=self.sleep,
            retryable=_retryable_core_error,
        )
        processed = 0
        for delivery in deliveries:
            result = self.command_executor.execute(delivery)
            retry_bounded(
                lambda result=result, delivery=delivery: (
                    self.core.acknowledge_command(
                        identity=self.identity,
                        session=self.session,
                        delivery_id=delivery["delivery_id"],
                        status=result["status"],
                        reason_code=result.get("reason_code"),
                        evidence=dict(result.get("evidence") or {}),
                    )
                ),
                max_attempts=self.config.retry_max_attempts,
                base_seconds=self.config.retry_base_seconds,
                sleep=self.sleep,
                retryable=_retryable_core_error,
            )
            processed += 1
        return processed

    def process_rule_packages_once(self) -> int:
        if not self.identity or not self.session:
            raise RuntimeError("HUB_SESSION_NOT_READY")
        if not self.session.allows(_GRANT_LOCAL_RULE_RUNTIME):
            return 0
        delivery = retry_bounded(
            lambda: self.core.claim_rule_packages(
                identity=self.identity,
                session=self.session,
                limit=10,
            ),
            max_attempts=self.config.retry_max_attempts,
            base_seconds=self.config.retry_base_seconds,
            sleep=self.sleep,
            retryable=_retryable_core_error,
        )
        processed = 0
        for control in delivery.get("controls") or []:
            # 只把**真的改了本地状态**的 control 记成进展。
            #
            # Core 的 control 目录是一份"当前被撤销/过期的包"的**全量列表**，
            # 不是一个会被消费掉的队列——同一条会在每次 claim 里原样返回。
            # 之前无条件 processed += 1，于是 _rule_loop 认为"有活干"而跳过
            # sleep，立刻再 claim，再拿到同一条……NAS 上实测 52 次/秒，从
            # 包被撤销那天起连续跑了 6 天。
            #
            # apply_control 一直都返回"是否真的删掉了行"，这里以前把它丢了。
            # 删除本身仍然每轮执行（幂等），所以包若重新出现照样会被清掉。
            if self.rule_store.apply_control(dict(control)):
                processed += 1
        for item in delivery.get("items") or []:
            package_id = str(item.get("package_id") or "")
            package_hash = str(item.get("payload_hash") or "")
            try:
                verified = verify_rule_package_delivery(
                    dict(item),
                    integration_instance_id=(
                        self.session.integration_instance_id
                    ),
                    trusted_key_ids=(
                        self.config.trusted_rule_package_key_ids
                    ),
                )
                self.rule_store.apply_package(verified)
                status = "applied"
                reason_code = None
                evidence = {
                    "runtime_version": (
                        verified.payload["runtime_version"]
                    ),
                    "applied_checksum": verified.package_hash,
                    "local_rule_count": self.rule_store.summary()[
                        "active_package_count"
                    ],
                }
            except Exception as exc:
                status = "failed"
                reason_code = str(exc)[:120]
                evidence = {"failure_stage": "package_validation"}
            receipt_id = _stable_runtime_id(
                "rpreceipt",
                f"{package_id}:{package_hash}:{status}",
            )
            retry_bounded(
                lambda: self.core.acknowledge_rule_package(
                    identity=self.identity,
                    session=self.session,
                    package_id=package_id,
                    receipt_id=receipt_id,
                    package_hash=package_hash,
                    status=status,
                    reason_code=reason_code,
                    evidence=evidence,
                ),
                max_attempts=self.config.retry_max_attempts,
                base_seconds=self.config.retry_base_seconds,
                sleep=self.sleep,
                retryable=_retryable_core_error,
            )
            processed += 1
        return processed

    def flush_rule_evidence_once(self) -> int:
        if not self.identity or not self.session:
            raise RuntimeError("HUB_SESSION_NOT_READY")
        if not self.session.allows(_GRANT_LOCAL_RULE_RUNTIME):
            return 0
        items = self.rule_store.pending_evidence(limit=100)
        if not items:
            return 0
        response = retry_bounded(
            lambda: self.core.upload_rule_evidence(
                identity=self.identity,
                session=self.session,
                items=[
                    {
                        key: value
                        for key, value in item.items()
                        if key != "connectivity_state"
                    }
                    for item in items
                ],
            ),
            max_attempts=self.config.retry_max_attempts,
            base_seconds=self.config.retry_base_seconds,
            sleep=self.sleep,
            retryable=_retryable_core_error,
        )
        accepted_ids = {
            str(item["execution_id"])
            for item in response.get("items") or []
            if item.get("ingest_status") in {"accepted", "duplicate"}
        }
        self.rule_store.mark_uploaded(execution_ids=sorted(accepted_ids))
        return len(accepted_ids)

    def run_forever(self) -> None:
        threads: list[threading.Thread] = []
        try:
            self.prepare()
            # prepare() 在未绑定时会一直等（A.5），走到这里理应已经绑定。
            # 仍然显式确认一次：万一将来有人给 prepare 加了提前返回的分支，
            # 这里会立刻炸而不是让数据面线程在未绑定状态下跑起来。
            self.ensure_data_plane_open()
            if self.stop_event.is_set():
                return
            if self.session and self.session.allows(_GRANT_INVENTORY_READ):
                self.enqueue_snapshot(run_type="bootstrap")
            threads = self._runtime_threads()
            for thread in threads:
                thread.start()
            while not self.stop_event.wait(0.5):
                pass
        finally:
            self.stop_event.set()
            self._disconnect_session()
            for thread in threads:
                thread.join(timeout=1)

    def request_stop(self, *, reason_code: str = "connector_shutdown") -> None:
        self._shutdown_reason_code = reason_code[:120]
        self.stop_event.set()

    def _runtime_threads(self) -> list[threading.Thread]:
        if self.session is None:
            raise RuntimeError("HUB_SESSION_NOT_READY")
        targets: list[tuple[str, Any]] = []
        if self.session.effective_grants & _SUBSCRIPTION_GRANTS:
            targets.append(("hub-subscription", self._subscription_loop))
        if self.session.effective_grants & (
            _EVENT_UPLINK_GRANTS | {_GRANT_INVENTORY_READ}
        ):
            targets.append(("hub-upload", self._upload_loop))
        if self.session.allows(_GRANT_COMMAND_DOWNLINK):
            targets.append(("hub-command", self._command_loop))
        if self.session.allows(_GRANT_LOCAL_RULE_RUNTIME):
            targets.append(("hub-rule", self._rule_loop))
        if self.session.allows(_GRANT_INVENTORY_READ):
            targets.append(("hub-inventory", self._inventory_loop))
        targets.append(("hub-maintenance", self._maintenance_loop))
        return [
            threading.Thread(name=name, target=target, daemon=True)
            for name, target in targets
        ]

    def _disconnect_session(self) -> None:
        with self._session_lock:
            identity = self.identity
            session = self.session
            self.session = None
        if identity is None or session is None:
            return
        try:
            self.core.disconnect_session(
                identity=identity,
                session=session,
                reason_code=self._shutdown_reason_code,
            )
        except Exception as error:  # noqa: BLE001
            self.breaker.failure()
            logger.warning(
                "Hub session disconnect failed (%s)",
                type(error).__name__,
            )

    def _subscription_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                for event in self.home_assistant.subscribe_state_events():
                    self.enqueue_event(event)
                    if self.stop_event.is_set():
                        return
            except Exception:
                self.sleep(5)

    def _upload_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                if not self.flush_once():
                    self.sleep(0.5)
            except HubSessionInvalidError as exc:
                self._recover_after_session_error(exc)
            except Exception as exc:
                try:
                    queue_summary = self.queue.summary()
                except Exception:
                    queue_summary = {
                        "queue_depth": "unavailable",
                        "queue_bytes": "unavailable",
                        "dropped_count": "unavailable",
                    }
                logger.warning(
                    "Hub uplink flush failed exception_type=%s "
                    "circuit_state=%s queue_depth=%s queue_bytes=%s "
                    "dropped_count=%s",
                    type(exc).__name__,
                    self.breaker.current_state(),
                    queue_summary["queue_depth"],
                    queue_summary["queue_bytes"],
                    queue_summary["dropped_count"],
                )
                self.sleep(1)

    def _command_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                if not self.process_commands_once():
                    self.sleep(1)
            except HubSessionInvalidError as exc:
                self._recover_after_session_error(exc)
            except Exception:
                self.sleep(1)

    def _rule_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                processed = self.process_rule_packages_once()
                uploaded = self.flush_rule_evidence_once()
                if not processed and not uploaded:
                    self.sleep(self.config.rule_poll_interval_seconds)
                else:
                    # 有活干时不等满一个轮询周期，但也不能一点不等。
                    # "有进展"是个由被调用方推断出来的信号，判断错了就退化成
                    # 忙等——这正是 control 目录踩过的坑。这里给一个下限，
                    # 让同类错误的代价从"每秒几十次"降到"每秒五次"。
                    # 排空 10 个包一批的正常场景，代价是每批多 0.2 秒。
                    self.sleep(_RULE_DRAIN_MIN_INTERVAL_SECONDS)
            except HubSessionInvalidError as exc:
                self._recover_after_session_error(exc)
            except Exception:
                self.sleep(self.config.rule_poll_interval_seconds)

    def _maintenance_loop(self) -> None:
        """只做心跳，不做别的。

        这里原先还顺带触发对账（采 HA 全量快照）。采集是同步的，慢起来能占住线程
        好几分钟，而租约只有 90 秒——心跳一停，会话必然过期。现网实测：心跳严格
        每 30 秒、一次不落，然后突然静默约 3 分钟，随后换新会话，如此每 13-16 分钟
        循环一次（6 小时 23 个会话，同期正常网关只有 2 个）。会话被自己的对账拖死，
        快照因此永远传不上去，reconciliation_required 也就永远清不掉。

        心跳是判定"这个客户端还活着"的唯一依据，它的线程不能承担任何可能变慢的
        工作。对账移到 _inventory_loop。
        """
        while not self.stop_event.wait(self.config.heartbeat_interval_seconds):
            try:
                self.heartbeat()
            except HubSessionInvalidError as exc:
                self._recover_after_session_error(exc)
            except Exception:
                self.breaker.failure()

    def _inventory_loop(self) -> None:
        """对账（采集并上传 HA 全量快照）。与心跳分开，慢也不会拖垮会话。"""
        last_reconciliation = time.monotonic()
        while not self.stop_event.wait(self.config.heartbeat_interval_seconds):
            try:
                if not (self.session and self.session.allows(_GRANT_INVENTORY_READ)):
                    continue
                due = (
                    time.monotonic() - last_reconciliation
                    >= self.config.reconciliation_interval_seconds
                )
                if not (self.queue.needs_reconciliation() or due):
                    continue
                if self.enqueue_reconciliation_if_needed(force=due):
                    last_reconciliation = time.monotonic()
            except HubSessionInvalidError as exc:
                self._recover_after_session_error(exc)
            except Exception:
                # 采集失败（含 HA_SNAPSHOT_DEADLINE_EXCEEDED）不影响心跳，
                # 下一轮按 needs_reconciliation 重来。
                self.breaker.failure()


def _contiguous_events(items: list[QueueItem]) -> list[QueueItem]:
    """从队首切出一段：连续 sequence、且 source_event_id 批内唯一。

    序号不连续要截断（Core 要求批内 sequence 连续）。批内 source_event_id 重复
    同样要截断——这是第二道保险：即便 id 生成再出问题（见 event_identity），也不会
    把一个必被 Core 整批拒绝的批发出去，导致客户端反复重投同一坏批、永远推不进
    （现网实测一条批次被拒 5946 次）。

    截断而非丢弃：重复的那条留在队列里，下一轮成为批首单独发出，不与自己冲突，
    因此不丢事件。每批至少含队首一条，不会截出空批。
    """
    result: list[QueueItem] = []
    expected = items[0].sequence
    seen_source_ids: set[str] = set()
    for item in items:
        if item.kind != "event" or item.sequence != expected:
            break
        source_id = item.payload.get("source_event_id")
        if source_id in seen_source_ids:
            break
        result.append(item)
        seen_source_ids.add(source_id)
        expected += 1
    return result


def _source_event_id(
    event: dict[str, Any],
    new_state: dict[str, Any],
) -> str:
    # 单一真源见 event_identity.build_source_event_id；这里保留薄封装，仅为不改动
    # 大量既有调用点。
    return build_source_event_id(event, new_state)


def _stable_runtime_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}_{digest}"


# 旧版 Core 的 409 不带秒数时的等待。取租约的一个量级，而不是立刻重试：
# 短了只是多撞几次，长了最多晚一个周期接管。
_LEASE_CONFLICT_FALLBACK_SECONDS = 30.0
# Core 给的秒数也设上限：一个异常的大值不该让连接器静默挂上几个小时。
_LEASE_CONFLICT_MAX_WAIT_SECONDS = 600.0


def _lease_conflict_wait_seconds(retry_after_seconds: float | None) -> float:
    if retry_after_seconds is None:
        return _LEASE_CONFLICT_FALLBACK_SECONDS
    # 多等 1 秒：Core 判「已过期」用的是 lease_expires_at < now，卡在整秒边界上
    # 再撞一次正好还差几毫秒。
    return min(max(retry_after_seconds, 0.0) + 1.0, _LEASE_CONFLICT_MAX_WAIT_SECONDS)


def _retryable_core_error(error: Exception) -> bool:
    return not isinstance(error, HubSessionInvalidError)
