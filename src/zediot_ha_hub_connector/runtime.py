from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from typing import Any

from zediot_ha_hub_connector.config import ConnectorConfig
from zediot_ha_hub_connector.command_executor import HubCommandExecutor
from zediot_ha_hub_connector.command_store import CommandReceiptStore
from zediot_ha_hub_connector.core_client import HubSession, IoTCoreHubClient
from zediot_ha_hub_connector.ha_client import HomeAssistantSupervisorClient
from zediot_ha_hub_connector.identity import (
    ConnectorIdentity,
    ConnectorIdentityStore,
)
from zediot_ha_hub_connector.queue import BoundedUplinkQueue, QueueItem
from zediot_ha_hub_connector.reliability import CircuitBreaker, retry_bounded
from zediot_ha_hub_connector.snapshot import build_snapshot_uplink


class HubConnectorRuntime:
    def __init__(
        self,
        config: ConnectorConfig,
        *,
        core: IoTCoreHubClient | None = None,
        home_assistant: HomeAssistantSupervisorClient | None = None,
        sleep=time.sleep,
    ) -> None:
        self.config = config
        self.core = core or IoTCoreHubClient(base_url=config.core_url)
        self.home_assistant = home_assistant or HomeAssistantSupervisorClient(
            supervisor_token=config.supervisor_token
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
        )
        self.breaker = CircuitBreaker(
            failure_threshold=config.circuit_failure_threshold,
            recovery_seconds=config.circuit_recovery_seconds,
        )
        self.sleep = sleep
        self.stop_event = threading.Event()
        self.identity: ConnectorIdentity | None = None
        self.session: HubSession | None = None
        self.cursor: dict[str, Any] = {"uplink_sequence": 0}

    def prepare(self) -> None:
        identity = self.identity_store.load_or_create()
        if not identity.connector_id:
            if not self.config.pairing_code:
                raise RuntimeError("HUB_PAIRING_REQUIRED")
            exchanged = self.core.exchange(
                pairing_code=self.config.pairing_code,
                installation_id=self.config.installation_id,
                display_name=self.config.display_name,
                public_key_pem=self.identity_store.public_key_pem(identity),
            )
            identity = self.identity_store.save_exchange(
                enrollment_id=exchanged["enrollment_id"],
                connector_id=exchanged["connector_id"],
                credential_id=exchanged["credential_id"],
                exchange_receipt=exchanged["exchange_receipt"],
            )
        if not identity.enrollment_id or not identity.exchange_receipt:
            raise RuntimeError("HUB_ENROLLMENT_STATE_INVALID")
        status = self.core.enrollment_status(
            enrollment_id=identity.enrollment_id,
            exchange_receipt=identity.exchange_receipt,
        )
        if status["status"] != "approved":
            raise RuntimeError(f"HUB_APPROVAL_{status['status'].upper()}")
        self.core.authenticate(identity)
        self.identity = identity
        self.session = self.core.connect_session(
            identity=identity,
            resume_cursor=self.cursor,
        )
        server_cursor = dict(self.session.resume_cursor or {})
        acknowledged = int(server_cursor.get("uplink_sequence") or 0)
        self.cursor = server_cursor or {"uplink_sequence": acknowledged}
        self.queue.acknowledge_through(acknowledged)
        self.queue.ensure_next_sequence_at_least(acknowledged + 1)

    def enqueue_snapshot(self, *, run_type: str) -> QueueItem:
        snapshot = self.home_assistant.collect_snapshot()
        return self.queue.enqueue(
            kind="snapshot",
            payload=build_snapshot_uplink(snapshot, run_type=run_type),
        )

    def enqueue_event(self, event: dict[str, Any]) -> QueueItem:
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
        return self.queue.enqueue(
            kind="event",
            payload={
                "source_event_id": source_event_id,
                "event_type": "state_changed",
                "observed_at": observed_at,
                "delivery_mode": "realtime",
                "is_replay": False,
                "payload": {"new_state": new_state},
            },
        )

    def flush_once(self) -> bool:
        if not self.breaker.allow():
            return False
        if not self.identity or not self.session:
            raise RuntimeError("HUB_SESSION_NOT_READY")
        items = self.queue.peek_all(limit=500)
        if not items:
            return False
        first = items[0]
        try:
            if first.kind == "snapshot":
                payload = {
                    **first.payload,
                    "sequence": first.sequence,
                }
                receipt = retry_bounded(
                    lambda: self.core.upload_snapshot(
                        identity=self.identity,
                        session=self.session,
                        payload=payload,
                    ),
                    max_attempts=self.config.retry_max_attempts,
                    base_seconds=self.config.retry_base_seconds,
                    sleep=self.sleep,
                )
                acknowledged = int(receipt["cursor_after"])
            else:
                event_items = _contiguous_events(items)
                events = [
                    {
                        **item.payload,
                        "sequence": item.sequence,
                        "delivery_mode": (
                            "realtime"
                            if item.payload.get("delivery_mode") == "realtime"
                            else "replay"
                        ),
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
                receipt = retry_bounded(
                    lambda: self.core.upload_events(
                        identity=self.identity,
                        session=self.session,
                        payload=payload,
                    ),
                    max_attempts=self.config.retry_max_attempts,
                    base_seconds=self.config.retry_base_seconds,
                    sleep=self.sleep,
                )
                acknowledged = int(receipt["cursor_after"])
            self.queue.acknowledge_through(acknowledged)
            self.cursor["uplink_sequence"] = acknowledged
            self.breaker.success()
            return True
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
            circuit_state=self.breaker.state,
        )

    def process_commands_once(self) -> int:
        if not self.identity or not self.session:
            raise RuntimeError("HUB_SESSION_NOT_READY")
        deliveries = retry_bounded(
            lambda: self.core.claim_commands(
                identity=self.identity,
                session=self.session,
                limit=10,
            ),
            max_attempts=self.config.retry_max_attempts,
            base_seconds=self.config.retry_base_seconds,
            sleep=self.sleep,
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
            )
            processed += 1
        return processed

    def run_forever(self) -> None:
        self.prepare()
        self.enqueue_snapshot(run_type="bootstrap")
        threads = [
            threading.Thread(target=self._subscription_loop, daemon=True),
            threading.Thread(target=self._upload_loop, daemon=True),
            threading.Thread(target=self._command_loop, daemon=True),
            threading.Thread(target=self._maintenance_loop, daemon=True),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

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
            except Exception:
                self.sleep(1)

    def _command_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                if not self.process_commands_once():
                    self.sleep(1)
            except Exception:
                self.sleep(1)

    def _maintenance_loop(self) -> None:
        last_reconciliation = time.monotonic()
        while not self.stop_event.wait(self.config.heartbeat_interval_seconds):
            try:
                self.heartbeat()
                if (
                    time.monotonic() - last_reconciliation
                    >= self.config.reconciliation_interval_seconds
                ):
                    self.enqueue_snapshot(run_type="reconciliation")
                    last_reconciliation = time.monotonic()
            except Exception:
                self.breaker.failure()


def _contiguous_events(items: list[QueueItem]) -> list[QueueItem]:
    result: list[QueueItem] = []
    expected = items[0].sequence
    for item in items:
        if item.kind != "event" or item.sequence != expected:
            break
        result.append(item)
        expected += 1
    return result


def _source_event_id(
    event: dict[str, Any],
    new_state: dict[str, Any],
) -> str:
    context = dict(event.get("context") or new_state.get("context") or {})
    if context.get("id"):
        return f"ha:{context['id']}"
    basis = {
        "entity_id": new_state.get("entity_id"),
        "last_updated": new_state.get("last_updated"),
        "state": new_state.get("state"),
    }
    digest = hashlib.sha256(
        json.dumps(basis, sort_keys=True).encode("utf-8")
    ).hexdigest()[:24]
    return f"haevt:{digest}"
