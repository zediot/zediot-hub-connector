from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from zediot_ha_hub_connector.command_store import CommandReceiptStore
from zediot_ha_hub_connector.ha_client import HomeAssistantSupervisorClient

TERMINAL_STATUSES = frozenset({"executed", "failed", "timeout"})


class HubCommandExecutor:
    def __init__(
        self,
        *,
        home_assistant: HomeAssistantSupervisorClient,
        receipts: CommandReceiptStore,
    ) -> None:
        self.home_assistant = home_assistant
        self.receipts = receipts

    def execute(self, delivery: dict[str, Any]) -> dict[str, Any]:
        command_id = str(delivery["command_id"])
        idempotency_key = str(delivery["idempotency_key"])
        envelope = validate_command_envelope(dict(delivery["envelope"]))
        existing = self.receipts.get(command_id=command_id)
        if existing and existing["status"] in TERMINAL_STATUSES:
            return existing
        if _deadline(delivery["deadline_at"]) <= datetime.now(UTC):
            return self.receipts.save(
                command_id=command_id,
                idempotency_key=idempotency_key,
                envelope=envelope,
                status="timeout",
                reason_code="command_deadline_expired",
                evidence={},
            )
        self.receipts.save(
            command_id=command_id,
            idempotency_key=idempotency_key,
            envelope=envelope,
            status="accepted",
            reason_code=None,
            evidence={},
        )
        try:
            result = self.home_assistant.call_service(
                domain=envelope["domain"],
                service=envelope["service"],
                entity_id=envelope["entity_id"],
                service_data=envelope["service_data"],
            )
        except TimeoutError:
            return self.receipts.save(
                command_id=command_id,
                idempotency_key=idempotency_key,
                envelope=envelope,
                status="timeout",
                reason_code="ha_service_timeout",
                evidence={},
            )
        except Exception:
            return self.receipts.save(
                command_id=command_id,
                idempotency_key=idempotency_key,
                envelope=envelope,
                status="failed",
                reason_code="ha_service_call_failed",
                evidence={},
            )
        return self.receipts.save(
            command_id=command_id,
            idempotency_key=idempotency_key,
            envelope=envelope,
            status="executed",
            reason_code=None,
            evidence={
                "provider_request_id": str(result.get("request_id") or ""),
                "provider_result": "success",
            },
        )


def validate_command_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    domain = str(envelope.get("domain") or "")
    service = str(envelope.get("service") or "")
    entity_id = str(envelope.get("entity_id") or "")
    service_data = dict(envelope.get("service_data") or {})
    if (
        domain != "light"
        or service not in {"turn_on", "turn_off"}
        or not entity_id.startswith("light.")
        or set(service_data) != {"entity_id"}
        or service_data.get("entity_id") != entity_id
    ):
        raise RuntimeError("HUB_COMMAND_NOT_ALLOWLISTED")
    return {
        "domain": domain,
        "service": service,
        "entity_id": entity_id,
        "service_data": {"entity_id": entity_id},
    }


def _deadline(value: str | datetime) -> datetime:
    parsed = (
        value
        if isinstance(value, datetime)
        else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    )
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
