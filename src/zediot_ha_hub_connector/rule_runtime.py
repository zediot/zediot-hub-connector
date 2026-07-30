from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any, Mapping

from zediot_ha_hub_connector.ha_client import HomeAssistantSupervisorClient
from zediot_ha_hub_connector.rule_package import (
    VerifiedRulePackage,
    parse_time,
    verify_stored_rule_package,
)
from zediot_ha_hub_connector.rule_store import LocalRuleStore

ALLOWED_ROOTS = {"event", "latest_state", "device", "space", "time"}
DENIED_SEGMENTS = {
    "raw",
    "raw_payload",
    "provider_payload",
    "provider_raw",
    "source_payload",
}


class HomeAssistantLocalRuleRuntime:
    def __init__(
        self,
        *,
        store: LocalRuleStore,
        home_assistant: HomeAssistantSupervisorClient,
        integration_instance_id: str,
        trusted_key_ids: frozenset[str],
    ) -> None:
        self.store = store
        self.home_assistant = home_assistant
        self.integration_instance_id = integration_instance_id
        self.trusted_key_ids = trusted_key_ids

    def process_event(
        self,
        event: dict[str, Any],
        *,
        connectivity_state: str,
    ) -> list[dict[str, Any]]:
        source_event_id, event_time, new_state = _event_identity(event)
        results: list[dict[str, Any]] = []
        for document in self.store.active_documents():
            package = verify_stored_rule_package(
                document,
                integration_instance_id=self.integration_instance_id,
                trusted_key_ids=self.trusted_key_ids,
            )
            binding = dict(
                package.payload["runtime_plan"]["event_binding"]
            )
            if binding["provider_entity_id"] != new_state["entity_id"]:
                continue
            results.append(
                self._execute(
                    package=package,
                    source_event_id=source_event_id,
                    event_time=event_time,
                    new_state=new_state,
                    connectivity_state=connectivity_state,
                )
            )
        return results

    def _execute(
        self,
        *,
        package: VerifiedRulePackage,
        source_event_id: str,
        event_time: datetime,
        new_state: dict[str, Any],
        connectivity_state: str,
    ) -> dict[str, Any]:
        payload = package.payload
        deployment_id = str(payload["deployment_id"])
        version_id = str(payload["version_id"])
        idempotency_key = (
            f"{deployment_id}:{version_id}:{source_event_id}"
        )
        execution_id = _stable_id("lrex", idempotency_key)
        binding = dict(payload["runtime_plan"]["event_binding"])
        context = {
            "event": {
                "entity_id": str(new_state["entity_id"]),
                "value": _canonical_state_value(new_state.get("state")),
                "observed_at": event_time.isoformat(),
            },
            "latest_state": {
                "value": _canonical_state_value(new_state.get("state")),
                "observed_at": event_time.isoformat(),
            },
            "device": {"device_id": binding["target_id"]},
            "space": {},
            "time": {"evaluated_at": datetime.now(UTC).isoformat()},
        }
        try:
            matched, trace = evaluate_condition(
                dict(payload["rule"].get("condition") or {}),
                context,
            )
            result = "hit" if matched else "skipped"
        except LocalRuleEvaluationError as exc:
            result = "error"
            trace = {
                "error_reason": exc.reason,
                "error_message": str(exc),
            }
        base = {
            "execution_id": execution_id,
            "package_id": package.package_id,
            "package_hash": package.package_hash,
            "deployment_id": deployment_id,
            "rule_id": str(payload["rule_id"]),
            "version_id": version_id,
            "version_no": int(payload["version_no"]),
            "source_event_id": source_event_id,
            "target_id": str(binding["target_id"]),
            "idempotency_key": idempotency_key,
            "result": result,
            "condition_trace": trace,
            "action_results": [],
            "executed_at": datetime.now(UTC).isoformat(),
            "trace_id": _stable_id("hatrace", idempotency_key),
            "connectivity_state": connectivity_state,
        }
        existing, created = self.store.reserve_execution(
            idempotency_key=idempotency_key,
            execution_id=execution_id,
            evidence=base,
        )
        if not created:
            return existing
        if result == "hit":
            base["action_results"] = self._dispatch_actions(
                package=package,
                execution_id=execution_id,
            )
        self.store.finalize_execution(base)
        return base

    def _dispatch_actions(
        self,
        *,
        package: VerifiedRulePackage,
        execution_id: str,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        actions = list(package.payload["runtime_plan"]["actions"])
        for index, raw_action in enumerate(actions):
            action = dict(raw_action)
            action_result_id = _stable_id(
                "lract",
                f"{execution_id}:{index}",
            )
            try:
                _validate_action(action)
                response = self.home_assistant.call_service(
                    domain="light",
                    service=str(action["provider_service"]),
                    entity_id=str(action["provider_entity_id"]),
                    service_data={
                        "entity_id": str(action["provider_entity_id"]),
                    },
                )
                result = {
                    "action_result_id": action_result_id,
                    "action_index": index,
                    "action_type": "device_command",
                    "status": "succeeded",
                    "reason_code": None,
                    "evidence": {
                        "provider_request_id": str(
                            response.get("request_id") or ""
                        ),
                        "provider_result": "success",
                    },
                }
            except TimeoutError:
                result = _failed_action(
                    action_result_id,
                    index,
                    "ha_service_timeout",
                )
            except Exception:
                result = _failed_action(
                    action_result_id,
                    index,
                    "ha_service_call_failed",
                )
            results.append(result)
        return results


class LocalRuleEvaluationError(ValueError):
    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def evaluate_condition(
    condition: Mapping[str, Any],
    context: Mapping[str, Any],
) -> tuple[bool, dict[str, Any]]:
    if not condition:
        return True, {"op": "always", "result": True}
    value, trace = _eval(condition, context)
    if not isinstance(value, bool):
        raise LocalRuleEvaluationError(
            "type_mismatch",
            "condition root must evaluate to boolean",
        )
    return value, trace


def _eval(node: Any, context: Mapping[str, Any]) -> tuple[Any, dict[str, Any]]:
    if not isinstance(node, Mapping):
        return node, {"literal": node}
    if "var" in node and not node.get("op"):
        path = str(node.get("var") or "")
        value = _resolve(path, context)
        return value, {"var": path, "value": value}
    op = str(node.get("op") or "")
    if op == "exists":
        path = str(node.get("var") or "")
        try:
            _resolve(path, context)
            result = True
        except LocalRuleEvaluationError as exc:
            if exc.reason != "missing_field":
                raise
            result = False
        return result, {"op": op, "var": path, "result": result}
    if op in {"and", "or"}:
        args = node.get("args")
        if not isinstance(args, list) or not args:
            raise LocalRuleEvaluationError(
                "invalid_condition",
                f"{op} requires non-empty args",
            )
        children = [_eval(child, context) for child in args]
        if not all(isinstance(value, bool) for value, _ in children):
            raise LocalRuleEvaluationError(
                "type_mismatch",
                f"{op} child must be boolean",
            )
        result = (
            all(value for value, _ in children)
            if op == "and"
            else any(value for value, _ in children)
        )
        return result, {
            "op": op,
            "args": [trace for _, trace in children],
            "result": result,
        }
    if op == "not":
        value, trace = _eval(node.get("arg"), context)
        if not isinstance(value, bool):
            raise LocalRuleEvaluationError(
                "type_mismatch",
                "not arg must be boolean",
            )
        return not value, {"op": op, "arg": trace, "result": not value}
    if op in {"eq", "ne", "gt", "gte", "lt", "lte", "contains"}:
        left, left_trace = _eval(node.get("left"), context)
        right, right_trace = _eval(node.get("right"), context)
        result = _compare(op, left, right)
        return result, {
            "op": op,
            "left": left_trace,
            "right": right_trace,
            "result": result,
        }
    raise LocalRuleEvaluationError(
        "invalid_operator",
        f"unsupported condition operator: {op}",
    )


def _resolve(path: str, context: Mapping[str, Any]) -> Any:
    parts = path.split(".")
    if not path or parts[0] not in ALLOWED_ROOTS:
        raise LocalRuleEvaluationError(
            "missing_field",
            f"context root not allowed: {parts[0] if parts else ''}",
        )
    if any(part in DENIED_SEGMENTS for part in parts):
        raise LocalRuleEvaluationError(
            "raw_payload_access_denied",
            "raw provider payload access is denied",
        )
    current: Any = context
    for part in parts:
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            raise LocalRuleEvaluationError(
                "missing_field",
                f"missing condition field: {path}",
            )
    return current


def _compare(op: str, left: Any, right: Any) -> bool:
    if op == "eq":
        return left == right
    if op == "ne":
        return left != right
    if op == "contains":
        if isinstance(left, str) and isinstance(right, str):
            return right in left
        if isinstance(left, list):
            return right in left
        raise LocalRuleEvaluationError(
            "type_mismatch",
            "contains requires string or list",
        )
    if isinstance(left, bool) or isinstance(right, bool):
        raise LocalRuleEvaluationError(
            "type_mismatch",
            f"{op} requires comparable operands",
        )
    if not (
        isinstance(left, (int, float))
        and isinstance(right, (int, float))
        or isinstance(left, str)
        and isinstance(right, str)
    ):
        raise LocalRuleEvaluationError(
            "type_mismatch",
            f"{op} requires comparable operands",
        )
    if op == "gt":
        return left > right
    if op == "gte":
        return left >= right
    if op == "lt":
        return left < right
    return left <= right


def _event_identity(
    event: dict[str, Any],
) -> tuple[str, datetime, dict[str, Any]]:
    data = dict(event.get("data") or {})
    new_state = dict(data.get("new_state") or {})
    entity_id = str(new_state.get("entity_id") or "")
    if not entity_id:
        raise RuntimeError("HA_STATE_EVENT_MISSING_NEW_STATE")
    context = dict(event.get("context") or new_state.get("context") or {})
    context_id = str(context.get("id") or "")
    event_time = parse_time(
        event.get("time_fired")
        or new_state.get("last_updated")
        or datetime.now(UTC)
    )
    if context_id:
        source_event_id = f"ha:{context_id}"
    else:
        digest = hashlib.sha256(
            f"{entity_id}:{event_time.isoformat()}:{new_state.get('state')}".encode(
                "utf-8"
            )
        ).hexdigest()[:24]
        source_event_id = f"haevt:{digest}"
    return source_event_id, event_time, new_state


def _canonical_state_value(value: Any) -> Any:
    normalized = str(value or "").strip()
    if normalized == "on":
        return True
    if normalized == "off":
        return False
    try:
        return float(normalized)
    except ValueError:
        return normalized


def _validate_action(action: dict[str, Any]) -> None:
    expected_service = "turn_on" if action.get("value") is True else "turn_off"
    if (
        action.get("action_type") != "device_command"
        or action.get("canonical_capability") != "light.power"
        or action.get("template_code") != "set_light_power"
        or action.get("provider_domain") != "light"
        or action.get("provider_service") != expected_service
        or not str(action.get("provider_entity_id") or "").startswith("light.")
    ):
        raise RuntimeError("LOCAL_RULE_ACTION_NOT_ALLOWLISTED")
    safety = dict(action.get("command_safety_evidence") or {})
    if not safety.get("reviewed") or safety.get("risk_class") != (
        "non_destructive"
    ):
        raise RuntimeError("LOCAL_RULE_ACTION_NOT_REVIEWED")


def _failed_action(
    action_result_id: str,
    index: int,
    reason_code: str,
) -> dict[str, Any]:
    return {
        "action_result_id": action_result_id,
        "action_index": index,
        "action_type": "device_command",
        "status": "failed",
        "reason_code": reason_code,
        "evidence": {},
    }


def _stable_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}_{digest}"
