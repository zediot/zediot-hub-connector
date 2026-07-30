from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PACKAGE_VERSION = "1.0"
RUNTIME_VERSION = "zediot-ha-rule-runtime-v1"
MAX_CLOCK_SKEW = timedelta(minutes=5)
FORBIDDEN_KEYS = frozenset(
    {
        "access_token",
        "refresh_token",
        "raw_token",
        "credential",
        "credentials",
        "secret",
        "private_key",
        "provider_payload",
        "provider_raw",
        "raw",
        "raw_payload",
        "source_payload",
        "yaml",
        "jinja",
        "script",
    }
)


@dataclass(frozen=True)
class VerifiedRulePackage:
    package_id: str
    package_hash: str
    signature: str
    signature_key_id: str
    signing_public_key_pem: str
    payload: dict[str, Any]
    valid_until: datetime

    def as_document(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "payload_hash": self.package_hash,
            "signature": self.signature,
            "signature_key_id": self.signature_key_id,
            "signing_public_key_pem": self.signing_public_key_pem,
            "payload": self.payload,
        }


def verify_rule_package_delivery(
    delivery: Mapping[str, Any],
    *,
    integration_instance_id: str,
    trusted_key_ids: frozenset[str],
    now: datetime | None = None,
) -> VerifiedRulePackage:
    payload = dict(delivery.get("payload") or {})
    ensure_safe(payload)
    canonical = canonical_bytes(payload)
    package_hash = hashlib.sha256(canonical).hexdigest()
    package_id = f"rpkg_{package_hash[:24]}"
    if delivery.get("package_id") != package_id:
        raise RuntimeError("RULE_PACKAGE_ID_MISMATCH")
    if delivery.get("payload_hash") != package_hash:
        raise RuntimeError("RULE_PACKAGE_HASH_MISMATCH")
    for field_name in (
        "deployment_id",
        "rule_id",
        "version_id",
        "version_no",
        "integration_instance_id",
    ):
        if (
            field_name in delivery
            and delivery.get(field_name) != payload.get(field_name)
        ):
            raise RuntimeError("RULE_PACKAGE_METADATA_MISMATCH")
    key_id = str(delivery.get("signature_key_id") or "")
    if key_id not in trusted_key_ids:
        raise RuntimeError("RULE_PACKAGE_SIGNING_KEY_UNTRUSTED")
    if payload.get("package_version") != PACKAGE_VERSION:
        raise RuntimeError("RULE_PACKAGE_VERSION_UNSUPPORTED")
    if payload.get("runtime_version") != RUNTIME_VERSION:
        raise RuntimeError("RULE_PACKAGE_RUNTIME_VERSION_UNSUPPORTED")
    if payload.get("profile_key") != "home_assistant":
        raise RuntimeError("RULE_PACKAGE_PROFILE_MISMATCH")
    if payload.get("integration_instance_id") != integration_instance_id:
        raise RuntimeError("RULE_PACKAGE_INSTANCE_MISMATCH")
    runtime_plan = dict(payload.get("runtime_plan") or {})
    if (
        runtime_plan.get("runtime") != "home_assistant"
        or runtime_plan.get("runtime_version") != RUNTIME_VERSION
    ):
        raise RuntimeError("RULE_PACKAGE_RUNTIME_PLAN_INVALID")
    _validate_runtime_plan(runtime_plan)
    issued_at = parse_time(payload.get("issued_at"))
    valid_until = parse_time(payload.get("valid_until"))
    current = now or datetime.now(UTC)
    if issued_at > current + MAX_CLOCK_SKEW:
        raise RuntimeError("RULE_PACKAGE_CLOCK_SKEW")
    if valid_until <= current:
        raise RuntimeError("RULE_PACKAGE_EXPIRED")
    signature = str(delivery.get("signature") or "")
    public_key_pem = str(delivery.get("signing_public_key_pem") or "")
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("not Ed25519")
        key.verify(
            base64.urlsafe_b64decode(_pad(signature)),
            canonical,
        )
    except Exception as exc:
        raise RuntimeError("RULE_PACKAGE_SIGNATURE_INVALID") from exc
    return VerifiedRulePackage(
        package_id=package_id,
        package_hash=package_hash,
        signature=signature,
        signature_key_id=key_id,
        signing_public_key_pem=public_key_pem,
        payload=payload,
        valid_until=valid_until,
    )


def verify_stored_rule_package(
    document: Mapping[str, Any],
    *,
    integration_instance_id: str,
    trusted_key_ids: frozenset[str],
    now: datetime | None = None,
) -> VerifiedRulePackage:
    return verify_rule_package_delivery(
        {
            "package_id": document.get("package_id"),
            "payload_hash": document.get("payload_hash"),
            "signature": document.get("signature"),
            "signature_key_id": document.get("signature_key_id"),
            "signing_public_key_pem": document.get("signing_public_key_pem"),
            "payload": document.get("payload"),
        },
        integration_instance_id=integration_instance_id,
        trusted_key_ids=trusted_key_ids,
        now=now,
    )


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    ensure_safe(payload)
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def ensure_safe(value: Any, *, path: str = "package") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).strip().lower()
            if normalized in FORBIDDEN_KEYS:
                raise RuntimeError(
                    f"RULE_PACKAGE_FORBIDDEN_FIELD:{path}.{normalized}"
                )
            ensure_safe(item, path=f"{path}.{normalized}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            ensure_safe(item, path=f"{path}[{index}]")


def parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _validate_runtime_plan(plan: Mapping[str, Any]) -> None:
    binding = dict(plan.get("event_binding") or {})
    if (
        binding.get("provider_event_type") != "state_changed"
        or not str(binding.get("provider_entity_id") or "")
        or binding.get("canonical_event_type")
        not in {
            "latest_state.changed",
            "telemetry.ingested",
            "device.presence.changed",
            "device.status.changed",
        }
        or not str(binding.get("target_id") or "")
    ):
        raise RuntimeError("RULE_PACKAGE_EVENT_BINDING_INVALID")
    actions = plan.get("actions")
    if not isinstance(actions, list) or not 1 <= len(actions) <= 20:
        raise RuntimeError("RULE_PACKAGE_ACTION_PLAN_INVALID")
    for action in actions:
        value = dict(action or {})
        if (
            value.get("action_type") != "device_command"
            or value.get("provider_domain") != "light"
            or value.get("provider_service") not in {"turn_on", "turn_off"}
            or not str(value.get("provider_entity_id") or "").startswith("light.")
            or value.get("canonical_capability") != "light.power"
            or value.get("template_code") != "set_light_power"
            or not isinstance(value.get("value"), bool)
        ):
            raise RuntimeError("RULE_PACKAGE_ACTION_PLAN_INVALID")
        safety = dict(value.get("command_safety_evidence") or {})
        if not safety.get("reviewed") or safety.get("risk_class") != (
            "non_destructive"
        ):
            raise RuntimeError("RULE_PACKAGE_ACTION_SAFETY_INVALID")


def _pad(value: str) -> bytes:
    encoded = value.encode("ascii")
    return encoded + b"=" * (-len(encoded) % 4)
