from __future__ import annotations

import hashlib
import json
from typing import Any

from zediot_ha_hub_connector.ha_client import HomeAssistantSnapshot


def build_snapshot_uplink(
    snapshot: HomeAssistantSnapshot,
    *,
    run_type: str,
) -> dict[str, Any]:
    objects = _snapshot_objects(snapshot)
    source_version = _source_version(objects)
    observed_at = snapshot.observed_at.isoformat().replace("+00:00", "Z")
    return {
        "run_type": run_type,
        "delivery_mode": "realtime",
        "profile_key": "home_assistant",
        "source_version": source_version,
        "idempotency_key": f"hub:{run_type}:{source_version}",
        "observed_at": observed_at,
        "coverage": {
            "mode": "full",
            "object_types": ["area", "device", "entity"],
        },
        "objects": objects,
    }


def _snapshot_objects(snapshot: HomeAssistantSnapshot) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    for area in snapshot.areas:
        area_id = str(area.get("area_id") or "")
        objects.append(
            {
                "object_type": "area",
                "external_id": area_id,
                "profile_schema_version": "1.0",
                "metadata": {"name": str(area.get("name") or area_id)},
                "provenance": {
                    "source_kind": "ha_area_registry",
                    "evidence_type": "inventory",
                },
            }
        )
    for device in snapshot.devices:
        device_id = str(device.get("id") or "")
        objects.append(
            {
                "object_type": "device",
                "external_id": device_id,
                "parent_external_ref": device.get("area_id"),
                "profile_schema_version": "1.0",
                "metadata": {
                    "name": str(
                        device.get("name_by_user")
                        or device.get("name")
                        or device_id
                    ),
                    "manufacturer": device.get("manufacturer"),
                    "model": device.get("model"),
                    "entry_type": device.get("entry_type"),
                    "via_device_id": device.get("via_device_id"),
                },
                "provenance": {
                    "source_kind": "ha_device_registry",
                    "evidence_type": "inventory",
                },
            }
        )
    state_by_entity = {
        str(item.get("entity_id") or ""): item for item in snapshot.states
    }
    for entity in snapshot.entities:
        entity_id = str(entity.get("entity_id") or "")
        state = state_by_entity.get(entity_id) or {}
        attributes = dict(state.get("attributes") or {})
        objects.append(
            {
                "object_type": "entity",
                "external_id": entity_id,
                "parent_external_ref": entity.get("device_id"),
                "profile_schema_version": "1.0",
                "metadata": {
                    "name": str(
                        entity.get("name")
                        or attributes.get("friendly_name")
                        or entity_id
                    ),
                    "domain": entity_id.partition(".")[0],
                    "platform": entity.get("platform"),
                    "unique_id": entity.get("unique_id"),
                    "device_class": (
                        entity.get("device_class")
                        or attributes.get("device_class")
                    ),
                    "unit": attributes.get("unit_of_measurement"),
                    "state_class": attributes.get("state_class"),
                    "entity_category": entity.get("entity_category"),
                    "disabled": bool(entity.get("disabled_by")),
                    "state_eligible": not bool(entity.get("disabled_by")),
                },
                "provenance": {
                    "source_kind": "ha_entity_registry",
                    "evidence_type": "inventory",
                },
            }
        )
    return objects


def _source_version(objects: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256(
        json.dumps(
            objects,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()[:20]
    return f"ha:{digest}"
