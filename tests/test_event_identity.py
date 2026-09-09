"""source_event_id 生成的回归。

现网实测：一条批次(seq 4661-4685)被 Core 以「source_event_id 必须批内唯一」拒绝
5946 次。根因是同一 HA context 内同一实体的两次 state_changed 算出了同一个 id。
"""

from zediot_ha_hub_connector.event_identity import build_source_event_id


def _event(context_id, entity_id, last_updated, state="on"):
    return {
        "time_fired": last_updated,
        "context": {"id": context_id},
        "data": {
            "new_state": {
                "entity_id": entity_id,
                "state": state,
                "last_updated": last_updated,
            }
        },
    }


def _id(ev):
    return build_source_event_id(ev, ev["data"]["new_state"])


def test_same_context_same_entity_two_changes_get_distinct_ids():
    """现网撞车场景：同 context、同实体、两次变更，必须得到不同 id。

    修复前两者都是 `ha:{context}:{sha(entity)[:16]}`，完全相同，整批被拒。
    """
    a = _id(_event("01M1ZV0AFE", "sensor.x", "2026-09-09T06:15:01.100000+00:00"))
    b = _id(_event("01M1ZV0AFE", "sensor.x", "2026-09-09T06:15:01.400000+00:00"))
    assert a != b, "同实体两次变更不能撞成同一个 id"


def test_shared_context_different_entities_stay_distinct():
    """保住原有语义：共享 context、不同实体，仍是两个不同 id（对应既有 runtime 测试）。"""
    ts = "2026-08-19T13:25:15+00:00"
    a = _id(_event("shared-context", "input_boolean.qa", ts))
    b = _id(_event("shared-context", "light.qa", ts))
    assert a != b


def test_same_event_is_idempotent():
    """同一条变更重复处理，id 必须不变——否则幂等失效、会重复投递。"""
    ev = _event("01M1ZV0AFE", "sensor.x", "2026-09-09T06:15:01.100000+00:00")
    assert _id(ev) == _id(dict(ev))


def test_id_shape_is_stable():
    """id 形状保持 `ha:{context}:{16hex}`，不因修复而改变结构。"""
    got = _id(_event("01M1ZV0AFE", "sensor.x", "2026-09-09T06:15:01.100000+00:00"))
    ctx, digest = got.removeprefix("ha:").rsplit(":", 1)
    assert got.startswith("ha:01M1ZV0AFE:")
    assert len(digest) == 16 and all(c in "0123456789abcdef" for c in digest)


def test_no_context_falls_back_to_content_digest():
    ev = {
        "time_fired": "2026-09-09T06:15:01+00:00",
        "data": {"new_state": {"entity_id": "sensor.x", "state": "on",
                               "last_updated": "2026-09-09T06:15:01+00:00"}},
    }
    got = build_source_event_id(ev, ev["data"]["new_state"])
    assert got.startswith("haevt:")
