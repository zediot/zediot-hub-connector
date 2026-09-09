"""组批的批内唯一性闸（A3，第二道保险）。

即便 source_event_id 生成再出问题，也不能把一个必被 Core 整批拒绝的批发出去。
_contiguous_events 遇到批内重复 source_event_id 时截断，重复条留到下一批。
"""

from datetime import datetime, timezone

from zediot_ha_hub_connector.queue import QueueItem
from zediot_ha_hub_connector.runtime import _contiguous_events


def _item(seq, source_id):
    return QueueItem(
        sequence=seq,
        kind="event",
        payload={"source_event_id": source_id, "event_type": "state_changed"},
        created_at=datetime.now(timezone.utc),
        byte_size=10,
    )


def test_batch_truncates_at_duplicate_source_event_id():
    items = [_item(1, "ha:a"), _item(2, "ha:b"), _item(3, "ha:a"), _item(4, "ha:c")]
    batch = _contiguous_events(items)
    ids = [i.payload["source_event_id"] for i in batch]
    assert ids == ["ha:a", "ha:b"], "应在重复点(seq 3 的 ha:a)之前截断"
    assert len(ids) == len(set(ids)), "发出的批必须批内唯一"


def test_duplicate_item_is_not_lost_becomes_next_batch_head():
    items = [_item(1, "ha:a"), _item(2, "ha:a")]
    first = _contiguous_events(items)
    assert [i.sequence for i in first] == [1]
    # 第一批确认后，重复条成为队首，单独成批，不与自己冲突
    second = _contiguous_events(items[1:])
    assert [i.sequence for i in second] == [2]


def test_sequence_gap_still_truncates():
    items = [_item(1, "ha:a"), _item(3, "ha:b")]  # 缺 seq 2
    assert [i.sequence for i in _contiguous_events(items)] == [1]


def test_every_batch_has_at_least_one_item():
    # 即使队首之后立刻重复，也至少发出队首一条，不会空批死循环
    items = [_item(5, "ha:dup"), _item(6, "ha:dup")]
    assert len(_contiguous_events(items)) == 1
