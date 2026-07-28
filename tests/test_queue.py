from pathlib import Path

from zediot_ha_hub_connector.queue import BoundedUplinkQueue


def test_queue_is_bounded_and_sequence_does_not_reset(tmp_path: Path):
    queue = BoundedUplinkQueue(
        tmp_path / "queue.sqlite3",
        max_bytes=100,
        max_age_seconds=3600,
    )
    first = queue.enqueue(kind="event", payload={"value": "a" * 60})
    second = queue.enqueue(kind="event", payload={"value": "b" * 60})

    assert first.sequence == 1
    assert second.sequence == 2
    summary = queue.summary()
    assert summary["queue_depth"] == 1
    assert summary["dropped_count"] == 1

    queue.acknowledge_through(2)
    third = queue.enqueue(kind="event", payload={"value": "c"})
    assert third.sequence == 3
