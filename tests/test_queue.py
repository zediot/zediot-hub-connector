import sqlite3
from datetime import datetime, timedelta, timezone
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
    assert first.accepted is True
    assert second.accepted is False
    assert second.drop_reason == "queue_capacity_exceeded"
    summary = queue.summary()
    assert summary["queue_depth"] == 1
    assert summary["oldest_sequence"] == 1
    assert summary["latest_sequence"] == 1
    assert summary["dropped_count"] == 1
    assert summary["reconciliation_required"] == 1

    queue.acknowledge_through(1)
    third = queue.enqueue(kind="event", payload={"value": "c"})
    assert third.sequence == 2
    assert third.accepted is True


def test_expired_prefix_resets_to_last_acknowledged_cursor(tmp_path: Path):
    path = tmp_path / "queue.sqlite3"
    queue = BoundedUplinkQueue(
        path,
        max_bytes=1024,
        max_age_seconds=60,
    )
    first = queue.enqueue(kind="event", payload={"value": "first"})
    queue.acknowledge_through(first.sequence)
    stale = queue.enqueue(kind="event", payload={"value": "stale"})
    assert stale.sequence == 2

    expired_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE uplink_queue SET created_at = ? WHERE sequence = ?",
            (expired_at.isoformat(), stale.sequence),
        )

    replacement = queue.enqueue(kind="event", payload={"value": "fresh"})

    assert replacement.accepted is True
    assert replacement.sequence == 2
    assert queue.peek_all(limit=10)[0].payload == {"value": "fresh"}
    assert queue.summary()["dropped_count"] == 1
    assert queue.needs_reconciliation() is True
