"""心跳不能被快照采集拖死。

现网实测：AIBox 的会话每 13-16 分钟就丢一次（6 小时 23 个会话，同期正常网关只有
2 个）。心跳严格每 30 秒、一次不落，然后突然静默约 3 分钟，随后换新会话。根因是
对账（采 HA 全量快照）与心跳在同一个线程里同步执行，采集一慢就占住线程，而租约
只有 90 秒——心跳一停，会话必然过期。会话被自己的对账拖死，快照因此永远传不上去，
reconciliation_required 也就永远清不掉，于是每 13 分钟重来一次。

这两条断言钉的是修复的两个支点，缺一条就会退回原样。
"""

from __future__ import annotations

import threading
import time

import pytest

from zediot_ha_hub_connector.ha_client import HomeAssistantClient


def test_heartbeat_and_inventory_are_separate_loops():
    """心跳线程里不能再出现对账调用。

    结构性断言：_maintenance_loop 只负责心跳，对账在 _inventory_loop。
    """
    import inspect

    from zediot_ha_hub_connector.runtime import HubConnectorRuntime

    maintenance = inspect.getsource(HubConnectorRuntime._maintenance_loop)
    assert "enqueue_reconciliation_if_needed" not in maintenance, (
        "对账不能回到心跳线程：采集慢会拖过租约，把会话拖死"
    )
    assert "self.heartbeat()" in maintenance
    inventory = inspect.getsource(HubConnectorRuntime._inventory_loop)
    assert "enqueue_reconciliation_if_needed" in inventory


def test_snapshot_collection_has_a_hard_deadline():
    """采集必须有总时限，且显著小于租约（默认 90s）。

    单次 recv 的 30s 超时封不住整体：_receive_non_ping 是循环，遇到持续 ping 流
    耗时无上界。
    """
    assert HomeAssistantClient.DEFAULT_SNAPSHOT_DEADLINE_SECONDS < 90
    assert HomeAssistantClient.DEFAULT_SNAPSHOT_DEADLINE_SECONDS > 0


class _PingFloodSocket:
    """一直回 ping 的 HA：修复前会让 _receive_non_ping 永远循环下去。"""

    def __init__(self):
        self.closed = False

    def recv(self):
        time.sleep(0.01)
        return '{"type": "ping", "id": 1}'

    def send(self, _payload):
        return None

    def close(self):
        self.closed = True


def test_ping_flood_cannot_hang_forever():
    """持续 ping 不能让采集无限期挂住——到点必须抛 TimeoutError。"""
    client = HomeAssistantClient(
        access_token="t",
        websocket_url="ws://ha/api/websocket",
        create_connection=lambda *a, **k: _PingFloodSocket(),
        snapshot_deadline_seconds=0.3,
    )
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        client.collect_snapshot()
    elapsed = time.monotonic() - started
    assert elapsed < 10, f"应在时限内退出，实际 {elapsed:.1f}s"
