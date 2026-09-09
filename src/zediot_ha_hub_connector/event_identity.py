"""HA state_changed 事件的 source_event_id —— 上行身份与本地规则幂等的单一真源。

## 为什么要单独一个模块

这段逻辑原先在 runtime._source_event_id 与 rule_runtime._event_identity 各写了一遍。
两者必须产出**同一个** id：上行事件用它做 Core 侧幂等键，本地规则用它做执行幂等键
（lrex），一旦分叉，同一个 HA 事件在两条账上就是两件事。放进一个两边都 import 的
叶子模块，改一处即可，不会漏。

## 为什么 id 里必须带 last_updated

HA 的 context.id 在一次自动化/场景里可被同一实体的多次 state_changed 共享
（灯先开、亮度再稳，同实体两次变更、同一个 context）。旧格式 `ha:{context}:{entity}`
把时间丢了，于是这两条算出同一个 id，进同一批被 Core 以「source_event_id 必须批内
唯一」整批拒绝——而客户端反复重投同一坏批，永远推不进。实测现网一条批次被拒 5946 次
都是这个原因。

last_updated 每次 state_changed 必变（每条都是新的 state 对象），把它折进摘要即可让
两条变更得到不同 id，同时同一条变更被重复处理时 id 仍相同（幂等不破）。
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping


def _event_last_updated(event: Mapping[str, Any], new_state: Mapping[str, Any]) -> str:
    # last_updated 是首选：它随每次状态/属性写入而变。time_fired 兜底，供极少数
    # 不带 last_updated 的事件使用。两者都缺时返回空串——此时退化为旧行为，但
    # 组批去重（flush 前的批内唯一性闸）仍是最后一道保险。
    return str(new_state.get("last_updated") or event.get("time_fired") or "")


def build_source_event_id(
    event: Mapping[str, Any], new_state: Mapping[str, Any]
) -> str:
    context = dict(event.get("context") or new_state.get("context") or {})
    context_id = str(context.get("id") or "")
    entity_id = str(new_state.get("entity_id") or "")
    last_updated = _event_last_updated(event, new_state)
    if context_id:
        # id 形状保持 `ha:{context}:{16hex}` 不变，只是摘要基底从 entity_id 扩到
        # entity_id + last_updated，两个不同实体仍得不同摘要（保住原有语义）。
        digest = hashlib.sha256(
            f"{entity_id}:{last_updated}".encode("utf-8")
        ).hexdigest()[:16]
        return f"ha:{context_id}:{digest}"
    digest = hashlib.sha256(
        f"{entity_id}:{last_updated}:{new_state.get('state')}".encode("utf-8")
    ).hexdigest()[:24]
    return f"haevt:{digest}"
