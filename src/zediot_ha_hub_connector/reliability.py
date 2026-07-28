from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Callable, TypeVar

T = TypeVar("T")


@dataclass
class CircuitBreaker:
    failure_threshold: int
    recovery_seconds: float
    clock: Callable[[], float] = time.monotonic
    state: str = "closed"
    failure_count: int = 0
    opened_at: float | None = None

    def allow(self) -> bool:
        if self.state != "open":
            return True
        if self.opened_at is None:
            return False
        if self.clock() - self.opened_at < self.recovery_seconds:
            return False
        self.state = "half_open"
        return True

    def success(self) -> None:
        self.state = "closed"
        self.failure_count = 0
        self.opened_at = None

    def failure(self) -> None:
        self.failure_count += 1
        if self.state == "half_open" or self.failure_count >= self.failure_threshold:
            self.state = "open"
            self.opened_at = self.clock()


def retry_bounded(
    operation: Callable[[], T],
    *,
    max_attempts: int,
    base_seconds: float,
    sleep: Callable[[float], None] = time.sleep,
    retryable: Callable[[Exception], bool] = lambda _exc: True,
) -> T:
    if max_attempts < 1:
        raise ValueError("max_attempts must be positive")
    for attempt in range(1, max_attempts + 1):
        try:
            return operation()
        except Exception as exc:
            if attempt == max_attempts or not retryable(exc):
                raise
            cap = min(base_seconds * (2 ** (attempt - 1)), 30.0)
            sleep(cap * (0.75 + random.random() * 0.5))
    raise RuntimeError("unreachable")
