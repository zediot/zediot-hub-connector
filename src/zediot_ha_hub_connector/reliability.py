from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class CircuitPermit:
    generation: int
    half_open_probe: bool


@dataclass
class CircuitBreaker:
    failure_threshold: int
    recovery_seconds: float
    clock: Callable[[], float] = time.monotonic
    state: str = "closed"
    failure_count: int = 0
    opened_at: float | None = None
    _generation: int = field(default=0, init=False, repr=False)
    _lock: threading.Lock = field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
    )

    def allow(self) -> CircuitPermit | None:
        with self._lock:
            if self.state == "closed":
                return CircuitPermit(
                    generation=self._generation,
                    half_open_probe=False,
                )
            if self.state == "half_open" or self.opened_at is None:
                return None
            if self.clock() - self.opened_at < self.recovery_seconds:
                return None
            self.state = "half_open"
            return CircuitPermit(
                generation=self._generation,
                half_open_probe=True,
            )

    def observe(self) -> CircuitPermit:
        with self._lock:
            return CircuitPermit(
                generation=self._generation,
                half_open_probe=self.state == "half_open",
            )

    def success(self, permit: CircuitPermit) -> bool:
        with self._lock:
            if permit.generation != self._generation:
                return False
            self._close()
            return True

    def failure(self) -> None:
        with self._lock:
            self._generation += 1
            self.failure_count += 1
            if (
                self.state == "half_open"
                or self.failure_count >= self.failure_threshold
            ):
                self.state = "open"
                self.opened_at = self.clock()

    def current_state(self) -> str:
        with self._lock:
            return self.state

    def _close(self) -> None:
        self.state = "closed"
        self.failure_count = 0
        self.opened_at = None


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
