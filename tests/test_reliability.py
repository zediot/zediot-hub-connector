import threading

import pytest

from zediot_ha_hub_connector.reliability import (
    CircuitBreaker,
    retry_bounded,
)


def test_circuit_breaker_opens_then_allows_one_half_open_probe():
    now = [10.0]
    breaker = CircuitBreaker(
        failure_threshold=2,
        recovery_seconds=30,
        clock=lambda: now[0],
    )
    breaker.failure()
    breaker.failure()
    assert breaker.state == "open"
    assert breaker.allow() is None
    now[0] = 41.0
    permit = breaker.allow()
    assert permit is not None
    assert breaker.state == "half_open"
    assert breaker.success(permit) is True
    assert breaker.state == "closed"


def test_stale_half_open_success_does_not_overwrite_concurrent_failure():
    breaker = CircuitBreaker(
        failure_threshold=1,
        recovery_seconds=0,
        clock=lambda: 10.0,
    )
    breaker.failure()
    permit = breaker.allow()
    assert permit is not None
    assert breaker.current_state() == "half_open"

    release_stale_success = threading.Event()
    stale_success_result: list[bool] = []

    def finish_stale_probe() -> None:
        release_stale_success.wait()
        stale_success_result.append(breaker.success(permit))

    thread = threading.Thread(target=finish_stale_probe)
    thread.start()
    breaker.failure()
    release_stale_success.set()
    thread.join(timeout=1)

    assert stale_success_result == [False]
    assert breaker.current_state() == "open"


def test_retry_is_bounded():
    attempts = []

    def fail():
        attempts.append(1)
        raise RuntimeError("transient")

    with pytest.raises(RuntimeError):
        retry_bounded(
            fail,
            max_attempts=3,
            base_seconds=0,
            sleep=lambda _seconds: None,
        )
    assert len(attempts) == 3
