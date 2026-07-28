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
    assert breaker.allow() is False
    now[0] = 41.0
    assert breaker.allow() is True
    assert breaker.state == "half_open"
    breaker.success()
    assert breaker.state == "closed"


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
