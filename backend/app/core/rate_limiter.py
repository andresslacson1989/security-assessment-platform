"""
Contract 01 & 08 Asynchronous Token Bucket Rate Limiter & Circuit Breaker.
"""

from __future__ import annotations
import asyncio
import time
from enum import Enum
from typing import Optional


class CircuitState(str, Enum):
    NORMAL = "NORMAL"
    THROTTLED = "THROTTLED"
    TRIPPED = "TRIPPED"


class TokenBucketRateLimiter:
    """
    Asynchronous token bucket rate limiter to throttle outbound requests.
    Supports rates from 1.0 to 20.0 RPS with burst capacity up to 10 tokens.
    """

    def __init__(self, rate_rps: float = 5.0, burst_capacity: float = 10.0):
        self.rate_rps = max(0.5, min(20.0, float(rate_rps)))
        self.capacity = max(1.0, float(burst_capacity))
        self.tokens = self.capacity
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_refill
        if elapsed > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_rps)
            self.last_refill = now

    async def acquire(self) -> None:
        """
        Asynchronously acquires 1 token, pausing execution if token bucket is empty.
        """
        while True:
            async with self._lock:
                self._refill()
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                # Calculate sleep duration needed for 1 full token
                needed = 1.0 - self.tokens
                sleep_time = max(0.01, needed / self.rate_rps)
            await asyncio.sleep(sleep_time)

    def halve_rate(self) -> None:
        """
        Halves the rate limit during target throttling.
        """
        self.rate_rps = max(0.5, self.rate_rps / 2.0)

    def reset_rate(self, rate_rps: float = 5.0) -> None:
        """
        Resets the rate limit to a specified RPS.
        """
        self.rate_rps = max(0.5, min(20.0, float(rate_rps)))


class CircuitBreaker:
    """
    Automated circuit breaker to protect target infrastructure.
    - 5 consecutive 5xx errors or 3 timeouts -> THROTTLED (10s pause, rate halved).
    - 5 additional errors while throttled -> TRIPPED (aborts scan safely).
    """

    def __init__(self, pause_seconds: float = 10.0):
        self.pause_seconds = pause_seconds
        self.consecutive_5xx = 0
        self.consecutive_timeouts = 0
        self.errors_in_throttled = 0
        self.state = CircuitState.NORMAL
        self.throttled_until: Optional[float] = None

    def record_success(self) -> None:
        """
        Resets error counts upon successful request (status < 500).
        """
        self.consecutive_5xx = 0
        self.consecutive_timeouts = 0
        if self.state == CircuitState.THROTTLED:
            now = time.monotonic()
            if self.throttled_until and now >= self.throttled_until:
                self.state = CircuitState.NORMAL
                self.errors_in_throttled = 0

    def record_response(self, status_code: Optional[int] = None, is_timeout: bool = False) -> CircuitState:
        """
        Records response status code or timeout and transitions circuit breaker state.
        """
        now = time.monotonic()

        if is_timeout:
            self.consecutive_timeouts += 1
        elif status_code and status_code >= 500:
            self.consecutive_5xx += 1
        else:
            self.record_success()
            return self.state

        if self.state == CircuitState.NORMAL:
            if self.consecutive_5xx >= 5 or self.consecutive_timeouts >= 3:
                self.state = CircuitState.THROTTLED
                self.throttled_until = now + self.pause_seconds
                self.errors_in_throttled = 0
        elif self.state == CircuitState.THROTTLED:
            self.errors_in_throttled += 1
            if self.errors_in_throttled >= 5:
                self.state = CircuitState.TRIPPED

        return self.state

    def is_tripped(self) -> bool:
        """
        Returns True if the circuit breaker has fatally tripped.
        """
        return self.state == CircuitState.TRIPPED

    async def check_throttle(self, rate_limiter: Optional[TokenBucketRateLimiter] = None) -> None:
        """
        Pauses execution if the circuit is in THROTTLED state.
        """
        if self.state == CircuitState.THROTTLED and self.throttled_until:
            now = time.monotonic()
            remaining = self.throttled_until - now
            if remaining > 0:
                if rate_limiter:
                    rate_limiter.halve_rate()
                await asyncio.sleep(remaining)
            # Recheck after sleep
            self.state = CircuitState.NORMAL
