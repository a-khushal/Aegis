from fastapi import Request
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import time
from collections import defaultdict


class RateLimiter:
    def __init__(self, requests: int, per_seconds: int) -> None:
        self.rule = f"{requests}/{per_seconds}seconds"
        self.requests = requests
        self.per_seconds = per_seconds
        self.storage = defaultdict(list)

    def limit(self):
        pass

    async def check(self, request: Request) -> None:
        key = get_remote_address(request)
        now = time.time()
        
        window_start = now - self.per_seconds
        self.storage[key] = [t for t in self.storage[key] if t > window_start]
        
        if len(self.storage[key]) >= self.requests:
            raise RateLimitExceeded(429, "Rate limit exceeded")
        
        self.storage[key].append(now)

