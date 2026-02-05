import time
from collections import defaultdict
from fastapi import Request
from app.utils.entropy import shannon_entropy


class BehaviourTracker:
    def __init__(self) -> None:
        self.features = defaultdict(lambda: {"count": 0, "errors": 0, "last_minute": []})

    async def capture(self, request: Request, status: int | None = None) -> dict:
        ip = request.client.host if request.client else "unknown"
        record = self.features[ip]
        now = time.time()
        record["last_minute"] = [t for t in record["last_minute"] if now - t < 60]
        record["last_minute"].append(now)
        record["count"] += 1
        if status and status >= 400:
            record["errors"] += 1
        if hasattr(request.state, "body"):
            body = request.state.body
        else:
            body = await request.body()
            request.state.body = body
        uri_entropy = shannon_entropy(request.url.path)
        payload_size = len(body)
        header_count = len(request.headers)
        rpm = len(record["last_minute"])
        error_ratio = record["errors"] / max(record["count"], 1)
        return {
            "ip": ip,
            "rpm": rpm,
            "uri_entropy": uri_entropy,
            "payload_size": payload_size,
            "header_count": header_count,
            "error_ratio": error_ratio,
        }

