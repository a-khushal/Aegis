import asyncio
import json
import logging
from datetime import datetime
from . import models


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
    )


async def log_event(db_path: str, ip: str, path: str, decision: str, reason: str, status: int) -> None:
    payload = {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "path": path,
        "decision": decision,
        "reason": reason,
        "status": status,
    }
    logging.info(json.dumps(payload))
    await models.log_request(db_path, payload)


def fire_and_forget(coro) -> None:
    loop = asyncio.get_event_loop()
    task = loop.create_task(coro)
    task.add_done_callback(lambda fut: fut.exception())

