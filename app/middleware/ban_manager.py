import time
from app.logging import models


class BanManager:
    def __init__(self, db_path: str, duration: int) -> None:
        self.db_path = db_path
        self.duration = duration

    async def is_banned(self, ip: str) -> dict | None:
        now_ts = int(time.time())
        return await models.active_ban(self.db_path, ip, now_ts)

    async def ban_ip(self, ip: str, reason: str) -> dict:
        expires_at = int(time.time()) + self.duration
        await models.record_ban(self.db_path, ip, reason, expires_at)
        return {"ip": ip, "reason": reason, "expires_at": expires_at}

