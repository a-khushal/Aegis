import aiosqlite


CREATE_REQUESTS = """
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    ip TEXT NOT NULL,
    path TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    status INTEGER NOT NULL
);
"""


CREATE_BANS = """
CREATE TABLE IF NOT EXISTS bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
"""


async def init_db(db_path: str) -> None:
    from pathlib import Path
    db_file = Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(db_path) as db:
        await db.execute(CREATE_REQUESTS)
        await db.execute(CREATE_BANS)
        await db.commit()


async def log_request(db_path: str, data: dict) -> None:
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT INTO requests (timestamp, ip, path, decision, reason, status) VALUES (?, ?, ?, ?, ?, ?)",
            (
                data["timestamp"],
                data["ip"],
                data["path"],
                data["decision"],
                data["reason"],
                data["status"],
            ),
        )
        await db.commit()


async def record_ban(db_path: str, ip: str, reason: str, expires_at: int) -> None:
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT INTO bans (ip, reason, expires_at) VALUES (?, ?, ?)",
            (ip, reason, expires_at),
        )
        await db.commit()


async def active_ban(db_path: str, ip: str, now_ts: int) -> dict | None:
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(
            "SELECT ip, reason, expires_at FROM bans WHERE ip=? AND expires_at > ? ORDER BY expires_at DESC LIMIT 1",
            (ip, now_ts),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return {"ip": row[0], "reason": row[1], "expires_at": row[2]}

