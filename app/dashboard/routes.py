from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import aiosqlite
from pathlib import Path
from datetime import datetime, timedelta
from app.config import get_settings


templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))


router = APIRouter()


async def fetch_rows(db_path: str, query: str, limit: int = 100):
    try:
        async with aiosqlite.connect(db_path) as db:
            cursor = await db.execute(query + " LIMIT ?", (limit,))
            rows = await cursor.fetchall()
        return rows
    except Exception:
        return []


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request, settings=Depends(get_settings)):
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/dashboard/logs")
async def dashboard_logs(settings=Depends(get_settings)):
    rows = await fetch_rows(settings.logging.db_path, "SELECT timestamp, ip, path, decision, reason, status FROM requests ORDER BY id DESC", 200)
    return JSONResponse([{"timestamp": r[0], "ip": r[1], "path": r[2], "decision": r[3], "reason": r[4], "status": r[5]} for r in rows])


@router.get("/dashboard/metrics")
async def dashboard_metrics(settings=Depends(get_settings)):
    try:
        async with aiosqlite.connect(settings.logging.db_path) as db:
            cursor = await db.execute("SELECT decision, count(*) FROM requests GROUP BY decision")
            rows = await cursor.fetchall()
        return JSONResponse({"counts": {r[0]: r[1] for r in rows}})
    except Exception:
        return JSONResponse({"counts": {}})


@router.get("/dashboard/traffic")
async def dashboard_traffic(settings=Depends(get_settings)):
    try:
        async with aiosqlite.connect(settings.logging.db_path) as db:
            cursor = await db.execute(
                "SELECT timestamp, count(*) FROM requests GROUP BY substr(timestamp, 1, 16) ORDER BY timestamp DESC LIMIT 50"
            )
            rows = await cursor.fetchall()
        return JSONResponse({"data": [{"time": r[0], "count": r[1]} for r in reversed(rows)]})
    except Exception:
        return JSONResponse({"data": []})


@router.get("/dashboard/attacks")
async def dashboard_attacks(settings=Depends(get_settings)):
    try:
        async with aiosqlite.connect(settings.logging.db_path) as db:
            cursor = await db.execute(
                "SELECT reason, count(*) FROM requests WHERE decision='blocked' GROUP BY reason ORDER BY count(*) DESC"
            )
            rows = await cursor.fetchall()
        return JSONResponse({"data": {r[0]: r[1] for r in rows}})
    except Exception:
        return JSONResponse({"data": {}})


@router.get("/dashboard/top_ips")
async def dashboard_top_ips(settings=Depends(get_settings)):
    try:
        async with aiosqlite.connect(settings.logging.db_path) as db:
            cursor = await db.execute(
                "SELECT ip, count(*) FROM requests WHERE decision='blocked' GROUP BY ip ORDER BY count(*) DESC LIMIT 10"
            )
            rows = await cursor.fetchall()
        return JSONResponse({"data": {r[0]: r[1] for r in rows}})
    except Exception:
        return JSONResponse({"data": {}})


@router.get("/dashboard/bans")
async def dashboard_bans(settings=Depends(get_settings)):
    rows = await fetch_rows(settings.logging.db_path, "SELECT ip, reason, expires_at FROM bans ORDER BY id DESC", 100)
    return JSONResponse([{"ip": r[0], "reason": r[1], "expires_at": r[2]} for r in rows])

