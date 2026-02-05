import asyncio
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from app.config import get_settings
from app.proxy import router as proxy_router
from app.dashboard.routes import router as dashboard_router
from app.logging.logger import setup_logging, log_event
from app.logging import models
from app.middleware.ban_manager import BanManager
from app.middleware.rule_engine import RuleEngine
from app.middleware.behaviour import BehaviourTracker
from app.middleware.anomaly import AnomalyDetector
from app.middleware.rate_limiter import RateLimiter
from pathlib import Path


settings = get_settings()
setup_logging(settings.logging.level)

app = FastAPI(title="WAF")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    await models.init_db(settings.logging.db_path)
    app.state.ban_manager = BanManager(settings.logging.db_path, settings.ban.duration_seconds)
    rules_path = Path(__file__).resolve().parent.parent / "rules" / "owasp_rules.yaml"
    app.state.rule_engine = RuleEngine(rules_path)
    app.state.behaviour = BehaviourTracker()
    app.state.anomaly = AnomalyDetector(settings.anomaly.threshold)
    app.state.rate_limiter = RateLimiter(settings.rate_limit.requests, settings.rate_limit.per_seconds)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    ip = request.client.host if request.client else "unknown"
    await log_event(settings.logging.db_path, ip, request.url.path, "blocked", "rate_limit", 429)
    return JSONResponse(status_code=429, content={"detail": "rate limit exceeded"})


app.include_router(dashboard_router)
app.include_router(proxy_router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

