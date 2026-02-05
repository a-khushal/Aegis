from fastapi import APIRouter, Request, Depends, Response
import httpx
from slowapi.errors import RateLimitExceeded
from app.config import get_settings
from app.middleware.ban_manager import BanManager
from app.middleware.rule_engine import RuleEngine
from app.middleware.behaviour import BehaviourTracker
from app.middleware.anomaly import AnomalyDetector
from app.logging.logger import log_event, fire_and_forget


router = APIRouter()


def get_ban_manager(request: Request) -> BanManager:
    return request.app.state.ban_manager


def get_rule_engine(request: Request) -> RuleEngine:
    return request.app.state.rule_engine


def get_behaviour(request: Request) -> BehaviourTracker:
    return request.app.state.behaviour


def get_anomaly(request: Request) -> AnomalyDetector:
    return request.app.state.anomaly


def get_rate_limiter(request: Request):
    return request.app.state.rate_limiter


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def forward(
    path: str,
    request: Request,
    settings=Depends(get_settings),
    ban_manager: BanManager = Depends(get_ban_manager),
    rule_engine: RuleEngine = Depends(get_rule_engine),
    behaviour: BehaviourTracker = Depends(get_behaviour),
    anomaly: AnomalyDetector = Depends(get_anomaly),
):
    ip = request.client.host if request.client else "unknown"
    banned = await ban_manager.is_banned(ip)
    if banned:
        await log_event(settings.logging.db_path, ip, request.url.path, "blocked", "banned", 403)
        return Response(status_code=403, content="banned")
    body = await request.body()
    if not hasattr(request.state, "body"):
        request.state.body = body
    verdict = await rule_engine.inspect(request)
    if verdict and verdict.get("action") == "block":
        ban = await ban_manager.ban_ip(ip, verdict.get("message", "blocked"))
        await log_event(settings.logging.db_path, ip, request.url.path, "blocked", verdict.get("message", "rule"), 403)
        return Response(status_code=403, content=f"blocked: {ban['reason']}")
    limiter = get_rate_limiter(request)
    try:
        await limiter.check(request)
    except RateLimitExceeded:
        await behaviour.capture(request, status=429)
        ban = await ban_manager.ban_ip(ip, "rate_limit")
        await log_event(settings.logging.db_path, ip, request.url.path, "blocked", "rate_limit", 429)
        return Response(status_code=429, content=f"rate limited: {ban['reason']}")
    features = await behaviour.capture(request)
    if settings.anomaly.enabled:
        score = anomaly.score(features)
        if score > settings.anomaly.threshold:
            ban = await ban_manager.ban_ip(ip, "anomaly")
            await log_event(settings.logging.db_path, ip, request.url.path, "blocked", "anomaly", 403)
            return Response(status_code=403, content=f"blocked: {ban['reason']}")
    headers = dict(request.headers)
    url = f"{settings.backend_url.rstrip('/')}/{path}"
    async with httpx.AsyncClient(follow_redirects=True) as client:
        proxied = await client.request(
            request.method,
            url,
            headers=headers,
            content=body if body else None,
            params=dict(request.query_params),
        )
    fire_and_forget(
        log_event(
            settings.logging.db_path,
            ip,
            request.url.path,
            "allowed",
            "ok",
            proxied.status_code,
        )
    )
    return Response(
        content=proxied.content,
        status_code=proxied.status_code,
        headers=dict(proxied.headers),
    )

