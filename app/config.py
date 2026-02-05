from functools import lru_cache
from pathlib import Path
import yaml
from pydantic import BaseModel


class RateLimitConfig(BaseModel):
    requests: int
    per_seconds: int


class AnomalyConfig(BaseModel):
    enabled: bool
    threshold: float


class BanConfig(BaseModel):
    duration_seconds: int


class LoggingConfig(BaseModel):
    db_path: str
    level: str


class DashboardConfig(BaseModel):
    secret_key: str


class Settings(BaseModel):
    backend_url: str
    rate_limit: RateLimitConfig
    anomaly: AnomalyConfig
    ban: BanConfig
    logging: LoggingConfig
    dashboard: DashboardConfig


def _load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


@lru_cache
def get_settings(config_path: Path | None = None) -> Settings:
    base = Path(__file__).resolve().parent.parent
    path = config_path or base / "config.yaml"
    data = _load_yaml(path)
    return Settings(**data)

