from pathlib import Path
import yaml
from fastapi import Request


class RuleEngine:
    def __init__(self, rules_path: Path) -> None:
        self.rules_path = rules_path
        self.rules = self._load_rules()

    def _load_rules(self) -> list[dict]:
        with self.rules_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("rules", [])

    async def inspect(self, request: Request) -> dict | None:
        url = str(request.url.path)
        query_params = str(request.query_params)
        if hasattr(request.state, "body"):
            body_bytes = request.state.body
        else:
            body_bytes = await request.body()
            request.state.body = body_bytes
        body_text = body_bytes.decode(errors="ignore")
        payload = f"{url}\n{query_params}\n{body_text}".lower()
        for rule in self.rules:
            if rule.get("type") == "contains":
                for pattern in rule.get("patterns", []):
                    if pattern.lower() in payload:
                        return {
                            "id": rule.get("id"),
                            "message": rule.get("message"),
                            "action": rule.get("action", "block"),
                        }
        return None

