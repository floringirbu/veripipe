"""Policy loading (hot-reloaded policy.yaml) and the circuit breaker."""
import hashlib
import math
import os
import re
from dataclasses import dataclass

import yaml

from . import config

_cache = {"key": None, "policy": None}


def load_policy() -> dict:
    path = config.policy_path()
    raw = path.read_bytes()
    key = (str(path), hashlib.sha256(raw).hexdigest())
    if _cache["key"] != key:
        policy = yaml.safe_load(raw) or {}
        policy["version"] = str(policy.get("version", "unversioned"))
        policy["policy_hash"] = key[1]
        _cache.update(key=key, policy=policy)
    return _cache["policy"]


def upstream_mode(policy: dict) -> str:
    mode = os.environ.get("VERIPIPE_UPSTREAM_MODE") or policy.get("upstream", {}).get("mode", "mock")
    return "openai" if str(mode).lower() == "openai" else "mock"


def public_view(policy: dict) -> dict:
    view = dict(policy)
    view["effective_upstream_mode"] = upstream_mode(policy)
    return view


def estimate_tokens(text: str) -> int:
    return math.ceil(len(text) / 4) if text else 0


def _normalize(text: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", text.lower()).split())


@dataclass
class Decision:
    allowed: bool
    code: str | None
    detail: str | None
    prompt_tokens: int
    completion_budget: int
    est_cost_usd: float


def evaluate(policy: dict, original_text: str, redacted_text: str, payload: dict) -> Decision:
    """Run the circuit breaker. Injection is checked on the original text,
    token/cost limits on the redacted text that would actually be forwarded."""
    cb = policy.get("circuit_breaker", {})
    prompt_tokens = estimate_tokens(redacted_text)

    requested = payload.get("max_tokens") or payload.get("max_completion_tokens")
    try:
        budget = int(requested) if requested else int(cb.get("default_completion_tokens", 256))
    except (TypeError, ValueError):
        budget = int(cb.get("default_completion_tokens", 256))

    pricing = policy.get("pricing", {})
    price = pricing.get("models", {}).get(str(payload.get("model")), pricing.get("default", {}))
    cost = round(
        prompt_tokens / 1000 * float(price.get("input_per_1k", 0))
        + budget / 1000 * float(price.get("output_per_1k", 0)),
        6,
    )

    def decision(code=None, detail=None):
        return Decision(code is None, code, detail, prompt_tokens, budget, cost)

    haystack = f" {_normalize(original_text)} "
    for phrase in cb.get("blocked_phrases", []):
        if f" {_normalize(str(phrase))} " in haystack:
            return decision("prompt_injection", f"matched blocked phrase '{phrase}'")

    max_prompt = cb.get("max_prompt_tokens")
    if max_prompt is not None and prompt_tokens > int(max_prompt):
        return decision("max_prompt_tokens", f"estimated {prompt_tokens} prompt tokens > limit {max_prompt}")

    max_completion = cb.get("max_completion_tokens")
    if max_completion is not None and budget > int(max_completion):
        return decision("max_completion_tokens", f"requested {budget} completion tokens > limit {max_completion}")

    max_cost = cb.get("max_estimated_cost_usd")
    if max_cost is not None and cost > float(max_cost):
        return decision("max_estimated_cost", f"estimated cost ${cost:.4f} > limit ${float(max_cost):.4f}")

    return decision()
