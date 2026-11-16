"""LLM upstreams: built-in Mock LLM (default, zero keys) and optional OpenAI pass-through."""
import os
import time
import uuid

import httpx

from .policy import estimate_tokens
from .redaction import messages_text


class UpstreamError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def mock_completion(payload: dict, redacted_messages: list) -> dict:
    """Deterministic OpenAI-compatible response that echoes exactly what the model was sent."""
    last_user = next(
        (m for m in reversed(redacted_messages) if isinstance(m, dict) and m.get("role") == "user"),
        redacted_messages[-1] if redacted_messages else {},
    )
    seen = messages_text([last_user]).strip()
    preview = seen if len(seen) <= 600 else seen[:600] + "..."
    content = (
        "[VeriPipe Mock LLM] Request received via the gateway. "
        f"This is the exact prompt that reached the model:\n\n{preview}"
    )
    prompt_tokens = estimate_tokens(messages_text(redacted_messages))
    completion_tokens = estimate_tokens(content)
    return {
        "id": "chatcmpl-mock-" + uuid.uuid4().hex[:24],
        "object": "chat.completion",
        "created": int(time.time()),
        "model": str(payload.get("model") or "veripipe-mock-1"),
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


def openai_completion(payload: dict, policy: dict, client_authorization: str | None) -> dict:
    cfg = policy.get("upstream", {})
    key = os.environ.get("OPENAI_API_KEY")
    auth = f"Bearer {key}" if key else client_authorization
    if not auth:
        raise UpstreamError(502, "Upstream mode is 'openai' but no OPENAI_API_KEY is set and the "
                                 "client sent no Authorization header.")
    url = str(cfg.get("openai_base_url", "https://api.openai.com/v1")).rstrip("/") + "/chat/completions"
    try:
        resp = httpx.post(url, json=payload, headers={"Authorization": auth},
                          timeout=float(cfg.get("timeout_seconds", 30)))
    except httpx.HTTPError as exc:
        raise UpstreamError(502, f"Upstream request failed: {exc.__class__.__name__}") from exc
    try:
        body = resp.json()
    except ValueError as exc:
        raise UpstreamError(502, f"Upstream returned non-JSON (HTTP {resp.status_code})") from exc
    if resp.status_code >= 400:
        msg = (body.get("error") or {}).get("message") if isinstance(body, dict) else None
        raise UpstreamError(resp.status_code, msg or f"Upstream returned HTTP {resp.status_code}")
    return body
