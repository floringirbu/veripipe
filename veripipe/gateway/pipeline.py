"""The request pipeline: redact -> circuit breaker -> upstream -> ledger receipt."""
import re

from . import ledger, upstream
from .policy import evaluate, load_policy, upstream_mode
from .redaction import messages_text, redact_messages


def _clean(value, default: str) -> str:
    """Client-supplied labels end up in the ledger: restrict to a safe charset."""
    value = re.sub(r"[^A-Za-z0-9_.:\-]", "", str(value or ""))[:64]
    return value or default


def process_chat(payload: dict, headers: dict | None = None, force_mock: bool = False) -> tuple[int, dict]:
    """Returns (http_status, response_body). Always appends exactly one ledger receipt."""
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    policy = load_policy()
    mode = "mock" if force_mock else upstream_mode(policy)
    messages = payload["messages"]

    pii_cfg = policy.get("pii", {})
    if pii_cfg.get("enabled", True):
        redacted, pii_counts = redact_messages(messages, pii_cfg.get("detectors"))
    else:
        redacted, pii_counts = messages, {}
    pii_total = sum(pii_counts.values())

    decision = evaluate(policy, messages_text(messages), messages_text(redacted), payload)

    receipt_fields = {
        "action": "ALLOWED" if decision.allowed else "BLOCKED",
        "block_reason": decision.code,
        "block_detail": decision.detail,
        "pii_redacted_count": pii_total,
        "pii_types": pii_counts,
        "policy_version": policy["version"],
        "policy_hash": policy["policy_hash"],
        "app_id": _clean(headers.get("x-veripipe-app-id"), "unidentified"),
        "data_classification": _clean(headers.get("x-veripipe-data-classification"), "unspecified"),
        "model": _clean(payload.get("model"), "unspecified"),
        "upstream": mode,
        "upstream_status": "not_called",
        "prompt_tokens_est": decision.prompt_tokens,
        "est_cost_usd": decision.est_cost_usd,
        # Hashes only: neither raw nor redacted prompt text is ever written to the ledger.
        "request_hash": ledger.sha256(ledger.canonical(redacted)),
        "response_hash": None,
    }
    veripipe = {"action": receipt_fields["action"], "pii_redacted": pii_counts,
                "redacted_messages": redacted, "upstream": mode}

    if not decision.allowed:
        veripipe["receipt"] = ledger.append(receipt_fields)
        return 403, {
            "error": {
                "message": f"Blocked by VeriPipe policy circuit breaker: {decision.detail}",
                "type": "veripipe_policy_violation",
                "code": decision.code,
            },
            "veripipe": veripipe,
        }

    forward = {**payload, "messages": redacted}
    try:
        if mode == "openai":
            body = upstream.openai_completion(forward, policy, headers.get("authorization"))
        else:
            body = upstream.mock_completion(forward, redacted)
    except upstream.UpstreamError as exc:
        receipt_fields["upstream_status"] = f"error_{exc.status}"
        veripipe["receipt"] = ledger.append(receipt_fields)
        return exc.status, {
            "error": {"message": exc.message, "type": "veripipe_upstream_error", "code": "upstream_error"},
            "veripipe": veripipe,
        }

    receipt_fields["upstream_status"] = "ok"
    receipt_fields["response_hash"] = ledger.sha256(ledger.canonical(body))
    veripipe["receipt"] = ledger.append(receipt_fields)
    return 200, {**body, "veripipe": veripipe}
