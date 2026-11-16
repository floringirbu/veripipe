"""Telemetry sources for the Proof Engine. Both expose the same five calls."""
from pathlib import Path


class InProcessClient:
    """Used when the Proof Engine runs inside the gateway process (no HTTP hop)."""

    def policy(self):
        from gateway.policy import load_policy, public_view
        return public_view(load_policy())

    def selftest(self):
        from gateway.selftest import run_selftest
        return run_selftest()

    def verify(self):
        from gateway import ledger
        return ledger.verify()

    def stats(self):
        from gateway import ledger
        from gateway.redaction import redact_text
        s = ledger.stats()
        s["pii_patterns_found_in_ledger_file"] = sum(redact_text(ledger.raw_text())[1].values())
        return s

    def scan(self):
        from gateway import config
        from gateway.policy import load_policy
        from pr_agent.scan import run_scan
        cfg = load_policy().get("pr_agent", {})
        target = (config.REPO_ROOT / cfg.get("scan_target", "sample-vulnerable-app")).resolve()
        result = run_scan(target, Path(config.data_dir()) / "pr_agent",
                          gateway_url=cfg.get("gateway_url", "http://localhost:8000/v1"),
                          base_dir=config.REPO_ROOT)
        return {k: v for k, v in result.items() if k not in ("patch", "summary_md", "findings")}


class HttpClient:
    """Used by the standalone CLI against a running gateway."""

    def __init__(self, base_url: str):
        import httpx
        self._http = httpx.Client(base_url=base_url.rstrip("/"), timeout=30)

    def _call(self, method, path):
        resp = self._http.request(method, path)
        resp.raise_for_status()
        return resp.json()

    def policy(self):
        return self._call("GET", "/v1/policy")

    def selftest(self):
        return self._call("POST", "/v1/selftest")

    def verify(self):
        return self._call("GET", "/v1/ledger/verify")

    def stats(self):
        return self._call("GET", "/v1/ledger/stats")

    def scan(self):
        r = self._call("POST", "/v1/pr-agent/scan")
        return {k: v for k, v in r.items() if k not in ("patch", "summary_md", "findings")}
