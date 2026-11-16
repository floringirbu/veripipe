"""VeriPipe gateway - FastAPI app.  Run:  uvicorn gateway.main:app --reload"""
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response

from pr_agent.scan import run_scan
from proof_engine.clients import InProcessClient
from proof_engine.engine import SAMPLE_CSV, resolve

from . import config, ledger
from .pipeline import process_chat
from .policy import load_policy, public_view
from .selftest import run_selftest

app = FastAPI(title="VeriPipe", version="0.1.0",
              description="Runtime-to-Revenue AI Security & Compliance Infrastructure")
DASHBOARD = config.REPO_ROOT / "dashboard" / "index.html"
app.mount("/assets", StaticFiles(directory=config.REPO_ROOT / "dashboard" / "vendor"), name="assets")


def _require_demo():
    if not load_policy().get("demo_mode", False):
        raise HTTPException(403, "demo_mode is disabled in policy.yaml")


# ------------------------------------------------------------------ dashboard

@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(DASHBOARD, media_type="text/html", headers={"Cache-Control": "no-store"})


@app.get("/health")
def health():
    policy = load_policy()
    return {"status": "ok", "policy_version": policy["version"],
            "upstream_mode": public_view(policy)["effective_upstream_mode"],
            "demo_mode": bool(policy.get("demo_mode")), "ledger_records": len(ledger.read_all())}


# ------------------------------------------------------------------ gateway

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(400, "Request body must be JSON")
    messages = payload.get("messages") if isinstance(payload, dict) else None
    if not isinstance(messages, list) or not messages:
        raise HTTPException(400, "'messages' must be a non-empty array")
    if payload.get("stream"):
        raise HTTPException(400, "stream=true is not supported by this MVP gateway; send stream=false")
    status, body = await run_in_threadpool(process_chat, payload, dict(request.headers))
    receipt = body["veripipe"]["receipt"]
    return JSONResponse(body, status_code=status, headers={
        "X-VeriPipe-Action": receipt["action"],
        "X-VeriPipe-Receipt-Id": receipt["receipt_id"],
        "X-VeriPipe-Chain-Hash": receipt["chain_hash"],
        "X-VeriPipe-PII-Redacted": str(receipt["pii_redacted_count"]),
        "X-VeriPipe-Policy-Version": receipt["policy_version"],
    })


@app.get("/v1/policy")
def get_policy():
    return public_view(load_policy())


@app.post("/v1/selftest")
def selftest():
    return run_selftest()


# ------------------------------------------------------------------ ledger

@app.get("/v1/ledger")
def get_ledger(limit: int = 200):
    records = ledger.read_all()
    return {"total_records": len(records), "records": records[-max(1, limit):]}


@app.get("/v1/ledger/verify")
def verify_ledger():
    return ledger.verify()


@app.get("/v1/ledger/stats")
def ledger_stats():
    return InProcessClient().stats()


@app.post("/v1/ledger/tamper")
def tamper_ledger():
    _require_demo()
    return ledger.tamper()


@app.post("/v1/ledger/restore")
def restore_ledger():
    _require_demo()
    return ledger.restore()


@app.post("/v1/ledger/reset")
def reset_ledger():
    _require_demo()
    return ledger.reset()


# ------------------------------------------------------------------ PR agent

def _pr_dir() -> Path:
    return config.data_dir() / "pr_agent"


@app.post("/v1/pr-agent/scan")
def pr_agent_scan(target_dir: str | None = None):
    cfg = load_policy().get("pr_agent", {})
    target = (config.REPO_ROOT / (target_dir or cfg.get("scan_target", "sample-vulnerable-app"))).resolve()
    if config.REPO_ROOT not in target.parents or not target.is_dir():
        raise HTTPException(400, "target_dir must be an existing directory inside the repository")
    return run_scan(target, _pr_dir(), gateway_url=cfg.get("gateway_url", "http://localhost:8000/v1"),
                    base_dir=config.REPO_ROOT)


@app.get("/v1/pr-agent/status")
def pr_agent_status():
    path = _pr_dir() / "scan_status.json"
    return json.loads(path.read_text()) if path.exists() else {"scanned_at": None, "detail": "no scan has run yet"}


# ------------------------------------------------------------------ proof engine

def _proof_dir() -> Path:
    d = config.data_dir() / "proof"
    d.mkdir(parents=True, exist_ok=True)
    return d


@app.post("/v1/proof/questionnaire")
async def proof_questionnaire(request: Request, format: str = "json"):
    """Body: raw CSV text (any content type). Empty body = bundled 12-question sample.
    ?format=json (default: trust pack + CSV text) | csv (completed CSV only)."""
    raw = await request.body()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(400, "CSV must be UTF-8 encoded")
    try:
        pack, csv_out = await run_in_threadpool(resolve, text, InProcessClient())
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    (_proof_dir() / "questionnaire_answers.csv").write_text(csv_out, encoding="utf-8")
    (_proof_dir() / "trust_pack.json").write_text(json.dumps(pack, indent=2), encoding="utf-8")
    if format == "csv":
        return Response(csv_out, media_type="text/csv",
                        headers={"Content-Disposition": 'attachment; filename="veripipe_answers.csv"'})
    return {"trust_pack": pack, "csv": csv_out}


@app.get("/v1/proof/sample.csv")
def proof_sample():
    return PlainTextResponse(SAMPLE_CSV.read_text(encoding="utf-8"), media_type="text/csv")


@app.get("/v1/proof/latest.{ext}")
def proof_latest(ext: str):
    name = {"csv": "questionnaire_answers.csv", "json": "trust_pack.json"}.get(ext)
    path = _proof_dir() / name if name else None
    if not path or not path.exists():
        raise HTTPException(404, "No questionnaire has been resolved yet")
    return FileResponse(path, media_type="text/csv" if ext == "csv" else "application/json",
                        filename=f"veripipe_{name}")
