"""Paths and environment-driven settings (resolved at call time so tests can override)."""
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    d = Path(os.environ.get("VERIPIPE_DATA_DIR", REPO_ROOT / "data"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def policy_path() -> Path:
    return Path(os.environ.get("VERIPIPE_POLICY_PATH", REPO_ROOT / "policy.yaml"))


def ledger_path() -> Path:
    return data_dir() / "audit_ledger.jsonl"
