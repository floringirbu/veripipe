"""Standalone runner:  python -m proof_engine.cli [questions.csv] [--gateway http://localhost:8000]

Without --gateway the engine reads telemetry in-process (same data dir as the gateway).
"""
import argparse
import json
import sys
from pathlib import Path

from .clients import HttpClient, InProcessClient
from .engine import resolve


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Resolve an InfoSec questionnaire from live VeriPipe telemetry.")
    ap.add_argument("csv", nargs="?", help="questionnaire CSV (default: bundled 12-question sample)")
    ap.add_argument("--gateway", help="base URL of a running gateway; omit to run in-process")
    ap.add_argument("--out-dir", default=".")
    args = ap.parse_args(argv)
    text = Path(args.csv).read_text(encoding="utf-8") if args.csv else None
    pack, csv_out = resolve(text, HttpClient(args.gateway) if args.gateway else InProcessClient())
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "questionnaire_answers.csv").write_text(csv_out, encoding="utf-8")
    (out / "trust_pack.json").write_text(json.dumps(pack, indent=2), encoding="utf-8")
    s = pack["summary"]
    print(f"{s['verified']}/{s['total_questions']} verified, {s['failed']} failed, "
          f"{s['needs_human_review']} need human review. pack_hash={pack['pack_hash']}")
    print(f"Wrote {out / 'questionnaire_answers.csv'} and {out / 'trust_pack.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
