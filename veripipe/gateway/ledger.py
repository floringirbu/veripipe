"""Tamper-evident, SHA-256 hash-chained audit ledger (append-only JSONL).

    payload_hash = sha256(canonical_json(all receipt fields except the three hash fields))
    chain_hash   = sha256(prev_hash + payload_hash + timestamp)

Because payload_hash covers every business field, editing *any* field of *any*
record (or deleting / reordering / inserting records) breaks verification.
"""
import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone

from . import config

GENESIS_HASH = "0" * 64
HASH_FIELDS = ("payload_hash", "prev_hash", "chain_hash")
_lock = threading.Lock()


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def payload_hash_of(record: dict) -> str:
    return sha256(canonical({k: v for k, v in record.items() if k not in HASH_FIELDS}))


def chain_hash_of(prev_hash: str, payload_hash: str, timestamp: str) -> str:
    return sha256(prev_hash + payload_hash + timestamp)


def _lines() -> list[str]:
    path = config.ledger_path()
    if not path.exists():
        return []
    return [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _backup_path():
    return config.data_dir() / ".tamper_backup.json"


def append(fields: dict) -> dict:
    """Append a receipt. `fields` must contain at least action / pii_redacted_count / policy_version."""
    with _lock:
        lines = _lines()
        prev_hash = GENESIS_HASH
        if lines:
            try:
                prev_hash = json.loads(lines[-1])["chain_hash"]
            except Exception:
                prev_hash = sha256(lines[-1])  # corrupted tail: keep chaining, verify will flag it
        record = {
            "receipt_id": "rcpt_" + uuid.uuid4().hex,
            "seq": len(lines),
            "timestamp": now_iso(),
            **fields,
        }
        record["payload_hash"] = payload_hash_of(record)
        record["prev_hash"] = prev_hash
        record["chain_hash"] = chain_hash_of(prev_hash, record["payload_hash"], record["timestamp"])
        with config.ledger_path().open("a", encoding="utf-8") as fh:
            fh.write(canonical(record) + "\n")
        return record


def read_all() -> list[dict]:
    out = []
    for i, line in enumerate(_lines()):
        try:
            out.append(json.loads(line))
        except Exception:
            out.append({"seq": i, "corrupt": True, "raw": line[:200]})
    return out


def merkle_root(leaves: list[str]) -> str | None:
    if not leaves:
        return None
    level = leaves[:]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def verify() -> dict:
    """Re-compute every hash from genesis to head."""
    with _lock:
        lines = _lines()
    result = {
        "valid": True,
        "total_records": len(lines),
        "broken_at_index": None,
        "reason": None,
        "genesis_hash": GENESIS_HASH,
        "head_hash": GENESIS_HASH,
        "merkle_root": None,
        "verified_at": now_iso(),
    }

    def broken(i, reason):
        result.update(valid=False, broken_at_index=i, reason=reason, head_hash=None, merkle_root=None)
        return result

    prev, leaves = GENESIS_HASH, []
    for i, line in enumerate(lines):
        try:
            rec = json.loads(line)
        except Exception:
            return broken(i, "record is not valid JSON")
        if not isinstance(rec, dict) or any(f not in rec for f in HASH_FIELDS + ("timestamp",)):
            return broken(i, "record is missing hash fields")
        if rec.get("seq") != i:
            return broken(i, f"sequence mismatch (expected {i}, found {rec.get('seq')})")
        if rec["prev_hash"] != prev:
            return broken(i, "prev_hash does not match the previous record's chain_hash")
        if payload_hash_of(rec) != rec["payload_hash"]:
            return broken(i, "payload_hash mismatch: record contents were modified")
        if chain_hash_of(prev, rec["payload_hash"], rec["timestamp"]) != rec["chain_hash"]:
            return broken(i, "chain_hash mismatch")
        prev = rec["chain_hash"]
        leaves.append(prev)
    result["head_hash"] = prev
    result["merkle_root"] = merkle_root(leaves)
    return result


def stats() -> dict:
    records = [r for r in read_all() if not r.get("corrupt")]
    pii_by_type, reasons, upstreams, models, versions, keys = {}, {}, {}, {}, {}, set()
    for r in records:
        keys |= set(r)
        for k, v in (r.get("pii_types") or {}).items():
            pii_by_type[k] = pii_by_type.get(k, 0) + v
        if r.get("action") == "BLOCKED":
            reasons[r.get("block_reason")] = reasons.get(r.get("block_reason"), 0) + 1
        for bucket, field in ((upstreams, "upstream"), (models, "model"), (versions, "policy_version")):
            bucket[str(r.get(field))] = bucket.get(str(r.get(field)), 0) + 1
    return {
        "total_records": len(records),
        "allowed": sum(r.get("action") == "ALLOWED" for r in records),
        "blocked": sum(r.get("action") == "BLOCKED" for r in records),
        "pii_redacted_total": sum(int(r.get("pii_redacted_count") or 0) for r in records),
        "pii_by_type": pii_by_type,
        "block_reasons": reasons,
        "upstreams": upstreams,
        "models": models,
        "policy_versions": versions,
        "records_missing_policy_version": sum(not r.get("policy_version") for r in records),
        "records_missing_upstream_or_model": sum(not r.get("upstream") or not r.get("model") for r in records),
        "blocked_missing_reason": sum(r.get("action") == "BLOCKED" and not r.get("block_reason") for r in records),
        "selftest_records": sum(r.get("app_id") == "veripipe-selftest" for r in records),
        "first_timestamp": records[0]["timestamp"] if records else None,
        "last_timestamp": records[-1]["timestamp"] if records else None,
        "record_fields": sorted(keys),
    }


def raw_text() -> str:
    path = config.ledger_path()
    return path.read_text(encoding="utf-8") if path.exists() else ""


# ---------------------------------------------------------------- demo helpers

def tamper() -> dict:
    """DEMO: silently rewrite one record on disk without fixing its hashes.
    Prefers flipping the latest BLOCKED record to ALLOWED (hiding an attack)."""
    with _lock:
        lines = _lines()
        if not lines:
            return {"tampered": False, "detail": "ledger is empty - send a request first"}
        records = [json.loads(ln) for ln in lines]
        idx = next((i for i in range(len(records) - 1, -1, -1) if records[i].get("action") == "BLOCKED"), None)
        if idx is not None:
            field, old, new = "action", "BLOCKED", "ALLOWED"
        else:
            idx = len(records) - 1
            field, old = "pii_redacted_count", records[idx].get("pii_redacted_count", 0)
            new = int(old or 0) + 7
        bpath = _backup_path()
        backup = json.loads(bpath.read_text()) if bpath.exists() else []
        if not any(b["index"] == idx for b in backup):
            backup.append({"index": idx, "line": lines[idx]})
            bpath.write_text(json.dumps(backup))
        records[idx][field] = new
        lines[idx] = canonical(records[idx])
        config.ledger_path().write_text("\n".join(lines) + "\n", encoding="utf-8")
        return {"tampered": True, "index": idx, "field": field, "old_value": old, "new_value": new,
                "receipt_id": records[idx].get("receipt_id")}


def restore() -> dict:
    """DEMO: undo tamper() by putting the original lines back."""
    with _lock:
        bpath = _backup_path()
        if not bpath.exists():
            return {"restored": 0}
        lines = _lines()
        backup = json.loads(bpath.read_text())
        for b in backup:
            if b["index"] < len(lines):
                lines[b["index"]] = b["line"]
        config.ledger_path().write_text("\n".join(lines) + "\n" if lines else "", encoding="utf-8")
        bpath.unlink()
        return {"restored": len(backup)}


def reset() -> dict:
    """DEMO: wipe the ledger."""
    with _lock:
        for p in (config.ledger_path(), _backup_path()):
            if p.exists():
                p.unlink()
    return {"reset": True}
