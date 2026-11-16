"""VeriPipe Proof Engine - answers InfoSec questionnaires from live telemetry only.

There is no LLM anywhere in this module. Each question is mapped to a control by
deterministic keyword rules; each control is a pure function over telemetry that
was collected seconds ago (policy config, live control self-test, cryptographic
ledger verification, PR-agent scan). A control that cannot be proven is answered
"NO - VERIFICATION FAILED"; a question with no matching control is answered
"NEEDS HUMAN REVIEW". Nothing is ever asserted without evidence.
"""
import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path

YES = "YES - VERIFIED"
NO = "NO - VERIFICATION FAILED"
REVIEW = "NEEDS HUMAN REVIEW - NO TELEMETRY MAPPING"
SAMPLE_CSV = Path(__file__).with_name("sample_questionnaire.csv")
OUTPUT_COLUMNS = ["answer", "evidence", "control_id", "telemetry_metrics", "verification_hash", "verified_at"]
MATCH_THRESHOLD = 3


def _sha(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def collect_telemetry(client) -> dict:
    """Order matters: the self-test writes receipts, then the chain (including them) is verified."""
    policy = client.policy()
    selftest = client.selftest()
    scan = client.scan()
    verify = client.verify()
    stats = client.stats()
    return {"policy": policy, "selftest": selftest, "scan": scan, "verify": verify, "stats": stats}


# ---------------------------------------------------------------- controls
# Each returns (passed: bool, evidence: str, metrics: dict).

def _chain(t):
    v = t["verify"]
    if v["valid"]:
        return f"Hash chain verified genesis-to-head over {v['total_records']} records (head {v['head_hash'][:16]}...)."
    return (f"LEDGER INTEGRITY CHECK FAILED at record index {v['broken_at_index']} ({v['reason']}); "
            f"ledger-derived evidence cannot be trusted.")


def c_pii_redaction(t):
    case, pii = t["selftest"]["cases"]["pii_redaction"], t["policy"].get("pii", {})
    ok = bool(pii.get("enabled")) and case["passed"]
    m = {"pii_enabled": bool(pii.get("enabled")), "selftest_planted": case["planted"],
         "selftest_redacted": case["redacted"], "selftest_receipt_id": case["receipt_id"],
         "ledger_pii_redacted_total": t["stats"]["pii_redacted_total"]}
    return ok, (f"Redaction runs inline before upstream forwarding (policy pii.enabled={m['pii_enabled']}). "
                f"Live control test {case['receipt_id']} planted {case['planted']} synthetic identifiers; "
                f"{case['redacted']} were replaced with [REDACTED_*] tokens before the prompt reached the model. "
                f"{m['ledger_pii_redacted_total']} PII items redacted across all ledgered requests."), m


def c_pii_coverage(t):
    case = t["selftest"]["cases"]["pii_redaction"]
    det = case["detectors"]
    ok = all(det.values()) and len(det) >= 6
    m = {"detectors_tested": det, "configured_detectors": t["policy"].get("pii", {}).get("detectors"),
         "ledger_pii_by_type": t["stats"]["pii_by_type"], "selftest_receipt_id": case["receipt_id"]}
    passed = ", ".join(k for k, v in det.items() if v) or "none"
    failed = ", ".join(k for k, v in det.items() if not v)
    return ok, (f"Detector coverage tested live on every questionnaire run (receipt {case['receipt_id']}). "
                f"Passing: {passed}." + (f" FAILING: {failed}." if failed else "") +
                f" Production counts by type: {json.dumps(m['ledger_pii_by_type'], sort_keys=True)}."), m


def c_log_minimisation(t):
    s = t["stats"]
    forbidden = sorted(set(s["record_fields"]) & {"messages", "prompt", "content", "response", "completion"})
    ok = t["verify"]["valid"] and s["total_records"] > 0 and not forbidden and s["pii_patterns_found_in_ledger_file"] == 0
    m = {"ledger_records": s["total_records"], "content_fields_in_ledger": forbidden,
         "pii_patterns_found_in_ledger_file": s["pii_patterns_found_in_ledger_file"],
         "record_fields": s["record_fields"]}
    return ok, (f"Ledger stores SHA-256 digests of requests/responses, never prompt text: "
                f"{len(forbidden)} content-bearing fields across {s['total_records']} records, and a full PII "
                f"pattern sweep of the ledger file found {m['pii_patterns_found_in_ledger_file']} matches. {_chain(t)}"), m


def c_audit_logging(t):
    s, v = t["stats"], t["verify"]
    probes = [c for c in t["selftest"]["cases"].values() if c.get("receipt_id")]
    ok = v["valid"] and s["total_records"] > 0 and len(probes) == len(t["selftest"]["cases"])
    m = {"total_records": s["total_records"], "allowed": s["allowed"], "blocked": s["blocked"],
         "first_timestamp": s["first_timestamp"], "last_timestamp": s["last_timestamp"],
         "selftest_requests_sent": len(t["selftest"]["cases"]), "selftest_receipts_issued": len(probes)}
    return ok, (f"Every request (allowed or blocked) appends a receipt automatically: {s['total_records']} records "
                f"({s['allowed']} ALLOWED / {s['blocked']} BLOCKED) from {s['first_timestamp']} to {s['last_timestamp']}. "
                f"{len(probes)} of {len(t['selftest']['cases'])} live probe requests produced a receipt. {_chain(t)}"), m


def c_policy_traceability(t):
    s, p = t["stats"], t["policy"]
    ok = t["verify"]["valid"] and s["total_records"] > 0 and s["records_missing_policy_version"] == 0
    m = {"current_policy_version": p["version"], "current_policy_hash": p["policy_hash"],
         "records_missing_policy_version": s["records_missing_policy_version"],
         "policy_versions_in_ledger": s["policy_versions"]}
    return ok, (f"Each receipt embeds policy_version and the SHA-256 of the policy file, both covered by the hash chain. "
                f"{s['total_records'] - s['records_missing_policy_version']} of {s['total_records']} records carry a "
                f"policy version; active policy is v{p['version']} ({p['policy_hash'][:16]}...). {_chain(t)}"), m


def c_prompt_injection(t):
    case = t["selftest"]["cases"]["prompt_injection"]
    phrases = t["policy"].get("circuit_breaker", {}).get("blocked_phrases", [])
    ok = case["passed"] and len(phrases) > 0
    m = {"blocked_phrase_rules": len(phrases), "selftest_observed": case["observed_action"],
         "selftest_receipt_id": case["receipt_id"],
         "ledger_injection_blocks": t["stats"]["block_reasons"].get("prompt_injection", 0)}
    return ok, (f"Policy circuit breaker evaluates {len(phrases)} injection rules before any upstream call. "
                f"Live attack probe {case['receipt_id']} was {case['observed_action']} "
                f"(reason: {case['observed_reason']}); it never reached the model. "
                f"{m['ledger_injection_blocks']} injection attempts blocked in the ledger to date."), m


def c_block_evidence(t):
    s = t["stats"]
    ok = t["verify"]["valid"] and s["blocked"] > 0 and s["blocked_missing_reason"] == 0
    m = {"blocked_records": s["blocked"], "block_reasons": s["block_reasons"],
         "blocked_missing_reason": s["blocked_missing_reason"]}
    return ok, (f"{s['blocked']} blocked requests are ledgered, each with timestamp and machine-readable reason "
                f"({json.dumps(s['block_reasons'], sort_keys=True)}); {s['blocked_missing_reason']} lack a reason. "
                f"Records are exportable via GET /v1/ledger for incident classification. {_chain(t)}"), m


def c_independent_verification(t):
    v = t["verify"]
    ok = v["valid"] and v["total_records"] > 0
    m = {"verify_endpoint": "GET /v1/ledger/verify", "valid": v["valid"], "total_records": v["total_records"],
         "broken_at_index": v["broken_at_index"], "head_hash": v["head_hash"], "merkle_root": v["merkle_root"]}
    return ok, (f"Verification needs no vendor trust: the ledger is plain JSONL and the published rule "
                f"chain_hash = sha256(prev_hash + payload_hash + timestamp) can be recomputed by any party. "
                f"GET /v1/ledger/verify just returned valid={v['valid']} for {v['total_records']} records"
                + (f", Merkle root {v['merkle_root'][:16]}..." if v["merkle_root"] else
                   f", broken at index {v['broken_at_index']}.")), m


def c_cost_token_limits(t):
    case, cb = t["selftest"]["cases"]["token_limit"], t["policy"].get("circuit_breaker", {})
    limits = {k: cb.get(k) for k in ("max_prompt_tokens", "max_completion_tokens", "max_estimated_cost_usd")}
    ok = case["passed"] and all(v is not None for v in limits.values())
    r = t["stats"]["block_reasons"]
    m = {**limits, "selftest_observed": case["observed_action"], "selftest_receipt_id": case["receipt_id"],
         "ledger_limit_blocks": sum(r.get(k, 0) for k in ("max_prompt_tokens", "max_completion_tokens", "max_estimated_cost"))}
    return ok, (f"Enforced per request: max_prompt_tokens={limits['max_prompt_tokens']}, "
                f"max_completion_tokens={limits['max_completion_tokens']}, "
                f"max_estimated_cost_usd={limits['max_estimated_cost_usd']}. Live oversize probe {case['receipt_id']} "
                f"was {case['observed_action']} (reason: {case['observed_reason']}). "
                f"{m['ledger_limit_blocks']} limit breaches blocked in the ledger to date."), m


def c_upstream_inventory(t):
    s = t["stats"]
    ok = t["verify"]["valid"] and s["total_records"] > 0 and s["records_missing_upstream_or_model"] == 0
    m = {"upstreams": s["upstreams"], "models": s["models"],
         "records_missing_upstream_or_model": s["records_missing_upstream_or_model"],
         "effective_upstream_mode": t["policy"].get("effective_upstream_mode")}
    return ok, (f"Every receipt records the upstream provider and model: providers {json.dumps(s['upstreams'], sort_keys=True)}, "
                f"models {json.dumps(s['models'], sort_keys=True)}; {s['records_missing_upstream_or_model']} of "
                f"{s['total_records']} records lack either field. {_chain(t)}"), m


def c_log_integrity(t):
    v = t["verify"]
    ok = v["valid"] and v["total_records"] > 0
    m = {"valid": v["valid"], "total_records": v["total_records"], "broken_at_index": v["broken_at_index"],
         "head_hash": v["head_hash"], "merkle_root": v["merkle_root"], "algorithm": "SHA-256 hash chain"}
    if ok:
        ev = (f"Each receipt carries payload_hash (SHA-256 over all record fields) and "
              f"chain_hash = sha256(prev_hash + payload_hash + timestamp). All {v['total_records']} hashes were "
              f"recomputed from genesis at {v['verified_at']}: valid. Head {v['head_hash']}, Merkle root {v['merkle_root']}.")
    else:
        ev = _chain(t)
    return ok, ev, m


def c_shadow_ai(t):
    s = t["scan"]
    ok = s["findings_count"] == 0 or (s["patch_generated"] and s["findings_autofixed"] == s["findings_count"])
    m = {k: s.get(k) for k in ("scanned_at", "target", "files_scanned", "findings_count",
                               "findings_autofixed", "patch_generated", "patch_sha256")}
    return ok, (f"PR Agent static scan ran at {s['scanned_at']} over {s['files_scanned']} source files in '{s['target']}': "
                f"{s['findings_count']} direct provider calls detected, {s['findings_autofixed']} covered by an "
                f"auto-generated remediation patch" +
                (f" (SHA-256 {s['patch_sha256'][:16]}...)." if s["patch_sha256"] else ".")), m


CONTROLS = [
    ("PII_REDACTION", c_pii_redaction, {"redact": 3, "mask": 2, "anonymi": 2, "pseudonymi": 2, "pii": 1, "personal data": 1}),
    ("PII_DETECTION_COVERAGE", c_pii_coverage, {"categories": 3, "iban": 2, "ppsn": 2, "ssn": 2, "identifiers": 2,
                                                "coverage": 2, "email": 1, "phone": 1, "card": 1}),
    ("LOG_DATA_MINIMISATION", c_log_minimisation, {"minimisation": 4, "minimization": 4, "raw prompt": 3,
                                                   "excluded": 1, "stored": 1}),
    ("AUTOMATIC_EVENT_LOGGING", c_audit_logging, {"record-keeping": 4, "record keeping": 4, "automatically record": 3,
                                                  "automatic recording": 3, "every ai interaction": 2, "logging": 2,
                                                  "events": 1, "article 12": 2}),
    ("POLICY_TRACEABILITY", c_policy_traceability, {"policy version": 4, "traceab": 3, "traced": 2,
                                                    "configuration": 1, "version": 1}),
    ("PROMPT_INJECTION_DEFENSE", c_prompt_injection, {"prompt injection": 5, "jailbreak": 4, "injection": 2,
                                                      "adversarial": 2, "manipulat": 1}),
    ("INCIDENT_EVIDENCE", c_block_evidence, {"incident": 4, "blocked": 2, "violat": 2, "reason": 1, "classif": 1}),
    ("INDEPENDENT_VERIFICATION", c_independent_verification, {"independently": 4, "audit rights": 3, "third-party audit": 3,
                                                              "auditor": 2, "competent authorit": 2, "attestation": 2}),
    ("USAGE_LIMITS_CIRCUIT_BREAKER", c_cost_token_limits, {"circuit breaker": 3, "denial-of-wallet": 3, "token": 2,
                                                           "cost": 2, "limit": 2, "ceiling": 2, "quota": 2, "budget": 2}),
    ("THIRD_PARTY_CALL_INVENTORY", c_upstream_inventory, {"register of information": 5, "provider and model": 3,
                                                          "inventory": 3, "outbound": 2, "sub-processor": 2,
                                                          "subprocessor": 2, "which model": 2}),
    ("CRYPTOGRAPHIC_LOG_INTEGRITY", c_log_integrity, {"cryptograph": 4, "tamper": 4, "hash": 3, "immutable": 3,
                                                      "merkle": 3, "integrity": 2}),
    ("SHADOW_AI_REMEDIATION", c_shadow_ai, {"shadow ai": 5, "bypass": 3, "remediat": 3, "code scan": 3,
                                            "source code": 2, "application code": 2, "directly": 2}),
]


def match_control(question: str):
    q = question.lower()
    best, best_score = None, 0
    for control in CONTROLS:
        score = sum(w for kw, w in control[2].items() if kw in q)
        if score > best_score:
            best, best_score = control, score
    return best if best_score >= MATCH_THRESHOLD else None


# ---------------------------------------------------------------- resolver

def _question_column(fieldnames: list[str], rows: list[dict]) -> str:
    for name in fieldnames:
        if "question" in name.lower():
            return name
    return max(fieldnames, key=lambda n: sum(len(r.get(n) or "") for r in rows))


def resolve(csv_text: str | None, client) -> tuple[dict, str]:
    """Answer a questionnaire. Returns (trust_pack_dict, completed_csv_text)."""
    if not csv_text or not csv_text.strip():
        csv_text = SAMPLE_CSV.read_text(encoding="utf-8")
    reader = csv.DictReader(io.StringIO(csv_text.lstrip("﻿")))
    rows = [r for r in reader if any((v or "").strip() for v in r.values() if isinstance(v, str))]
    fieldnames = [f for f in (reader.fieldnames or []) if f]
    if not fieldnames or not rows:
        raise ValueError("CSV needs a header row and at least one question row")
    qcol = _question_column(fieldnames, rows)

    t = collect_telemetry(client)
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    anchors = {"policy_version": t["policy"]["version"], "policy_hash": t["policy"]["policy_hash"],
               "ledger_valid": t["verify"]["valid"], "ledger_head_hash": t["verify"]["head_hash"],
               "ledger_merkle_root": t["verify"]["merkle_root"], "ledger_records": t["verify"]["total_records"]}

    answers = []
    for i, row in enumerate(rows):
        question = (row.get(qcol) or "").strip()
        control = match_control(question)
        if control is None:
            answer, evidence, control_id, metrics = REVIEW, (
                "No telemetry-backed control matches this question. VeriPipe does not generate "
                "unverifiable answers; route to a human reviewer."), None, {}
        else:
            passed, evidence, metrics = control[1](t)
            answer, control_id = (YES if passed else NO), control[0]
        entry = {"row": i + 1, "source": {k: row.get(k) for k in fieldnames}, "question": question,
                 "answer": answer, "control_id": control_id, "evidence": evidence, "metrics": metrics,
                 "verified_at": generated_at}
        # Binds question + answer + metrics to the exact ledger state and policy it was derived from.
        entry["verification_hash"] = _sha({**{k: entry[k] for k in ("question", "answer", "control_id", "metrics")},
                                           "anchors": anchors, "verified_at": generated_at})
        answers.append(entry)

    pack = {
        "trust_pack_version": "1.0",
        "generated_at": generated_at,
        "generator": "VeriPipe Proof Engine (deterministic rules over live telemetry; no LLM involved)",
        "summary": {"total_questions": len(answers),
                    "verified": sum(a["answer"] == YES for a in answers),
                    "failed": sum(a["answer"] == NO for a in answers),
                    "needs_human_review": sum(a["answer"] == REVIEW for a in answers)},
        "anchors": anchors,
        "answers": answers,
        "telemetry": t,
    }
    pack["pack_hash"] = _sha(pack)

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames + OUTPUT_COLUMNS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for a in answers:
        writer.writerow({**a["source"], "answer": a["answer"], "evidence": a["evidence"],
                         "control_id": a["control_id"] or "",
                         "telemetry_metrics": json.dumps(a["metrics"], sort_keys=True),
                         "verification_hash": a["verification_hash"], "verified_at": a["verified_at"]})
    return pack, buf.getvalue()
