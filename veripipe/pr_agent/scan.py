#!/usr/bin/env python3
"""VeriPipe PR Agent - finds direct, ungoverned OpenAI calls and writes the fix.

    python pr_agent/scan.py <target_dir> [--gateway-url URL] [--app-id ID] [--out-dir DIR]

Outputs (in --out-dir, default: current directory):
    remediation.patch   unified git diff re-routing every call through the VeriPipe gateway
    PR_SUMMARY.md       ready-to-paste pull request description
    scan_status.json    machine-readable status (consumed by the Proof Engine)

Standard library only, so it can run in any CI job.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_GATEWAY_URL = "http://localhost:8000/v1"
PY_EXT = {".py"}
JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".next"}

PY_CTOR = re.compile(r"(?<![\w.])((?:openai\.)?(?:Async)?OpenAI)\s*\(")
JS_CTOR = re.compile(r"\bnew\s+(OpenAI)\s*\(")
OPENAI_URL = re.compile(r"https?://api\.openai\.com(/v1)?")
AUTH_LINE = re.compile(r"""^(\s*)["']?Authorization["']?\s*:""")

RULES = {
    "unprotected-sdk-client": "OpenAI SDK client created without a gateway base URL - prompts go "
                              "straight to api.openai.com with no PII redaction, policy check or audit receipt.",
    "direct-api-url": "Hard-coded api.openai.com endpoint - raw HTTP call bypasses the VeriPipe gateway.",
}


def compliance_headers(app_id: str) -> list[tuple[str, str]]:
    return [
        ("X-VeriPipe-App-Id", app_id),
        ("X-VeriPipe-Data-Classification", "confidential"),
        ("X-VeriPipe-Regulatory-Scope", "gdpr,eu-ai-act,dora"),
    ]


# ------------------------------------------------------------------ helpers

def _matching_paren(text: str, open_idx: int) -> int | None:
    """Index of the ')' closing the '(' at open_idx, skipping string literals."""
    depth, i, n = 0, open_idx, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'`":
            quote = text[i:i + 3] if text[i:i + 3] in ('"""', "'''") else ch
            i += len(quote)
            while i < n and not text.startswith(quote, i):
                i += 2 if text[i] == "\\" else 1
            i += len(quote)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def _indent_at(text: str, idx: int) -> str:
    start = text.rfind("\n", 0, idx) + 1
    return re.match(r"[ \t]*", text[start:]).group(0)


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith(("#", "//", "*", "/*"))


def _line_text(text: str, idx: int) -> str:
    start = text.rfind("\n", 0, idx) + 1
    end = text.find("\n", idx)
    return text[start:end if end != -1 else len(text)]


# ------------------------------------------------------------------ rewrites

def _rewrite_constructors(text: str, lang: str, gateway_url: str, app_id: str, findings: list, rel: str) -> str:
    pattern = PY_CTOR if lang == "python" else JS_CTOR
    edits = []
    for m in pattern.finditer(text):
        if _is_comment(_line_text(text, m.start())):
            continue
        open_idx = m.end() - 1
        close_idx = _matching_paren(text, open_idx)
        if close_idx is None:
            continue
        args = text[open_idx + 1:close_idx]
        if re.search(r"\bbase_?url\b", args, re.IGNORECASE):
            continue  # already has an explicit endpoint (a literal api.openai.com is caught by the URL rule)
        indent = _indent_at(text, m.start())
        headers = compliance_headers(app_id)
        if lang == "python":
            inner = args.strip().rstrip(",").rstrip()
            pad = indent + "    "
            lines = [f"{m.group(1)}("]
            if inner:
                lines.append(f"{pad}{inner},")
            lines.append(f'{pad}base_url="{gateway_url}",  # routed through the VeriPipe gateway')
            lines.append(f"{pad}default_headers={{")
            lines += [f'{pad}    "{k}": "{v}",' for k, v in headers]
            lines += [f"{pad}}},", f"{indent})"]
            replacement, start = "\n".join(lines), m.start()
        else:
            stripped = args.strip()
            if stripped and not (stripped.startswith("{") and stripped.endswith("}")):
                findings.append(_finding(rel, text, m.start(), "unprotected-sdk-client", lang, autofix=False))
                continue
            inner = stripped[1:-1].strip().rstrip(",").rstrip() if stripped else ""
            pad = indent + "  "
            lines = ["new OpenAI({"]
            if inner:
                lines.append(f"{pad}{inner},")
            lines.append(f'{pad}baseURL: "{gateway_url}", // routed through the VeriPipe gateway')
            lines.append(f"{pad}defaultHeaders: {{")
            lines += [f'{pad}  "{k}": "{v}",' for k, v in headers]
            lines += [f"{pad}}},", f"{indent}}})"]
            replacement, start = "\n".join(lines), m.start()
        findings.append(_finding(rel, text, m.start(), "unprotected-sdk-client", lang, autofix=True))
        edits.append((start, close_idx + 1, replacement))
    for start, end, replacement in reversed(edits):
        text = text[:start] + replacement + text[end:]
    return text


def _rewrite_urls(text: str, gateway_url: str, app_id: str) -> tuple[str, int, int]:
    """Replace api.openai.com literals; add compliance headers next to an Authorization header.
    Returns (text, urls_rewritten, header_blocks_added)."""
    gateway_root = re.sub(r"/v1/?$", "", gateway_url)
    lines = text.split("\n")
    out, urls, header_blocks = [], 0, 0
    pending = 0  # lines left in which to look for an Authorization header
    for line in lines:
        if not _is_comment(line) and OPENAI_URL.search(line):
            line, n = OPENAI_URL.subn(lambda m: gateway_url if m.group(1) else gateway_root, line)
            urls += n
            pending = 12
        out.append(line)
        if pending:
            m = AUTH_LINE.match(line)
            if m:
                if not line.rstrip().endswith(","):
                    out[-1] = line.rstrip() + ","
                out += [f'{m.group(1)}"{k}": "{v}",' for k, v in compliance_headers(app_id)]
                header_blocks += 1
                pending = 0
            else:
                pending -= 1
    return "\n".join(out), urls, header_blocks


def _finding(rel: str, text: str, idx: int, rule: str, lang: str, autofix: bool) -> dict:
    return {"file": rel, "line": _line_of(text, idx), "rule": rule, "language": lang,
            "snippet": _line_text(text, idx).strip()[:160], "description": RULES[rule], "autofix": autofix}


def remediate_source(text: str, rel: str, lang: str, gateway_url: str, app_id: str) -> tuple[str, list]:
    findings: list = []
    for m in OPENAI_URL.finditer(text):
        if not _is_comment(_line_text(text, m.start())):
            findings.append(_finding(rel, text, m.start(), "direct-api-url", lang, autofix=True))
    new_text = _rewrite_constructors(text, lang, gateway_url, app_id, findings, rel)
    new_text, _, header_blocks = _rewrite_urls(new_text, gateway_url, app_id)
    url_findings = [f for f in findings if f["rule"] == "direct-api-url"]
    for f in url_findings:
        f["headers_added"] = header_blocks >= len(url_findings)
    findings.sort(key=lambda f: f["line"])
    return new_text, findings


# ------------------------------------------------------------------ diff + report

def _git_diff(rel: str, old: str, new: str) -> str:
    def split(s):
        parts = s.splitlines(keepends=True)
        if parts and not parts[-1].endswith("\n"):
            parts[-1] += "\n\\ No newline at end of file\n"
        return parts
    body = "".join(difflib.unified_diff(split(old), split(new), fromfile=f"a/{rel}", tofile=f"b/{rel}"))
    return f"diff --git a/{rel} b/{rel}\n{body}" if body else ""


def _summary_md(result: dict, patch: str) -> str:
    f_count = len(result["findings"])
    if not f_count:
        return (f"# VeriPipe scan: no ungoverned LLM calls found\n\n"
                f"Scanned `{result['target']}` ({result['files_scanned']} source files) at {result['scanned_at']}. "
                f"Every OpenAI call already routes through a gateway base URL. No changes required.\n")
    rows = "\n".join(
        f"| `{f['file']}:{f['line']}` | `{f['rule']}` | `{f['snippet'].replace('|', chr(92) + '|')}` | "
        f"{'auto-fixed' if f['autofix'] else 'manual review'} |" for f in result["findings"])
    manual = [f for f in result["findings"] if not f["autofix"] or f.get("headers_added") is False]
    manual_md = ""
    if manual:
        manual_md = "\n### Needs manual follow-up\n\n" + "\n".join(
            f"- `{f['file']}:{f['line']}` - " + ("constructor arguments could not be rewritten automatically"
                                                 if not f["autofix"] else
                                                 "URL re-routed, but no `Authorization` header line was found nearby; "
                                                 "add the `X-VeriPipe-*` headers by hand")
            for f in manual) + "\n"
    headers_md = "\n".join(f"| `{k}` | `{v}` |" for k, v in compliance_headers(result["app_id"]))
    return f"""# Route LLM traffic through the VeriPipe gateway ({f_count} ungoverned call{'s' if f_count != 1 else ''})

> Generated by the VeriPipe PR Agent on {result['scanned_at']} - target `{result['target']}`

## Why

{f_count} call site{'s' if f_count != 1 else ''} in {result['files_affected']} file{'s' if result['files_affected'] != 1 else ''} send prompts **directly to `api.openai.com`**. Those requests have:

- no PII redaction (emails, phone numbers, IBANs, card numbers, PPSN/SSN leave the perimeter in clear text),
- no prompt-injection / token / cost circuit breaker,
- no tamper-evident audit receipt (EU AI Act Art. 12 record-keeping, DORA Art. 28/30 auditability).

## Findings

| Location | Rule | Code | Status |
|---|---|---|---|
{rows}
{manual_md}
## What this PR changes

- SDK clients (`OpenAI(...)` / `new OpenAI(...)`) get `base_url` / `baseURL` = `{result['gateway_url']}` plus default compliance headers.
- Raw HTTP calls to `https://api.openai.com/v1/...` are re-pointed at `{result['gateway_url']}/...` and carry the same headers.
- No business logic, model names, prompts or API-key handling is touched. The gateway is OpenAI-wire-compatible, so responses are unchanged.

| Compliance header | Value |
|---|---|
{headers_md}

## How to apply

```bash
git apply --check remediation.patch   # dry run
git apply remediation.patch
```

Patch SHA-256: `{result['patch_sha256']}`

## Reviewer checklist

- [ ] Gateway URL `{result['gateway_url']}` is correct for this environment (prefer an env var per deploy stage)
- [ ] `X-VeriPipe-App-Id` identifies the owning service
- [ ] Egress firewall blocks direct access to `api.openai.com` once merged
- [ ] `GET /v1/ledger/verify` returns `valid: true` after a smoke test

## Diff

```diff
{patch.rstrip()}
```
"""


# ------------------------------------------------------------------ entry points

def scan_directory(target, gateway_url: str = DEFAULT_GATEWAY_URL, app_id: str | None = None,
                   base_dir=None) -> dict:
    """Scan `target`; return findings, patch text and PR summary (nothing is written to disk).
    Diff paths are relative to `base_dir` (default: cwd if target is inside it, else target's parent)."""
    target = Path(target).resolve()
    if not target.is_dir():
        raise NotADirectoryError(f"{target} is not a directory")
    if base_dir is None:
        cwd = Path.cwd().resolve()
        base_dir = cwd if target != cwd and cwd in target.parents else target.parent
    base_dir = Path(base_dir).resolve()
    app_id = app_id or re.sub(r"[^A-Za-z0-9_.-]", "-", target.name) or "app"
    gateway_url = gateway_url.rstrip("/")

    findings, diffs, files_scanned = [], [], 0
    for path in sorted(target.rglob("*")):
        if not path.is_file() or path.suffix not in PY_EXT | JS_EXT:
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(target).parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        files_scanned += 1
        rel = path.relative_to(base_dir).as_posix()
        lang = "python" if path.suffix in PY_EXT else "javascript"
        new_text, file_findings = remediate_source(text, rel, lang, gateway_url, app_id)
        findings += file_findings
        if new_text != text:
            diffs.append(_git_diff(rel, text, new_text))

    patch = "".join(diffs)
    result = {
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": target.relative_to(base_dir).as_posix() if base_dir in target.parents else str(target),
        "gateway_url": gateway_url,
        "app_id": app_id,
        "files_scanned": files_scanned,
        "files_affected": len({f["file"] for f in findings}),
        "findings_count": len(findings),
        "findings_autofixed": sum(f["autofix"] for f in findings),
        "findings": findings,
        "patch_generated": bool(patch),
        "patch_sha256": hashlib.sha256(patch.encode()).hexdigest() if patch else None,
    }
    result["patch"] = patch
    result["summary_md"] = _summary_md(result, patch)
    return result


def run_scan(target, out_dir=".", **kwargs) -> dict:
    """scan_directory() + write remediation.patch, PR_SUMMARY.md and scan_status.json to out_dir."""
    result = scan_directory(target, **kwargs)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "remediation.patch").write_text(result["patch"], encoding="utf-8")
    (out / "PR_SUMMARY.md").write_text(result["summary_md"], encoding="utf-8")
    status = {k: v for k, v in result.items() if k not in ("patch", "summary_md")}
    (out / "scan_status.json").write_text(json.dumps(status, indent=2), encoding="utf-8")
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Scan for ungoverned OpenAI calls and generate a remediation PR.")
    ap.add_argument("target_dir")
    ap.add_argument("--gateway-url", default=DEFAULT_GATEWAY_URL)
    ap.add_argument("--app-id", default=None, help="value for X-VeriPipe-App-Id (default: target dir name)")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--fail-on-findings", action="store_true", help="exit 1 if anything is found (for CI)")
    args = ap.parse_args(argv)
    try:
        result = run_scan(args.target_dir, args.out_dir, gateway_url=args.gateway_url, app_id=args.app_id)
    except NotADirectoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"VeriPipe PR Agent - scanned {result['files_scanned']} files in {result['target']}")
    for f in result["findings"]:
        print(f"  [{f['rule']}] {f['file']}:{f['line']}  {f['snippet']}")
    out = Path(args.out_dir)
    print(f"{result['findings_count']} finding(s) in {result['files_affected']} file(s).")
    print(f"Wrote {out / 'remediation.patch'}, {out / 'PR_SUMMARY.md'}, {out / 'scan_status.json'}")
    return 1 if args.fail_on_findings and result["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
