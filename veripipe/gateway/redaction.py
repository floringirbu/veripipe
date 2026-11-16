"""Real-time PII redaction engine (pure regex + checksum validation, no ML, no network)."""
import copy
import re

ALL_DETECTORS = ["EMAIL", "IBAN", "CREDIT_CARD", "SSN", "PPSN", "PHONE"]  # applied in this order

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,3})?\b")
_CARD = re.compile(r"(?<![\w-])\d(?:[ -]?\d){12,18}(?![\w-])")
_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_PPSN = re.compile(r"\b\d{7}[A-W][A-IW]?\b")
_PHONE = re.compile(r"(?<![\w+])\+?\(?\d[\d ().-]{5,}\d(?!\w)")
_DATE = re.compile(r"^\d{4}[-.]\d{2}[-.]\d{2}")


def _iban_valid(compact: str) -> bool:
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    return int("".join(str(int(c, 36)) for c in rearranged)) % 97 == 1


def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _sub_iban(m: re.Match) -> str:
    candidate = m.group(0)
    # The pattern may swallow trailing upper-case words; trim back to the longest valid IBAN.
    parts = re.split(r"([ -])", candidate)
    for end in range(len(parts), 0, -2):
        prefix = "".join(parts[:end])
        if _iban_valid(re.sub(r"[ -]", "", prefix)):
            return "[REDACTED_IBAN]" + candidate[len(prefix):]
    # No checksum-valid form: still redact anything IBAN-shaped (fail closed).
    return "[REDACTED_IBAN]" if len(re.sub(r"[ -]", "", candidate)) >= 15 else candidate


def _sub_card(m: re.Match) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    return "[REDACTED_CREDIT_CARD]" if _luhn_valid(digits) else m.group(0)


def _sub_phone(m: re.Match) -> str:
    cand = m.group(0)
    if _DATE.match(cand):
        return cand
    n = len(re.sub(r"\D", "", cand))
    if cand.startswith("+"):
        ok = 8 <= n <= 15
    elif cand[0] in "0(":
        ok = 9 <= n <= 12
    else:
        ok = 10 <= n <= 12 and (bool(re.search(r"[ ()-]", cand)) or cand.count(".") >= 2)
    return "[REDACTED_PHONE]" if ok else cand


_RULES = {
    "EMAIL": (_EMAIL, lambda m: "[REDACTED_EMAIL]"),
    "IBAN": (_IBAN, _sub_iban),
    "CREDIT_CARD": (_CARD, _sub_card),
    "SSN": (_SSN, lambda m: "[REDACTED_SSN]"),
    "PPSN": (_PPSN, lambda m: "[REDACTED_PPSN]"),
    "PHONE": (_PHONE, _sub_phone),
}


def redact_text(text: str, detectors=None) -> tuple[str, dict]:
    """Return (redacted_text, {TYPE: count})."""
    enabled = set(ALL_DETECTORS if detectors is None else detectors)
    counts: dict[str, int] = {}
    for name in ALL_DETECTORS:
        if name not in enabled:
            continue
        pattern, repl = _RULES[name]
        token = f"[REDACTED_{name}]"
        before = text.count(token)
        text = pattern.sub(repl, text)
        found = text.count(token) - before
        if found > 0:
            counts[name] = found
    return text, counts


def redact_messages(messages: list, detectors=None) -> tuple[list, dict]:
    """Redact every text field of an OpenAI-style messages array (deep copy)."""
    out = copy.deepcopy(messages)
    totals: dict[str, int] = {}

    def apply(text: str) -> str:
        red, counts = redact_text(text, detectors)
        for k, v in counts.items():
            totals[k] = totals.get(k, 0) + v
        return red

    for msg in out:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if isinstance(content, str):
            msg["content"] = apply(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    part["text"] = apply(part["text"])
    return out, totals


def messages_text(messages: list) -> str:
    chunks = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if isinstance(content, str):
            chunks.append(content)
        elif isinstance(content, list):
            chunks += [p["text"] for p in content if isinstance(p, dict) and isinstance(p.get("text"), str)]
    return "\n".join(chunks)
