"""Free-text and value scrubbing (shared by every format handler)."""
from __future__ import annotations

import base64
import binascii
import re

from . import lexicon as L
from .engine import (CLIN_PROTECT, COMMON_WORDS, DEVA, NAME_SEQ, RX_DIGITRUN, RX_DOCTOR, RX_EMAIL, RX_IDTOK,
                     RX_MASKED_AADHAAR, RX_PAN, classify_digits, clean_name_seq, id_digits_ok, norm,
                     shift_dates_in)

_M0, _M1, _MB = "", "", 0xE100
_MARK = re.compile("([-]+)")


class Masker:
    def __init__(self):
        self.store: list[str] = []

    def put(self, s: str) -> str:
        self.store.append(s)
        return _M0 + "".join(chr(_MB + int(c)) for c in str(len(self.store) - 1)) + _M1

    def restore(self, t: str) -> str:
        for _ in range(6):
            n = _MARK.sub(lambda m: self.store[int("".join(str(ord(c) - _MB) for c in m.group(1)))], t)
            if n == t:
                break
            t = n
        return t


class Ctx:
    """Per-record scrubbing context."""

    def __init__(self, H, psn: str | None, days: int, order: str, band, stats):
        self.H, self.psn, self.days, self.order, self.band, self.stats = H, psn, days, order, band, stats

    @property
    def patient_token(self) -> str:
        return self.psn or "[PATIENT]"


# ---------------------------------------------------------------- compiled sweeps (built once per run)
class Sweeper:
    def __init__(self, H):
        self.H = H
        lat_full = sorted({n for n in H.full_names if not re.search(rf"[{DEVA}]", n)}, key=len, reverse=True)
        dev_full = sorted({n for n in H.full_names if re.search(rf"[{DEVA}]", n)}, key=len, reverse=True)
        lat_tok = sorted({t for t in H.name_tokens if not re.search(rf"[{DEVA}]", t)}, key=len, reverse=True)
        dev_tok = sorted({t for t in H.name_tokens if re.search(rf"[{DEVA}]", t)}, key=len, reverse=True)
        sep = r"[\s_.\-]+"

        def alt(items, f=lambda x: x):
            return "|".join(f(i) for i in items) or r"(?!x)x"

        latf = alt(lat_full, lambda n: sep.join(re.escape(p) for p in n.split()))
        self.rx_lat_full = re.compile(rf"(?i)(?<![A-Za-z])(?:{latf})(?![A-Za-z])")
        devf = alt(dev_full, lambda n: r"\s+".join(re.escape(p) for p in n.split()))
        self.rx_dev_full = re.compile(rf"(?<![{DEVA}])(?:{devf})(?![{DEVA}])")
        self.rx_lat_tok = re.compile(rf"(?i)(?<![A-Za-z])(?:{alt(lat_tok, re.escape)})(?![A-Za-z])")
        self.rx_dev_tok = re.compile(rf"(?<![{DEVA}])(?:{alt(dev_tok, re.escape)})(?![{DEVA}])")
        places = sorted((p for p in H.places if p not in H.safe_places), key=len, reverse=True)
        self.rx_place = re.compile(
            rf"(?i)(?<![A-Za-z{DEVA}])(?:{alt(places, lambda n: sep.join(re.escape(x) for x in n.split()))})(?![A-Za-z{DEVA}])")
        ids = sorted(H.ids, key=len, reverse=True)
        self.rx_ids = re.compile(
            rf"(?i)(?<![A-Za-z0-9])(?:{alt(ids, lambda i: r'[\s/\-_.]*'.join(re.escape(c) for c in i))})(?![A-Za-z0-9])")
        digs = sorted(H.id_digits | H.phones, key=len, reverse=True)
        self.rx_digits = re.compile(rf"(?<!\d)(?:{alt(digs, re.escape)})(?!\d)")


# ---------------------------------------------------------------- pieces
RX_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
RX_ADDR_LINE = re.compile(L.ADDRESS_LABEL.pattern + r"([^\n]*)", re.I)
RX_KEEP_ADMIN = re.compile(rf"(?i)^\s*(?:distt?\.?|district|jila|zila|जिला|जनपद)\s*[:.]?\s*([A-Za-z{DEVA} ]+?)\s*$")
RX_PIN_TAIL = re.compile(r"(?<!\d)([1-8]\d{2})\s?(\d{3})(?!\d)")
RX_HOUSE = re.compile(rf"(?i)(?:\b(?:H\.?\s?No\.?|House\s*(?:No\.?)?|Makan\s*(?:No\.?)?|Flat\s*(?:No\.?)?|Plot\s*(?:No\.?)?|Qtr\.?\s*No\.?)|मकान\s*(?:नं\.?|नंबर)?|म\.\s*नं\.?)\s*[:\-]?\s*[\w/\-]+")
RX_MOHALLA = re.compile(rf"(?i)\b(?:Mohalla|Mohallah|Mohala|Muhalla|Colony|Nagar\s+Colony|Ward\s+No\.?)\s+[A-Z][\w]*(?:\s+[A-Z][\w]*)?|मोहल्ला\s+[{DEVA}]+(?:\s+[{DEVA}]+)?")
RX_WARDNUM = re.compile(r"(?i)\bWard\s*(?:No\.?)?\s*\d+(?!\s*\()")
RX_LANDMARK = re.compile(rf"(?i)\b(?:near|opp\.?|opposite|behind|beside|in\s+front\s+of|next\s+to)\s+(?:the\s+)?[A-Z][\w]*(?:\s+[A-Z][\w]*){{0,3}}|[{DEVA}]+(?:\s+[{DEVA}]+){{0,3}}\s+(?:के\s+)?(?:पास|पीछे|सामने)")
RX_VILL = re.compile(rf"(?i)\b(?:Vill(?:age)?\.?|Gram|Gaon)\s*[:\-.]?\s*([A-Z][\w]*(?:\s+[A-Z][\w]*){{0,2}})|(?:ग्राम|गाँव|गांव)\s*[:\-]?\s*([{DEVA}]+(?:\s+[{DEVA}]+){{0,2}})")
RX_PIN_CTX = re.compile(r"(?i)(?:\bPIN(?:\s*code)?|\bPincode|पिन(?:\s*कोड)?)\s*[:\-]?\s*([1-8]\d{2})\s?(\d{3})\b|(?<=[\s,\-])([1-8]\d{2})\s?(\d{3})(?=\s*$|\s*\n)")
RX_AGE = re.compile(rf"(?i)((?:\bAge(?:/Sex)?|\bAge\s*/\s*Gender|आयु|उम्र|\bUmar|\bUmra)\s*[:\-]?\s*)(\d{{1,3}})(\s*(?:Yrs?\.?|Years?|Y|वर्ष|saal|sal)?)"
                    rf"|(?<![\w.x×])(\d{{1,3}})(\s*(?:Yrs?|Y|years)\s*/\s*[MFmf]\b)")
RX_KIN = re.compile(rf"(?i)\b({L.KIN})\.?\s*[:\-]?\s*(?:\(\s*)?({NAME_SEQ})")
RX_LABEL = re.compile(L.NAME_LABEL.pattern + rf"({NAME_SEQ})")
RX_HON_AFTER = re.compile(rf"({NAME_SEQ})(\s+{L.HONORIFIC_AFTER})\b")
RX_HON_BEFORE = re.compile(rf"\b({L.HONORIFIC_BEFORE})\s+({NAME_SEQ})")


def _name_ok(toks: list[str]) -> bool:
    if not toks:
        return False
    for t in toks:
        tl = t.strip(".").lower()
        if tl in COMMON_WORDS or tl in L.CLINICAL_WORDS:
            return False
    return True


def generalize_address(value: str, band_pin: bool = True) -> str:
    """Keep only district-level information (and a 3-digit PIN prefix)."""
    parts = [p.strip() for p in re.split(r"[,;]| - |\n", value) if p.strip()]
    kept = []
    for p in parts:
        m = RX_KEEP_ADMIN.match(p)
        if m:
            kept.append(p.strip())
    pin = RX_PIN_TAIL.search(value)
    out = ", ".join(kept)
    if pin and band_pin:
        out = (out + " - " if out else "") + pin.group(1) + "XXX"
    return out or "[ADDRESS]"


def b64_scrub(tok: str, ctx: "Ctx", sw: "Sweeper") -> str:
    try:
        raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True)
        txt = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return tok
    if not txt or sum(c.isprintable() or c in "\n\r\t" for c in txt) / len(txt) < 0.9:
        return tok
    clean = scrub_text(txt, ctx, sw, allow_b64=False)
    if clean == txt:
        return tok
    ctx.stats["identifiers"] += 1
    return base64.b64encode(clean.encode("utf-8")).decode("ascii")


def scrub_text(text: str, ctx: Ctx, sw: Sweeper, allow_b64: bool = True) -> str:
    if not text or not text.strip():
        return text
    st = ctx.stats
    M = Masker()
    t = text

    def put(s):
        return M.put(s)

    def red(tag):
        def f(m):
            st["identifiers"] += 1
            return put(tag)
        return f

    if allow_b64:
        t = RX_B64.sub(lambda m: put(b64_scrub(m.group(0), ctx, sw)), t)

    # 1. labelled address lines -> district level only
    def addr(m):
        st["identifiers"] += 1
        return m.group(0)[: m.start(1) - m.start(0)] + put(generalize_address(m.group(1)))
    t = RX_ADDR_LINE.sub(addr, t)

    # 2. protect doctor names and clinical expressions
    t = RX_DOCTOR.sub(lambda m: put(m.group(0)), t)

    # 3. dates -> per-patient shift (masked so later digit rules never touch them)
    t = shift_dates_in(t, ctx.days, ctx.order, wrap=put)

    # 4. strong identifiers
    t = RX_EMAIL.sub(red("[EMAIL]"), t)
    t = RX_MASKED_AADHAAR.sub(red("[AADHAAR]"), t)
    t = sw.rx_ids.sub(lambda m: (st.__setitem__("identifiers", st["identifiers"] + 1), put(ctx.psn or "[ID]"))[1], t)

    def digrun(m):
        kind = classify_digits(m.group(1))
        if not kind:
            return m.group(0)
        st["identifiers"] += 1
        return put(f"[{kind}]")
    t = RX_DIGITRUN.sub(digrun, t)
    t = sw.rx_digits.sub(red("[ID]"), t)
    t = RX_PAN.sub(red("[PAN]"), t)

    def idtok(m):
        tok = m.group(0)
        if not id_digits_ok(tok):
            return tok
        st["identifiers"] += 1
        return put(ctx.psn or "[ID]")
    t = RX_IDTOK.sub(idtok, t)

    for rx in L_CLIN:
        t = rx.sub(lambda m: put(m.group(0)), t)

    # 5. labelled names / kinship / honorifics
    def lab(m):
        toks = clean_name_seq(m.group(m.lastindex))
        if not _name_ok(toks):
            return m.group(0)
        seq = m.group(m.lastindex)
        consumed = len(" ".join(toks)) if " ".join(toks) in seq else len(seq)
        st["identifiers"] += 1
        return m.group(0)[: m.start(m.lastindex) - m.start(0)] + put(ctx.patient_token) + seq[consumed:]
    t = RX_LABEL.sub(lab, t)

    def kin(m):
        rel, seq = m.group(1), m.group(2)
        toks = clean_name_seq(seq)
        if not toks:
            return m.group(0)
        if rel.upper().startswith("C/O") and (L.COMPLAINT_WORDS.match(toks[0]) or toks[0][:1].islower()):
            return m.group(0)
        if not _name_ok(toks):
            return m.group(0)
        st["identifiers"] += 1
        head = m.group(0)[: m.start(2) - m.start(0)]
        joined = " ".join(toks)
        rest = seq[len(joined):] if seq.startswith(joined) else ""
        return head + put("[RELATIVE]") + rest
    t = RX_KIN.sub(kin, t)

    def hon_after(m):
        toks = clean_name_seq(m.group(1))
        if not _name_ok(toks):
            return m.group(0)
        st["identifiers"] += 1
        return put(ctx.patient_token) + m.group(2)
    t = RX_HON_AFTER.sub(hon_after, t)

    def hon_before(m):
        toks = clean_name_seq(m.group(2))
        if not _name_ok(toks):
            return m.group(0)
        st["identifiers"] += 1
        return m.group(1) + " " + put(ctx.patient_token)
    t = RX_HON_BEFORE.sub(hon_before, t)

    # 6. harvested names anywhere (full names first, then single tokens)
    for rx in (sw.rx_lat_full, sw.rx_dev_full):
        t = rx.sub(red("[NAME]"), t)
    for rx in (sw.rx_lat_tok, sw.rx_dev_tok):
        t = rx.sub(red("[NAME]"), t)

    # 7. address fragments
    t = RX_HOUSE.sub(red("[ADDRESS]"), t)
    t = RX_MOHALLA.sub(red("[LOCALITY]"), t)
    t = RX_LANDMARK.sub(red("[LANDMARK]"), t)

    def vill(m):
        g = 1 if m.group(1) else 2
        st["identifiers"] += 1
        return m.group(0)[: m.start(g) - m.start(0)] + put("[VILLAGE]")
    t = RX_VILL.sub(vill, t)
    t = sw.rx_place.sub(red("[PLACE]"), t)

    def pin(m):
        st["identifiers"] += 1
        g = 1 if m.group(1) else 3
        return m.group(0)[: m.start(g) - m.start(0)] + put(m.group(g) + "XXX")
    t = RX_PIN_CTX.sub(pin, t)
    t = RX_WARDNUM.sub(red("[LOCALITY]"), t)

    # 8. labelled ages -> truthful bands
    def age(m):
        if m.group(2):
            a = int(m.group(2))
            return m.group(1) + put(ctx.band(a)) + (m.group(3) or "")
        a = int(m.group(4))
        return put(ctx.band(a)) + m.group(5)
    t = RX_AGE.sub(age, t)

    return M.restore(t)


L_CLIN = CLIN_PROTECT
