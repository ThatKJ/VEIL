"""Rakshak: offline, CPU-only, LLM-free privacy firewall for multilingual hospital records.

Two passes over the input:
  pass 1  parse every file -> records + evidence; harvest identity values (names, IDs,
          villages) from structured fields and labelled free text; learn date order.
  link    cluster records into patients (strong IDs, then name + second clue) with
          cannot-link constraints; keyed HMAC pseudonyms and per-patient date shifts.
  pass 2  rewrite every file (structured rules + free-text scrubber), verify the output
          with an independent leak scan, then write report.json / records.jsonl.

Never prints, logs or stores personal data or RAKSHA_SECRET.
"""
from __future__ import annotations

import base64
import binascii
import csv
import datetime as dt
import hashlib
import hmac
import io
import json
import os
import re
import sys
import time
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

from . import lexicon as L
from .linker import Linker

SECRET = os.environ.get("RAKSHA_SECRET", "").encode()
DEVA = L.DEVA
WORD = rf"[A-Za-z{DEVA}]"
_ALPH = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


# ============================================================== keyed helpers
def hk(*parts: str) -> bytes:
    return hmac.new(SECRET, "|".join(parts).encode("utf-8"), hashlib.sha256).digest()


def pseudonym(key: str) -> str:
    n = int.from_bytes(hk("psn", key)[:5], "big")
    return "PSN-" + "".join(_ALPH[(n >> (5 * i)) & 31] for i in range(6))


def shift_days(key: str, max_days: int) -> int:
    v = int.from_bytes(hk("shift", key)[:4], "big") % (2 * max_days + 1) - max_days
    return v if v else 1


def opaque(kind: str, value: str, n: int = 6) -> str:
    """Deterministic, non-reversible replacement token (used for keys/filenames)."""
    d = int.from_bytes(hk(kind, value)[:5], "big")
    return "".join(_ALPH[(d >> (5 * i)) & 31] for i in range(n))


def norm(s: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", s).casefold().split())


# ============================================================== I/O
def decode(raw: bytes) -> str | None:
    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            return raw[3:].decode("utf-8")
        except UnicodeDecodeError:
            return None
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if len(raw) > 4 and raw[1:2] == b"\x00" and raw[3:4] == b"\x00":
        try:
            return raw.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        t = raw.decode("cp1252")
    except UnicodeDecodeError:
        return None
    return t


def looks_binary(text: str) -> bool:
    if not text:
        return False
    sample = text[:4000]
    bad = sum(1 for c in sample if (ord(c) < 32 and c not in "\t\r\n\f") or c in "�\x7f")
    return bad / len(sample) > 0.02


def _delimited(text: str) -> str | None:
    lines = [l for l in text.splitlines() if l.strip()][:40]
    if len(lines) < 3:
        return None
    for d in ("|", "\t", ";"):
        counts = [l.count(d) for l in lines]
        c0 = counts[0]
        if c0 >= 2 and sum(1 for c in counts if c == c0) >= 0.7 * len(counts):
            return d
    return None


def sniff_kind(ext: str, text: str) -> str:
    s = text.lstrip()
    if ext in (".jsonl", ".ndjson"):
        return "jsonl"
    if ext in (".txt", "") and _delimited(text):
        return "table"
    if ext == ".json" or (s[:1] in "{[" and ext in (".csv", ".tsv", ".txt", "")):
        if s[:1] in "{[":
            return "json"
    if ext in (".csv", ".tsv"):
        return "table"
    if ext in (".txt", ".md", ".log", ".text", ""):
        return "text"
    return "unsupported"


def sniff_delim(text: str, ext: str) -> str:
    if ext not in (".csv", ".tsv"):
        d = _delimited(text)
        if d:
            return d
    first = text.split("\n", 1)[0]
    cands = {"\t": first.count("\t"), ",": first.count(","), ";": first.count(";"), "|": first.count("|")}
    if ext == ".tsv" and cands["\t"]:
        return "\t"
    best = max(cands, key=lambda k: (cands[k], k == ","))
    return best if cands[best] else ("\t" if ext == ".tsv" else ",")


_INDIC_DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")

# ============================================================== dates
_MON = {m: i + 1 for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"])}
_HI_MON = {"जनवरी": 1, "फ़रवरी": 2, "फरवरी": 2, "मार्च": 3, "अप्रैल": 4, "अप्रेल": 4, "मई": 5, "जून": 6, "जुलाई": 7,
           "अगस्त": 8, "सितंबर": 9, "सितम्बर": 9, "अक्टूबर": 10, "अक्तूबर": 10, "नवंबर": 11, "नवम्बर": 11,
           "दिसंबर": 12, "दिसम्बर": 12, "जानेवारी": 1, "फेब्रुवारी": 2, "एप्रिल": 4, "मे": 5, "जुलै": 7,
           "ऑगस्ट": 8, "सप्टेंबर": 9, "ऑक्टोबर": 10, "नोव्हेंबर": 11, "डिसेंबर": 12}
_HI_NAMES = {1: "जनवरी", 2: "फ़रवरी", 3: "मार्च", 4: "अप्रैल", 5: "मई", 6: "जून", 7: "जुलाई", 8: "अगस्त", 9: "सितंबर",
             10: "अक्टूबर", 11: "नवंबर", 12: "दिसंबर"}
RX_HID = re.compile(r"(?<![\d०-९])([\d०-९]{1,2})\s+(" + "|".join(sorted(_HI_MON, key=len, reverse=True)) + r")\s*,?\s+((?:19|20|१९|२०)[\d०-९]{2})(?![\d०-९])")
_MON_FULL = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
             "November", "December"]
RX_DMY = re.compile(r"(?<![\d/.\-])(\d{1,2})([/\-.])(\d{1,2})\2((?:19|20)\d{2})(?![\d/.\-])")
RX_ISO = re.compile(r"(?<![\d/.\-])((?:19|20)\d{2})([-/.])(\d{2})\2(\d{2})(?![\d/.\-])")
RX_TEXTD = re.compile(r"(?i)\b(\d{1,2})(st|nd|rd|th)?([\s\-/.]+)(jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)([a-z]*\.?)"
                      r"(,?[\s\-/.]+)((?:19|20)?\d{2})\b")
RX_TEXTM = re.compile(r"(?i)\b(jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)([a-z]*\.?)[\s\-]+(\d{1,2})(st|nd|rd|th)?,?[\s\-]+((?:19|20)\d{2})\b")


def date_votes(text: str) -> tuple[int, int]:
    dmy = mdy = 0
    for m in RX_DMY.finditer(text):
        a, b = int(m.group(1)), int(m.group(3))
        if a > 12 and b <= 12:
            dmy += 1
        elif b > 12 and a <= 12:
            mdy += 1
    return dmy, mdy


def _mk(y: int, m: int, d: int) -> dt.date | None:
    try:
        return dt.date(y, m, d)
    except ValueError:
        return None


def shift_dates_in(text: str, days: int, order: str, counter: list | None = None, wrap=None) -> str:
    """Shift every recognisable date in text by `days`, keeping each date's own format."""
    if not days:
        return text
    delta = dt.timedelta(days=days)
    w = wrap or (lambda x: x)

    def dmy(m):
        a, sep, b, y = m.group(1), m.group(2), m.group(3), m.group(4)
        ia, ib = int(a), int(b)
        o = order
        if ia > 12 and ib <= 12:
            o = "dmy"
        elif ib > 12 and ia <= 12:
            o = "mdy"
        d = _mk(int(y), ib, ia) if o == "dmy" else _mk(int(y), ia, ib)
        if not d:
            return m.group(0)
        n = d + delta
        first, second = (n.day, n.month) if o == "dmy" else (n.month, n.day)
        f1 = f"{first:02d}" if len(a) == 2 else str(first)
        f2 = f"{second:02d}" if len(b) == 2 else str(second)
        if counter is not None:
            counter.append(1)
        return w(f"{f1}{sep}{f2}{sep}{n.year}")

    def iso(m):
        d = _mk(int(m.group(1)), int(m.group(3)), int(m.group(4)))
        if not d:
            return m.group(0)
        n = d + delta
        sep = m.group(2)
        if counter is not None:
            counter.append(1)
        return w(f"{n.year}{sep}{n.month:02d}{sep}{n.day:02d}")

    def textd(m):
        mon = _MON.get(m.group(4).lower()[:3])
        yy = m.group(7)
        d = _mk(int(yy) + (2000 if len(yy) == 2 else 0), mon, int(m.group(1)))
        if not d:
            return m.group(0)
        n = d + delta
        name = m.group(4) + m.group(5)
        new_mon = _MON_FULL[n.month - 1]
        if len(name.rstrip(".")) <= 4:
            new_mon = new_mon[:3] + ("." if name.endswith(".") else "")
        if name.isupper():
            new_mon = new_mon.upper()
        suf = _ord(n.day) if m.group(2) else ""
        if m.group(2) and m.group(2).isupper():
            suf = suf.upper()
        ys = str(n.year) if len(yy) == 4 else f"{n.year % 100:02d}"
        ds = f"{n.day:02d}" if len(m.group(1)) == 2 else str(n.day)
        return w(f"{ds}{suf}{m.group(3)}{new_mon}{m.group(6)}{ys}")

    def textm(m):
        mon = _MON.get(m.group(1).lower()[:3])
        d = _mk(int(m.group(5)), mon, int(m.group(3)))
        if not d:
            return m.group(0)
        n = d + delta
        name = m.group(1) + m.group(2)
        new_mon = _MON_FULL[n.month - 1]
        if len(name.rstrip(".")) <= 4:
            new_mon = new_mon[:3] + ("." if name.endswith(".") else "")
        return w(f"{new_mon} {n.day}{_ord(n.day) if m.group(4) else ''}, {n.year}")

    def hid(m):
        d = _mk(int(m.group(3).translate(_INDIC_DIGITS)), _HI_MON[m.group(2)], int(m.group(1).translate(_INDIC_DIGITS)))
        if not d:
            return m.group(0)
        n = d + delta
        return w(f"{n.day} {_HI_NAMES[n.month]} {n.year}")

    text = RX_HID.sub(hid, text)
    text = RX_ISO.sub(iso, text)
    text = RX_DMY.sub(dmy, text)
    text = RX_TEXTD.sub(textd, text)
    text = RX_TEXTM.sub(textm, text)
    return text


def _ord(d: int) -> str:
    return "th" if 11 <= d % 100 <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(d % 10, "th")


def parse_date(s: str, order: str) -> dt.date | None:
    s = s.strip()
    m = RX_ISO.search(s)
    if m:
        return _mk(int(m.group(1)), int(m.group(3)), int(m.group(4)))
    m = RX_DMY.search(s)
    if m:
        a, b, y = int(m.group(1)), int(m.group(3)), int(m.group(4))
        if a > 12:
            return _mk(y, b, a)
        if b > 12:
            return _mk(y, a, b)
        return _mk(y, b, a) if order == "dmy" else _mk(y, a, b)
    m = RX_TEXTD.search(s)
    if m:
        return _mk(int(m.group(7)), _MON[m.group(4).lower()[:3]], int(m.group(1)))
    m = RX_HID.search(s)
    if m:
        return _mk(int(m.group(3)), _HI_MON[m.group(2)], int(m.group(1)))
    return None


# ============================================================== identifier patterns
RX_EMAIL = re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+")
RX_PAN = re.compile(r"(?<![A-Za-z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9])")
RX_DOTTED_AADHAAR = re.compile(r"(?<![\d.])\d{4}\.\d{4}\.\d{4}(?![\d.])")
RX_DOTTED_PHONE = re.compile(r"(?<![\d.])(?:\+?91[\s.\-]?)?[6-9]\d{4}[.·]\d{5}(?![\d.])|(?<![\d.])[6-9]\d{2}[.·]\d{3}[.·]\d{4}(?![\d.])")
RX_MASKED_AADHAAR = re.compile(r"(?i)(?<![\w])[x*•]{4}[\s\-]?[x*•]{4}[\s\-]?\d{4}(?!\d)")
RX_DIGITRUN = re.compile(r"(?<![\w/:])(?<!\d\.)(\+?[0-9०-९][0-9०-९\s\-]{6,22}[0-9०-९])(?![\w/:]|\.\d)")
# Hospital / insurance style IDs: letters + >=4 digits, with optional / - separators
RX_IDTOK = re.compile(r"(?<![\w/\-:#])(?=[\w/\-:#]{0,40}\d{3})(?=[\w/\-:#]{0,40}[A-Za-z])[A-Za-z]{1,8}[A-Za-z0-9]{0,16}(?:[/\-:#][A-Za-z0-9]{1,16}){1,6}(?![\w/\-:#])"
                      r"|(?<![\w/\-])[A-Za-z]{2,8}\d{5,16}(?![\w/\-])")


def classify_digits(run: str) -> str | None:
    run = run.translate(_INDIC_DIGITS)
    groups = [len(g) for g in re.findall(r"\d+", run)]
    d = re.sub(r"\D", "", run)
    n = len(d)
    if n == 14 and groups in ([14], [2, 4, 4, 4]):
        return "ABHA"
    if n == 12 and groups in ([12], [4, 4, 4]) and not (d.startswith("91") and d[2] in "6789" and groups != [4, 4, 4]):
        return "AADHAAR"
    core = d[2:] if n == 12 and d.startswith("91") else d[1:] if n == 11 and d[0] == "0" else d
    if len(core) == 10 and core[0] in "6789" and all(g >= 2 for g in groups) and max(groups) <= 10:
        return "PHONE"
    if n == 10 and d[0] == "0" and max(groups) <= 6:
        return "PHONE"
    return None


def id_digits_ok(tok: str) -> bool:
    digits = re.sub(r"\D", "", tok)
    if len(digits) < 4:
        return False
    if re.fullmatch(r"(?i)[A-Z]\d{2}(\.\d+)?", tok):      # ICD-10
        return False
    return True


# ============================================================== clinical protection
CLIN_PROTECT = [
    re.compile(r"(?i)\b(?:BP|B\.P\.)\s*[:\-]?\s*\d{2,3}\s*/\s*\d{2,3}(?:\s*mm\s*hg)?"),
    re.compile(r"(?i)\b\d{2,3}\s*/\s*\d{2,3}\s*mm\s*hg"),
    re.compile(r"(?i)\b\d+(?:\.\d+)?\s*(?:mg/dl|g/dl|mmol/l|meq/l|iu/l|u/l|ng/ml|pg/ml|mg|mcg|ml|gm|g|iu|units?|%|/min|bpm|°f|°c|f\b|kg|cm|mm)\b"),
    re.compile(r"\b[0-4]-[0-4]-[0-4](?:-[0-4])?\b"),
    re.compile(r"(?i)\bx\s*\d+\s*(?:days?|wks?|weeks?|months?|yrs?|years?|din|hafte)\b"),
    re.compile(r"\b[A-TV-Z]\d{2}(?:\.\d{1,2})?\b"),        # ICD-10
    re.compile(r"(?i)\b(?:Ward|वार्ड)\s*\d+\s*\([^)]{2,30}\)"),
    re.compile(r"(?i)\bBed\s*(?:No\.?)?\s*\d+\b"),
    re.compile(r"\bASHA\b|(?i:\basha\s+(?:workers?|sahayika|facilitator))"),
]
RX_DOCTOR = re.compile(rf"(?:\bDr\.?|\bDR\.?|डॉ\.?|डा\.)\s*(?:[A-Z][a-zA-Z.']+|[{DEVA}]+)(?:\s+(?:[A-Z][a-zA-Z.']+|[{DEVA}]+)){{0,2}}")

NAME_TOK = rf"(?:[A-Z][a-zA-Z'’]*\.?|[A-Z]{{2,}}|[{DEVA}]+)"
NAME_SEQ = rf"{NAME_TOK}(?:[ \t]{{1,2}}{NAME_TOK}){{0,3}}"
STOP_WORDS = {"age", "sex", "uhid", "ipd", "opd", "mobile", "address", "dob", "date", "ward", "bed", "dr", "dr.",
              "consultant", "diagnosis", "yrs", "years", "male", "female", "m", "f", "आयु", "वर्ष", "उम्र",
              "लिंग", "पता", "ग्राम", "तारीख", "मोबाइल", "patient", "name", "hospital", "rx", "adv", "tab", "inj",
              "the", "and", "of", "on", "at", "in", "for", "with", "to", "is", "was", "no", "not", "nil", "na", "n/a",
              "phone", "tehsil", "distt", "district", "village", "pin", "reg", "attendant", "informed", "ka", "ki",
              "ke", "ne", "को", "का", "की", "के", "है", "मरीज़", "मरीज", "he", "she", "his", "her", "patient's"}
COMMON_WORDS = {"fever", "pain", "patient", "hospital", "medicine", "ward", "bed", "doctor", "discharge", "summary",
                "admission", "history", "diagnosis", "treatment", "advice", "review", "tab", "inj", "cap", "syp",
                "normal", "stable", "date", "time", "report", "lab", "test", "result", "blood", "urine", "sugar",
                "india", "uttar", "pradesh", "worker", "workers", "lucknow", "nagar", "road", "street", "district", "tehsil", "the",
                "and", "with", "from", "new", "old", "general", "medical", "surgery", "care", "center", "centre",
                "clinic", "health", "city", "public", "primary", "school", "mandir", "masjid", "near"}


def clean_name_seq(seq: str) -> list[str]:
    toks = []
    for t in re.split(r"[ \t]+", seq.strip()):
        tl = t.strip(".,;:'’").lower()
        if not tl or tl in STOP_WORDS:
            break
        toks.append(t.strip(",;:"))
    return toks


# ============================================================== harvest store
class Harvest:
    def __init__(self):
        self.full_names: set[str] = set()       # normalised full-name strings (patients + relatives)
        self.name_tokens: set[str] = set()      # casefolded tokens (latin) / raw tokens (deva)
        self.name_skels: set[str] = set()
        self.doctor_tokens: set[str] = set()
        self.ids: set[str] = set()              # normalised alnum IDs (MRN/insurance)
        self.id_digits: set[str] = set()        # digit cores of IDs (>=5 digits)
        self.phones: set[str] = set()
        self.places: set[str] = set()           # village / locality strings (normalised)
        self.safe_places: set[str] = set()      # tehsil / district names (never redact)

    def add_name(self, value: str):
        if not value or not isinstance(value, str):
            return
        v = re.sub(rf"(?i)\b{L.HONORIFIC_BEFORE}\s+", " ", value)
        v = re.sub(r"(?i)\b(?:S/O|D/O|W/O|H/O|C/O)\b\.?", " ", v)
        toks = [t.strip(".,;:()'’") for t in re.split(r"[\s,/]+", v) if t.strip(".,;:()'’")]
        toks = [t for t in toks if not t.isdigit() and len(t) > 1]
        if not toks or len(toks) > 6:
            return
        if len(toks) >= 2:
            self.full_names.add(norm(" ".join(toks)))
        for t in toks:
            tl = t.lower()
            if (tl in L.GENERIC_NAME_TOKENS or tl in COMMON_WORDS or tl in L.MED_ACRONYMS
                    or len(tl) < 3 and not re.search(rf"[{DEVA}]", t)):
                continue
            self.name_tokens.add(tl)
            s = L.skel(t)
            if len(s) >= 3:
                self.name_skels.add(s)

    def add_id(self, value: str):
        v = str(value).strip()
        if not v:
            return
        a = re.sub(r"[^0-9A-Za-z]", "", v).upper()
        if len(a) >= 5:
            self.ids.add(a)
        d = re.sub(r"\D", "", v)
        if len(d) >= 5:
            self.id_digits.add(d)
        for g in re.findall(r"\d{5,}", v):
            self.id_digits.add(g)

    def add_place(self, value: str):
        if isinstance(value, str) and value.strip() and not value.strip().isdigit():
            n = norm(value.strip(" ,."))
            if len(n) >= 4 and n not in COMMON_WORDS and n not in STOP_WORDS and re.search(rf"[A-Z{DEVA}]", value):
                self.places.add(n)


# ============================================================== records & evidence
class Rec:
    __slots__ = ("file", "loc", "ev", "pid", "key", "is_patient")

    def __init__(self, file: str, loc: str):
        self.file, self.loc = file, loc
        self.ev = {"names": [], "rel": [], "ids": set(), "phones": set(), "dob": None, "age": None,
                   "gender": None, "village": None, "date": None}
        self.pid = None
        self.key = None
        self.is_patient = False


def gender_of(v) -> str | None:
    s = str(v).strip().lower()
    if s in ("m", "male", "पुरुष", "purush", "man", "boy"):
        return "M"
    if s in ("f", "female", "महिला", "mahila", "woman", "girl", "स्त्री"):
        return "F"
    return None


def age_of(v) -> int | None:
    m = re.search(r"\d{1,3}", str(v))
    if m and 0 <= int(m.group(0)) <= 120:
        return int(m.group(0))
    return None


DOB_RX = re.compile(L.DOB_LABEL.pattern + r"(\d{1,2}[/\-.]\d{1,2}[/\-.](?:19|20)\d{2}|(?:19|20)\d{2}-\d{2}-\d{2})")
