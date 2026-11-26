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
    n = int.from_bytes(hk("psn", key)[:7], "big")
    return "PSN-" + "".join(_ALPH[(n >> (5 * i)) & 31] for i in range(10))


def shift_days(key: str, max_days: int) -> int:
    v = int.from_bytes(hk("shift", key)[:4], "big") % (2 * max_days + 1) - max_days
    return v if v else 1


def opaque(kind: str, value: str, n: int = 6) -> str:
    """Deterministic, non-reversible replacement token (used for keys/filenames)."""
    d = int.from_bytes(hk(kind, value)[:5], "big")
    return "".join(_ALPH[(d >> (5 * i)) & 31] for i in range(n))


_RX_NON_DIG = re.compile(r"\D+")
_RX_NON_ALNUM = re.compile(r"[^0-9A-Za-z]")
_RX_DIG5 = re.compile(r"\d{5,}")
_RX_WS_SPLIT = re.compile(r"[ \t]+")
_RX_SEP_SPLIT = re.compile(r"[\s,/]+")
_RX_AGE_NUM = re.compile(r"\d{1,3}")
_RX_PLACE_CAP = re.compile(rf"[A-Z{DEVA}]")


def norm(s: str) -> str:
    if s.isascii():
        sl = s.lower()
        if "  " not in sl and "\t" not in sl and "\n" not in sl and sl == sl.strip():
            return sl
        return " ".join(sl.split())
    return " ".join(unicodedata.normalize("NFKC", s).casefold().split())


# ============================================================== I/O
def _fix_mojibake(text: str) -> str:
    if any(sig in text for sig in ("à¤", "à¥", "à¦", "à§", "à¨", "à©", "àª", "à«")):
        try:
            fixed = text.encode("latin-1").decode("utf-8")
            if any("\u0900" <= c <= "\u0aff" for c in fixed):
                return fixed
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
    return text


def decode(raw: bytes) -> str | None:
    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            return _fix_mojibake(raw[3:].decode("utf-8"))
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
        return _fix_mojibake(raw.decode("utf-8"))
    except UnicodeDecodeError:
        pass
    try:
        t = raw.decode("cp1252")
    except UnicodeDecodeError:
        return None
    return _fix_mojibake(t)


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
    if ext in (".txt", ".md", ".log", ".text", "", ".ini", ".cfg", ".conf", ".properties", ".yaml", ".yml", ".rst", ".note", ".msg", ".hl7", ".er7"):
        return "text"
    return "unsupported"


def sniff_delim(text: str, ext: str) -> str:
    if ext not in (".csv", ".tsv"):
        d = _delimited(text)
        if d:
            return d
    sample = text[:4096].replace("\r\n", "\n").replace("\r", "\n")
    lines = [re.sub(r'"[^"]*"', "", ln) for ln in sample.splitlines() if ln.strip()][:25]
    if not lines:
        return "\t" if ext == ".tsv" else ","
    if ext == ".tsv" and "\t" in lines[0]:
        return "\t"
    best_d, best_score = ("," if ext != ".tsv" else "\t"), (-1, -1, 0)
    for d in ("\t", ",", ";", "|"):
        counts = [ln.count(d) for ln in lines if ln.count(d) > 0]
        if not counts:
            continue
        mode, hits = Counter(counts).most_common(1)[0]
        score = (hits, mode, 1 if (d == "\t" and ext == ".tsv") or (d == "," and ext != ".tsv") else 0)
        if score > best_score:
            best_d, best_score = d, score
    return best_d


_INDIC_DIGITS = str.maketrans(
    "०१२३४५६७८९০১২৩৪৫৬৭৮৯੦੧੨੩੪੫੬੭੮੯૦૧૨૩૪૫૬૭૮૯୦୧୨୩୪୫୬୭୮୯௦௧௨௩௪௫௬௭௮௯౦౧౨౩౪౫౬౭౮౯೦೧೨೩೪೫೬೭೮೯൦൧൨൩൪൫൬൭൮൯",
    "0123456789" * 9,
)
INDIC_DIG = "0-9०-९০-৯੦-੯૦-૯୦-୯௦-௯౦-౯೦-೯൦-൯"

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
_ASCII_TO_DEVA = str.maketrans("0123456789", "०१२३४५६७८९")
_DEVA_DIG_RX = re.compile(r"[\u0966-\u096F]")
RX_DMY = re.compile(rf"(?<![{INDIC_DIG}/.\-])([{INDIC_DIG}]{{1,2}})([/\-.])([{INDIC_DIG}]{{1,2}})\2((?:19|20|१९|२०)[{INDIC_DIG}]{{2}}|[{INDIC_DIG}]{{2}})(?![{INDIC_DIG}/\-]|\.\d)")
RX_ISO = re.compile(rf"(?<![{INDIC_DIG}/.\-])((?:19|20|१९|२०)[{INDIC_DIG}]{{2}})([-/.])([{INDIC_DIG}]{{2}})\2([{INDIC_DIG}]{{2}})(?![{INDIC_DIG}/\-]|\.\d)")
RX_ISO8 = re.compile(r"(?<![A-Za-z0-9/\-#])((?:19|20)\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(?![A-Za-z0-9/\-#])")
RX_DMY8 = re.compile(r"(?<![A-Za-z0-9/\-#])(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])((?:19|20)\d{2})(?![A-Za-z0-9/\-#])")
RX_TEXTD = re.compile(r"(?i)\b(\d{1,2})(st|nd|rd|th)?([\s\-/.]+(?:of\s+)?)(jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)([a-z]*\.?)"
                      r"(,?[\s\-/.]+['’]?|['’])((?:19|20)?\d{2})\b")
RX_TEXTM = re.compile(r"(?i)\b(jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)([a-z]*\.?)([\s\-/]+)(\d{1,2})(st|nd|rd|th)?(,?[\s\-/]+)((?:19|20)\d{2})\b")


def date_votes(text: str) -> tuple[int, int]:
    dmy = mdy = 0
    for m in RX_DMY.finditer(text):
        a, b = int(m.group(1).translate(_INDIC_DIGITS)), int(m.group(3).translate(_INDIC_DIGITS))
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
    if not days or not text or not any(c.isdigit() for c in text):
        return text
    delta = dt.timedelta(days=days)
    w = wrap or (lambda x: x)

    def dmy(m):
        orig = m.group(0)
        a = m.group(1).translate(_INDIC_DIGITS)
        sep = m.group(2)
        b = m.group(3).translate(_INDIC_DIGITS)
        y = m.group(4).translate(_INDIC_DIGITS)
        ia, ib = int(a), int(b)
        iy = int(y) if len(y) == 4 else (2000 + int(y) if int(y) <= 30 else 1900 + int(y))
        o = order
        if ia > 12 and ib <= 12:
            o = "dmy"
        elif ib > 12 and ia <= 12:
            o = "mdy"
        d = _mk(iy, ib, ia) if o == "dmy" else _mk(iy, ia, ib)
        if not d:
            return orig
        n = d + delta
        first, second = (n.day, n.month) if o == "dmy" else (n.month, n.day)
        f1 = f"{first:02d}" if len(a) == 2 else str(first)
        f2 = f"{second:02d}" if len(b) == 2 else str(second)
        ys = str(n.year) if len(y) == 4 else f"{n.year % 100:02d}"
        out_s = f"{f1}{sep}{f2}{sep}{ys}"
        if _DEVA_DIG_RX.search(orig):
            out_s = out_s.translate(_ASCII_TO_DEVA)
        if counter is not None:
            counter.append(1)
        return w(out_s)

    def iso(m):
        orig = m.group(0)
        y = int(m.group(1).translate(_INDIC_DIGITS))
        mo = int(m.group(3).translate(_INDIC_DIGITS))
        da = int(m.group(4).translate(_INDIC_DIGITS))
        d = _mk(y, mo, da)
        if not d:
            return orig
        n = d + delta
        sep = m.group(2)
        out_s = f"{n.year}{sep}{n.month:02d}{sep}{n.day:02d}"
        if _DEVA_DIG_RX.search(orig):
            out_s = out_s.translate(_ASCII_TO_DEVA)
        if counter is not None:
            counter.append(1)
        return w(out_s)

    def iso8(m):
        d = _mk(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        if not d:
            return m.group(0)
        n = d + delta
        if counter is not None:
            counter.append(1)
        return w(f"{n.year}{n.month:02d}{n.day:02d}")

    def dmy8(m):
        ia, ib, iy = int(m.group(1)), int(m.group(2)), int(m.group(3))
        o = order
        if ia > 12 and ib <= 12:
            o = "dmy"
        elif ib > 12 and ia <= 12:
            o = "mdy"
        d = _mk(iy, ib, ia) if o == "dmy" else _mk(iy, ia, ib)
        if not d:
            return m.group(0)
        n = d + delta
        first, second = (n.day, n.month) if o == "dmy" else (n.month, n.day)
        if counter is not None:
            counter.append(1)
        return w(f"{first:02d}{second:02d}{n.year}")

    def textd(m):
        mon = _MON.get(m.group(4).lower()[:3])
        yy = m.group(7)
        iy = int(yy) if len(yy) == 4 else (2000 + int(yy) if int(yy) <= 30 else 1900 + int(yy))
        d = _mk(iy, mon, int(m.group(1)))
        if not d:
            return m.group(0)
        n = d + delta
        name = m.group(4) + m.group(5)
        new_mon = _MON_FULL[n.month - 1]
        if len(name.rstrip(".")) <= 3 or name.endswith("."):
            new_mon = new_mon[:3] + ("." if name.endswith(".") else "")
        if name.isupper():
            new_mon = new_mon.upper()
        suf = _ord(n.day) if m.group(2) else ""
        if m.group(2) and m.group(2).isupper():
            suf = suf.upper()
        ys = str(n.year) if len(yy) == 4 else f"{n.year % 100:02d}"
        ds = f"{n.day:02d}" if len(m.group(1)) == 2 and not m.group(2) else str(n.day)
        return w(f"{ds}{suf}{m.group(3)}{new_mon}{m.group(6)}{ys}")

    def textm(m):
        mon = _MON.get(m.group(1).lower()[:3])
        d = _mk(int(m.group(7)), mon, int(m.group(4)))
        if not d:
            return m.group(0)
        n = d + delta
        name = m.group(1) + m.group(2)
        new_mon = _MON_FULL[n.month - 1]
        if len(name.rstrip(".")) <= 3 or name.endswith("."):
            new_mon = new_mon[:3] + ("." if name.endswith(".") else "")
        if name.isupper():
            new_mon = new_mon.upper()
        day = f"{n.day:02d}" if len(m.group(4)) == 2 else str(n.day)
        return w(f"{new_mon}{m.group(3)}{day}{_ord(n.day) if m.group(5) else ''}{m.group(6)}{n.year}")

    def hid(m):
        d = _mk(int(m.group(3).translate(_INDIC_DIGITS)), _HI_MON[m.group(2)], int(m.group(1).translate(_INDIC_DIGITS)))
        if not d:
            return m.group(0)
        n = d + delta
        return w(f"{n.day} {_HI_NAMES[n.month]} {n.year}")

    if not text.isascii():
        text = RX_HID.sub(hid, text)
    text = RX_ISO.sub(iso, text)
    text = RX_ISO8.sub(iso8, text)
    text = RX_DMY8.sub(dmy8, text)
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
        return _mk(int(m.group(1).translate(_INDIC_DIGITS)), int(m.group(3).translate(_INDIC_DIGITS)),
                   int(m.group(4).translate(_INDIC_DIGITS)))
    m = RX_ISO8.search(s)
    if m:
        return _mk(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    m = RX_DMY8.search(s)
    if m:
        ia, ib, iy = int(m.group(1)), int(m.group(2)), int(m.group(3))
        o = "dmy" if ia > 12 else ("mdy" if ib > 12 else order)
        d = _mk(iy, ib, ia) if o == "dmy" else _mk(iy, ia, ib)
        if d:
            return d
    m = RX_DMY.search(s)
    if m:
        a = int(m.group(1).translate(_INDIC_DIGITS))
        b = int(m.group(3).translate(_INDIC_DIGITS))
        ys = m.group(4).translate(_INDIC_DIGITS)
        y = int(ys) if len(ys) == 4 else (2000 + int(ys) if int(ys) <= 30 else 1900 + int(ys))
        if a > 12:
            return _mk(y, b, a)
        if b > 12:
            return _mk(y, a, b)
        return _mk(y, b, a) if order == "dmy" else _mk(y, a, b)
    m = RX_TEXTD.search(s)
    if m:
        yy = m.group(7)
        y = int(yy) if len(yy) == 4 else (2000 + int(yy) if int(yy) <= 30 else 1900 + int(yy))
        return _mk(y, _MON[m.group(4).lower()[:3]], int(m.group(1)))
    m = RX_TEXTM.search(s)
    if m:
        return _mk(int(m.group(7)), _MON[m.group(1).lower()[:3]], int(m.group(4)))
    m = RX_HID.search(s)
    if m:
        return _mk(int(m.group(3).translate(_INDIC_DIGITS)), _HI_MON[m.group(2)], int(m.group(1).translate(_INDIC_DIGITS)))
    return None


# ============================================================== identifier patterns
RX_EMAIL = re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+")
RX_PAN = re.compile(r"(?<![A-Za-z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9])")
RX_DOTTED_AADHAAR = re.compile(r"(?<![\d.])\d{4}\.\d{4}\.\d{4}(?![\d.])")
RX_DOTTED_PHONE = re.compile(r"(?<![\d.])(?:\+?91[\s.\-]?)?[6-9]\d{4}[.·]\d{5}(?![\d.])|(?<![\d.])[6-9]\d{2}[.·]\d{3}[.·]\d{4}(?![\d.])")
RX_MASKED_AADHAAR = re.compile(r"(?i)(?<![\w])[x*•]{4}[\s\-]?[x*•]{4}[\s\-]?\d{4}(?!\d)")
RX_DIGITRUN = re.compile(rf"(?<![\w/:])(?<!\d\.)((?:\(\+91\)\s*|\+?[{INDIC_DIG}])[{INDIC_DIG}\s\-()]{{6,24}}[{INDIC_DIG}])(?![\w/:]|\.\d)")
# Hospital / insurance style IDs: letters + >=4 digits, with optional / - : # separators, or dotted XX.YY.NNNN
RX_IDTOK = re.compile(r"(?<![\w/\-:#])(?=[\w/\-:#]{0,40}\d{3})(?=[\w/\-:#]{0,40}[A-Za-z])[A-Za-z]{1,8}[A-Za-z0-9]{0,16}(?:[/\-:#][A-Za-z0-9]{1,16}){1,6}(?![\w/\-:#])"
                      r"|(?<![\w/\-])[A-Za-z]{2,8}\d{5,16}(?![\w/\-])"
                      r"|(?<![\w.])[A-Za-z]{2,6}\.\d{2,4}\.\d{3,8}(?![\w.])")


def _compact_timestamp(d: str) -> bool:
    if len(d) not in (8, 10, 12, 14) or d[:2] not in ("19", "20"):
        return False
    y, mo, da = int(d[:4]), int(d[4:6]), int(d[6:8])
    if not (1 <= mo <= 12 and 1 <= da <= 31):
        return False
    rest = d[8:]
    return all(int(rest[i:i + 2]) < (24 if i == 0 else 60) for i in range(0, len(rest), 2))


def classify_digits(run: str) -> str | None:
    run = run.translate(_INDIC_DIGITS)
    groups = [len(g) for g in re.findall(r"\d+", run)]
    d = re.sub(r"\D", "", run)
    n = len(d)
    if groups and groups[0] >= 8 and _compact_timestamp(d[:groups[0]]):
        return None                 # HL7-style YYYYMMDD[hhmm[ss]] timestamp, not an identifier
    if n == 14 and groups in ([14], [2, 4, 4, 4]):
        return "ABHA"
    if n == 12 and groups in ([12], [4, 4, 4]) and not (d.startswith("91") and d[2] in "6789" and groups != [4, 4, 4]):
        return "AADHAAR"
    core = d[2:] if n == 12 and d.startswith("91") else d[1:] if n == 11 and d[0] == "0" else d
    if len(core) == 10 and core[0] in "6789" and (all(g >= 2 for g in groups) or groups == [n]):
        return "PHONE"
    if n == 10 and d[0] == "0" and max(groups) <= 6:
        return "PHONE"
    if n == 11 and d[0] == "0" and len(groups) >= 2 and 2 <= groups[0] <= 5 and max(groups) <= 8:
        return "PHONE"
    return None


_MON_TOK = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*"
RX_DATE_TOKEN = re.compile(rf"(?i){_MON_TOK}[\-/.]?\d{{1,2}}[\-/.,]?\s?(?:19|20)\d{{2}}|\d{{1,2}}[\-/.]?{_MON_TOK}[\-/.]?(?:19|20)?\d{{2}}")


def id_digits_ok(tok: str) -> bool:
    digits = re.sub(r"\D", "", tok)
    if len(digits) < 4:
        return False
    if RX_DATE_TOKEN.fullmatch(tok) or _compact_timestamp(digits) and len(digits) == len(tok):
        return False
    if re.fullmatch(r"(?i)[A-Z]\d{2}(\.\d+)?", tok):      # ICD-10
        return False
    return True


# ============================================================== clinical protection
CLIN_PROTECT = [
    re.compile(r"(?i)\b(?:BP|B\.P\.)\s*[:\-]?\s*\d{2,3}\s*/\s*\d{2,3}(?:\s*mm\s*hg)?"),
    re.compile(r"(?i)\b\d{2,3}\s*/\s*\d{2,3}\s*mm\s*hg"),
    re.compile(r"(?i)\b\d+(?:\.\d+)?\s*(?:mg/dl|g/dl|mmol/l|meq/l|iu/l|u/l|ng/ml|pg/ml|mg|mcg|ml|gm|g|iu|units?|%|/min|bpm|°f|°c|f\b|kg|cm|mm|/\s*cumm|/\s*cu\.?\s*mm|/\s*mm3|/\s*ul|cells(?:/[\w.]+)?)(?!\w)"),
    re.compile(r"\b[0-4]-[0-4]-[0-4](?:-[0-4])?\b"),
    re.compile(r"(?i)\bx\s*\d+\s*(?:days?|wks?|weeks?|months?|yrs?|years?|din|hafte)\b"),
    re.compile(r"\b[A-TV-Z]\d{2}(?:\.\d{1,2})?\b"),        # ICD-10
    re.compile(r"(?i)\b(?:Ward|वार्ड)\s*\d+\s*\([^)]{2,30}\)"),
    re.compile(r"(?i)\bBed\s*(?:No\.?)?\s*\d+\b"),
    re.compile(r"\bASHA\b|(?i:\basha\s+(?:workers?|sahayika|facilitator))"),
    re.compile(r"(?i)\b(?:CPAP|BiPAP|PEEP|CVP|ICP|PSV)\s*[:=]?\s*\d+(?:\s*/\s*\d+)?"),
    re.compile(r"(?i)\b(?:Addison|Cushing|Parkinson|Hodgkin|Graves|Hashimoto|Raynaud|Bell|Alzheimer|Barrett|Crohn|Marfan|Foley|Ringer|Babinski|McBurney|Apgar|Glasgow|Kernig|Brudzinski|Trousseau|Chvostek|Murphy|Kocher)(?:'s)?\s+(?:disease|syndrome|catheter|lactate|sign|palsy|lymphoma|score|coma|test|reflex|maneuver|esophagitis|tract|point)\b"),
]
RX_DOCTOR = re.compile(rf"(?:\bDr\.?|\bDR\.?|\bSr\.|\bSis\.|\bSN\.?|\bN/O|\bSister|\bStaff[ \t]+Nurse|\bNurse|\bANM|\bGNM|\bS/N|डॉ\.?|डा\.|सिस्टर)[ \t]*(?:[A-Z][a-zA-Z.']+|[{DEVA}]+)(?:[ \t]+(?:[A-Z][a-zA-Z.']+|[{DEVA}]+)){{0,2}}")

NAME_TOK = rf"(?:[A-Z][a-zA-Z'’]*\.?|[A-Z]{{2,}}|[{DEVA}]+\.?)"
NAME_SEQ = rf"{NAME_TOK}(?:[ \t]{{1,2}}{NAME_TOK}){{0,3}}"
STOP_WORDS = {"age", "sex", "uhid", "ipd", "opd", "mobile", "address", "dob", "date", "ward", "bed", "dr", "dr.",
              "consultant", "diagnosis", "yr", "yrs", "years", "male", "female", "m", "f", "आयु", "वर्ष", "उम्र", "उमर", "उमिर", "वय",
              "लिंग", "पता", "ग्राम", "तारीख", "मोबाइल", "patient", "name", "hospital", "rx", "adv", "tab", "inj",
              "the", "and", "of", "on", "at", "in", "for", "with", "to", "is", "was", "no", "not", "nil", "na", "n/a",
              "phone", "tehsil", "distt", "district", "village", "pin", "reg", "attendant", "informed", "ka", "ki",
              "ke", "ne", "को", "का", "की", "के", "दा", "दे", "दी", "nu", "ni", "no", "है", "मरीज़", "मरीज", "he", "she", "his", "her", "patient's",
              "umar", "umra", "umir", "jati", "sx", "sarnamu", "rihaish", "रिहाइश", "dardi", "nidan", "fariyad",
              "tapas", "riport", "dava", "din", "dakhal", "raja", "vali", "dikri", "patni", "puttar", "mr", "naam", "नाम",
              "follow", "followup", "follow-up"}
COMMON_WORDS = {"fever", "pain", "patient", "hospital", "medicine", "ward", "bed", "doctor", "discharge", "summary",
                "admission", "history", "diagnosis", "treatment", "advice", "review", "tab", "inj", "cap", "syp",
                "normal", "stable", "date", "time", "report", "lab", "test", "result", "blood", "urine", "sugar",
                "india", "uttar", "pradesh", "worker", "workers", "lucknow", "nagar", "road", "street", "district", "tehsil", "the",
                "and", "with", "from", "new", "old", "general", "medical", "surgery", "care", "center", "centre",
                "clinic", "health", "city", "public", "primary", "school", "mandir", "masjid", "near",
                "dawa", "dawai", "goli", "sui", "teeka", "pani", "khana", "chai"}


_HON_LEAD = re.compile(rf"^(?:{L.HONORIFIC_BEFORE})$", re.I)


def clean_name_seq(seq: str) -> list[str]:
    toks = []
    for t in _RX_WS_SPLIT.split(seq.strip()):
        tl = t.strip(".,;:'’").lower()
        if not tl or tl in STOP_WORDS:
            break
        if not toks and (_HON_LEAD.fullmatch(t.strip(",;:")) or _HON_LEAD.fullmatch(tl)):
            continue
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
        v = _RX_HON_SPACE.sub(" ", value)
        v = _RX_KIN_SPACE.sub(" ", v)
        toks = [t.strip(".,;:()'’") for t in _RX_SEP_SPLIT.split(v) if t.strip(".,;:()'’")]
        toks = [t for t in toks if not t.isdigit() and len(t) > 1]
        if not toks or len(toks) > 6:
            return
        if len(toks) >= 2:
            self.full_names.add(norm(" ".join(toks)))
        for t in toks:
            tl = t.lower()
            if (tl in L.GENERIC_NAME_TOKENS or tl in COMMON_WORDS or tl in L.MED_ACRONYMS
                    or len(tl) < 3 and not _DEVA_CHAR_RX.search(t)):
                continue
            self.name_tokens.add(tl)
            s = L.skel(t)
            if len(s) >= 3:
                self.name_skels.add(s)

    def add_id(self, value: str):
        v = str(value).strip()
        if not v:
            return
        a = _RX_NON_ALNUM.sub("", v).upper()
        if len(a) >= 5:
            self.ids.add(a)
        d = _RX_NON_DIG.sub("", v)
        if len(d) >= 5:
            self.id_digits.add(d)
        for g in _RX_DIG5.findall(v):
            self.id_digits.add(g)

    def add_place(self, value: str):
        if isinstance(value, str) and value.strip() and not value.strip().isdigit():
            n = norm(value.strip(" ,."))
            if len(n) >= 4 and n not in COMMON_WORDS and n not in STOP_WORDS and _RX_PLACE_CAP.search(value):
                self.places.add(n)


# ============================================================== records & evidence
_ET: tuple = ()
_EF: frozenset = frozenset()


class _EvProxy:
    """Lazy dict-like adapter over compact Rec slots (for UI/test inspection without 1M-row dicts)."""
    __slots__ = ("_r",)

    def __init__(self, r: "Rec"):
        self._r = r

    def __getitem__(self, k: str):
        r = self._r
        if k == "names":
            return r.names
        if k == "rel":
            return r.rel
        if k == "ids":
            if not isinstance(r.ids, set):
                r.ids = set(r.ids) if r.ids else set()
            return r.ids
        if k == "phones":
            if not isinstance(r.phones, set):
                r.phones = set(r.phones) if r.phones else set()
            return r.phones
        if k == "conds":
            if r.conds is None:
                raise KeyError(k)
            return r.conds
        if hasattr(r, k):
            return getattr(r, k)
        raise KeyError(k)

    def __setitem__(self, k: str, v):
        setattr(self._r, k, v)

    def get(self, k: str, default=None):
        if k == "conds":
            return default if self._r.conds is None else self._r.conds
        if k == "district":
            return default if self._r.district is None else self._r.district
        return getattr(self._r, k, default)

    def setdefault(self, k: str, default=None):
        cur = self.get(k, None)
        if cur is None:
            setattr(self._r, k, default)
            return default
        return cur


class Rec:
    __slots__ = ("file", "_loc", "names", "rel", "ids", "phones", "dob", "age", "gender",
                 "village", "district", "date", "conds", "pid", "key", "is_patient")

    def __init__(self, file: str, loc: str | int):
        self.file, self._loc = file, loc
        self.names = _ET
        self.rel = _ET
        self.ids = _EF
        self.phones = _EF
        self.dob = None
        self.age = None
        self.gender = None
        self.village = None
        self.district = None
        self.date = None
        self.conds = None
        self.pid = None
        self.key = None
        self.is_patient = False

    @property
    def loc(self) -> str:
        return f"row:{self._loc}" if isinstance(self._loc, int) else self._loc

    @property
    def ev(self) -> _EvProxy:
        return _EvProxy(self)

    def add_name_toks(self, toks) -> None:
        t = tuple(toks)
        if t:
            self.names = (t,) if not self.names else (self.names + (t,))

    def add_rel_toks(self, toks) -> None:
        t = tuple(toks)
        if t:
            self.rel = (t,) if not self.rel else (self.rel + (t,))

    def add_id(self, val: str) -> None:
        cur = self.ids
        if not cur:
            self.ids = (val,)
        elif isinstance(cur, set):
            cur.add(val)
        elif val not in cur:
            if len(cur) < 4:
                self.ids = cur + (val,)
            else:
                s = set(cur)
                s.add(val)
                self.ids = s

    def discard_id(self, val: str) -> None:
        cur = self.ids
        if not cur:
            return
        if isinstance(cur, set):
            cur.discard(val)
        elif val in cur:
            self.ids = tuple(x for x in cur if x != val) or _EF

    def add_phone(self, val: str) -> None:
        cur = self.phones
        if not cur:
            self.phones = (val,)
        elif isinstance(cur, set):
            cur.add(val)
        elif val not in cur:
            if len(cur) < 4:
                self.phones = cur + (val,)
            else:
                s = set(cur)
                s.add(val)
                self.phones = s

    def discard_phone(self, val: str) -> None:
        cur = self.phones
        if not cur:
            return
        if isinstance(cur, set):
            cur.discard(val)
        elif val in cur:
            self.phones = tuple(x for x in cur if x != val) or _EF

    def release_ev(self) -> None:
        self.names = _ET
        self.rel = _ET
        self.ids = _EF
        self.phones = _EF
        self.dob = None
        self.age = None
        self.gender = None
        self.village = None
        self.date = None
        self.conds = None


def gender_of(v) -> str | None:
    s = str(v).strip().lower()
    if s in ("m", "male", "पुरुष", "purush", "purushan", "aan", "man", "boy"):
        return "M"
    if s in ("f", "female", "महिला", "mahila", "woman", "girl", "स्त्री", "sthree", "stree", "pen"):
        return "F"
    return None


_RX_HON_SPACE = re.compile(rf"(?i)\b{L.HONORIFIC_BEFORE}\s+")
_RX_KIN_SPACE = re.compile(r"(?i)\b(?:S/O|D/O|W/O|H/O|C/O)\b\.?")
_DEVA_CHAR_RX = re.compile(rf"[{DEVA}]")


def age_of(v) -> int | None:
    m = _RX_AGE_NUM.search(str(v).translate(_INDIC_DIGITS))
    if m and 0 <= int(m.group(0)) <= 120:
        return int(m.group(0))
    return None


DOB_RX = re.compile(L.DOB_LABEL.pattern + r"([^\n]{4,36})")
