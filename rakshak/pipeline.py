"""Two-pass pipeline: parse + harvest -> link -> rewrite -> verify -> report."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from . import lexicon as L
from . import privacy as P
from .engine import (DEVA, INDIC_DIG, RX_DIGITRUN, RX_DOCTOR, RX_DOTTED_PHONE, RX_EMAIL, RX_IDTOK, RX_PAN,
                     _INDIC_DIGITS, Harvest, Rec, age_of, classify_digits, date_votes, decode, gender_of,
                     id_digits_ok, looks_binary, norm, opaque, parse_date, pseudonym, shift_dates_in, sniff_delim,
                     sniff_kind)
from .linker import Linker
from .scrub import NAME_VALUE, Masker
from .scrub import (RX_HON_AFTER, RX_HON_BEFORE, RX_ID_LABEL, RX_KIN, RX_KIN_POSS, RX_LABEL, RX_NAME_ROLE,
                    RX_PRE_KIN, RX_PRE_PAREN_KIN, RX_VILL, Ctx, Sweeper, _name_ok, generalize_address, scrub_text)
from .engine import clean_name_seq, DOB_RX, COMMON_WORDS, NAME_SEQ, STOP_WORDS

UNSUPPORTED = {".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".xml", ".doc", ".docx", ".xls",
               ".xlsx", ".zip", ".gz", ".rar", ".7z", ".bin", ".exe", ".dcm", ".hl7", ".rtf", ".odt", ".ppt", ".pptx",
               ".heic", ".webp", ".mp3", ".mp4", ".wav"}
ID_KINDS = {"MRN", "AADHAAR", "ABHA", "PAN", "EMAIL", "INSURANCE", "PHONE"}
STRUCT_KEYS = {"resourceType", "id", "fullUrl", "reference", "system", "url", "profile", "status", "type", "use",
               "mode", "contentType", "language", "coding", "code", "unit", "versionId", "schema",
               "loinc", "interpretation", "category", "intent", "priority", "valueQuantity", "comparator"}
GENDER_TOK = {"gender", "sex", "sx", "ling", "लिंग"}
DISTRICT_TOK = {"district", "distt", "jila", "jillo", "जिला", "ज़िला", "zila", "janpad"}
TEHSIL_TOK = {"tehsil", "तहसील", "तह", "taluka", "taluko", "block", "ta"}


class Stats(dict):
    def __missing__(self, k):
        return 0


class FileJob:
    __slots__ = ("rel", "raw", "sha", "ext", "kind", "text", "data", "delim", "rows", "order", "recs", "status",
                 "reason", "out_rel", "bom", "crlf", "indent", "doc_rec", "colkinds", "rec_ptrs", "branches",
                 "out_locs", "preamble", "widths", "repeat_headers", "keyed")

    def __init__(self, rel, raw):
        self.rel, self.raw = rel, raw
        self.sha = hashlib.sha256(raw).hexdigest()
        self.ext = os.path.splitext(rel)[1].lower()
        self.kind = self.text = self.data = self.delim = self.rows = None
        self.order = "dmy"
        self.recs: list[Rec] = []
        self.status = "sanitized"
        self.reason = None
        self.out_rel = rel
        self.bom = raw.startswith(b"\xef\xbb\xbf")
        self.crlf = False
        self.indent = 2
        self.doc_rec = None
        self.colkinds = []
        self.rec_ptrs = {}
        self.branches = set()
        self.out_locs = {}
        self.preamble = []
        self.widths = []
        self.repeat_headers = set()
        self.keyed = set()


# ================================================================ field kinds
def kind_of_key(key: str) -> str | None:
    toks = L.key_tokens(key)
    if any(t in ("age", "umar", "umra", "आयु", "उम्र", "yr", "yrs", "vaya", "वय") for t in toks) and L.classify_key(key) not in ("DOB", "DATE"):
        return "AGE"
    return L.classify_key(key)


def child_kind(key: str, parent: str | None) -> str | None:
    if key in STRUCT_KEYS:
        return "STRUCT"
    k = kind_of_key(key)
    if parent == "STRUCT":
        return "STRUCT"
    if k is None:
        return parent
    if parent in ("REL_NAME", "DOCTOR", "SAFE") and k == "NAME":
        return parent
    if parent in ID_KINDS and k in ("SAFE", "NAME"):
        return parent
    if parent == "ADDRESS" and k == "NAME":
        return "ADDRESS"
    return k


def ext_value_kind(obj: dict) -> str | None:
    """FHIR extensions carry their meaning in `url` (e.g. .../mothers-name)."""
    url = obj.get("url")
    if isinstance(url, str) and any(k.startswith("value") for k in obj):
        k = kind_of_key(url.rstrip("/").rsplit("/", 1)[-1])
        if k and k not in ("SAFE", "STRUCT", "DATE"):
            return k
    return None


def shape_kind(values: list[str]) -> str | None:
    vals = [v.strip() for v in values if isinstance(v, str) and v.strip()][:50]
    if len(vals) < 2:
        return None
    c = Counter()
    for v in vals:
        if RX_EMAIL.fullmatch(v):
            c["EMAIL"] += 1
        elif RX_PAN.fullmatch(v):
            c["PAN"] += 1
        else:
            k = classify_digits(v) if re.fullmatch(r"[+\d\s\-]{8,}", v) else None
            if k in ("PHONE", "AADHAAR", "ABHA"):
                c[k] += 1
            elif RX_IDTOK.fullmatch(v) and id_digits_ok(v):
                c["MRN"] += 1
    if c:
        k, n = c.most_common(1)[0]
        if n >= 0.6 * len(vals):
            if k == "MRN" and len(set(vals)) < 0.5 * len(vals):
                return None          # a repeated code (facility/batch), not a patient identifier
            return k
    from .scrub import NAME_VALUE
    named = [v for v in vals if NAME_VALUE.fullmatch(v) and _name_ok(v.split())]
    if len(named) >= 0.7 * len(vals) and len(set(named)) >= 0.5 * len(named):
        return "NAME_SHAPE"
    return None


# ================================================================ evidence helpers
def add_ev(rec: Rec, H: Harvest, kind: str, v, district: dict | None = None, order: str = "dmy"):
    if v is None or v == "":
        return
    s = str(v).strip()
    if not s:
        return
    e = rec.ev
    if kind in ("NAME", "REL_NAME") and re.match(r"(?i)\s*(?:dr|sr|sister|nurse|staff\s+nurse|anm|gnm|s/n)\b\.?", s):
        return                      # clinical staff, not a patient or relative
    if kind in ("NAME", "REL_NAME") and (len(re.sub(r"\D", "", s)) >= 3 or (RX_IDTOK.fullmatch(s) and id_digits_ok(s))):
        kind = "MRN" if kind == "NAME" else None      # an ID-shaped value is never a person name
        if kind is None:
            return
    if kind == "NAME":
        kin_m = re.search(rf"(?i)(?:\n|\s+)(?:{L.KIN})\.?\s*[:\-]?\s*(.+)$", s)
        pt_part = s[:kin_m.start()].strip() if kin_m else s
        rel_part = kin_m.group(1).strip() if kin_m else None
        H.add_name(pt_part)
        toks = [t for t in re.split(r"[\s,]+", re.sub(r"(?i)\b(?:S/O|D/O|W/O|C/O)\b", " ", pt_part)) if t]
        if toks:
            e["names"].append(toks)
        if rel_part:
            H.add_name(rel_part)
            rtoks = [t for t in re.split(r"[\s,]+", rel_part) if t]
            if rtoks:
                e["rel"].append(rtoks)
        rec.is_patient = True
    elif kind == "REL_NAME":
        rp = re.sub(r"(?i)^(?:Shri|Sri|Smt\.?|श्री|श्रीमती)\s+|'s\s+(?:wife|husband|son|daughter|father|mother)\b", " ", s).strip()
        H.add_name(rp)
        toks = [t for t in re.split(r"[\s,]+", re.sub(r"(?i)\b(?:S/O|D/O|W/O|H/O|C/O|Dikri|Patni|Puttar)\b\.?\s*\-?", " ", rp)) if t]
        if toks:
            e["rel"].append(toks)
    elif kind == "MRN":
        H.add_id(s)
        a = re.sub(r"[^0-9A-Za-z]", "", s).upper()
        if len(a) >= 4:
            e["ids"].add("M:" + a)
            rec.is_patient = True
    elif kind in ("AADHAAR", "ABHA"):
        d = re.sub(r"\D", "", s.translate(_INDIC_DIGITS))
        if len(d) >= 8:
            H.id_digits.add(d)
            e["ids"].add(("A:" if kind == "AADHAAR" else "B:") + d)
            rec.is_patient = True
    elif kind == "PAN":
        H.add_id(s)
        e["ids"].add("N:" + s.upper())
    elif kind == "INSURANCE":
        H.add_id(s)
        a = re.sub(r"[^0-9A-Za-z]", "", s).upper()
        if len(a) >= 5:
            e["ids"].add("I:" + a)
    elif kind == "EMAIL":
        H.ids.add(re.sub(r"[^0-9A-Za-z]", "", s).upper())
        e["ids"].add("E:" + s.lower())
    elif kind == "PHONE":
        d = re.sub(r"\D", "", s.translate(_INDIC_DIGITS))
        if len(d) >= 10:
            d = d[-10:]
            H.phones.add(d)
            e["phones"].add(d)
    elif kind == "DOB":
        d = parse_date(s, order if order in ("dmy", "mdy") else "dmy")
        e["dob"] = d.isoformat() if d else s
    elif kind == "DATE":
        if not e["date"]:
            d = parse_date(s, order if order in ("dmy", "mdy") else "dmy")
            if d and 1990 <= d.year <= 2035:
                e["date"] = d.year
    elif kind == "AGE":
        a = age_of(s)
        if a is not None:
            e["age"] = a
    elif kind == "VILLAGE":
        H.add_place(s)
        e["village"] = norm(s)
    elif kind == "ADDRESS":
        for part in re.split(r"[,;]| - ", s):
            p = part.strip()
            if p and not re.search(r"(?i)tehsil|distt|district|जिला|तहसील|\d{6}", p) and re.search(rf"[A-Za-z{DEVA}]{{3,}}", p):
                pp = re.sub(r"(?i)^(?:near|opp\.?|vill\.?|mohalla|c/o)\s+", "", p)
                if not re.match(r"(?i)^(?:h\.?\s?no|house|makan|ward|मकान)", pp):
                    H.add_place(pp)


RX_KV = re.compile(r"(?m)^([ \t]*\|[ \t]*)([^|\n]{1,40}?)([ \t]*\|[ \t]*)([^|\n]+?)([ \t]*\|[ \t]*)$"
                   r"|^([ \t]*[-*•]?[ \t]*\**)([A-Za-z\u0900-\u097F][^:\n|]{0,30}?)(\**[ \t]*[:：][ \t]*\**)([^\n]+?)([ \t]*)$")
KV_KINDS = {"NAME", "REL_NAME", "MRN", "PHONE", "AADHAAR", "ABHA", "PAN", "EMAIL", "INSURANCE", "DOB", "AGE", "VILLAGE",
            "ADDRESS", "PIN"}


def _kv_kind(label: str, value: str):
    k = kind_of_key(label.strip(" *"))
    if k in ("NAME", "REL_NAME") and (re.search(r"\d", value) or not re.search(r"[A-Za-z\u0900-\u097F]{2}", value)):
        return None                  # "Pt: 30y | M" is an age line, not a name
    return k if k in KV_KINDS else None


_NEXT_LABEL = re.compile(r"\s{2,}(?=[^\s:：][^:：\n]{0,30}[:：])|\s+[-–]\s+(?=[A-Z])")


def kv_rows(text):
    """Label/value rows inside free text: Markdown/pipe tables and 'Label: value' lines.
    Yields (label, value, value_start, value_end); a colon value stops where the next label begins."""
    for m in RX_KV.finditer(text):
        if m.group(2) is not None:
            yield m.group(2), m.group(4), m.start(4), m.end(4)
        else:
            v = m.group(9)
            cut = _NEXT_LABEL.search(v)
            if cut:
                v = v[:cut.start()]
            yield m.group(7), v, m.start(9), m.start(9) + len(v)


RX_ICD = re.compile(r"\b([A-TV-Z]\d{2}(?:\.\d{1,2})?)\b")
COND_TOK = {"diagnosis", "diagnoses", "condition", "conditions", "procedure", "procedures", "impression", "icd",
            "disease", "illness", "surgery", "operation", "rog", "बीमारी", "निदान"}


_PAT_HON_RX = re.compile(
    rf"({NAME_SEQ})(\s+(?:ji|jee|sahab|saheb|sahib|didi|bhai|ben|bai|bibi|amma|baba|paaji|kaka|bhau|tai|dada|aaji|babu|chachaji|garu|anna|akka|banna|hukum|bhaisa|apa|जी|साहब|दीदी|भाई|बहन))\b"
    rf"|({NAME_SEQ})(\s+(?:di|da|chacha))(?=\s+(?:ka|ki|ke|ko|se|ne|par|me)\b|:)"
)


def text_evidence(text: str, rec: Rec, H: Harvest, order: str):
    e = rec.ev
    for lab, val, _, _ in kv_rows(text):
        k = _kv_kind(lab, val)
        if k and k not in ("ADDRESS", "PIN"):
            add_ev(rec, H, k, val.strip(" *"), order=order)
    for m in RX_ICD.finditer(text):
        e.setdefault("conds", set()).add(m.group(1))
    first_label = None
    for m in RX_LABEL.finditer(text):
        toks = clean_name_seq(m.group(m.lastindex))
        if _name_ok(toks) and (toks[0][:1].isupper() or re.search(rf"[{DEVA}]", toks[0])):
            H.add_name(" ".join(toks))
            if first_label is None:
                first_label = toks
    for m in _PAT_HON_RX.finditer(text):
        seq = m.group(1) or m.group(3)
        toks = clean_name_seq(seq)
        if _name_ok(toks) and (toks[0][:1].isupper() or re.search(rf"[{DEVA}]", toks[0])):
            H.add_name(" ".join(toks))
            if first_label is None:
                first_label = toks
    for m in RX_HON_BEFORE.finditer(text):
        toks = clean_name_seq(m.group(2))
        if _name_ok(toks):
            H.add_name(" ".join(toks))
    if not first_label:
        for rx_k in (RX_PRE_KIN, RX_PRE_PAREN_KIN):
            for m in rx_k.finditer(text):
                if rx_k is RX_PRE_PAREN_KIN and "." in m.group(1):
                    continue
                toks = clean_name_seq(m.group(1))
                if not (_name_ok(toks) and (toks[0][:1].isupper() or re.search(rf"[{DEVA}]", toks[0]))):
                    continue
                if rx_k is RX_PRE_PAREN_KIN:
                    if toks[-1].lower() in ("attendant", "relative", "visitor", "guardian", "witness"):
                        continue
                    rtoks = clean_name_seq(m.group(2))
                    if not (rtoks and _name_ok(rtoks) and not L.COMPLAINT_WORDS.match(rtoks[0])
                            and (rtoks[0][:1].isupper() or re.search(rf"[{DEVA}]", rtoks[0]))):
                        continue
                H.add_name(" ".join(toks))
                first_label = toks
                break
            if first_label:
                break
    for m in RX_PRE_PAREN_KIN.finditer(text):
        if "." in m.group(1):
            continue
        toks = clean_name_seq(m.group(1))
        rtoks = clean_name_seq(m.group(2))
        if (toks and _name_ok(toks) and (toks[0][:1].isupper() or re.search(rf"[{DEVA}]", toks[0]))
                and toks[-1].lower() not in ("attendant", "relative", "visitor", "guardian", "witness")
                and rtoks and _name_ok(rtoks) and not L.COMPLAINT_WORDS.match(rtoks[0])
                and (rtoks[0][:1].isupper() or re.search(rf"[{DEVA}]", rtoks[0]))):
            H.add_name(" ".join(rtoks))
            e["rel"].append(rtoks)
    if first_label:
        e["names"].append(first_label)
        rec.is_patient = True
    for m in RX_KIN_POSS.finditer(text):
        toks = clean_name_seq(m.group(1))
        if toks and _name_ok(toks):
            H.add_name(" ".join(toks))
            e["rel"].append(toks)
    for m in RX_KIN.finditer(text):
        rel, toks = m.group(1), clean_name_seq(m.group(2))
        if not toks or not _name_ok(toks):
            continue
        if rel.upper().startswith("C/O") and (L.COMPLAINT_WORDS.match(toks[0]) or toks[0][:1].islower()):
            continue
        H.add_name(" ".join(toks))
        e["rel"].append(toks)
    for m in re.finditer(rf"(?i)([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?|[{DEVA}]+(?:\s+[{DEVA}]+)?)\s*\(\s*C/o\s*\)", text):
        toks = clean_name_seq(m.group(1))
        if toks and _name_ok(toks):
            H.add_name(" ".join(toks))
            e["rel"].append(toks)
    for m in RX_NAME_ROLE.finditer(text):
        toks = clean_name_seq(m.group(1))
        if toks and _name_ok(toks) and (toks[0][:1].isupper() or re.search(rf"[{DEVA}]", toks[0])):
            H.add_name(" ".join(toks))
            e["rel"].append(toks)
    id_scan = re.sub(r"(?i)\b(?:https?://[^\s\"'<>?]+|urn:(?:uuid|oid):[\w.\-]+)", " ", text)
    for m in RX_IDTOK.finditer(id_scan):
        tok = m.group(0)
        if id_digits_ok(tok):
            a = re.sub(r"[^0-9A-Za-z]", "", tok).upper()
            e["ids"].add("M:" + a)
            H.add_id(tok)
            rec.is_patient = True
    for m in RX_ID_LABEL.finditer(text):
        tok = m.group(1).strip(" :-.")
        digits = re.sub(r"\D", "", tok)
        if len(digits) >= 4 and not re.fullmatch(r"\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}", tok):
            a = re.sub(r"[^0-9A-Za-z]", "", tok).upper()
            if len(a) >= 4:
                e["ids"].add("M:" + a)
                H.add_id(tok)
                rec.is_patient = True
    for m in RX_DIGITRUN.finditer(text):
        k = classify_digits(m.group(1))
        d = re.sub(r"\D", "", m.group(1).translate(_INDIC_DIGITS))
        if k == "PHONE":
            e["phones"].add(d[-10:])
            H.phones.add(d[-10:])
        elif k in ("AADHAAR", "ABHA"):
            e["ids"].add(("A:" if k == "AADHAAR" else "B:") + d)
            H.id_digits.add(d)
    for m in RX_DOTTED_PHONE.finditer(text):
        d = re.sub(r"\D", "", m.group(0).translate(_INDIC_DIGITS))
        if len(d) >= 10:
            e["phones"].add(d[-10:])
            H.phones.add(d[-10:])
    for m in RX_EMAIL.finditer(text):
        e["ids"].add("E:" + m.group(0).lower())
    m = DOB_RX.search(text)
    if m:
        d = parse_date(m.group(1), order)
        if d:
            e["dob"] = d.isoformat()
    m = re.search(rf"(?i)(?:\bAge(?:/(?:Sex|Gender|Sx|Jati))?|\bYrs?(?:/(?:Sex|Gender|Sx))?|(?:आयु|उम्र|उमर|वय)(?:/(?:लिंग|लिग|sex|gender|sx))?|\bUmar(?:/(?:Jati|Sx|Sex))?|\bUmra)\s*[:\-]?\s*([{INDIC_DIG}]{{1,3}})", text)
    if m:
        e["age"] = int(m.group(1).translate(_INDIC_DIGITS))
    m = re.search(r"(?i)\b\d{1,3}\s*(?:Yrs?|Y|years)?\s*/\s*([MF])\b|\b(?:Sex|Gender|Jati)\s*[:\-]\s*(Male|Female|M|F)\b|लिंग\s*[:\-]\s*(पुरुष|महिला)", text)
    if m:
        e["gender"] = gender_of(next(g for g in m.groups() if g))
    for m in RX_VILL.finditer(text):
        v = m.group(1) or m.group(2)
        if v:
            v = " ".join(t for t in v.split() if t.lower() not in STOP_WORDS)
            if v:
                H.add_place(v)
                e["village"] = e["village"] or norm(v)
    if e["date"] is None:
        dm = re.search(r"(?:तारीख|तिथि|Date|DOA|DOD|Admitted|Discharged)\s*[:\-]?\s*([^\n]{4,24})", text, re.I)
        d = parse_date(dm.group(1), order) if dm else None
        if d and 2015 <= d.year <= 2035:
            e["date"] = d.year


def guard_ids(recs: list) -> None:
    """Drop identifiers that are shared by records that clearly belong to different people."""
    from .linker import name_keys
    by = defaultdict(list)
    for r in recs:
        for i in r.ev["ids"]:
            by[i].append(r)
        for p in r.ev["phones"]:
            by["P:" + p].append(r)
    for i, rs in by.items():
        if len(rs) < 2:
            continue
        genders = {r.ev["gender"] for r in rs if r.ev["gender"]}
        dobs = {r.ev["dob"] for r in rs if r.ev["dob"]}
        keys = [set(k) for r in rs for k in (name_keys(n) for n in r.ev["names"]) if k]
        disjoint = any(not (a & b) for x, a in enumerate(keys) for b in keys[x + 1:])
        if len(genders) > 1 or len(dobs) > 1 or disjoint:
            for r in rs:
                if i.startswith("P:"):
                    r.ev["phones"].discard(i[2:])
                else:
                    r.ev["ids"].discard(i)


MAX_JSON_DEPTH = 64


def json_depth(obj) -> int:
    """Iterative nesting depth (no recursion)."""
    best, stack = 0, [(obj, 1)]
    while stack:
        o, d = stack.pop()
        best = max(best, d)
        if best > MAX_JSON_DEPTH:
            return best
        if isinstance(o, dict):
            stack.extend((v, d + 1) for v in o.values())
        elif isinstance(o, list):
            stack.extend((v, d + 1) for v in o)
    return best


# ================================================================ pass 1
def _table_list(v) -> bool:
    return (isinstance(v, list) and len(v) >= 2 and isinstance(v[0], list) and v[0]
            and all(isinstance(h, str) for h in v[0]) and all(isinstance(x, list) for x in v[1:]))


def _pairs(v) -> bool:
    if not (isinstance(v, list) and v and all(isinstance(x, list) and len(x) == 2 and isinstance(x[0], str) for x in v)):
        return False
    c0_known = sum(kind_of_key(x[0]) is not None for x in v[:12])
    if any(isinstance(x[1], (dict, list)) for x in v):
        return c0_known >= 2 or kind_of_key(v[0][0]) in ("NAME", "MRN")
    if len(v) >= 2 and kind_of_key(v[0][1]) is not None and c0_known <= 1:
        return False
    return True


def _ext_table(d: dict):
    """{"cols": [names...], "rows": [[...], ...]} -> (rows_key, header) or None."""
    if not isinstance(d, dict):
        return None
    heads = [(k, v) for k, v in d.items() if isinstance(v, list) and len(v) >= 2 and all(isinstance(h, str) for h in v)]
    for hk_, header in heads:
        for k, v in d.items():
            if k != hk_ and isinstance(v, list) and v and all(isinstance(r, list) for r in v):
                if sum(1 for r in v if len(r) == len(header)) >= 0.6 * len(v):
                    return k, header
    return None


def _row_dict(header, row) -> dict:
    return {str(h): row[i] for i, h in enumerate(header) if i < len(row)}


_NON_PATIENT_KEYS = {"result", "results", "tests", "panels", "loinc", "unit", "range", "dose", "dosage", "frequency",
                     "price", "rate", "amount", "tariff", "items", "medications", "drugs", "diagnoses"}


def _patient_list(v) -> bool:
    """A list of objects whose items carry patient evidence (judged by the evidence extractor itself)."""
    if not (isinstance(v, list) and v and all(isinstance(x, dict) for x in v)):
        return False
    hits = 0
    sample = v[:12]
    for x in sample:
        r = Rec("", "")
        walk_evidence(x, None, r, Harvest(), "dmy")
        e = r.ev
        has_strong = bool(e["ids"] or e["phones"] or e["dob"])
        has_clin_shape = any(k.lower() in _NON_PATIENT_KEYS for k in x) and not (has_strong or e["rel"] or e["age"] is not None or e["gender"])
        if (e["names"] and not has_clin_shape) or has_strong:
            hits += 1
    return hits >= max(1, len(sample) // 2)


def _field_columns(items):
    """Recognise a list of {label: ..., value: ...} cells within one record."""
    if not isinstance(items, list) or not items or not isinstance(items[0], dict):
        return None
    first = items[0]
    if len(first) != 2:
        return None
    label = next((k for k in first if k.casefold() in {"k", "key", "label", "field", "fieldname", "attribute"}), None)
    if label is None:
        return None
    value = next(k for k in first if k != label)
    if value.casefold() not in {"v", "val", "value", "data", "content"}:
        return None
    if all(isinstance(item, dict) and item.keys() == first.keys() and isinstance(item[label], str) for item in items):
        return label, value
    return None


def _patient_map(node):
    """Repeated sibling objects with shared field names and independent patient clues."""
    if not isinstance(node, dict) or len(node) < 2 or not all(isinstance(v, dict) for v in node.values()):
        return False
    import itertools
    sample = list(itertools.islice(node.values(), 12))
    common = set(sample[0])
    for item in sample[1:]:
        common.intersection_update(item)
    return bool(common) and _patient_list(sample)


def _pointer(path):
    return "".join("/" + str(x).replace("~", "~0").replace("/", "~1") for x in path) or "doc"


def _direct_patient(obj):
    return isinstance(obj, dict) and any(
        kind_of_key(k) in {"NAME", "MRN", "AADHAAR", "ABHA"} and isinstance(v, (str, int))
        for k, v in obj.items())


def json_records(node, job, path=()):
    """Yield each record's path, value and optional row schema. A parent with its
    own patient fields owns its encounters unless those encounters identify patients."""
    if not isinstance(node, (dict, list)):
        return
    if isinstance(node, dict) and node.get("resourceType") == "Bundle":
        entries = node.get("entry", [])
        if isinstance(entries, list):
            patients = [(i, item) for i, item in enumerate(entries) if isinstance(item, dict)
                        and isinstance(item.get("resource"), dict) and item["resource"].get("resourceType") == "Patient"]
            if len(patients) > 1:
                for i, item in patients:
                    yield path + ("entry", i), item, None
        return
    if _pairs(node) or _field_columns(node):
        return
    if _table_list(node):
        for i, row in enumerate(node[1:], 1):
            yield path + (i,), row, node[0]
        return
    et = _ext_table(node) if isinstance(node, dict) else None
    if et:
        k, header = et
        for i, row in enumerate(node[k]):
            yield path + (k, i), row, header
        return
    keyed = _patient_map(node)
    bearing = keyed or _patient_list(node)
    if keyed:
        job.keyed.add(path)
    parts = node.items() if isinstance(node, dict) else enumerate(node)
    for k, item in parts:
        if not isinstance(item, (dict, list)):
            continue
        if isinstance(k, str) and kind_of_key(k) == "DOCTOR":
            continue          # staff / care-team sub-maps never own patient records
        subpath = path + (k,)
        if bearing and _direct_patient(item):
            yield subpath, item, None
            continue
        nested = list(json_records(item, job, subpath))
        if nested:
            yield from nested
        elif bearing:
            yield subpath, item, None


def _metadata(node, path, job):
    if path in job.rec_ptrs:
        return None
    if path not in job.branches:
        return node
    if isinstance(node, dict):
        return {k: _metadata(v, path + (k,), job) for k, v in node.items()}
    return [_metadata(v, path + (i,), job) for i, v in enumerate(node)]


def _table_header(rows):
    """Find the start of a rectangular table following short report metadata."""
    if len(rows) < 3 or len(rows[0]) > 1:
        return 0
    for i in range(1, min(len(rows) - 1, 64)):
        width = len(rows[i])
        if width >= 2 and len(rows[i + 1]) == width and all(h.strip() for h in rows[i]):
            return i
    return 0


def _fixed_rows(text):
    """Use header tab stops only when multiple data lines confirm the alignment."""
    lines = text.splitlines()
    if len(lines) < 3:
        return None
    header = lines[0]
    spans = list(re.finditer(r"\S(?:.*?\S)?(?= {2,}|$)", header.strip()))
    if len(spans) < 3 or sum(kind_of_key(m.group()) is not None for m in spans) < 2:
        return None
    starts = [m.start() for m in spans]
    sample = [line for line in lines[1:10] if line.strip()]
    if not sample or not all(sum(len(line) > s and line[s - 1].isspace() for s in starts[1:])
                             >= (len(starts) - 1) * .75 for line in sample):
        return None
    bounds = list(zip(starts, starts[1:] + [None]))
    return [[line[a:b].strip() for a, b in bounds] for line in lines], starts


def walk_evidence(obj, kind, rec: Rec, H: Harvest, order: str, res_kind=None):
    if isinstance(obj, dict):
        rk = res_kind
        rt = obj.get("resourceType")
        if rt in ("Practitioner", "PractitionerRole", "Organization", "Location", "Device", "HealthcareService"):
            rk = "DOCTOR"
        elif rt == "RelatedPerson":
            rk = "REL_NAME"
        elif rt == "Patient":
            rk = None
        base = rk if rk else kind
        ext_kind = ext_value_kind(obj)
        for k, v in obj.items():
            ck = ext_kind if (ext_kind and k.startswith("value")) else child_kind(k, base)
            if (k == "gender" or set(L.key_tokens(k)) & GENDER_TOK) and ck != "AGE":
                g = gender_of(v) if isinstance(v, str) else None
                if g:
                    rec.ev["gender"] = g
                continue
            if ck == "AGE" and isinstance(v, str):
                gm = re.search(r"(?i)/\s*([MF])\b", v)
                if gm:
                    rec.ev["gender"] = gm.group(1).upper()
            if set(L.key_tokens(k)) & DISTRICT_TOK and isinstance(v, str):
                H.safe_places.add(norm(v))
                rec.ev.setdefault("district", v)
                continue
            if set(L.key_tokens(k)) & TEHSIL_TOK and isinstance(v, str):
                H.safe_places.add(norm(v))
                continue
            if set(L.key_tokens(k)) & COND_TOK and isinstance(v, str):
                rec.ev.setdefault("conds", set()).add(norm(v))
            walk_evidence(v, ck, rec, H, order, rk)
    elif isinstance(obj, list):
        cols = _field_columns(obj)
        if cols:
            label, value = cols
            for item in obj:
                walk_evidence({item[label]: item[value]}, kind, rec, H, order, res_kind)
            return
        if _pairs(obj):
            for lab, val in obj:
                walk_evidence({lab: val}, kind, rec, H, order, res_kind)
            return
        for x in obj:
            walk_evidence(x, kind, rec, H, order, res_kind)
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        if kind == "DATE":
            if isinstance(obj, str) and not rec.ev["date"]:
                d = parse_date(obj, order)
                if d and 1990 <= d.year <= 2035:
                    rec.ev["date"] = d.year
            return
        if kind in ("DOCTOR", "STRUCT", "RELATION"):
            return
        if kind in (None, "SAFE"):
            if isinstance(obj, str) and len(obj) > 3:
                text_evidence(obj, rec, H, order)
            return
        if kind == "COND" and isinstance(obj, str):
            rec.ev.setdefault("conds", set()).add(norm(obj))
            return
        if kind == "NAME" and not isinstance(obj, str):
            return
        add_ev(rec, H, kind, obj, order=order)


def pass1(job: FileJob, H: Harvest):
    if job.ext in UNSUPPORTED:
        job.status, job.reason = "quarantined", "unsupported_format"
        return
    if not job.raw.strip():
        job.status, job.reason = "quarantined", "empty_file"
        return
    text = decode(job.raw)
    if text is None:
        job.status, job.reason = "quarantined", "undecodable_text"
        return
    if looks_binary(text):
        job.status, job.reason = "quarantined", "binary_content"
        return
    job.text = text
    job.crlf = "\r\n" in text[:2000]
    kind = sniff_kind(job.ext, text)
    if kind == "unsupported":
        job.status, job.reason = "quarantined", "unsupported_format"
        return
    d, m = date_votes(text)
    if re.search(r"(?i)MM/DD", text[:3000]):
        m += 5
    if re.search(r"(?i)DD/MM", text[:3000]):
        d += 5
    job.order = "mdy" if m > d else ("dmy" if d > m else "?")
    if kind == "json" and job.ext != ".json":
        try:
            json.loads(text)
        except (ValueError, RecursionError):
            kind = "table" if job.ext in (".csv", ".tsv") else "text"
    fixed = _fixed_rows(text) if kind == "text" else None
    if fixed:
        kind = "table"
    try:
        if kind == "jsonl":
            job.kind = "jsonl"
            job.data = []
            for i, line in enumerate(l for l in text.splitlines() if l.strip()):
                try:
                    obj = json.loads(line)
                except ValueError:
                    obj = line
                job.data.append(obj)
                r = Rec(job.rel, f"row:{i}")
                if isinstance(obj, (dict, list)):
                    walk_evidence(obj, None, r, H, job.order)
                else:
                    text_evidence(obj, r, H, job.order)
                job.recs.append(r)
            return
        if kind == "json":
            job.data = json.loads(text)
            if json_depth(job.data) > MAX_JSON_DEPTH:
                raise ValueError("too_deep")
            first_nl = text.lstrip()[1:].lstrip(" ")
            mm = re.match(r"\r?\n( +)", text.lstrip()[1:])
            job.indent = len(mm.group(1)) if mm else None
            job.kind = "json"
            for path, item, hdr in json_records(job.data, job):
                r = Rec(job.rel, _pointer(path))
                walk_evidence(_row_dict(hdr, item) if hdr else item, None, r, H, job.order)
                job.recs.append(r)
                job.rec_ptrs[path] = (r, hdr)
                job.branches.update(path[:i] for i in range(len(path)))
            if job.rec_ptrs:
                meta = Rec(job.rel, "@meta")
                walk_evidence(_metadata(job.data, (), job), None, meta, H, job.order)
            else:
                r = Rec(job.rel, "doc")
                walk_evidence(job.data, None, r, H, job.order)
                job.recs.append(r)
                job.doc_rec = r
        elif kind == "table":
            job.kind = "table"
            job.delim = sniff_delim(text, job.ext)
            body = text.replace("\r\n", "\n").replace("\r", "\n")
            if fixed:
                job.rows, job.widths = fixed
            else:
                job.rows = list(csv.reader(io.StringIO(body, newline=""), delimiter=job.delim, strict=True))
            start = _table_header(job.rows)
            job.preamble, job.rows = job.rows[:start], job.rows[start:]
            if not job.rows:
                raise ValueError("empty_table")
            header = job.rows[0]
            kinds = []
            for ci, h in enumerate(header):
                k = kind_of_key(h)
                toks = set(L.key_tokens(h))
                if toks & GENDER_TOK and k != "AGE":
                    k = "GENDER"
                elif toks & DISTRICT_TOK:
                    k = "DISTRICT"
                elif toks & TEHSIL_TOK:
                    k = "TEHSIL"
                if k in (None, "SAFE"):
                    sk = shape_kind([r[ci] for r in job.rows[1:] if ci < len(r)])
                    if sk:
                        k = sk
                kinds.append(k)
            job.colkinds = kinds
            for i, row in enumerate(job.rows[1:]):
                r = Rec(job.rel, f"row:{i}")
                if row == header or not any(v.strip() for v in row):
                    job.repeat_headers.add(i)
                    job.recs.append(r)
                    continue
                for ci, v in enumerate(row):
                    k = kinds[ci] if ci < len(kinds) else None
                    if k == "GENDER":
                        r.ev["gender"] = gender_of(v)
                    elif k == "DISTRICT":
                        H.safe_places.add(norm(v))
                        r.ev["district"] = v
                    elif k == "TEHSIL":
                        H.safe_places.add(norm(v))
                    elif k == "NAME_SHAPE":
                        H.add_name(v)
                    elif k in (None, "SAFE"):
                        if ci < len(header) and set(L.key_tokens(header[ci])) & COND_TOK and v.strip():
                            r.ev.setdefault("conds", set()).add(norm(v))
                        if len(v) > 3:
                            text_evidence(v, r, H, job.order)
                    elif k == "DATE":
                        if not r.ev["date"]:
                            d = parse_date(v, job.order)
                            if d and 1990 <= d.year <= 2035:
                                r.ev["date"] = d.year
                    elif k not in ("DOCTOR", "RELATION", "STRUCT"):
                        add_ev(r, H, k, v, order=job.order)
                        if k == "AGE" and isinstance(v, str):
                            gm = re.search(r"(?i)/\s*([MF])\b", v)
                            if gm:
                                r.ev["gender"] = gm.group(1).upper()
                # split first/last name columns -> one name
                names = [row[ci] for ci, k in enumerate(kinds) if k == "NAME" and ci < len(row) and row[ci].strip()]
                if len(names) > 1:
                    r.ev["names"] = [" ".join(names).split()]
                job.recs.append(r)
        else:
            job.kind = "text"
            r = Rec(job.rel, "doc")
            text_evidence(text, r, H, job.order)
            job.recs.append(r)
            job.doc_rec = r
    except (ValueError, RecursionError, csv.Error, UnicodeError, KeyError, TypeError):
        job.status, job.reason = "quarantined", "malformed_content"
        job.recs = []
    except Exception:  # noqa: BLE001 - fail safe: never crash the release on one file
        job.status, job.reason = "quarantined", "processing_error"
        job.recs = []


# ================================================================ pass 2 (transform)
class Rewriter:
    def __init__(self, H: Harvest, sw: Sweeper, stats: Stats, policy: dict):
        self.H, self.sw, self.st, self.pol = H, sw, stats, policy

    def value(self, v, kind, ctx: Ctx, rec: Rec | None):
        st = self.st
        if isinstance(v, bool) or v is None:
            return v
        if isinstance(v, (int, float)):
            if kind in ("AADHAAR", "ABHA", "PHONE", "MRN", "INSURANCE"):
                st["identifiers"] += 1
                return 0
            if kind == "PIN":
                st["identifiers"] += 1
                if ctx.rule is not None and ctx.rule.pin == "keep6":
                    return v
                s = str(int(v))
                if ctx.rule is not None and ctx.rule.pin == "drop":
                    return 0
                return int(s[:3] + "000") if len(s) == 6 else 0
            if kind == "AGE" and isinstance(v, int):
                if ctx.rule is not None and ctx.rule.band <= 1:
                    return v
                st["generalized"] += 1
                return ctx.band(v)
            return v
        s = v
        if not s.strip():
            return s
        if kind == "NAME":
            st["identifiers"] += 1
            if len(re.sub(r"\D", "", s)) >= 3:
                return ctx.psn or "[ID]"
            return ctx.patient_token
        if kind == "REL_NAME":
            st["identifiers"] += 1
            m = re.match(r"(?i)\s*(S/O|D/O|W/O|H/O|C/O|S\.O\.|D\.O\.|W\.O\.)\.?\s*", s)
            return (m.group(1) + " " if m else "") + "[RELATIVE]"
        if kind in ("STRUCT", "RELATION"):
            return s
        if kind == "DOCTOR":
            if re.search(r"(?i)(?:\bnaam\s*[=:]|\bpatient\b|\buhid\b|\bmrn\b|\d{4})", s):
                return scrub_text(s, ctx, self.sw)
            return s
        if kind == "MRN":
            st["identifiers"] += 1
            return ctx.psn or "[ID]"
        if kind in ("AADHAAR", "ABHA", "PAN", "EMAIL", "INSURANCE", "PHONE"):
            st["identifiers"] += 1
            return f"[{kind}]"
        if kind == "DOB":
            st["identifiers"] += 1
            if ctx.rule is not None and ctx.rule.dob == "year_drop":
                st["generalized"] += 1
                return "[DOB]"
            out = shift_dates_in(s, ctx.days, ctx.order)
            return out if out != s else "[DOB]"
        if kind == "DATE":
            return shift_dates_in(s, ctx.days, ctx.order) if ctx.days else s
        if kind == "AGE":
            m = re.search(r"\d{1,3}", s)
            if m:
                st["generalized"] += 1
                return s[: m.start()] + ctx.band(int(m.group(0))) + s[m.end():]
            return s
        if kind == "PIN":
            st["identifiers"] += 1
            rule = ctx.rule
            if rule is not None and rule.pin == "keep6":
                return s
            m = re.search(r"([1-8]\d{2})\s?\d{3}", s)
            if rule is not None and rule.pin == "drop":
                return "[PIN]"
            return (m.group(1) + "XXX") if m else "[PIN]"
        if kind == "VILLAGE":
            st["identifiers"] += 1
            st["generalized"] += 1
            if ctx.rule is not None and ctx.rule.dist == "drop":
                return "[VILLAGE]"
            dist = rec.ev.get("district") if rec else None
            return dist or "[VILLAGE]"
        if kind == "ADDRESS":
            st["identifiers"] += 1
            if ctx.rule is not None and ctx.rule.dist == "drop":
                return "[ADDRESS]"
            return generalize_address(s)
        if kind == "TEHSIL" and (ctx.rule is None or ctx.rule.tehsil == "drop"):
            st["generalized"] += 1
            if ctx.rule is not None and ctx.rule.dist == "drop":
                return "[TEHSIL]"
            return (rec.ev.get("district") if rec else None) or "[TEHSIL]"
        if kind == "DISTRICT" and ctx.rule is not None and ctx.rule.dist == "drop":
            st["identifiers"] += 1
            st["generalized"] += 1
            return "[DISTRICT]"
        if kind in ("DISTRICT", "TEHSIL", "GENDER"):
            return scrub_text(s, ctx, self.sw) if re.search(r"\d{3}|[A-Z][a-z]+\s+[A-Z][a-z]+", s) else s
        if kind == "NAME_SHAPE":
            st["identifiers"] += 1
            return "[NAME]"
        if kind is None and NAME_VALUE.fullmatch(s.strip()) and _name_ok(s.split()) and len(s.split()) >= 2:
            st["identifiers"] += 1
            return "[NAME]"
        return scrub_text(s, ctx, self.sw)

    def key(self, k: str, ctx: Ctx, seen: set) -> str:
        if k in STRUCT_KEYS or self.schema_key(k):
            seen.add(k)
            return k
        nk = scrub_text(k, ctx, self.sw)
        if nk != k:
            nk = re.sub(r"\[[A-Z_]+\]|PSN-[0-9A-Z]{6}", "", nk).strip(" _-:") or "key"
            nk = f"{nk}_{opaque('key', k, 5)}" if nk != "key" else f"key_{opaque('key', k, 5)}"
        while nk in seen:
            nk += "_"
        seen.add(nk)
        return nk

    def schema_key(self, k: str) -> bool:
        """Identifier-style schema keys ("data", "patientInfo", "opd_sessions") are not person names,
        even when a patient happens to be called "Data": skip single-token name matching for them, but
        still rename on full names, e-mails, phones or long digit runs."""
        if not re.fullmatch(r"[a-z][a-zA-Z0-9_]{0,40}", k) or re.search(r"\d{4,}", k):
            return False
        spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", k).replace("_", " ")
        return not (self.sw.rx_lat_full.search(spaced) or self.sw.rx_ids.search(k))

    def walk(self, obj, kind, ctx: Ctx, rec, res_kind=None):
        if isinstance(obj, dict):
            rk = res_kind
            rt = obj.get("resourceType")
            if rt in ("Practitioner", "PractitionerRole", "Organization", "Location", "Device", "HealthcareService"):
                rk = "DOCTOR"
            elif rt == "RelatedPerson":
                rk = "REL_NAME"
            elif rt == "Patient":
                rk = None
            base = rk if rk else kind
            ext_kind = ext_value_kind(obj)
            out, seen = {}, set()
            is_fhir_patient = rt == "Patient"
            for k, v in obj.items():
                ck = ext_kind if (ext_kind and k.startswith("value")) else child_kind(k, base)
                if is_fhir_patient and k == "birthDate" and ctx.rule is not None and ctx.rule.dob == "year_drop":
                    self.st["identifiers"] += 1
                    self.st["generalized"] += 1
                    continue
                toks = set(L.key_tokens(k))
                if toks & GENDER_TOK and not isinstance(v, (dict, list)) and ck != "AGE":
                    ck = "GENDER"
                elif toks & DISTRICT_TOK and isinstance(v, str):
                    ck = "DISTRICT"
                elif toks & TEHSIL_TOK and isinstance(v, str):
                    ck = "TEHSIL"
                out[self.key(k, ctx, seen)] = self.walk(v, ck, ctx, rec, rk)
            return out
        if isinstance(obj, list):
            cols = _field_columns(obj)
            if cols:
                label, value = cols
                return [{label: self.key(item[label], ctx, set()),
                         value: self.walk(item[value], child_kind(item[label], kind), ctx, rec, res_kind)}
                        for item in obj]
            if _pairs(obj):
                out = []
                for lab, val in obj:
                    ck = child_kind(lab, kind) if lab not in STRUCT_KEYS else "STRUCT"
                    out.append([self.value(lab, None, ctx, rec), self.walk(val, ck, ctx, rec, res_kind)])
                return out
            return [self.walk(x, kind, ctx, rec, res_kind) for x in obj]
        return self.value(obj, kind, ctx, rec)


def rewrite_json(rw, node, path, job, meta_ctx, ctx_for, kind=None, out_path=(), safe_path=None):
    if path in job.rec_ptrs:
        rec, header = job.rec_ptrs[path]
        ctx = ctx_for(rec, job)
        if safe_path is not None:
            job.out_locs[rec.loc] = (_pointer(safe_path), _pointer(out_path))
        if header is not None:
            return [rw.walk(v, child_kind(str(header[i]), None) if i < len(header) else None, ctx, rec)
                    for i, v in enumerate(node)]
        return rw.walk(node, None, ctx, rec)
    if path not in job.branches:
        return rw.walk(node, kind, meta_ctx, None)
    if isinstance(node, dict):
        out, seen = {}, set()
        # Some systems number rows inside an object. Preserve verified ordinals
        # if they are not also present as identifiers harvested from records.
        ordinals = False
        if path in job.keyed:
            matches = [re.fullmatch(r"([^0-9]*)([0-9]{1,8})", k) for k in node]
            if all(matches) and len({m[1] for m in matches}) == 1:
                numbers = sorted(int(m[2]) for m in matches)
                ordinals = numbers[0] in (0, 1) and numbers == list(range(numbers[0], numbers[0] + len(numbers)))
        for k, v in node.items():
            if path in job.keyed and not (ordinals and re.sub(r"[^A-Za-z0-9]", "", k).upper() not in rw.H.ids):
                nk = "key_" + opaque("record key", k, 12)
                while nk in seen:
                    nk += "_"
                seen.add(nk)
            elif path in job.keyed:
                nk = k
                seen.add(k)
            else:
                nk = rw.key(k, meta_ctx, seen)
            safe = path if nk != k and safe_path is None else safe_path
            out[nk] = rewrite_json(rw, v, path + (k,), job, meta_ctx, ctx_for, child_kind(k, kind),
                                   out_path + (nk,), safe)
        return out
    return [rewrite_json(rw, v, path + (i,), job, meta_ctx, ctx_for, kind, out_path + (i,), safe_path)
            for i, v in enumerate(node)]


def kv_rewrite(text: str, rw, ctx, rec) -> str:
    """Apply field-kind rules to label/value rows found in free text (dates are left to the scrubber,
    which shifts every date exactly once; a DOB that policy drops is removed here)."""
    out, last = [], 0
    for lab, v, a, b in kv_rows(text):
        k = _kv_kind(lab, v)
        if not k:
            continue
        if k == "DOB" and not (ctx.rule is not None and ctx.rule.dob == "year_drop"):
            continue
        nv = rw.value(v.strip(" *"), k, ctx, rec)
        if nv == v.strip(" *"):
            continue
        out.append(text[last:a])
        out.append(str(nv))
        last = b
    out.append(text[last:])
    return "".join(out)


# ================================================================ filenames
_DATELIKE = re.compile(r"(?:19|20)\d{2}(?:[_\-.]\d{1,2}){0,2}|\d{1,2}[_\-.]\d{1,2}[_\-.](?:19|20)\d{2}")


def scrub_component(comp: str, H: Harvest, sw: Sweeper, salt: str) -> str:
    stem, ext = os.path.splitext(comp)
    orig_stem = stem
    flagged = False

    def cluster(m):
        nonlocal flagged
        c = m.group(0)
        if len(re.sub(r"\D", "", c)) >= 5 and not _DATELIKE.fullmatch(c):
            flagged = True
            return ""
        return c
    stem = re.sub(r"\d+(?:[_\-.\s]\d+)+", cluster, stem)
    # Strip full multi-separator names and structured/digit IDs BEFORE token splitting so
    # hyphenated MRNs (e.g. R-2024-A-5670) or CamelCase names (MaheeAwasthi) never survive.
    for rx in (sw.rx_lat_full, sw.rx_dev_full, sw.rx_ids, sw.rx_digits):
        s2 = rx.sub("", stem)
        if s2 != stem:
            flagged = True
            stem = s2
    s2 = RX_IDTOK.sub(lambda m: "" if id_digits_ok(m.group(0)) else m.group(0), stem)
    if s2 != stem:
        flagged = True
        stem = s2
    # Split CamelCase runs (except common uppercase abbreviations >=2 chars followed by lowercase)
    camel_split = re.sub(r"([a-z])([A-Z])", r"\1_\2", stem)
    parts = re.split(r"([_\-\s.()]+)", camel_split)
    keep = []
    for p in parts:
        pl = p.lower()
        if not p or re.fullmatch(r"[_\-\s.()]+", p):
            keep.append(p)
            continue
        digits = re.sub(r"\D", "", p)
        bad = (pl in H.name_tokens or (len(p) >= 3 and L.skel(p) in H.name_skels and p[:1].isalpha())
               or len(digits) >= 5 or re.sub(r"[^0-9A-Za-z]", "", p).upper() in H.ids
               or (RX_IDTOK.fullmatch(p) and id_digits_ok(p)))
        if bad and pl not in COMMON_FILE_WORDS:
            flagged = True
            continue
        keep.append(p)
    caps = [p for p in parts if p and not re.fullmatch(r"[_\-\s.()]+", p)]
    for a, b in zip(caps, caps[1:]):
        if (re.fullmatch(r"[A-Z][a-z]{2,}", a) and re.fullmatch(r"[A-Z][a-z]{2,}", b)
                and not ({a.lower(), b.lower()} & (COMMON_FILE_WORDS | COMMON_WORDS | L.CLINICAL_WORDS))):
            flagged = True
            keep = [p for p in keep if p not in (a, b)]
    if not flagged:
        return comp
    base = re.sub(r"[_\-\s.()]{2,}", "_", "".join(keep)).strip("_-. ") or "file"
    if not base and orig_stem:
        base = "file"
    return f"{base}_{opaque('fname', salt, 6)}{ext}"


COMMON_FILE_WORDS = {"discharge", "summary", "report", "nursing", "notes", "rx", "lab", "opd", "ipd", "bundle",
                     "export", "visits", "patients", "results", "claims", "registration", "ds", "note", "file",
                     "data", "json", "csv", "txt", "tsv"}


# ================================================================ verification (independent of the scrubber)
_VERIFY_TOK = re.compile(rf"[a-z0-9{DEVA}]{{3,}}")


def build_verify_index(crit: list[str]) -> tuple[list[str], dict[str, list[str]]]:
    """Index critical strings by their longest alnum/Indic token for O(N) verification."""
    by_tok: dict[str, list[str]] = defaultdict(list)
    fallback: list[str] = []
    for c in crit:
        toks = _VERIFY_TOK.findall(c)
        if toks:
            anchor = max(toks, key=len)
            by_tok[anchor].append(c)
        elif c:
            fallback.append(c)
    return fallback, by_tok


def verify_text(text: str, crit: list[str], index: tuple[list[str], dict[str, list[str]]] | None = None) -> tuple[str, int]:
    """Exact-substring check of critical harvested values on the NFKC/casefold view; masks any survivor."""
    hits = 0
    M = Masker()
    text = RX_DOCTOR.sub(lambda m: M.put(m.group(0)), text)
    low = text.casefold()
    if index is not None:
        fallback, by_tok = index
        cands = list(fallback)
        seen_toks = set(_VERIFY_TOK.findall(low))
        for tok in seen_toks:
            if tok in by_tok:
                cands.extend(by_tok[tok])
        cands.sort(key=len, reverse=True)
    else:
        cands = crit
    for c in cands:
        if c and c in low:
            idx = 0
            while True:
                j = text.casefold().find(c, idx)
                if j < 0:
                    break
                text = text[:j] + "[REDACTED]" + text[j + len(c):]
                hits += 1
                idx = j + 10
            low = text.casefold()
    return M.restore(text), hits


# ================================================================ time budget (fail-safe against pathological inputs)
import signal
from contextlib import contextmanager

FILE_BUDGET_S = 45


def _file_budget(raw_len: int) -> int:
    return max(FILE_BUDGET_S, min(240, FILE_BUDGET_S + raw_len // 250_000))


class BudgetExceeded(Exception):
    pass


@contextmanager
def time_budget(seconds: int):
    if not hasattr(signal, "SIGALRM"):
        yield
        return

    def _raise(signum, frame):
        raise BudgetExceeded()
    old = signal.signal(signal.SIGALRM, _raise)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


# ================================================================ main
def peak_rss_mb() -> float:
    try:
        import resource
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(r / 1024 if sys.platform != "darwin" else r / 1048576, 1)
    except Exception:  # noqa: BLE001
        return 0.0


def load_policy(path: Path) -> dict:
    pol = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if ":" in line:
                k, v = (x.strip() for x in line.split(":", 1))
                pol[k] = int(v) if v.lstrip("-").isdigit() else v
    for k, v in os.environ.items():            # experiment overrides (ignored unless RAKSHAK_EXPERIMENT=1)
        if k.startswith("RAKSHAK_P_") and os.environ.get("RAKSHAK_EXPERIMENT") == "1":
            pol[k[10:].lower()] = int(v) if v.lstrip("-").isdigit() else v
    return pol


def run(inp: Path, out: Path, policy: dict) -> int:
    t0 = time.monotonic()
    sys.setrecursionlimit(4000)
    st = Stats()
    H = Harvest()
    jobs = []
    paths = [p for p in inp.rglob("*") if p.is_file() or p.is_symlink()]
    for path in sorted(paths, key=lambda p: p.relative_to(inp).as_posix()):
        rel = path.relative_to(inp).as_posix()
        unreadable = path.is_symlink()            # never follow links out of the input tree
        try:
            raw = b"" if unreadable else path.read_bytes()
        except OSError:
            raw, unreadable = b"", True
        job = FileJob(rel, raw)
        if unreadable:
            job.status, job.reason = "quarantined", "unreadable"
        else:
              with time_budget(_file_budget(len(job.raw))):
                try:
                    pass1(job, H)
                except BudgetExceeded:
                    job.status, job.reason, job.recs = "quarantined", "processing_timeout", []
        jobs.append(job)

    # date order for ambiguous files: vote by path tokens of files with evidence
    votes = defaultdict(Counter)
    for j in jobs:
        if j.order in ("dmy", "mdy"):
            for tok in set(re.findall(r"[a-z]{4,}", j.rel.lower())):
                votes[tok][j.order] += 1
    for j in jobs:
        if j.order == "?":
            c = Counter()
            for tok in set(re.findall(r"[a-z]{4,}", j.rel.lower())):
                c.update(votes.get(tok, {}))
            j.order = "mdy" if c["mdy"] > c["dmy"] else "dmy"

    # ---- link
    recs = [r for j in jobs for r in j.recs]
    date_orders = {j.rel: j.order for j in jobs}
    for r in recs:
        if r.ev["dob"]:
            j_order = date_orders[r.file]
            d = parse_date(r.ev["dob"], j_order)
            r.ev["dob"] = d.isoformat() if d else None
    # guard_ids(recs) measured harmful (dev link recall 0.94 -> 0.50); kept for reference only
    if str(policy.get("link", "on")) == "off":           # ablation only
        roots = list(range(len(recs)))
    else:
        roots = Linker([r.ev for r in recs]).run()
    groups = defaultdict(list)
    for r, g in zip(recs, roots):
        groups[g].append(r)
    # A rejected shared identifier must never rejoin distinct clusters at export.
    # Prefer a unique identifier. Otherwise the first input locator identifies this group.
    owners = {}
    for g, members in groups.items():
        for m in members:
            for ident in m.ev["ids"]:
                if owners.setdefault(ident, g) != g:
                    owners[ident] = None
    used_pids = set()
    for g, members in groups.items():
        if not any(m.is_patient for m in members):
            continue
        key = min((i for m in members for i in m.ev["ids"] if owners[i] == g), default=None)
        if key is None:
            first = min((m.file, m.loc) for m in members)
            key = json.dumps(first, ensure_ascii=False)
        pid = pseudonym(key)
        # Six base32 digits are required by existing clients. Resolve birthday collisions.
        attempt = 0
        while pid in used_pids:
            attempt += 1
            pid = pseudonym(f"{key}|collision|{attempt}")
        used_pids.add(pid)
        for m in members:
            m.key, m.pid = key, pid

    # ---- privacy plan (per patient)
    plan = P.plan(groups, policy)

    sw = Sweeper(H)
    rw = Rewriter(H, sw, st, policy)
    crit = sorted({n for n in H.full_names if len(n) >= 6} | {d for d in H.phones} |
                  {d for d in H.id_digits if len(d) >= 6}, key=len, reverse=True)
    verify_idx = build_verify_index(crit)
    maxd = int(policy.get("date_shift_max_days", 180))

    def ctx_for(rec: Rec | None, job: FileJob) -> Ctx:
        if rec is not None and rec.pid:
            days = P.days_for(rec.key, maxd)
            band = plan.band_fn(rec.key)
            return Ctx(H, rec.pid, days, job.order, band, st, plan.rule(rec.key))
        days = P.days_for(f"{job.rel}#{rec.loc}" if rec is not None else job.rel, maxd)
        return Ctx(H, None, days, job.order, plan.band_fn(None), st, plan.default)

    # ---- output names
    san = out / "sanitized"
    used = set()
    for j in jobs:
        if j.status != "sanitized":
            continue
        comps = j.rel.split("/")
        try:
            new = [scrub_component(c, H, sw, j.rel + "#" + str(i)) for i, c in enumerate(comps)]
        except Exception:  # noqa: BLE001
            new = [f"file_{opaque('fname', j.rel, 8)}{os.path.splitext(j.rel)[1]}"]
        o = "/".join(new)
        while o.lower() in used:
            stem, ext = os.path.splitext(o)
            o = stem + "_" + ext
        used.add(o.lower())
        j.out_rel = o

    # ---- rewrite
    records_out = []
    for j in jobs:
        if j.status != "sanitized":
            continue
        try:
          with time_budget(_file_budget(len(j.raw))):
              if j.kind == "jsonl":
                  lines = []
                  for r, obj in zip(j.recs, j.data):
                      c = ctx_for(r, j)
                      if isinstance(obj, (dict, list)):
                          lines.append(json.dumps(rw.walk(obj, None, c, r), ensure_ascii=False))
                      else:
                          lines.append(scrub_text(obj, c, sw))
                  result = "\n".join(lines) + "\n"
              elif j.kind == "json":
                  if j.rec_ptrs:
                      meta_ctx = ctx_for(None, j)
                      data = rewrite_json(rw, j.data, (), j, meta_ctx, ctx_for)
                  else:
                      r = j.doc_rec
                      data = rw.walk(j.data, None, ctx_for(r, j), r)
                  result = json.dumps(data, ensure_ascii=False, indent=j.indent) + "\n"
              if j.kind in ("jsonl", "json"):
                  pass
              elif j.kind == "table":
                  buf = io.StringIO()
                  w = csv.writer(buf, delimiter=j.delim, lineterminator="\r\n" if j.crlf else "\n")
                  hctx = ctx_for(None, j)
                  header = [scrub_text(h, hctx, sw) for h in j.rows[0]]
                  def write_row(values):
                      if j.widths:
                          fields = [v.ljust(b - a) for v, a, b in zip(values, j.widths, j.widths[1:])]
                          buf.write("".join(fields) + values[-1] + ("\r\n" if j.crlf else "\n"))
                      else:
                          w.writerow(values)
                  for row in j.preamble:
                      write_row([scrub_text(v, hctx, sw) for v in row])
                  write_row(header)
                  name_cols = [ci for ci, k in enumerate(j.colkinds) if k == "NAME"]
                  for i, row in enumerate(j.rows[1:]):
                      if i in j.repeat_headers:
                          write_row(header if row == j.rows[0] else row)
                          continue
                      r = j.recs[i]
                      c = ctx_for(r, j)
                      new_row = []
                      ragged = len(row) != len(j.colkinds)
                      for ci, v in enumerate(row):
                          k = j.colkinds[ci] if ci < len(j.colkinds) else None
                          if ragged and k not in ("NAME", "REL_NAME", "MRN", "AADHAAR", "ABHA", "PAN", "PHONE", "EMAIL", "INSURANCE"):
                              new_row.append(scrub_text(v, c, sw))
                              continue
                          if k == "NAME" and name_cols and ci != name_cols[0] and v.strip():
                              st["identifiers"] += 1
                              new_row.append("")
                              continue
                          new_row.append(rw.value(v, k, c, r))
                      write_row(new_row)
                  result = buf.getvalue()
              else:
                  r = j.doc_rec
                  c = ctx_for(r, j)
                  result = scrub_text(kv_rewrite(j.text, rw, c, r), c, sw)
                  if r is not None and r.pid and r.pid not in result:
                      result = f"Patient: {r.pid}\n" + result
              if str(policy.get("verify", "on")) != "off":     # ablation switch; always on in config
                  result, hits = verify_text(result, crit, verify_idx)
                  st["verify_hits"] += hits
        except Exception:  # noqa: BLE001 - fail safe: quarantine, never export half-cleaned data
            j.status, j.reason = "quarantined", "processing_error"
            continue
        dest = (san / j.out_rel).resolve()
        if not dest.is_relative_to(san.resolve()):
            j.status, j.reason = "quarantined", "unsafe_path"
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "w", encoding="utf-8", newline="") as f:
            f.write(result)
        for idx, r in enumerate(j.recs):
            if idx in j.repeat_headers or r.loc.startswith("@"):
                continue
            row = {"file": f"sanitized/{j.out_rel}", "loc": r.loc, "patient": r.pid}
            if r.loc in j.out_locs:
                row["loc"], row["out"] = j.out_locs[r.loc]
                row["patient"] = None
            records_out.append(row)
            st["records"] += 1

    with open(out / "records.jsonl", "w", encoding="utf-8") as f:
        for r in records_out:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    files = []
    for j in jobs:
        e = {"input_sha256": j.sha}
        if j.status == "sanitized":
            e.update(output=f"sanitized/{j.out_rel}", status="sanitized")
        else:
            e.update(output=None, status="quarantined", reason=j.reason)
        files.append(e)
    n_san = sum(e["status"] == "sanitized" for e in files)
    report = {
        "schema": "raksha-report/1",
        "files": files,
        "counts": {
            "files_total": len(files), "files_sanitized": n_san, "files_quarantined": len(files) - n_san,
            "records_processed": len(records_out), "identifiers_detected": st["identifiers"],
            "records_linked": sum(r["patient"] is not None for r in records_out),
            "records_generalized": st["generalized"], "records_suppressed": st["suppressed"],
            "records_quarantined": 0,
        },
        "entities": {},
        "timing": {"seconds": round(time.monotonic() - t0, 2)},
        "resources": {"peak_rss_mb": peak_rss_mb()},
    }
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"files {len(files)} sanitized {n_san} quarantined {len(files) - n_san} records {len(records_out)}")
    return 0
