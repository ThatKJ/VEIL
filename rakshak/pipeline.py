"""Two-pass pipeline: parse + harvest -> link -> rewrite -> verify -> report."""
from __future__ import annotations

import ast
import csv
import gc
from functools import lru_cache
import hashlib
import io
import json
import math
import os
import re
import sys
import time
from collections import Counter, defaultdict
from itertools import chain
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
ID_KINDS = {"MRN", "AADHAAR", "ABHA", "PAN", "EMAIL", "INSURANCE", "PHONE", "FAMILY_ID"}
STRUCT_KEYS = {"resourceType", "id", "fullUrl", "reference", "system", "url", "profile", "status", "type", "use",
               "mode", "contentType", "language", "coding", "code", "unit", "versionId", "schema",
               "loinc", "interpretation", "category", "intent", "priority", "valueQuantity", "comparator"}
GENDER_TOK = {"gender", "sex", "sx", "ling", "linga", "aan", "pen", "लिंग"}
DISTRICT_TOK = {"district", "distt", "jila", "jillo", "जिला", "ज़िला", "zila", "janpad"}
TEHSIL_TOK = {"tehsil", "तहसील", "तह", "taluka", "taluko", "block", "ta"}


class Stats(dict):
    def __missing__(self, k):
        return 0


class FileJob:
    __slots__ = ("rel", "raw", "raw_len", "src_path", "reparse", "sha", "ext", "kind", "text", "data", "delim",
                 "rows", "order", "recs", "status", "reason", "out_rel", "bom", "crlf", "indent", "doc_rec",
                 "colkinds", "rec_ptrs", "branches", "out_locs", "preamble", "widths", "repeat_headers",
                 "keyed", "eav", "col_map", "str_records")

    def __init__(self, rel, raw, src_path: Path | None = None):
        self.rel, self.raw = rel, raw
        self.raw_len = len(raw)
        self.src_path = src_path
        self.reparse = False
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
        self.eav = None
        self.col_map = {}
        self.str_records = set()


# ================================================================ field kinds
_RX_GROUP_PATH = re.compile(r"[a-z_][a-z0-9_]{2,}(?:/[a-z_][a-z0-9_]{2,})+")
_INSTITUTIONAL_EMAIL = re.compile(
    r"(?i)^(?:reports?|noreply|no-reply|billing|pathology|diagnostics?|"
    r"records?|notifications?|alerts?|portal|frontdesk)@"
)


def _is_personal_email(addr: str) -> bool:
    return not _INSTITUTIONAL_EMAIL.match(addr.strip().lower())


@lru_cache(maxsize=16384)
def kind_of_key(key: str) -> str | None:
    # form-builder group path (grp_patient/age, Kobo/ODK): the leaf names the field when it is known.
    # Combined labels ('Boyos/Linga') are not paths and keep whole-key classification.
    if _RX_GROUP_PATH.fullmatch(key) and kind_of_key(key.rsplit("/", 1)[1]) is not None:
        key = key.rsplit("/", 1)[1]
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
_INLINE_KV_CELL = re.compile(
    r"(?i)^\s*(?:thamasa\s*sthalam|address|pata|vilasam|melvilasam|fon|phone|veedu\s*fon|ration|kasp|aadhaar|abha|dob|janana)\s*[:：\-]"
)
_RX_DR_STAFF = re.compile(r"^(?:(?i:dr|sr|sis\.?|sister|nurse|staff\s+nurse|anm|gnm|s/n)\.?\s+|(?:DEO|N/O)\s+)")
_RX_LOOKS_ADDR = re.compile(r"(?i)\b(?:door|house|road|street|lane|ward|pin|near|opp|vill|post|dist|tk|dt)\b")
_RX_CODE_ID = re.compile(r"[A-Z]{2,8}[\s/\-\d#:.]{3,24}")
_RX_DIG3 = re.compile(r"\d{3}")
_RX_DIGIT1 = re.compile(r"\d")
_RX_KIN_TAIL = re.compile(rf"(?i)(?:\n|\s+)\b({L.KIN})(?![A-Za-z{DEVA}])\.?\s*[:\-]?\s*(.+)$")
_RX_SPACE_KIN = re.compile(r"(?i)\b(?:S/O|D/O|W/O|C/O)\b")
_RX_COMMA_WS = re.compile(r"[\s,]+")
_RX_REL_STRIP = re.compile(r"(?i)^(?:Shri|Sri|Smt\.?|श्री|श्रीमती)\s+|'s\s+(?:wife|husband|son|daughter|father|mother)\b")
_RX_REL_KIN_STRIP = re.compile(r"(?i)\b(?:S/O|D/O|W/O|H/O|C/O|Dikri|Patni|Puttar)\b\.?\s*\-?")
_RX_NON_ALNUM_PL = re.compile(r"[^0-9A-Za-z]")
_RX_NON_DIG_PL = re.compile(r"\D+")
_RX_SEX_SLASH = re.compile(r"(?i)/\s*([MF])\b")
_RX_URL_MASK = re.compile(r"(?i)\b(?:https?://[^\s\"'<>?]+|urn:(?:uuid|oid):[\w.\-]+|(?:[a-z0-9\-]+\.)+[a-z]{2,6}/[^\s\"'<>?]+)")
_RX_CO_PAREN = re.compile(rf"(?i)([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?|[{DEVA}]+(?:\s+[{DEVA}]+)?)\s*\(\s*C/o\s*\)")
_RX_AGE_TEXT = re.compile(rf"(?i)(?:\bAge(?:/(?:Sex|Gender|Sx|Jati))?|\bYrs?(?:/(?:Sex|Gender|Sx))?|(?:आयु|उम्र|उमर|वय)(?:/(?:लिंग|लिग|sex|gender|sx))?|\bUmar(?:/(?:Jati|Sx|Sex))?|\bUmra)\s*[:\-]?\s*([{INDIC_DIG}]{{1,3}})")
_RX_GENDER_TEXT = re.compile(r"(?i)\b\d{1,3}\s*(?:Yrs?|Y|years)?\s*/\s*([MF])\b|\b(?:Sex|Gender|Jati)\s*[:\-]\s*(Male|Female|M|F)\b|लिंग\s*[:\-]\s*(पुरुष|महिला)")
_RX_DATE_TEXT = re.compile(r"(?:तारीख|तिथि|Date|DOA|DOD|Admitted|Discharged)\s*[:\-]?\s*([^\n]{4,24})", re.I)
_RX_DEVA_CHR = re.compile(rf"[{DEVA}]")


def add_ev(rec: Rec, H: Harvest, kind: str, v, district: dict | None = None, order: str = "dmy"):
    if v is None or v == "":
        return
    s = str(v).strip()
    if not s:
        return
    e = rec.ev
    if kind in ("NAME", "REL_NAME") and _RX_DR_STAFF.match(s):
        return                      # clinical staff, not a patient or relative
    if kind in ("NAME", "REL_NAME") and _INLINE_KV_CELL.match(s):
        text_evidence(s, rec, H, order)
        return
    if kind in ("NAME", "REL_NAME"):
        _looks_addr = bool("," in s or _RX_LOOKS_ADDR.search(s) or (len(s) > 36 and _RX_DIGIT1.search(s)))
        _code_id = bool(_RX_CODE_ID.fullmatch(s) and _RX_DIG3.search(s))
        if ((not _looks_addr and len(s) <= 28 and len(s.split()) <= 2) or _code_id) and (len(_RX_NON_DIG_PL.sub("", s)) >= 3 or (RX_IDTOK.fullmatch(s) and id_digits_ok(s))):
            kind = "MRN" if kind == "NAME" else None      # an ID-shaped value is never a person name
            if kind is None:
                return
        elif _looks_addr:
            text_evidence(s, rec, H, order)
            return
    if kind == "NAME":
        kin_m = re.search(rf"(?i)(?:\n|\s+)\b({L.KIN})(?![A-Za-z{DEVA}])\.?\s*[:\-]?\s*(.+)$", s)
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
    elif kind == "FAMILY_ID":
        H.add_id(s)
    elif kind == "MRN":
        H.add_id(s)
        a = re.sub(r"[^0-9A-Za-z]", "", s).upper()
        if _phone_like(a):                       # a contact number in an ID-labelled field links as a phone
            e["phones"].add(re.sub(r"\D", "", a)[-10:])
        elif len(a) >= 4:
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
        if _is_personal_email(s):
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


RX_KV = re.compile(r"(?m)^([ \t]*[|│][ \t]*)([^|│\n]{1,40}?)([ \t]*[|│][ \t]*)([^|│\n]+?)([ \t]*[|│][ \t]*)$"
                   r"|^([ \t]*[-*•]?[ \t]*\**)([A-Za-z\u0900-\u097F][^:=\n|│(),;\[\]]{0,30}?)(\**[ \t]*[:：=][ \t]*\**)([^\n]+?)([ \t]*)$")
KV_KINDS = {"NAME", "REL_NAME", "MRN", "PHONE", "AADHAAR", "ABHA", "PAN", "EMAIL", "INSURANCE", "FAMILY_ID", "DOB", "AGE",
            "VILLAGE", "ADDRESS", "PIN"}

_RX_STRUCT_BLOCK = re.compile(r"(-----BEGIN STRUCTURED-----\s*\n)(.*?)(\n\s*-----END STRUCTURED-----)", re.S)


def _parse_json_str(v):
    if not isinstance(v, str) or len(v) > 20_000:
        return None
    s = v.strip()
    if not (s.startswith("{") and s.endswith("}")):
        return None
    try:
        o = json.loads(s)
    except (ValueError, RecursionError):
        return None
    return o if isinstance(o, dict) and json_depth(o) <= 16 else None


_COL_MAP_KEY = re.compile(r"(?i)^(?:col(?:umn)?_?(?:codes?|maps?|names?|labels?)|field_?(?:codes?|maps?)|headers?|schema_?map)$")


def _extract_col_map(node) -> dict[str, str]:
    if not isinstance(node, dict):
        return {}
    out: dict[str, str] = {}
    for mk, mv in node.items():
        if not (isinstance(mk, str) and isinstance(mv, dict) and 2 <= len(mv) <= 200):
            continue
        items = [(k, v) for k, v in mv.items() if isinstance(k, str) and isinstance(v, str)]
        if len(items) != len(mv):
            continue
        # Only accept schema-named codebooks or code-shaped keys whose values look like short field names (no digits/phones/prose).
        explicit = bool(_COL_MAP_KEY.match(mk))
        coded_keys = all(re.fullmatch(r"[A-Za-z]{1,4}\d{1,3}|col_?\w{1,8}", k) for k, _ in items)
        clean_vals = all(len(v) <= 32 and not re.search(r"[:/@\d]", v) for _, v in items)
        if (explicit or coded_keys) and clean_vals and sum(kind_of_key(v) is not None for _, v in items[:30]) >= 2:
            for k, v in items:
                out[k] = v
    return out


def _kv_kind(label: str, value: str):
    k = kind_of_key(label.strip(" *"))
    if k in ("NAME", "REL_NAME") and (re.search(r"\d", value) or not re.search(r"[A-Za-z\u0900-\u097F]{2}", value)):
        return None                  # "Pt: 30y | M" is an age line, not a name
    return k if k in KV_KINDS else None


_NEXT_LABEL = re.compile(r"(?:\s{2,}|,\s+)(?=[^\s:：][^:：\n]{0,24}[:：=])|\s+[-–]\s+(?=[A-Z])")


def kv_rows(text):
    """Label/value rows inside free text: Markdown/pipe tables and 'Label: value' lines.
    Yields (label, value, value_start, value_end); a colon value stops where the next label begins."""
    for m in RX_KV.finditer(text):
        if m.group(2) is not None:
            yield m.group(2), m.group(4), m.start(4), m.end(4)
        else:
            lab = m.group(7)
            if len(lab.split()) > 3:
                continue
            v = m.group(9)
            cut = _NEXT_LABEL.search(v)
            if cut:
                v = v[:cut.start()]
            yield lab, v, m.start(9), m.start(9) + len(v)


RX_ICD = re.compile(r"\b([A-TV-Z]\d{2}(?:\.\d{1,2})?)\b")
COND_TOK = {"diagnosis", "diagnoses", "condition", "conditions", "procedure", "procedures", "impression", "icd",
            "disease", "illness", "surgery", "operation", "rog", "बीमारी", "निदान"}


_PAT_HON_RX = re.compile(
    rf"({NAME_SEQ})(\s+(?:ji|jee|sahab|saheb|sahib|didi|bhai|ben|bai|bibi|amma|baba|paaji|kaka|bhau|tai|dada|aaji|babu|chachaji|garu|anna|akka|banna|hukum|bhaisa|apa|जी|साहब|दीदी|भाई|बहन))\b"
    rf"|({NAME_SEQ})(\s+(?:di|da|chacha))(?=\s+(?:ka|ki|ke|ko|se|ne|par|me)\b|:)"
)


_RX_SQL_INS = re.compile(r"(?i)\bINSERT\s+INTO\s+\w+\s*\(([^)]+)\)\s*VALUES\s*\(([^;]+)\)")


def text_evidence(text: str, rec: Rec, H: Harvest, order: str):
    if text.startswith("{"):
        po = _parse_json_str(text)
        if po is not None:
            walk_evidence(po, None, rec, H, order)
            return
    if "-----BEGIN STRUCTURED-----" in text:
        for bm in _RX_STRUCT_BLOCK.finditer(text):
            bp = _parse_json_str(bm.group(2))
            if bp is not None:
                walk_evidence(bp, None, rec, H, order)
    if "insert " in text.lower():
        for sm in _RX_SQL_INS.finditer(text):
            cols = [c.strip(" `\"'") for c in sm.group(1).split(",")]
            vals = [a or b or c for a, b, c in re.findall(r"'((?:\\.|[^'])*)'|\"((?:\\.|[^\"])*)\"|([^,\s]+)", sm.group(2))]
            for col, val in zip(cols, vals):
                ck = kind_of_key(col)
                if ck and ck not in ("DOCTOR", "SAFE", "STRUCT", "RELATION", "DATE", "PIN"):
                    add_ev(rec, H, ck, val, order=order)
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
        if _name_ok(toks) and (toks[0][:1].isupper() or _RX_DEVA_CHR.search(toks[0])):
            H.add_name(" ".join(toks))
            if first_label is None:
                first_label = toks
    for m in _PAT_HON_RX.finditer(text):
        seq = m.group(1) or m.group(3)
        toks = clean_name_seq(seq)
        if _name_ok(toks) and (toks[0][:1].isupper() or _RX_DEVA_CHR.search(toks[0])):
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
                if not (_name_ok(toks) and (toks[0][:1].isupper() or _RX_DEVA_CHR.search(toks[0]))):
                    continue
                if rx_k is RX_PRE_PAREN_KIN:
                    if toks[-1].lower() in ("attendant", "relative", "visitor", "guardian", "witness"):
                        continue
                    rtoks = clean_name_seq(m.group(2))
                    if not (rtoks and _name_ok(rtoks) and not L.COMPLAINT_WORDS.match(rtoks[0])
                            and (rtoks[0][:1].isupper() or _RX_DEVA_CHR.search(rtoks[0]))):
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
        if (toks and _name_ok(toks) and (toks[0][:1].isupper() or _RX_DEVA_CHR.search(toks[0]))
                and toks[-1].lower() not in ("attendant", "relative", "visitor", "guardian", "witness")
                and rtoks and _name_ok(rtoks) and not L.COMPLAINT_WORDS.match(rtoks[0])
                and (rtoks[0][:1].isupper() or _RX_DEVA_CHR.search(rtoks[0]))):
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
        if rel.upper().startswith(("C/O", "S/O", "H/O")) and (L.COMPLAINT_WORDS.match(toks[0]) or (toks[0][:1].isascii() and toks[0][:1].islower())):
            continue
        H.add_name(" ".join(toks))
        e["rel"].append(toks)
    if "c/o" in text.lower():
        for m in _RX_CO_PAREN.finditer(text):
            toks = clean_name_seq(m.group(1))
            if toks and _name_ok(toks):
                H.add_name(" ".join(toks))
                e["rel"].append(toks)
    for m in RX_NAME_ROLE.finditer(text):
        toks = clean_name_seq(m.group(1))
        if toks and _name_ok(toks) and (toks[0][:1].isupper() or _RX_DEVA_CHR.search(toks[0])):
            H.add_name(" ".join(toks))
            e["rel"].append(toks)
    id_scan = _RX_URL_MASK.sub(" ", text) if ("/" in text or ":" in text) else text
    for m in RX_IDTOK.finditer(id_scan):
        tok = m.group(0)
        if id_digits_ok(tok) and not _phone_like(_RX_NON_ALNUM_PL.sub("", tok)):
            a = _RX_NON_ALNUM_PL.sub("", tok).upper()
            e["ids"].add("M:" + a)
            H.add_id(tok)
            rec.is_patient = True
    for m in RX_ID_LABEL.finditer(text):
        tok = m.group(1).strip(" :-.")
        digits = _RX_NON_DIG_PL.sub("", tok)
        if len(digits) >= 4 and not re.fullmatch(r"\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}", tok):
            a = _RX_NON_ALNUM_PL.sub("", tok).upper()
            if len(a) >= 4 and not _phone_like(a):
                e["ids"].add("M:" + a)
                H.add_id(tok)
                rec.is_patient = True
    for m in RX_DIGITRUN.finditer(text):
        k = classify_digits(m.group(1))
        d = _RX_NON_DIG_PL.sub("", m.group(1).translate(_INDIC_DIGITS))
        if k == "PHONE":
            e["phones"].add(d[-10:])
            H.phones.add(d[-10:])
        elif k in ("AADHAAR", "ABHA"):
            e["ids"].add(("A:" if k == "AADHAAR" else "B:") + d)
            H.id_digits.add(d)
    for m in RX_DOTTED_PHONE.finditer(text):
        d = _RX_NON_DIG_PL.sub("", m.group(0).translate(_INDIC_DIGITS))
        if len(d) >= 10:
            e["phones"].add(d[-10:])
            H.phones.add(d[-10:])
    if "@" in text:
        for m in RX_EMAIL.finditer(text):
            em = m.group(0).lower()
            if _is_personal_email(em):
                e["ids"].add("E:" + em)
    m = DOB_RX.search(text)
    if m:
        d = parse_date(m.group(1), order)
        if d:
            e["dob"] = d.isoformat()
    m = _RX_AGE_TEXT.search(text)
    if m:
        e["age"] = int(m.group(1).translate(_INDIC_DIGITS))
    m = _RX_GENDER_TEXT.search(text)
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
        dm = _RX_DATE_TEXT.search(text)
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


_DOSE_SHAPE = re.compile(r"(?i)\b\d+(?:\.\d+)?\s*(?:mg|mcg|ml|g|iu|units?|%)\b|\b(?:tab|cap|inj|syp|syrup)\.?\s")


def _patient_list(v, col_map: dict[str, str] | None = None) -> bool:
    """A list of objects (or JSON-encoded objects) whose items carry patient evidence."""
    if not (isinstance(v, list) and v):
        return False
    objs = []
    for x in v[:12]:
        if isinstance(x, dict):
            objs.append(x)
        else:
            po = _parse_json_str(x)
            if po is None:
                return False
            objs.append(po)
    cmap = col_map or {}
    vals = [x.get(k) for x in objs for k in x if kind_of_key(cmap.get(k, k)) == "NAME" and isinstance(x.get(k), str)]
    if vals and sum(1 for x in vals if _DOSE_SHAPE.search(x)) >= 0.5 * len(vals):
        return False             # a medication / order list ({"name": "Tab Metformin 500 mg"}), not patients
    hits = 0
    for x in objs:
        r = Rec("", "")
        walk_evidence(x, None, r, Harvest(), "dmy", col_map=col_map)
        e = r.ev
        has_strong = bool(e["ids"] or e["phones"] or e["dob"])
        has_clin_shape = (any(cmap.get(k, k).lower() in _NON_PATIENT_KEYS for k in x)
                          and not (has_strong or e["rel"] or e["age"] is not None or e["gender"]))
        if (e["names"] and not has_clin_shape) or has_strong:
            hits += 1
    return hits >= max(1, len(objs) // 2)


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


def _phone_like(a: str) -> bool:
    """An 'identifier' that is really a contact number (optionally +91/0-prefixed, at most 2 letters)."""
    d = re.sub(r"\D", "", a)
    return 10 <= len(d) <= 13 and len(a) - len(d) <= 2 and classify_digits(d) == "PHONE"


_RX_BAREKEY = re.compile(r"([A-Za-z_][\w-]{0,40})\s*:")
_RX_LIT_QUOTED_OR_CTL = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|([{,]\s*)([A-Za-z_][\w-]{0,40})\s*:|,\s*([}\]])')
_LENIENT_MAX_LINE = 20_000
_LENIENT_MAX_PARSES = 400
_LENIENT_MAX_BYTES = 1_500_000
_LENIENT_MAX_NODES = 5_000


def _quote_bare_keys(t: str) -> str:
    """Quote bare identifier keys and drop trailing commas outside string literals."""
    def repl(m):
        if m.group(2) is not None:
            return f'{m.group(1)}"{m.group(2)}":'
        if m.group(3) is not None:
            return m.group(3)
        return m.group(0)
    return _RX_LIT_QUOTED_OR_CTL.sub(repl, t)


def _bracket_depth(t: str) -> int:
    """Measure unquoted bracket/brace/paren nesting depth before ast.literal_eval."""
    depth = best = 0
    q = None
    esc = False
    for ch in t:
        if esc:
            esc = False
        elif q:
            if ch == "\\":
                esc = True
            elif ch == q:
                q = None
        elif ch in ("'", '"'):
            q = ch
        elif ch in "{[(":
            depth += 1
            if depth > best:
                best = depth
                if best > MAX_JSON_DEPTH:
                    return best
        elif ch in "}])":
            depth = max(0, depth - 1)
    return best


def _json_safe(obj, max_depth: int = MAX_JSON_DEPTH, max_nodes: int = _LENIENT_MAX_NODES) -> bool:
    """Reject non-JSON Python literals (tuple/set/bytes/complex/Ellipsis), non-str dict keys, huge ints, or deep trees."""
    nodes = 0
    stack = [(obj, 1)]
    while stack:
        o, d = stack.pop()
        if d > max_depth:
            return False
        nodes += 1
        if nodes > max_nodes:
            return False
        if o is None or isinstance(o, (bool, str)):
            continue
        if isinstance(o, int):
            if o.bit_length() > 332:  # ~100 decimal digits, safe under json str-digit limit
                return False
            continue
        if isinstance(o, float):
            if not math.isfinite(o):
                return False
            continue
        if isinstance(o, dict):
            for k, v in o.items():
                if not isinstance(k, str):
                    return False
                stack.append((v, d + 1))
            continue
        if isinstance(o, list):
            for v in o:
                stack.append((v, d + 1))
            continue
        return False
    return True


def _lenient_obj(line: str, budget: list[int] | None = None):
    """A JSON-Lines row written as a Python dict / JS object literal (single quotes, bare keys,
    trailing commas). Parsed only with bounded literal parsers, never evaluated; otherwise kept as text."""
    t = line.strip()
    if not (t.startswith("{") and t.endswith("}")) or len(t) > _LENIENT_MAX_LINE:
        return line
    if budget is not None:
        if budget[0] >= _LENIENT_MAX_PARSES or budget[1] + len(t) > _LENIENT_MAX_BYTES:
            return line
        budget[0] += 1
        budget[1] += len(t)
    if _bracket_depth(t) > MAX_JSON_DEPTH:
        return line
    quoted = _quote_bare_keys(t)
    for cand in (t,) if quoted == t else (t, quoted):
        try:
            obj = ast.literal_eval(cand)
        except (ValueError, SyntaxError, MemoryError, RecursionError):
            continue
        if isinstance(obj, dict) and _json_safe(obj):
            return obj
    return line


def _mrn_values(obj, depth=0):
    """Hospital identifiers stored INSIDE a record (two levels deep)."""
    out = []
    if isinstance(obj, dict) and depth <= 2:
        for k, v in obj.items():
            if isinstance(v, (str, int)) and kind_of_key(k) == "MRN":
                out.append(v)
            elif isinstance(v, dict):
                out += _mrn_values(v, depth + 1)
    return out


def _pointer(path):
    return "".join("/" + str(x).replace("~", "~0").replace("/", "~1") for x in path) or "doc"


def _direct_patient(obj, col_map: dict[str, str] | None = None):
    cmap = col_map or {}
    return isinstance(obj, dict) and any(
        kind_of_key(cmap.get(k, k)) in {"NAME", "MRN", "AADHAAR", "ABHA"} and isinstance(v, (str, int))
        for k, v in obj.items())


def json_records(node, job, path=()):
    """Yield each record's path, value and optional row schema. A parent with its
    own patient fields owns its encounters unless those encounters identify patients."""
    if not isinstance(node, (dict, list)):
        return
    if isinstance(node, dict):
        lmap = _extract_col_map(node)
        if lmap:
            job.col_map.update(lmap)
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
    cmap = job.col_map or None
    keyed = _patient_map(node)
    bearing = keyed or _patient_list(node, cmap)
    if keyed:
        job.keyed.add(path)
    parts = node.items() if isinstance(node, dict) else enumerate(node)
    for k, item in parts:
        subpath = path + (k,)
        if isinstance(item, str) and bearing:
            po = _parse_json_str(item)
            if po is not None:
                job.str_records.add(subpath)
                yield subpath, po, None
                continue
        if not isinstance(item, (dict, list)):
            continue
        if isinstance(k, str) and kind_of_key((cmap or {}).get(k, k)) == "DOCTOR":
            continue          # staff / care-team sub-maps never own patient records
        if bearing and _direct_patient(item, cmap):
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


_SAFE_CSV_HDRS = {"id", "sr", "no", "value", "val", "test", "unit", "range", "diagnosis", "result",
                  "khana", "keemat", "field", "attribute", "remark", "remarks", "note", "notes"}
_EAV_ATTR = {"key", "field", "fieldname", "attr", "attribute", "khana", "label", "param", "parameter"}
_EAV_VAL = {"val", "value", "data", "content", "keemat", "kimat"}


def _eav_cell_kind(attr: str) -> str | None:
    toks = set(L.key_tokens(attr))
    k = kind_of_key(attr)
    if toks & GENDER_TOK and k != "AGE":
        return "GENDER"
    if toks & DISTRICT_TOK:
        return "DISTRICT"
    if toks & TEHSIL_TOK:
        return "TEHSIL"
    if toks & COND_TOK:
        return "COND"
    return k


def _hdr_known(row) -> int:
    return sum(1 for c in row if c.strip() and (kind_of_key(c) is not None or c.strip().lower() in _SAFE_CSV_HDRS))


def _is_super_header(rows) -> bool:
    if len(rows) < 3 or len(rows[0]) <= 1 or len(rows[0]) != len(rows[1]) or len(rows[0]) < 3:
        return False
    b0 = sum(1 for c in rows[0] if not c.strip())
    b1 = sum(1 for c in rows[1] if not c.strip())
    k0, k1 = _hdr_known(rows[0]), _hdr_known(rows[1])
    return b0 >= 2 and b1 == 0 and k1 > k0 and k1 >= 2 and not any(re.search(r"\d{3,}", c) for c in rows[1])


def _table_header(rows):
    """Find the start of a rectangular table following short report metadata."""
    if len(rows) < 3:
        return 0
    if len(rows[0]) > 1:
        if _is_super_header(rows):
            return 0
        k0 = _hdr_known(rows[0])
        if k0 >= 2:
            return 0
        for i in range(1, min(len(rows) - 1, 64)):
            width = len(rows[i])
            if width >= 2 and len(rows[i + 1]) == width and all(h.strip() for h in rows[i]) and _hdr_known(rows[i]) >= 2 and _hdr_known(rows[i]) > k0:
                return i
        return 0
    first_rect = None
    for i in range(1, min(len(rows) - 1, 64)):
        width = len(rows[i])
        if width >= 2 and len(rows[i + 1]) == width and all(h.strip() for h in rows[i]):
            if _hdr_known(rows[i]) >= 2:
                return i
            if first_rect is None:
                first_rect = i
    return first_rect or 0


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


def walk_evidence(obj, kind, rec: Rec, H: Harvest, order: str, res_kind=None, col_map: dict[str, str] | None = None):
    if isinstance(obj, dict):
        lmap = _extract_col_map(obj)
        cmap = {**(col_map or {}), **lmap} if lmap else col_map
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
            eff_k = cmap.get(k, k) if cmap else k
            ck = ext_kind if (ext_kind and eff_k.startswith("value")) else child_kind(eff_k, base)
            toks = set(L.key_tokens(eff_k))
            if (eff_k == "gender" or toks & GENDER_TOK) and ck != "AGE":
                g = gender_of(v) if isinstance(v, str) else None
                if g:
                    rec.ev["gender"] = g
                continue
            if ck == "AGE" and isinstance(v, str):
                gm = re.search(r"(?i)/\s*([MF])\b", v)
                if gm:
                    rec.ev["gender"] = gm.group(1).upper()
            if toks & DISTRICT_TOK and isinstance(v, str):
                H.safe_places.add(norm(v))
                rec.ev.setdefault("district", v)
                continue
            if toks & TEHSIL_TOK and isinstance(v, str):
                H.safe_places.add(norm(v))
                continue
            if toks & COND_TOK and isinstance(v, str):
                rec.ev.setdefault("conds", set()).add(norm(v))
            walk_evidence(v, ck, rec, H, order, rk, cmap)
    elif isinstance(obj, list):
        cols = _field_columns(obj)
        if cols:
            label, value = cols
            for item in obj:
                walk_evidence({item[label]: item[value]}, kind, rec, H, order, res_kind, col_map)
            return
        if _pairs(obj):
            for lab, val in obj:
                walk_evidence({lab: val}, kind, rec, H, order, res_kind, col_map)
            return
        for x in obj:
            walk_evidence(x, kind, rec, H, order, res_kind, col_map)
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
                po = _parse_json_str(obj)
                if po is not None:
                    walk_evidence(po, None, rec, H, order, res_kind, col_map)
                else:
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
    if RX_HL7.match(text):
        kind = "text"            # handled field-by-field below (structure preserved)
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
            stream_mode = job.src_path is not None and job.raw_len >= _SINGLE_REPARSE_THRESHOLD
            job.data = None if stream_mode else []
            lenient_budget = [0, 0]
            for i, line in enumerate(l for l in text.splitlines() if l.strip()):
                try:
                    obj = json.loads(line)
                    if not isinstance(obj, (dict, list)) or json_depth(obj) > MAX_JSON_DEPTH:
                        obj = line
                except (ValueError, RecursionError):
                    obj = _lenient_obj(line, lenient_budget)
                if not stream_mode:
                    job.data.append(obj)
                r = Rec(job.rel, f"row:{i}")
                if isinstance(obj, (dict, list)):
                    walk_evidence(obj, None, r, H, job.order)
                else:
                    text_evidence(obj if isinstance(obj, str) else line, r, H, job.order)
                job.recs.append(r)
            if stream_mode:
                job.reparse = True
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
                walk_evidence(_row_dict(hdr, item) if hdr else item, None, r, H, job.order, col_map=job.col_map or None)
                job.recs.append(r)
                job.rec_ptrs[path] = (r, hdr)
                job.branches.update(path[:i] for i in range(len(path)))
            if job.rec_ptrs:
                meta = Rec(job.rel, "@meta")
                walk_evidence(_metadata(job.data, (), job), None, meta, H, job.order, col_map=job.col_map or None)
            else:
                r = Rec(job.rel, "doc")
                walk_evidence(job.data, None, r, H, job.order, col_map=job.col_map or None)
                job.recs.append(r)
                job.doc_rec = r
        elif kind == "table":
            job.kind = "table"
            job.delim = sniff_delim(text, job.ext)
            stream_mode = (not fixed) and (job.src_path is not None) and (job.raw_len >= _SINGLE_REPARSE_THRESHOLD)
            if fixed:
                row_iter = iter(fixed[0])
                job.widths = fixed[1]
            else:
                body = text.replace("\r\n", "\n").replace("\r", "\n") if "\r" in text else text
                row_iter = csv.reader(io.StringIO(body, newline=""), delimiter=job.delim, strict=True)
            # Peek up to 64 rows to detect preamble, grouped super-header, and value shapes
            peek = []
            for _ in range(64):
                rw_p = next(row_iter, None)
                if rw_p is None:
                    break
                peek.append(rw_p)
            start = _table_header(peek)
            job.preamble = peek[:start]
            table_head_rows = peek[start:]
            if not table_head_rows:
                raise ValueError("empty_table")
            super_hdr = _is_super_header(table_head_rows)
            header = table_head_rows[1] if super_hdr else table_head_rows[0]
            sample_start = 2 if super_hdr else 1
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
                    sk = shape_kind([r[ci] for r in table_head_rows[sample_start:] if ci < len(r)])
                    if sk:
                        k = sk
                kinds.append(k)
            job.colkinds = kinds
            attr_ci = next((ci for ci, h in enumerate(header) if h.strip().lower() in _EAV_ATTR), None)
            val_ci = next((ci for ci, h in enumerate(header) if h.strip().lower() in _EAV_VAL), None)
            if attr_ci is not None and val_ci is not None and attr_ci != val_ci:
                job.eav = (attr_ci, val_ci)
            if stream_mode:
                job.rows = None
                job.reparse = True
                data_iter = chain(table_head_rows[1:], row_iter)
            else:
                all_data = list(chain(table_head_rows, row_iter))
                job.rows = all_data
                data_iter = iter(all_data[1:])
            for i, row in enumerate(data_iter):
                r = Rec(job.rel, f"row:{i}")
                if (super_hdr and i == 0) or row == header or not any(v.strip() for v in row):
                    job.repeat_headers.add(i)
                    job.recs.append(r)
                    continue
                if len(row) != len(kinds):
                    for v in row:
                        if len(v.strip()) > 3:
                            text_evidence(v, r, H, job.order)
                    job.recs.append(r)
                    continue
                attr_v = row[job.eav[0]] if job.eav else None
                for ci, v in enumerate(row):
                    k = (_eav_cell_kind(attr_v) or kinds[ci]) if (job.eav and ci == job.eav[1] and attr_v is not None) else kinds[ci]
                    if k == "GENDER":
                        g_v = gender_of(v)
                        if g_v:
                            r.ev["gender"] = sys.intern(g_v)
                    elif k == "DISTRICT":
                        H.safe_places.add(norm(v))
                        r.ev["district"] = sys.intern(v) if len(v) <= 64 else v
                    elif k == "TEHSIL":
                        H.safe_places.add(norm(v))
                    elif k == "COND" and v.strip():
                        r.ev.setdefault("conds", set()).add(sys.intern(norm(v)) if len(v) <= 80 else norm(v))
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
            if stream_mode:
                job.text = None
                del peek, row_iter, data_iter
        else:
            job.kind = "text"
            r = Rec(job.rel, "doc")
            if RX_HL7.match(text):
                hl7_evidence(text, r, H)
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
_SAFE_SURROGATE_KEY = re.compile(
    r"(?i)^(?:vc|v|vis|visit|enc|encounter|rec|record|row|item|case|slot|entry|adm|opd|ipd|tx|seq|ep|episode|pt|sub)"
    r"(?:\d{1,8}|[_-][0-9a-z]{1,12})$"
)
_SAFE_MAP_KEY_TOK = {
    "visit", "visits", "record", "records", "entry", "entries", "item", "items", "row", "rows", "case", "cases",
    "slot", "slots", "ward", "bed", "unit", "block", "day", "days", "week", "weeks", "month", "months", "year",
    "years", "quarter", "note", "notes", "file", "data", "opd", "ipd", "lab", "rx", "ds",
}


class Rewriter:
    def __init__(self, H: Harvest, sw: Sweeper, stats: Stats, policy: dict,
                 rec_ids: set[str] | None = None, rec_digs: set[str] | None = None):
        self.H, self.sw, self.st, self.pol = H, sw, stats, policy
        self.rec_ids = H.ids if rec_ids is None else rec_ids
        self.rec_digs = H.id_digits if rec_digs is None else rec_digs

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
        if kind in ("NAME", "REL_NAME") and _INLINE_KV_CELL.match(s):
            return scrub_text(kv_rewrite(s, self, ctx, rec), ctx, self.sw)
        if kind == "NAME":
            if re.match(r"^(?:(?i:dr|sr|sis\.?|sn\.?|sister|nurse|staff\s+nurse|anm|gnm|s/n)\.?\s+|(?:DEO|N/O)\s+)", s):
                return s
            st["identifiers"] += 1
            if (len(re.sub(r"\D", "", s)) >= 3 and "," not in s and len(s.split()) <= 2) or (
                re.fullmatch(r"[A-Z]{2,8}[\s/\-\d#:.]{3,24}", s) and re.search(r"\d{3}", s)
            ):
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
        if kind == "FAMILY_ID":
            st["identifiers"] += 1
            return "[ID]"
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
        if kind in (None, "SAFE", "COND"):
            po = _parse_json_str(s)
            if po is not None:
                return json.dumps(self.walk(po, None, ctx, rec), ensure_ascii=False)
        if kind is None and NAME_VALUE.fullmatch(s.strip()) and _name_ok(s.split()) and len(s.split()) >= 2:
            st["identifiers"] += 1
            return "[NAME]"
        return scrub_text(s, ctx, self.sw)

    def key(self, k: str, ctx: Ctx, seen: set) -> str:
        if k in STRUCT_KEYS or self.schema_key(k) or (re.fullmatch(r"\d{8}", k) and parse_date(k, "dmy")):
            seen.add(k)
            return k
        nk = scrub_text(k, ctx, self.sw)
        if nk != k:
            nk = re.sub(r"\[[A-Z_]+\]|PSN-[0-9A-Z]{6,16}", "", nk).strip(" _-:") or "key"
            nk = f"{nk}_{opaque('key', k, 5)}" if nk != "key" else f"key_{opaque('key', k, 5)}"
        while nk in seen:
            nk += "_"
        seen.add(nk)
        return nk

    def key_has_pii(self, k: str, value=None) -> bool:
        """True if a record key carries ANY harvested or unharvested PII (MRN/ID, national ID, PAN, phone,
        email, or patient name token). A key differing from the record's own hospital ID is NOT assumed safe:
        only keys free of patient-record PII and matching an explicit visit/record surrogate shape keep locators."""
        sw = self.sw
        spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", k).replace("_", " ")
        norm_k = re.sub(r"[^A-Za-z0-9]", "", k).upper()
        digs_k = re.sub(r"\D", "", k)
        if norm_k in self.rec_ids or (len(digs_k) >= 5 and digs_k in self.rec_digs):
            return True
        if sw.rx_lat_full.search(spaced) or sw.rx_dev_full.search(k):
            return True
        if RX_EMAIL.search(k) or RX_PAN.search(k) or any(classify_digits(m.group(1)) for m in RX_DIGITRUN.finditer(k)):
            return True
        if sw.rx_dev_tok.search(k):
            return True
        toks = [w.lower() for w in re.split(rf"[^A-Za-z{DEVA}]+", spaced) if w]
        if any(t in self.H.name_tokens and t not in _SAFE_MAP_KEY_TOK for t in toks):
            return True
        if _SAFE_SURROGATE_KEY.fullmatch(k):
            return False
        if norm_k in self.H.ids or sw.rx_ids.search(k) or sw.rx_digits.search(k):
            return True
        if (RX_IDTOK.fullmatch(k) and id_digits_ok(k)) or len(digs_k) >= 6:
            return True
        return False

    def schema_key(self, k: str) -> bool:
        """Identifier-style schema keys ("data", "patientInfo", "opd_sessions") are not person names,
        even when a patient happens to be called "Data": skip single-token name matching for them, but
        still rename on full names, e-mails, phones or long digit runs."""
        if not re.fullmatch(r"[a-z][a-zA-Z0-9_]{0,40}", k) or re.search(r"\d{4,}", k):
            return False
        spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", k).replace("_", " ")
        return not (self.sw.rx_lat_full.search(spaced) or self.sw.rx_ids.search(k))

    def walk(self, obj, kind, ctx: Ctx, rec, res_kind=None, depth: int = 0, col_map: dict[str, str] | None = None):
        if depth > MAX_JSON_DEPTH:
            raise ValueError("too_deep")
        if isinstance(obj, dict):
            lmap = _extract_col_map(obj)
            cmap = {**(col_map or {}), **lmap} if lmap else col_map
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
                eff_k = cmap.get(k, k) if cmap else k
                ck = ext_kind if (ext_kind and eff_k.startswith("value")) else child_kind(eff_k, base)
                if (lmap and isinstance(v, dict) and len(v) >= 2
                        and all(isinstance(a, str) and isinstance(b, str) and lmap.get(a) == b for a, b in v.items())):
                    ck = "STRUCT"
                if is_fhir_patient and eff_k == "birthDate" and ctx.rule is not None and ctx.rule.dob == "year_drop":
                    self.st["identifiers"] += 1
                    self.st["generalized"] += 1
                    continue
                toks = set(L.key_tokens(eff_k))
                if toks & GENDER_TOK and not isinstance(v, (dict, list)) and ck != "AGE":
                    ck = "GENDER"
                elif toks & DISTRICT_TOK and isinstance(v, str):
                    ck = "DISTRICT"
                elif toks & TEHSIL_TOK and isinstance(v, str):
                    ck = "TEHSIL"
                out[self.key(k, ctx, seen)] = self.walk(v, ck, ctx, rec, rk, depth + 1, cmap)
            return out
        if isinstance(obj, list):
            cols = _field_columns(obj)
            if cols:
                label, value = cols
                return [{label: self.key(item[label], ctx, set()),
                         value: self.walk(item[value], child_kind(item[label], kind), ctx, rec, res_kind, depth + 1, col_map)}
                        for item in obj]
            if _pairs(obj):
                out = []
                for lab, val in obj:
                    ck = child_kind(lab, kind) if lab not in STRUCT_KEYS else "STRUCT"
                    out.append([self.value(lab, None, ctx, rec), self.walk(val, ck, ctx, rec, res_kind, depth + 1, col_map)])
                return out
            return [self.walk(x, kind, ctx, rec, res_kind, depth + 1, col_map) for x in obj]
        return self.value(obj, kind, ctx, rec)


def rewrite_json(rw, node, path, job, meta_ctx, ctx_for, kind=None, out_path=(), safe_path=None):
    cmap = job.col_map or None
    if path in job.rec_ptrs:
        rec, header = job.rec_ptrs[path]
        ctx = ctx_for(rec, job)
        if safe_path is not None:
            job.out_locs[rec.loc] = (_pointer(safe_path), _pointer(out_path))
        if path in job.str_records and isinstance(node, str):
            po = _parse_json_str(node)
            if po is not None:
                return json.dumps(rw.walk(po, None, ctx, rec, col_map=cmap), ensure_ascii=False)
        if header is not None:
            return [rw.walk(v, child_kind(str(header[i]), None) if i < len(header) else None, ctx, rec, col_map=cmap)
                    for i, v in enumerate(node)]
        return rw.walk(node, None, ctx, rec, col_map=cmap)
    if path not in job.branches:
        return rw.walk(node, kind, meta_ctx, None, col_map=cmap)
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
            # A record key is renamed only if it actually carries patient PII (a harvested identifier,
            # name, phone, ...). Opaque visit / encounter codes are kept so locators stay exact.
            key_pii = rw.key_has_pii(k, v) if path in job.keyed else False
            if path in job.keyed and key_pii and not (ordinals and re.sub(r"[^A-Za-z0-9]", "", k).upper() not in rw.H.ids):
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
            eff_k = cmap.get(k, k) if cmap else k
            out[nk] = rewrite_json(rw, v, path + (k,), job, meta_ctx, ctx_for, child_kind(eff_k, kind),
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
        vs = v.strip(" *")
        # Never obliterate multi-clause narrative sentences after inline labels; let scrub_text handle spans cleanly.
        if k in ("MRN", "PHONE", "AADHAAR", "ABHA", "PAN", "PIN", "FAMILY_ID", "NAME", "REL_NAME") and len(vs.split()) > 5:
            continue
        nv = rw.value(vs, k, ctx, rec)
        if nv == vs:
            continue
        out.append(text[last:a])
        out.append(str(nv))
        last = b
    out.append(text[last:])
    return "".join(out)


# ================================================================ HL7 v2 (pipe-delimited segments)
RX_HL7 = re.compile(r"\A\ufeff?\s*MSH\|")
RX_TS = re.compile(r"^((?:19|20)\d{6})(\d{2,6}(?:\.\d+)?)?([+\-]\d{4})?$")
# (segment, field number) -> kind; field numbers follow HL7 v2.x (MSH counts its separator as field 1)
HL7_FIELDS = {("PID", 2): "MRN", ("PID", 3): "MRN", ("PID", 4): "MRN", ("PID", 5): "NAME", ("PID", 6): "REL_NAME",
              ("PID", 7): "DOB", ("PID", 8): "GENDER", ("PID", 9): "NAME", ("PID", 11): "ADDRESS",
              ("PID", 13): "PHONE", ("PID", 14): "PHONE", ("PID", 18): "MRN", ("PID", 19): "AADHAAR",
              ("PID", 20): "MRN", ("PID", 21): "MRN", ("NK1", 2): "REL_NAME", ("NK1", 4): "ADDRESS",
              ("NK1", 5): "PHONE", ("NK1", 6): "PHONE", ("PV1", 19): "MRN", ("PV1", 50): "MRN",
              ("IN1", 16): "REL_NAME", ("IN1", 36): "INSURANCE", ("GT1", 3): "REL_NAME", ("GT1", 5): "ADDRESS",
              ("GT1", 6): "PHONE", ("MRG", 1): "MRN", ("MRG", 7): "NAME"}
HL7_DOCTOR = {("PV1", 7), ("PV1", 8), ("PV1", 9), ("PV1", 17), ("OBR", 16), ("OBR", 32), ("ORC", 12), ("TXA", 5)}


def _hl7_segments(text):
    return re.split(r"(\r\n|\r|\n)", text)


def _hl7_name(v):
    parts = [p for p in v.split("^")[:3] if p.strip()]
    return " ".join(parts[1:] + parts[:1]) if parts else ""


def hl7_evidence(text, rec, H):
    for seg in _hl7_segments(text):
        f = seg.split("|")
        sid = f[0].strip()
        for i, v in enumerate(f[1:], 1):
            k = HL7_FIELDS.get((sid, i))
            if not k or not v.strip():
                continue
            for rep in v.split("~"):
                comp = rep.split("^")
                if k in ("NAME", "REL_NAME"):
                    add_ev(rec, H, k, _hl7_name(rep))
                elif k == "MRN":
                    typ = comp[4].upper() if len(comp) > 4 else ""
                    add_ev(rec, H, "AADHAAR" if typ in ("NI", "NNIND", "UID") or len(re.sub(r"\D", "", comp[0])) == 12 else "MRN", comp[0])
                elif k == "DOB":
                    m = RX_TS.match(comp[0])
                    if m:
                        d = m.group(1)
                        add_ev(rec, H, "DOB", f"{d[:4]}-{d[4:6]}-{d[6:8]}")
                elif k == "GENDER":
                    g = gender_of(comp[0])
                    if g:
                        rec.ev["gender"] = g
                elif k in ("PHONE", "AADHAAR", "INSURANCE"):
                    add_ev(rec, H, k, comp[0])


def _hl7_shift(v, days):
    m = RX_TS.match(v)
    if not m or not days:
        return v
    import datetime as _dt
    d = m.group(1)
    try:
        n = _dt.date(int(d[:4]), int(d[4:6]), int(d[6:8])) + _dt.timedelta(days=days)
    except ValueError:
        return v
    return n.strftime("%Y%m%d") + (m.group(2) or "") + (m.group(3) or "")


def hl7_rewrite(text, rw, ctx, rec, sw):
    out = []
    for seg in _hl7_segments(text):
        if seg in ("\r\n", "\r", "\n") or not seg:
            out.append(seg)
            continue
        f = seg.split("|")
        sid = f[0].strip()
        if sid == "MSH":                 # separators, routing, type: keep; MSH-7 (message time) shifts per patient
            if len(f) > 6:
                f[6] = _hl7_shift(f[6], ctx.days)
            out.append("|".join(f))
            continue
        nf = [f[0]]
        for i, v in enumerate(f[1:], 1):
            k = HL7_FIELDS.get((sid, i))
            if (sid, i) in HL7_DOCTOR or not v:
                nf.append(v)
            elif k:
                reps = []
                for rep in v.split("~"):
                    comp = rep.split("^")
                    if k in ("NAME", "REL_NAME", "MRN", "AADHAAR", "INSURANCE"):
                        tok = rw.value(comp[0] if k not in ("NAME", "REL_NAME") else _hl7_name(rep) or comp[0], k, ctx, rec)
                        comp = [str(tok)] + [c if j >= 3 else "" for j, c in enumerate(comp[1:], 1)]
                    elif k == "DOB":
                        comp[0] = "" if ctx.rule is not None and ctx.rule.dob == "year_drop" else _hl7_shift(comp[0], ctx.days)
                    elif k == "ADDRESS":
                        # XAD component order varies between senders: keep only known district/tehsil names
                        # and 2-3 letter state/country codes; drop street, locality, village and PIN.
                        comp = [c if (norm(c) in rw.H.safe_places or re.fullmatch(r"[A-Z]{2,3}", c)) else "" for c in comp]
                    elif k == "PHONE":
                        comp = ["[PHONE]"] + ["" for _ in comp[1:3]]
                    reps.append("^".join(comp))
                nf.append("~".join(reps))
            else:
                parts = []
                for c in v.split("^"):
                    parts.append(_hl7_shift(c, ctx.days) if RX_TS.match(c) else scrub_text(c, ctx, sw))
                nf.append("^".join(parts))
        out.append("|".join(nf))
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


_MEM_TEXT_BUDGET = 32 * 1024 * 1024
_SINGLE_REPARSE_THRESHOLD = 2 * 1024 * 1024
_STREAM_CHUNK_ROWS = 2000


def _iter_reparse_jsonl(j: FileJob):
    text = decode(j.src_path.read_bytes())
    if text is None:
        raise ValueError("undecodable_on_reparse")
    lenient_budget = [0, 0]
    for line in (l for l in text.splitlines() if l.strip()):
        try:
            obj = json.loads(line)
            if not isinstance(obj, (dict, list)) or json_depth(obj) > MAX_JSON_DEPTH:
                obj = line
        except (ValueError, RecursionError):
            obj = _lenient_obj(line, lenient_budget)
        yield obj


def _iter_reparse_table(j: FileJob):
    text = decode(j.src_path.read_bytes())
    if text is None:
        raise ValueError("undecodable_on_reparse")
    fixed = _fixed_rows(text)
    if fixed:
        rows = fixed[0][len(j.preamble):]
        del text, fixed
        for row in rows:
            yield row
        return
    body = text.replace("\r\n", "\n").replace("\r", "\n")
    del text
    reader = csv.reader(io.StringIO(body, newline=""), delimiter=j.delim, strict=True)
    for _ in range(len(j.preamble)):
        next(reader, None)
    for row in reader:
        yield row


def _rehydrate_job(j: FileJob) -> None:
    """Re-read a memory-released file from its immutable input path for Pass 2."""
    if not j.reparse or j.src_path is None:
        return
    if j.kind in ("jsonl", "table"):
        return
    text = decode(j.src_path.read_bytes())
    if text is None:
        raise ValueError("undecodable_on_reparse")
    if j.kind == "json":
        j.data = json.loads(text)
    else:
        j.text = text


def run(inp: Path, out: Path, policy: dict) -> int:
    out.mkdir(parents=True, exist_ok=True)
    _old_rec = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(max(_old_rec, 4000))
        return _run_impl(inp, out, policy)
    finally:
        sys.setrecursionlimit(_old_rec)


def _run_impl(inp: Path, out: Path, policy: dict) -> int:
    t0 = time.monotonic()
    st = Stats()
    H = Harvest()
    jobs = []
    cached_bytes = 0
    paths = [p for p in inp.rglob("*") if p.is_file() or p.is_symlink()]
    for path in sorted(paths, key=lambda p: p.relative_to(inp).as_posix()):
        rel = path.relative_to(inp).as_posix()
        unreadable = path.is_symlink()            # never follow links out of the input tree
        try:
            raw = b"" if unreadable else path.read_bytes()
        except OSError:
            raw, unreadable = b"", True
        job = FileJob(rel, raw, src_path=None if unreadable else path)
        if unreadable:
            job.status, job.reason = "quarantined", "unreadable"
        else:
            with time_budget(_file_budget(job.raw_len)):
                try:
                    pass1(job, H)
                except BudgetExceeded:
                    job.status, job.reason, job.recs = "quarantined", "processing_timeout", []
        # Never hold raw input bytes or redundant text alongside parsed structures
        job.raw = b""
        if job.status == "sanitized":
            if job.kind in ("table", "json", "jsonl"):
                job.text = None
            cached_bytes += job.raw_len
            if job.src_path is not None and (job.raw_len >= _SINGLE_REPARSE_THRESHOLD or cached_bytes > _MEM_TEXT_BUDGET):
                job.reparse = True
                job.rows = None
                job.data = None
                job.text = None
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
            if d and r.ev.get("age") is not None and r.ev["age"] >= 75 and d.year >= 2000:
                if (d.year - (2026 - r.ev["age"])) >= 90:
                    try:
                        d = d.replace(year=d.year - 100)
                    except ValueError:
                        d = d.replace(year=d.year - 100, day=28)
            r.ev["dob"] = d.isoformat() if d else None
    if str(policy.get("link", "on")) == "off":           # ablation only
        roots = list(range(len(recs)))
    else:
        if len(recs) >= 50_000:
            gc.collect()
        linker = Linker([r.ev for r in recs], release=True)
        roots = linker.run()
        del linker
    groups = defaultdict(list)
    for r, g in zip(recs, roots):
        groups[g].append(r)
    del recs, roots
    # A rejected shared identifier must never rejoin distinct clusters at export.
    # Prefer a unique identifier. Otherwise the first input locator identifies this group.
    owners = {}
    for g, members in groups.items():
        for m in members:
            for ident in m.ev["ids"]:
                if owners.setdefault(ident, g) != g:
                    owners[ident] = None
    used_pids = set()
    canonical_groups = []
    for g, members in groups.items():
        if not any(m.is_patient for m in members):
            continue
        key = min((i for m in members for i in m.ev["ids"] if owners[i] == g), default=None)
        if key is None:
            first = min((m.file, m.loc) for m in members)
            key = json.dumps(first, ensure_ascii=False)
        canonical_groups.append((key, g, members))
    # Sort canonically by key so collision tie-breaking is order-independent across file/record orderings.
    for key, g, members in sorted(canonical_groups, key=lambda x: x[0]):
        pid = pseudonym(key)
        attempt = 0
        while pid in used_pids:
            attempt += 1
            pid = pseudonym(f"{key}|collision|{attempt}")
        used_pids.add(pid)
        for m in members:
            m.key, m.pid = key, pid

    # ---- privacy plan (per patient)
    plan = P.plan(groups, policy)
    groups.clear()
    del canonical_groups, owners

    # Release heavy per-record evidence collections BEFORE allocating Sweeper/verify_idx
    # so Linker memory and Pass-2 verification indexes do not overlap at 250k-1M+ scale.
    rec_ids = set()
    rec_digs = set()
    total_recs = 0
    for j in jobs:
        for r in j.recs:
            total_recs += 1
            ev = r.ev
            for i in ev["ids"]:
                if ":" in i:
                    code = i.split(":", 1)[1].upper()
                    rec_ids.add(code)
                    d = _RX_NON_DIG_PL.sub("", code)
                    if len(d) >= 5:
                        rec_digs.add(d)
            for p in ev["phones"]:
                code = _RX_NON_ALNUM_PL.sub("", p)
                rec_ids.add(code)
                d = _RX_NON_DIG_PL.sub("", code)
                if len(d) >= 5:
                    rec_digs.add(d)
            dist_keep = ev.get("district")
            r.ev = {"district": dist_keep} if dist_keep else {}
    if total_recs >= 20_000:
        gc.collect()

    sw = Sweeper(H)
    rw = Rewriter(H, sw, st, policy, rec_ids=rec_ids, rec_digs=rec_digs)
    crit = sorted({n for n in H.full_names if len(n) >= 6} | set(H.phones) |
                  {d for d in H.id_digits if len(d) >= 6 and not (len(d) == 8 and parse_date(d, "dmy"))},
                  key=len, reverse=True)
    verify_idx = build_verify_index(crit)
    maxd = int(policy.get("date_shift_max_days", 180))
    verify_on = str(policy.get("verify", "on")) != "off"

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

    # ---- rewrite & stream records.jsonl atomically per file
    records_total = 0
    records_linked = 0
    rj_tmp = out / "records.jsonl.tmp"
    with open(rj_tmp, "w", encoding="utf-8", buffering=1024 * 1024) as rjf:
        for j in jobs:
            if j.status != "sanitized":
                continue
            dest = (san / j.out_rel).resolve()
            if not dest.is_relative_to(san.resolve()):
                j.status, j.reason = "quarantined", "unsafe_path"
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp_dest = dest.with_name(f".veil_tmp_{os.getpid()}_{dest.name}")
            try:
                with time_budget(_file_budget(j.raw_len)):
                    if j.reparse:
                        _rehydrate_job(j)
                    if j.kind in ("jsonl", "table"):
                        with open(tmp_dest, "w", encoding="utf-8", newline="", buffering=1024 * 1024) as out_f:
                            chunk_buf: list[str] = []

                            def flush_chunk():
                                if not chunk_buf:
                                    return
                                block = "".join(chunk_buf)
                                chunk_buf.clear()
                                if verify_on:
                                    block, hits = verify_text(block, crit, verify_idx)
                                    st["verify_hits"] += hits
                                out_f.write(block)

                            if j.kind == "jsonl":
                                data_iter = _iter_reparse_jsonl(j) if j.reparse else iter(j.data)
                                for r, obj in zip(j.recs, data_iter):
                                    c = ctx_for(r, j)
                                    if isinstance(obj, (dict, list)):
                                        line_out = json.dumps(rw.walk(obj, None, c, r), ensure_ascii=False)
                                    else:
                                        line_out = scrub_text(obj, c, sw)
                                    chunk_buf.append(line_out + "\n")
                                    if len(chunk_buf) >= _STREAM_CHUNK_ROWS:
                                        flush_chunk()
                                flush_chunk()
                            else:
                                line_buf = io.StringIO()
                                w = csv.writer(line_buf, delimiter=j.delim, lineterminator="\r\n" if j.crlf else "\n")
                                hctx = ctx_for(None, j)
                                row_iter = _iter_reparse_table(j) if j.reparse else iter(j.rows)
                                hdr_raw = next(row_iter)
                                header = [scrub_text(h, hctx, sw) for h in hdr_raw]

                                def emit_row(values):
                                    if j.widths:
                                        fields = [v.ljust(b - a) for v, a, b in zip(values, j.widths, j.widths[1:])]
                                        chunk_buf.append("".join(fields) + values[-1] + ("\r\n" if j.crlf else "\n"))
                                    else:
                                        line_buf.seek(0)
                                        line_buf.truncate(0)
                                        w.writerow(values)
                                        chunk_buf.append(line_buf.getvalue())
                                    if len(chunk_buf) >= _STREAM_CHUNK_ROWS:
                                        flush_chunk()

                                for row in j.preamble:
                                    emit_row([scrub_text(v, hctx, sw) for v in row])
                                emit_row(header)
                                name_cols = [ci for ci, k in enumerate(j.colkinds) if k == "NAME"]
                                for i, row in enumerate(row_iter):
                                    if i in j.repeat_headers:
                                        emit_row(header if row == hdr_raw else [scrub_text(v, hctx, sw) for v in row])
                                        continue
                                    r = j.recs[i]
                                    c = ctx_for(r, j)
                                    new_row = []
                                    ragged = len(row) != len(j.colkinds)
                                    attr_v = row[j.eav[0]] if (j.eav and not ragged and j.eav[0] < len(row)) else None
                                    for ci, v in enumerate(row):
                                        k = j.colkinds[ci] if ci < len(j.colkinds) else None
                                        if j.eav and not ragged and ci == j.eav[1] and attr_v is not None:
                                            k = _eav_cell_kind(attr_v) or k
                                        if ragged and k not in ("NAME", "REL_NAME", "MRN", "AADHAAR", "ABHA", "PAN", "PHONE", "EMAIL", "INSURANCE", "FAMILY_ID"):
                                            new_row.append(scrub_text(v, c, sw))
                                            continue
                                        if k == "NAME" and name_cols and ci != name_cols[0] and v.strip():
                                            st["identifiers"] += 1
                                            new_row.append("")
                                            continue
                                        if k == "COND":
                                            new_row.append(scrub_text(v, c, sw))
                                            continue
                                        new_row.append(rw.value(v, k, c, r))
                                    emit_row(new_row)
                                flush_chunk()
                    else:
                        if j.kind == "json":
                            if j.rec_ptrs:
                                meta_ctx = ctx_for(None, j)
                                data = rewrite_json(rw, j.data, (), j, meta_ctx, ctx_for)
                            else:
                                r = j.doc_rec
                                data = rw.walk(j.data, None, ctx_for(r, j), r, col_map=j.col_map or None)
                            result = json.dumps(data, ensure_ascii=False, indent=j.indent) + "\n"
                        else:
                            r = j.doc_rec
                            c = ctx_for(r, j)
                            if RX_HL7.match(j.text):
                                result = hl7_rewrite(j.text, rw, c, r, sw)
                            else:
                                blocks = []

                                def _rw_struct(m):
                                    bp = _parse_json_str(m.group(2))
                                    if bp is None:
                                        return m.group(0)
                                    tag = f"@@VEILSTRUCT_{len(blocks)}@@"
                                    blocks.append((tag, m.group(1) + json.dumps(rw.walk(bp, None, c, r), ensure_ascii=False) + m.group(3)))
                                    return tag

                                masked_t = _RX_STRUCT_BLOCK.sub(_rw_struct, j.text)
                                result = scrub_text(kv_rewrite(masked_t, rw, c, r), c, sw)
                                for tag, body in blocks:
                                    result = result.replace(tag, body)
                            if r is not None and r.pid and r.pid not in result:
                                result = f"Patient: {r.pid}\n" + result
                        if verify_on:
                            result, hits = verify_text(result, crit, verify_idx)
                            st["verify_hits"] += hits
                        with open(tmp_dest, "w", encoding="utf-8", newline="") as out_f:
                            out_f.write(result)
                    os.replace(tmp_dest, dest)
            except Exception:  # noqa: BLE001 - fail safe: quarantine, never export half-cleaned data
                if tmp_dest.exists():
                    tmp_dest.unlink(missing_ok=True)
                j.status, j.reason = "quarantined", "processing_error"
                j.data = j.rows = j.text = None
                continue

            for idx, r in enumerate(j.recs):
                if idx in j.repeat_headers or r.loc.startswith("@"):
                    continue
                row = {"file": f"sanitized/{j.out_rel}", "loc": r.loc, "patient": r.pid}
                if r.loc in j.out_locs:
                    row["loc"], row["out"] = j.out_locs[r.loc]
                    row["patient"] = None
                rjf.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
                records_total += 1
                if row["patient"] is not None:
                    records_linked += 1
                st["records"] += 1
            j.data = None
            j.rows = None
            j.text = None
            j.recs = []

    os.replace(rj_tmp, out / "records.jsonl")

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
            "records_processed": records_total, "identifiers_detected": st["identifiers"],
            "records_linked": records_linked,
            "records_generalized": st["generalized"], "records_suppressed": st["suppressed"],
            "records_quarantined": 0,
        },
        "entities": {},
        "timing": {"seconds": round(time.monotonic() - t0, 2)},
        "resources": {"peak_rss_mb": peak_rss_mb()},
    }
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"files {len(files)} sanitized {n_san} quarantined {len(files) - n_san} records {records_total}")
    return 0
