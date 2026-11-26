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
from .engine import (DEVA, RX_DIGITRUN, RX_EMAIL, RX_IDTOK, RX_PAN, Harvest, Rec, age_of, classify_digits,
                     date_votes, decode, gender_of, id_digits_ok, looks_binary, norm, opaque, parse_date,
                     pseudonym, shift_dates_in, sniff_delim, sniff_kind)
from .linker import Linker
from .scrub import NAME_VALUE
from .scrub import (RX_HON_AFTER, RX_HON_BEFORE, RX_KIN, RX_LABEL, RX_VILL, Ctx, Sweeper, _name_ok,
                    generalize_address, scrub_text)
from .engine import clean_name_seq, DOB_RX, COMMON_WORDS

UNSUPPORTED = {".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".xml", ".doc", ".docx", ".xls",
               ".xlsx", ".zip", ".gz", ".rar", ".7z", ".bin", ".exe", ".dcm", ".hl7", ".rtf", ".odt", ".ppt", ".pptx",
               ".heic", ".webp", ".mp3", ".mp4", ".wav"}
ID_KINDS = {"MRN", "AADHAAR", "ABHA", "PAN", "EMAIL", "INSURANCE", "PHONE"}
STRUCT_KEYS = {"resourceType", "id", "fullUrl", "reference", "system", "url", "profile", "status", "type", "use",
               "mode", "lastUpdated", "contentType", "language", "coding", "code", "unit", "versionId", "schema",
               "loinc", "interpretation", "category", "intent", "priority", "valueQuantity", "comparator"}
GENDER_TOK = {"gender", "sex", "ling", "लिंग"}
DISTRICT_TOK = {"district", "distt", "jila", "जिला", "zila", "janpad"}
TEHSIL_TOK = {"tehsil", "तहसील", "taluka", "block"}


class Stats(dict):
    def __missing__(self, k):
        return 0


class FileJob:
    __slots__ = ("rel", "raw", "sha", "ext", "kind", "text", "data", "delim", "rows", "order", "recs", "status",
                 "reason", "out_rel", "bom", "crlf", "indent", "doc_rec", "colkinds", "rec_ptrs")

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


# ================================================================ field kinds
def kind_of_key(key: str) -> str | None:
    toks = L.key_tokens(key)
    if any(t in ("age", "umar", "umra", "आयु", "उम्र") for t in toks) and L.classify_key(key) not in ("DOB", "DATE"):
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
def add_ev(rec: Rec, H: Harvest, kind: str, v, district: dict | None = None):
    if v is None or v == "":
        return
    s = str(v).strip()
    if not s:
        return
    e = rec.ev
    if kind in ("NAME", "REL_NAME") and (len(re.sub(r"\D", "", s)) >= 3 or (RX_IDTOK.fullmatch(s) and id_digits_ok(s))):
        kind = "MRN" if kind == "NAME" else None      # an ID-shaped value is never a person name
        if kind is None:
            return
    if kind == "NAME":
        H.add_name(s)
        toks = [t for t in re.split(r"[\s,]+", re.sub(r"(?i)\b(?:S/O|D/O|W/O|C/O)\b", " ", s)) if t]
        if toks:
            e["names"].append(toks)
        rec.is_patient = True
    elif kind == "REL_NAME":
        H.add_name(s)
        toks = [t for t in re.split(r"[\s,]+", re.sub(r"(?i)\b(?:S/O|D/O|W/O|H/O|C/O)\b\.?", " ", s)) if t]
        if toks:
            e["rel"].append(toks)
    elif kind == "MRN":
        H.add_id(s)
        a = re.sub(r"[^0-9A-Za-z]", "", s).upper()
        if len(a) >= 4:
            e["ids"].add("M:" + a)
            rec.is_patient = True
    elif kind in ("AADHAAR", "ABHA"):
        d = re.sub(r"\D", "", s)
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
        d = re.sub(r"\D", "", s)
        if len(d) >= 10:
            d = d[-10:]
            H.phones.add(d)
            e["phones"].add(d)
    elif kind == "DOB":
        e["dob"] = s
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


RX_ICD = re.compile(r"\b([A-TV-Z]\d{2}(?:\.\d{1,2})?)\b")
COND_TOK = {"diagnosis", "diagnoses", "condition", "conditions", "procedure", "procedures", "impression", "icd",
            "disease", "illness", "surgery", "operation", "rog", "बीमारी", "निदान"}


def text_evidence(text: str, rec: Rec, H: Harvest, order: str):
    e = rec.ev
    for m in RX_ICD.finditer(text):
        e.setdefault("conds", set()).add(m.group(1))
    first_label = None
    for m in RX_LABEL.finditer(text):
        toks = clean_name_seq(m.group(m.lastindex))
        if _name_ok(toks):
            H.add_name(" ".join(toks))
            if first_label is None:
                first_label = toks
    for m in RX_HON_AFTER.finditer(text):
        toks = clean_name_seq(m.group(1))
        if _name_ok(toks) and toks[0][:1].isupper() or (toks and re.search(rf"[{DEVA}]", toks[0])):
            H.add_name(" ".join(toks))
            if first_label is None:
                first_label = toks
    for m in RX_HON_BEFORE.finditer(text):
        toks = clean_name_seq(m.group(2))
        if _name_ok(toks):
            H.add_name(" ".join(toks))
    if first_label:
        e["names"].append(first_label)
        rec.is_patient = True
    for m in RX_KIN.finditer(text):
        rel, toks = m.group(1), clean_name_seq(m.group(2))
        if not toks or not _name_ok(toks):
            continue
        if rel.upper().startswith("C/O") and (L.COMPLAINT_WORDS.match(toks[0]) or toks[0][:1].islower()):
            continue
        H.add_name(" ".join(toks))
        e["rel"].append(toks)
    for m in RX_IDTOK.finditer(text):
        tok = m.group(0)
        if id_digits_ok(tok):
            a = re.sub(r"[^0-9A-Za-z]", "", tok).upper()
            e["ids"].add("M:" + a)
            H.add_id(tok)
            rec.is_patient = True
    for m in RX_DIGITRUN.finditer(text):
        k = classify_digits(m.group(1))
        d = re.sub(r"\D", "", m.group(1))
        if k == "PHONE":
            e["phones"].add(d[-10:])
            H.phones.add(d[-10:])
        elif k in ("AADHAAR", "ABHA"):
            e["ids"].add(("A:" if k == "AADHAAR" else "B:") + d)
            H.id_digits.add(d)
    for m in RX_EMAIL.finditer(text):
        e["ids"].add("E:" + m.group(0).lower())
    m = DOB_RX.search(text)
    if m:
        e["dob"] = m.group(1)
    m = re.search(rf"(?i)(?:\bAge(?:/Sex)?|आयु|उम्र|Umar)\s*[:\-]?\s*(\d{{1,3}})", text)
    if m:
        e["age"] = int(m.group(1))
    m = re.search(r"(?i)\b\d{1,3}\s*(?:Yrs?|Y|years)\s*/\s*([MF])\b|\b(?:Sex|Gender)\s*[:\-]\s*(Male|Female|M|F)\b|लिंग\s*[:\-]\s*(पुरुष|महिला)", text)
    if m:
        e["gender"] = gender_of(next(g for g in m.groups() if g))
    for m in RX_VILL.finditer(text):
        v = m.group(1) or m.group(2)
        if v:
            H.add_place(v)
            e["village"] = e["village"] or norm(v)


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


# ================================================================ pass 1
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
        if e["names"] or e["ids"] or e["phones"] or e["dob"]:
            hits += 1
    return hits >= max(1, len(sample) // 2)


def json_records(data, path=(), depth=0) -> list[tuple]:
    """Arrays of patient-bearing objects at any depth -> list of paths; [] = whole document."""
    if depth == 0 and isinstance(data, dict):
        if data.get("resourceType") == "Bundle":
            return []
        if any(kind_of_key(k) == "NAME" and isinstance(v, (dict, str)) for k, v in data.items()):
            return []
    if depth > 6:
        return []
    if _patient_list(data):
        deeper = []
        for i, v in enumerate(data):
            for k, vv in v.items():
                if isinstance(vv, (dict, list)):
                    deeper += json_records(vv, path + (i, k), depth + 2)
        return deeper or [path]          # prefer the innermost array of patient objects
    out = []
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                out += json_records(v, path + (k,), depth + 1)
    elif isinstance(data, list):
        for i, v in enumerate(data):
            if isinstance(v, (dict, list)):
                out += json_records(v, path + (i,), depth + 1)
    return out


def _strip_lists(data, ptrs):
    """Copy of data without the patient arrays (for metadata harvesting)."""
    if () in ptrs:
        return None
    if isinstance(data, dict):
        return {k: _strip_lists(v, [p[1:] for p in ptrs if p and p[0] == k]) if any(p and p[0] == k for p in ptrs) else v
                for k, v in data.items()}
    if isinstance(data, list):
        return [_strip_lists(v, [p[1:] for p in ptrs if p and p[0] == i]) if any(p and p[0] == i for p in ptrs) else v
                for i, v in enumerate(data)]
    return data


def _ptr(path: tuple, i: int) -> str:
    return "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in path) + f"/{i}"


def _get(data, path):
    for p in path:
        data = data[p]
    return data


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
        for x in obj:
            walk_evidence(x, kind, rec, H, order, res_kind)
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        if kind in ("DOCTOR", "STRUCT", "RELATION", "DATE"):
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
        add_ev(rec, H, kind, obj)


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
    try:
        if kind == "json":
            job.data = json.loads(text)
            first_nl = text.lstrip()[1:].lstrip(" ")
            mm = re.match(r"\r?\n( +)", text.lstrip()[1:])
            job.indent = len(mm.group(1)) if mm else None
            job.kind = "json"
            ptrs = json_records(job.data)
            if ptrs:
                for path in ptrs:
                    for i, item in enumerate(_get(job.data, path)):
                        r = Rec(job.rel, _ptr(path, i))
                        walk_evidence(item, None, r, H, job.order)
                        job.recs.append(r)
                        job.rec_ptrs[(path, i)] = r
                meta = Rec(job.rel, "@meta")
                walk_evidence(_strip_lists(job.data, ptrs), None, meta, H, job.order)
            else:
                r = Rec(job.rel, "doc")
                walk_evidence(job.data, None, r, H, job.order)
                job.recs.append(r)
                job.doc_rec = r
        elif kind == "table":
            job.kind = "table"
            job.delim = sniff_delim(text, job.ext)
            body = text.replace("\r\n", "\n")
            job.rows = list(csv.reader(io.StringIO(body, newline=""), delimiter=job.delim))
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
                        if set(L.key_tokens(header[ci])) & COND_TOK and v.strip():
                            r.ev.setdefault("conds", set()).add(norm(v))
                        if len(v) > 3:
                            text_evidence(v, r, H, job.order)
                    elif k not in ("DOCTOR", "DATE", "RELATION", "STRUCT"):
                        add_ev(r, H, k, v)
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
            return s if re.match(r"(?i)\s*(?:dr\.?|डॉ)", s) or not re.search(r"\d{4}", s) else scrub_text(s, ctx, self.sw)
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
            dist = rec.ev.get("district") if rec else None
            return dist or "[VILLAGE]"
        if kind == "ADDRESS":
            st["identifiers"] += 1
            return generalize_address(s)
        if kind == "TEHSIL" and (ctx.rule is None or ctx.rule.tehsil == "drop"):
            st["generalized"] += 1
            return (rec.ev.get("district") if rec else None) or "[TEHSIL]"
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
        if k in STRUCT_KEYS:
            return k
        nk = scrub_text(k, ctx, self.sw)
        if nk != k:
            nk = re.sub(r"\[[A-Z_]+\]|PSN-[0-9A-Z]{6}", "", nk).strip(" _-:") or "key"
            nk = f"{nk}_{opaque('key', k, 5)}" if nk != "key" else f"key_{opaque('key', k, 5)}"
        while nk in seen:
            nk += "_"
        seen.add(nk)
        return nk

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
            for k, v in obj.items():
                ck = ext_kind if (ext_kind and k.startswith("value")) else child_kind(k, base)
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
            return [self.walk(x, kind, ctx, rec, res_kind) for x in obj]
        return self.value(obj, kind, ctx, rec)


def rewrite_json(rw, node, path, job, meta_ctx, ctx_for, kind=None):
    paths = {p for p, _ in job.rec_ptrs}
    if path in paths and isinstance(node, list):
        out = []
        for i, item in enumerate(node):
            r = job.rec_ptrs.get((path, i))
            out.append(rw.walk(item, None, ctx_for(r, job), r))
        return out
    deeper = any(p[: len(path)] == path and len(p) > len(path) for p in paths)
    if isinstance(node, dict) and deeper:
        new, seen = {}, set()
        for k, v in node.items():
            nk = rw.key(k, meta_ctx, seen)
            new[nk] = rewrite_json(rw, v, path + (k,), job, meta_ctx, ctx_for, child_kind(k, kind))
        return new
    if isinstance(node, list) and deeper:
        return [rewrite_json(rw, v, path + (i,), job, meta_ctx, ctx_for, kind) for i, v in enumerate(node)]
    return rw.walk(node, kind, meta_ctx, None)


# ================================================================ filenames
_DATELIKE = re.compile(r"(?:19|20)\d{2}(?:[_\-.]\d{1,2}){0,2}|\d{1,2}[_\-.]\d{1,2}[_\-.](?:19|20)\d{2}")


def scrub_component(comp: str, H: Harvest, sw: Sweeper, salt: str) -> str:
    stem, ext = os.path.splitext(comp)
    flagged = False

    def cluster(m):
        nonlocal flagged
        c = m.group(0)
        if len(re.sub(r"\D", "", c)) >= 5 and not _DATELIKE.fullmatch(c):
            flagged = True
            return ""
        return c
    stem = re.sub(r"\d+(?:[_\-.\s]\d+)+", cluster, stem)
    parts = re.split(r"([_\-\s.()]+)", stem)
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
            parts = [p for p in parts if p not in (a, b)]
    if not flagged:
        # whole-stem checks (full names spanning separators)
        if sw.rx_lat_full.search(stem) or sw.rx_dev_full.search(stem) or sw.rx_ids.search(stem):
            flagged = True
            keep = [re.sub(r"[^A-Za-z_]", "", stem.split("_")[0]) or "file"]
        else:
            return comp
    base = re.sub(r"[_\-\s.()]{2,}", "_", "".join(keep)).strip("_-. ") or "file"
    return f"{base}_{opaque('fname', salt, 6)}{ext}"


COMMON_FILE_WORDS = {"discharge", "summary", "report", "nursing", "notes", "rx", "lab", "opd", "ipd", "bundle",
                     "export", "visits", "patients", "results", "claims", "registration", "ds", "note", "file",
                     "data", "json", "csv", "txt", "tsv"}


# ================================================================ verification (independent of the scrubber)
def verify_text(text: str, crit: list[str]) -> tuple[str, int]:
    """Exact-substring check of critical harvested values on the NFKC/casefold view; masks any survivor."""
    hits = 0
    low = text.casefold()
    for c in crit:
        if c and c in low:
            idx = 0
            while True:
                j = text.casefold().find(c, idx)
                if j < 0:
                    break
                text = text[:j] + "[REDACTED]" + text[j + len(c):]
                hits += 1
                idx = j + 10
    return text, hits


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
    for k, v in os.environ.items():            # experiment overrides: RAKSHAK_P_<key>=<value>
        if k.startswith("RAKSHAK_P_"):
            pol[k[10:].lower()] = int(v) if v.lstrip("-").isdigit() else v
    return pol


def run(inp: Path, out: Path, policy: dict) -> int:
    t0 = time.monotonic()
    sys.setrecursionlimit(4000)
    st = Stats()
    H = Harvest()
    jobs = []
    for path in sorted((p for p in inp.rglob("*") if p.is_file()), key=lambda p: p.relative_to(inp).as_posix()):
        rel = path.relative_to(inp).as_posix()
        try:
            raw = path.read_bytes()
        except OSError:
            raw = b""
        job = FileJob(rel, raw)
        pass1(job, H)
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
    for r in recs:
        if r.ev["dob"]:
            j_order = next((j.order for j in jobs if j.rel == r.file), "dmy")
            d = parse_date(r.ev["dob"], j_order)
            r.ev["dob"] = d.isoformat() if d else None
    # guard_ids(recs) measured harmful (dev link recall 0.94 -> 0.50); kept for reference only
    roots = Linker([r.ev for r in recs]).run()
    groups = defaultdict(list)
    for r, g in zip(recs, roots):
        groups[g].append(r)
    for g, members in groups.items():
        patientish = [m for m in members if m.is_patient]
        if not patientish:
            continue
        keys = sorted(i for m in members for i in m.ev["ids"]) or sorted(f"{m.file}#{m.loc}" for m in members)
        key = keys[0]
        for m in members:
            m.key = key
            m.pid = pseudonym(key)

    # ---- privacy plan (per patient)
    plan = P.plan(groups, policy)

    sw = Sweeper(H)
    rw = Rewriter(H, sw, st, policy)
    crit = sorted({n for n in H.full_names if len(n) >= 6} | {d for d in H.phones} |
                  {d for d in H.id_digits if len(d) >= 6}, key=len, reverse=True)
    maxd = int(policy.get("date_shift_max_days", 180))

    def ctx_for(rec: Rec | None, job: FileJob) -> Ctx:
        if rec is not None and rec.pid:
            days = P.days_for(rec.key, maxd)
            band = plan.band_fn(rec.key)
            return Ctx(H, rec.pid, days, job.order, band, st, plan.rule(rec.key))
        return Ctx(H, None, 0, job.order, plan.band_fn(None), st, plan.default)

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
            if j.kind == "json":
                if j.rec_ptrs:
                    meta_ctx = ctx_for(None, j)
                    data = rewrite_json(rw, j.data, (), j, meta_ctx, ctx_for)
                else:
                    r = j.doc_rec
                    data = rw.walk(j.data, None, ctx_for(r, j), r)
                result = json.dumps(data, ensure_ascii=False, indent=j.indent) + "\n"
            elif j.kind == "table":
                buf = io.StringIO()
                w = csv.writer(buf, delimiter=j.delim, lineterminator="\r\n" if j.crlf else "\n")
                hctx = ctx_for(None, j)
                header = [scrub_text(h, hctx, sw) for h in j.rows[0]]
                w.writerow(header)
                name_cols = [ci for ci, k in enumerate(j.colkinds) if k == "NAME"]
                for i, row in enumerate(j.rows[1:]):
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
                    w.writerow(new_row)
                result = buf.getvalue()
            else:
                r = j.doc_rec
                c = ctx_for(r, j)
                result = scrub_text(j.text, c, sw)
                if r is not None and r.pid and r.pid not in result:
                    result = f"Patient: {r.pid}\n" + result
            result, hits = verify_text(result, crit)
            st["verify_hits"] += hits
        except Exception:  # noqa: BLE001 - fail safe: quarantine, never export half-cleaned data
            j.status, j.reason = "quarantined", "processing_error"
            continue
        dest = san / j.out_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "w", encoding="utf-8", newline="") as f:
            f.write(result)
        for r in j.recs:
            if r.loc.startswith("@"):
                continue
            records_out.append({"file": f"sanitized/{j.out_rel}", "loc": r.loc, "patient": r.pid})
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
