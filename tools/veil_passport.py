#!/usr/bin/env python3
"""VEIL Privacy Passport 3.0: offline record/field/temporal release-assurance audit.

Development / demo tool only. It is NOT imported by main.py and is not needed at evaluation time.

    python3 tools/veil_passport.py --input <input dir> --output <VEIL output dir> [--metrics harness_metrics.json] \
        [--html passport.html] [--json passport.json]

Every metric in the Passport is measured directly on the given input/output release pair with ZERO ground truth.
It distinguishes PASS, FAIL, WARNING, SKIPPED, and INCONCLUSIVE across:
  A. Independent privacy residue (normalized + base64/hex/URL/\\uXXXX decoded + headers/keys/filenames)
  B. Occurrence-aware field-level clinical integrity (medications, doses, frequencies, vitals, labs, ICD-10, staff)
  C. Record-level identity & cross-format temporal integrity (exact CSV/TSV rows, RFC 6901 JSON pointers, FHIR, notes)
  D. Structural integrity (1:1 physical SHA-256 accounting, no unexpected exports/escapes, FHIR refs, valid parses)

A clean Passport is evidence, not proof: it does not certify compliance or guarantee anonymity.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import csv
import datetime as dt
import hashlib
import html
import io
import json
import re
import sys
import time
import unicodedata
import urllib.parse
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------- independent detectors (not VEIL's own rules)
PHONE = re.compile(r"(?<![\w\-])(?:\+?91[\s\-.]?)?[6-9]\d{2}[\s\-.]?\d{3}[\s\-.]?\d{4}(?!\d)")
AADHAAR = re.compile(r"(?<![\w\-])[2-9]\d{3}[\s\-.]?\d{4}[\s\-.]?\d{4}(?![\w\-])")
ABHA = re.compile(r"(?<![\w\-])\d{2}[\-\s]?\d{4}[\-\s]?\d{4}[\-\s]?\d{4}(?![\w\-])")
_COMPACT_TS = re.compile(r"^(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:[01]\d|2[0-3])(?:[0-5]\d)(?:[0-5]\d)?$")
EMAIL = re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+")
PAN = re.compile(r"(?<![A-Z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Z0-9])")
B64 = re.compile(r"[A-Za-z0-9+/]{12,4096}={0,2}")  # 12+: a base64-encoded 10-digit phone has 14 data chars
HEX = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}){10,256}(?![0-9A-Za-z])")
UESC = re.compile(r"(?:\\u[0-9a-fA-F]{4})+")
PCT = re.compile(r"(?:%[0-9a-fA-F]{2}){2,}")
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
SHA_HEX = re.compile(r"\b[0-9a-fA-F]{32,128}\b")
DATE = re.compile(
    r"(?<!\d)(\d{1,2})[/\-.](\d{1,2})[/\-.]((?:19|20)\d{2})(?!\d)"
    r"|(?<!\d)((?:19|20)\d{2})-(\d{2})-(\d{2})(?!\d)"
)
FHIR_DT = re.compile(r"^(?:19|20)\d{2}(?:-(?:0[1-9]|1[0-2])(?:-(?:0[1-9]|[12]\d|3[01])(?:T\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2})?)?)?)?$")

CLINICAL = [
    ("medication", re.compile(r"(?i)\b(?:Tab\.?|Cap\.?|Inj\.?|Syp\.?|ORS)\s+[A-Za-z]{3,24}")),
    ("blood pressure", re.compile(r"(?i)\bBP\s*[:\-]?\s*\d{2,3}\s*/\s*\d{2,3}(?:\s*mm\s*hg)?")),
    ("dose", re.compile(r"(?i)\b\d+(?:\.\d+)?\s*(?:mg|mcg|ml|iu|units?)\b")),
    ("lab value", re.compile(r"(?i)\b\d+(?:\.\d+)?\s*(?:mg/dl|g/dl|mmol/l|/cumm|u/l|iu/l|ng/ml|miu/l|%)")),
    ("frequency", re.compile(r"\b[0-4]-[0-4]-[0-4]\b")),
    ("ICD-10 code", re.compile(r"\b[A-TV-Z]\d{2}\.\d{1,2}\b")),
    ("clinician", re.compile(r"\b(?:Dr\.|N/O|Sis\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?")),
]
NON_PERSON = re.compile(
    r"(?i)facility|hospital|organi[sz]ation|practitioner|location|healthcareservice|"
    r"clinic|centre|center|institute|institution|publisher|assigner|issuer|custodian|"
    r"lab|panel|test|doctor|department|ward|branch|"
    r"referr|consult|staff|nurse|drug|medic|package|procedure|diagnos|code|display|scheme|insurer|tpa"
)
INSTITUTIONAL_PHRASE = re.compile(
    r"(?i)\b(?:hospital|clinic|sadan|sansthan|charitable|multispeciality|super\s*speciality|"
    r"medical\s+college|trust|foundation|pathology|diagnostics?|laboratory|dispensary|"
    r"aspatal|aspataal|sehat\s+kendra|swasthya\s+kendra|arogya\s+kendra|chikitsalaya|aushadhalaya|aspatre|aashupathri|aspathri)\b"
)
# Clinician / staff titles (patients do not carry these); shared by harvest and hit counting.
_STAFF_TITLE = r"(?:dr|sr|sis|sister|sn|s/n|staff\s+nurse|nurse|anm|gnm|n/o|deo|doctor)"
_STAFF_PREFIX = re.compile(rf"(?i)\s*{_STAFF_TITLE}\.?\s")
# A value that is a clinical expression (dose/unit) is not a personal identifier.
_CLINICAL_VALUE = re.compile(r"(?i)\b\d+(?:\.\d+)?\s*(?:mg|mcg|µg|ml|g|iu|units?|mmhg|mg/dl|g/dl|mmol/l|%)\b")
_DOB_KEY = re.compile(r"(?i)^(?:birthDate|dob|date_of_birth|birthdate|janam|born|deathDate|deceasedDateTime)$")
_DOB_LINE = re.compile(r"(?im)^.*\b(?:dob|date\s+of\s+birth|birth\s*date|janam|जन्म\s*तिथि)\b.*$")
ID_KEY = re.compile(r"(?i)(?:^|_|\b)(?:name|naam|patient|uhid|mrn|aadha?a?r|abha|mobile|phone|contact|email)(?:$|_|\b)")
PSN = re.compile(r"PSN-[0-9A-Z]{6,16}")
_PSN_EXACT_TOKEN = re.compile(r"(?<![A-Za-z0-9_\-])PSN-[0-9A-Z]{6,16}(?![A-Za-z0-9_\-])")


def norm(s: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", s).casefold().split())


def decode(raw: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


_STAFF_CTX = re.compile(rf"(?:^|[^a-z]){_STAFF_TITLE}\.?\s+(?:[^\W\d_]+\s+){{0,2}}$")


def _only_in_staff_context(value: str, low: str) -> bool:
    """True when every occurrence of a harvested value is directly preceded by a clinician/staff title
    (e.g. 'dr. anand shukla'). A single bare occurrence still counts as residue."""
    occ = [m.start() for m in re.finditer(re.escape(value), low)]
    return bool(occ) and all(_STAFF_CTX.search(low[max(0, i - 40):i]) for i in occ)


def with_decoded_extras(text: str) -> str:
    extra = []
    for m in B64.finditer(text):
        tok = m.group(0)
        try:
            core = tok.rstrip("=")  # re-pad canonically: tokens already ending in '==' must not get extra padding
            extra.append(base64.b64decode(core + "=" * (-len(core) % 4)).decode("utf-8", "ignore"))
        except (binascii.Error, ValueError):
            pass
    for m in HEX.finditer(text):
        try:
            extra.append(bytes.fromhex(m.group(0)).decode("utf-8", "ignore"))
        except ValueError:
            pass
    if "\\u" in text:
        for m in UESC.finditer(text):
            try:
                extra.append(json.loads('"' + m.group(0) + '"'))
            except ValueError:
                pass
    if "%" in text:
        for m in PCT.finditer(text):
            extra.append(urllib.parse.unquote(m.group(0)))
    return text + "\n" + "\n".join(extra) if extra else text


def _tabular_delim(suf: str, text: str) -> str:
    if suf == ".tsv":
        return "\t"
    head = [ln for ln in text.splitlines()[:10] if ln.strip()]
    if head and head[0].count("\t") >= 2 and head[0].count(",") == 0:
        return "\t"
    return ","


def _harvest_independent_identifiers(inp: Path) -> tuple[set[str], set[str]]:
    """Independent harvest of personal identifier values across CSV/TSV headers and JSON keys,
    separating genuine institutional/facility strings using resourceType & contextual paths."""
    vals: set[str] = set()
    inst_vals: set[str] = set()

    def _has_strong_id(raw_s: str) -> bool:
        return bool(PHONE.search(raw_s) or AADHAAR.search(raw_s) or ABHA.search(raw_s) or PAN.search(raw_s) or EMAIL.search(raw_s))

    def add(v, ctx_path: str = ""):
        if not isinstance(v, (str, int)):
            return
        raw_s = str(v).strip()
        if len(raw_s) < 5:
            return
        sv = norm(raw_s)
        if sv in ("patient_name", "patient", "relative", "unknown"):
            return
        if _CLINICAL_VALUE.search(raw_s) and not _has_strong_id(raw_s):
            return
        if INSTITUTIONAL_PHRASE.search(sv) and not _has_strong_id(raw_s):
            inst_vals.add(sv)
            return
        if NON_PERSON.search(ctx_path):
            return
        vals.add(sv)

    def walk(o, key="", ctx=""):
        if isinstance(o, dict):
            rt = o.get("resourceType")
            ctx2 = f"{ctx}/{rt}" if isinstance(rt, str) and rt else ctx
            for k, v in o.items():
                walk(v, k, f"{ctx2}/{k}")
        elif isinstance(o, list):
            for x in o:
                walk(x, key, ctx)
        elif ID_KEY.search(str(key)) and not _STAFF_PREFIX.match(str(o)):
            add(o, ctx)

    for p in sorted(inp.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        with p.open("rb") as fh:
            t = decode(fh.read(20_000_000))
        suf = p.suffix.lower()
        if suf == ".json":
            try:
                walk(json.loads(t))
            except (ValueError, RecursionError):
                pass
        elif suf in (".jsonl", ".ndjson"):
            for ln in t.splitlines():
                if not ln.strip():
                    continue
                try:
                    walk(json.loads(ln))
                except (ValueError, RecursionError):
                    pass
        elif suf in (".csv", ".tsv"):
            delim = _tabular_delim(suf, t)
            try:
                rows = list(csv.reader(io.StringIO(t), delimiter=delim))
            except csv.Error:
                continue
            if rows:
                cols = [(i, h) for i, h in enumerate(rows[0]) if ID_KEY.search(h)]
                for r in rows[1:]:
                    for i, h in cols:
                        if i < len(r):
                            val = r[i].strip()
                            if val and not _STAFF_PREFIX.match(val):
                                add(val, h)
    person = {v for v in vals if not v.isdigit() or len(v) >= 6}
    return person, inst_vals


def input_identifiers(inp: Path) -> set[str]:
    """Independent harvest of personal identifier values across CSV/TSV headers and JSON keys."""
    return _harvest_independent_identifiers(inp)[0]


def _infer_mdy(text: str) -> bool:
    raw = []
    for m in DATE.finditer(text):
        if m.group(3):
            raw.append((int(m.group(1)), int(m.group(2))))
    return any(b > 12 for a, b in raw) and not any(a > 12 for a, b in raw)


def dates_in(text: str, mdy: bool | None = None) -> list[tuple[int, int, int]]:
    raw = []
    for m in DATE.finditer(text):
        if m.group(3):
            raw.append(("x", int(m.group(3)), int(m.group(1)), int(m.group(2))))
        else:
            raw.append(("iso", int(m.group(4)), int(m.group(5)), int(m.group(6))))
    if mdy is None:
        mdy = any(k == "x" and b > 12 for k, y, a, b in raw) and not any(k == "x" and a > 12 for k, y, a, b in raw)
    return [(y, a, b) if k == "iso" else ((y, a, b) if mdy else (y, b, a)) for k, y, a, b in raw]


def ordinal(d):
    try:
        return dt.date(*d).toordinal()
    except ValueError:
        return None


def _json_ptr(obj, pointer: str):
    if pointer in ("", "doc"):
        return obj
    if not pointer.startswith("/"):
        raise KeyError(pointer)
    cur = obj
    for part in pointer.split("/")[1:]:
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            if not part.isdigit():
                raise KeyError(pointer)
            cur = cur[int(part)]
        elif isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            raise KeyError(pointer)
    return cur


def _flat_json(obj, skip_dob: bool = False) -> str:
    parts = []

    def rec(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if skip_dob and _DOB_KEY.match(str(k)):
                    continue
                parts.append(str(k))
                rec(v)
        elif isinstance(o, list):
            for x in o:
                rec(x)
        elif o is not None:
            parts.append(str(o))

    rec(obj)
    return "\n".join(parts)


class _GramIndex:
    """Exact O(N + L) multi-pattern substring matcher via rarest 5-gram + multi-gram O(1) gating.

    Mathematically equivalent to `[s for s in strings if s in text]` with zero missed matches.
    """

    def __init__(self, strings: set[str] | list[str]):
        items = sorted({s for s in strings if s})
        self.short: tuple[str, ...] = tuple(s for s in items if len(s) < 5)
        long_items = [s for s in items if len(s) >= 5]
        # Value per bucket is (s, g_head, g_mid, g_tail) so false anchor hits fail in O(1) without scanning `text`.
        self.by_gram: dict[str, list[tuple[str, str, str, str]]] = {}
        if long_items:
            gram_df: Counter = Counter()
            for s in long_items:
                for g in {s[j : j + 5] for j in range(len(s) - 4)}:
                    gram_df[g] += 1
            for s in long_items:
                best = min((s[j : j + 5] for j in range(len(s) - 4)), key=gram_df.__getitem__)
                mid = (len(s) - 5) // 2
                entry = (s, s[:5], s[mid : mid + 5], s[-5:])
                self.by_gram.setdefault(best, []).append(entry)
        self.grams: frozenset[str] = frozenset(self.by_gram)

    def find_hits(self, text: str) -> list[str]:
        if not text or (not self.short and not self.grams):
            return []
        matched = [s for s in self.short if s in text]
        if self.grams and len(text) >= 5:
            tgrams = {text[j : j + 5] for j in range(len(text) - 4)}
            hits = tgrams & self.grams
            for g in hits:
                for s, gh, gm, gt in self.by_gram[g]:
                    if gh in tgrams and gm in tgrams and gt in tgrams and s in text:
                        matched.append(s)
        return matched


class _ParsedOutputFile:
    """Lazy parser for resolving exact exported/input records (CSV/TSV row, JSON pointer, JSONL line, text)."""

    def __init__(self, path: Path, raw_decode: bool = False):
        self.path = path
        if path.is_file():
            self.text = decode(path.read_bytes()) if raw_decode else path.read_text(encoding="utf-8", errors="replace")
        else:
            self.text = ""
        self.suf = path.suffix.lower()
        self.rows = None
        self.obj = None
        self.lines = None
        self.parse_error = False
        if self.suf in (".csv", ".tsv"):
            try:
                self.rows = list(csv.reader(io.StringIO(self.text), delimiter=_tabular_delim(self.suf, self.text)))
            except csv.Error:
                self.rows = []
                self.parse_error = True
        elif self.suf in (".jsonl", ".ndjson"):
            self.lines = [ln for ln in self.text.splitlines() if ln.strip()]
            for ln in self.lines[:500]:
                try:
                    json.loads(ln)
                except ValueError:
                    self.parse_error = True
                    break
        elif self.suf == ".json":
            try:
                self.obj = json.loads(self.text)
            except ValueError:
                self.obj = None
                self.parse_error = True

    def resolve_record(self, loc: str, skip_dob: bool = False) -> tuple[str, bool]:
        if loc in ("doc", "@file"):
            txt = _flat_json(self.obj, skip_dob=True) if (skip_dob and self.obj is not None) else self.text
            return txt, bool(self.text)
        if loc.startswith("row:") and re.fullmatch(r"row:\d+", loc):
            idx = int(loc[4:])
            if self.lines is not None:
                return (self.lines[idx], True) if idx < len(self.lines) else ("", False)
            if self.rows is not None:
                row_idx = idx + 1  # data row after header row[0]
                if row_idx >= len(self.rows):
                    return "", False
                if skip_dob and self.rows:
                    hdr = self.rows[0]
                    vals = [v for ci, v in enumerate(self.rows[row_idx]) if ci >= len(hdr) or not _DOB_KEY.search(hdr[ci].strip())]
                    return "\n".join(vals), True
                return "\n".join(self.rows[row_idx]), True
        if loc.startswith("/") and self.obj is not None:
            try:
                return _flat_json(_json_ptr(self.obj, loc), skip_dob=skip_dob), True
            except KeyError:
                return "", False
        if loc.startswith("/"):
            return self.text, bool(self.text)
        return "", False


def _audit_fhir_bundle(obj: dict) -> tuple[int, int, int, int]:
    """Return (refs_ok, refs_total, dates_ok, dates_total) on a FHIR Bundle."""
    if not isinstance(obj, dict) or obj.get("resourceType") != "Bundle":
        return 0, 0, 0, 0
    full_urls = set()
    res_ids = set()
    refs = []
    dates = []

    def collect(o):
        if isinstance(o, dict):
            fu = o.get("fullUrl")
            if isinstance(fu, str) and fu:
                full_urls.add(fu)
            rt = o.get("resourceType")
            rid = o.get("id")
            if isinstance(rt, str) and isinstance(rid, str) and rid:
                res_ids.add(f"{rt}/{rid}")
                res_ids.add(f"#{rid}")  # contained-resource (local fragment) reference
            if isinstance(o.get("reference"), str):
                refs.append(o["reference"])
            for k in ("birthDate", "effectiveDateTime", "authoredOn", "issued", "recordedDate", "start", "end", "lastUpdated"):
                v = o.get(k)
                if isinstance(v, str) and v.strip():
                    dates.append(v.strip())
            for v in o.values():
                collect(v)
        elif isinstance(o, list):
            for x in o:
                collect(x)

    collect(obj)
    refs_ok = sum(1 for r in refs if r in full_urls or r in res_ids)
    dates_ok = sum(1 for dv in dates if FHIR_DT.fullmatch(dv) or "[" in dv)
    return refs_ok, len(refs), dates_ok, len(dates)


def _extract_clinical_counts(text: str) -> Counter:
    counts: Counter = Counter()
    for label, rx in CLINICAL:
        for m in rx.finditer(text):
            counts[(label, norm(m.group(0)))] += 1
    return counts


def _make_check(status: str, passed: int, total: int, detail: str = "") -> dict:
    cov = f"{passed}/{total}" if total else "0/0 (no eligible items)"
    return {"status": status, "passed": passed, "total": total, "coverage": cov, "detail": detail}


def audit(inp: Path, out: Path) -> dict:
    t0 = time.monotonic()
    rep_text = (out / "report.json").read_text(encoding="utf-8")
    rep = json.loads(rep_text)
    rj_text = (out / "records.jsonl").read_text(encoding="utf-8")
    recs = [json.loads(l) for l in rj_text.splitlines() if l.strip()]
    assigned_psns = {str(r["patient"]) for r in recs if r.get("patient") and PSN.fullmatch(str(r["patient"]))}
    files_rep = rep.get("files", [])
    by_sha_q: dict[str, list[dict]] = {}
    for e in files_rep:
        by_sha_q.setdefault(e["input_sha256"], []).append(e)
    in_list = [p for p in sorted(inp.rglob("*")) if p.is_file() and not p.is_symlink()]
    in_pairs = [(hashlib.sha256(p.read_bytes()).hexdigest(), p) for p in in_list]
    R: dict = {
        "assurance_version": "3.0",
        "verdict": "SKIPPED",
        "privacy": {},
        "clinical": {},
        "identity": {},
        "temporal": {},
        "structural": {},
        "checks": {},
        "residual_risks": [],
    }

    # ---------------- D. Structural integrity
    used_entries = []
    accounted = 0
    for s, p in in_pairs:
        q = by_sha_q.get(s)
        e = q.pop(0) if q else None
        if e is not None:
            accounted += 1
        used_entries.append((p, e))
    exported = [e for e in files_rep if e.get("status") == "sanitized"]
    declared_outs = {str(e.get("output", "")).replace("sanitized/", "", 1) for e in exported if e.get("output")}
    san_root = (out / "sanitized").resolve()
    actual_san_files = {
        p.relative_to(san_root).as_posix()
        for p in san_root.rglob("*")
        if p.is_file() and not p.is_symlink()
    } if san_root.is_dir() else set()
    unsafe_paths = sum(
        1 for p in (out / "sanitized").rglob("*") if p.is_symlink() or not p.resolve().is_relative_to(san_root)
    ) if san_root.is_dir() else 0
    unexpected_exports = len(actual_san_files - declared_outs)

    missing_out = [e for e in exported if not (out / e["output"]).is_file()]
    parse_ok = parse_fail = 0
    row_match = row_total = 0
    fhir_refs_ok = fhir_refs_tot = fhir_dates_ok = fhir_dates_tot = 0
    fhir_refs_broken = 0  # references that resolved in the input bundle but not in its sanitized output
    parsed_cache: dict[str, _ParsedOutputFile] = {}
    in_parsed_cache: dict[Path, _ParsedOutputFile] = {}

    for p, e in used_entries:
        if not e or e.get("status") != "sanitized":
            continue
        out_rel = e["output"]
        o = out / out_rel
        if not o.is_file():
            continue
        pf = parsed_cache.get(out_rel)
        if pf is None:
            pf = _ParsedOutputFile(o)
            parsed_cache[out_rel] = pf
        ipf = in_parsed_cache.get(p)
        if ipf is None:
            ipf = _ParsedOutputFile(p, raw_decode=True)
            in_parsed_cache[p] = ipf
        suf = o.suffix.lower()
        try:
            if pf.parse_error:
                raise ValueError("malformed_exported_file")
            if suf == ".json":
                obj = pf.obj if pf.obj is not None else json.loads(pf.text)
                rok, rtot, dok, dtot = _audit_fhir_bundle(obj)
                try:
                    iobj = ipf.obj if getattr(ipf, "obj", None) is not None else json.loads(ipf.text)
                    irok = _audit_fhir_bundle(iobj)[0]
                except (ValueError, TypeError):
                    irok = 0
                fhir_refs_broken += max(0, irok - rok)
                fhir_refs_ok += rok
                fhir_refs_tot += rtot
                fhir_dates_ok += dok
                fhir_dates_tot += dtot
            elif suf in (".csv", ".tsv"):
                orows = pf.rows if pf.rows is not None else []
                irows = ipf.rows if ipf.rows is not None else []
                row_total += 1
                row_match += len(orows) == len(irows)
            parse_ok += 1
        except (ValueError, csv.Error):
            parse_fail += 1

    counts = rep.get("counts", {})
    honest = (
        counts.get("files_total") == len(files_rep)
        and counts.get("files_sanitized") == len(exported)
        and counts.get("records_processed") == len(recs)
        and accounted == len(in_pairs)
    )
    R["structural"] = {
        "input_files": len(in_pairs),
        "unique_sha256_inputs": len({s for s, _ in in_pairs}),
        "accounted_in_report": accounted,
        "exported": len(exported),
        "quarantined": sum(1 for e in files_rep if e.get("status") == "quarantined"),
        "declared_outputs_missing": len(missing_out),
        "unexpected_exports": unexpected_exports,
        "unsafe_symlinks_or_paths": unsafe_paths,
        "outputs_parse_ok": parse_ok,
        "outputs_parse_fail": parse_fail,
        "tables_row_count_preserved": f"{row_match}/{row_total}",
        "fhir_references_resolved": f"{fhir_refs_ok}/{fhir_refs_tot}" if fhir_refs_tot else "0/0 (N/A)",
        "fhir_references_broken_by_sanitization": fhir_refs_broken,
        "report_counts_consistent": honest,
    }
    struct_ok = (
        accounted == len(in_pairs)
        and len(missing_out) == 0
        and parse_fail == 0
        and unexpected_exports == 0
        and unsafe_paths == 0
        and honest
        and row_match == row_total
        and fhir_refs_broken == 0
    )
    R["checks"]["structural"] = _make_check(
        "PASS" if struct_ok else "FAIL",
        accounted - len(missing_out) - parse_fail - unexpected_exports - unsafe_paths,
        len(in_pairs),
        "1:1 SHA-256 accounting, valid parses, zero unexpected exports or unsafe paths",
    )
    if not struct_ok:
        struct_errs = []
        if accounted != len(in_pairs):
            struct_errs.append(f"accounting {accounted}/{len(in_pairs)}")
        if missing_out:
            struct_errs.append(f"{len(missing_out)} missing declared output(s)")
        if parse_fail:
            struct_errs.append(f"{parse_fail} output parse failure(s)")
        if unexpected_exports:
            struct_errs.append(f"{unexpected_exports} unexpected export(s)")
        if unsafe_paths:
            struct_errs.append(f"{unsafe_paths} unsafe symlink/path(s)")
        if not honest:
            struct_errs.append("report.json counts mismatch exported artifacts")
        if row_match != row_total:
            struct_errs.append(f"{row_total - row_match} table(s) changed row count")
        if fhir_refs_broken:
            struct_errs.append(f"{fhir_refs_broken} FHIR reference(s) broken by sanitization")
        R["residual_risks"].append("Structural verification failed: " + ", ".join(struct_errs))

    # ---------------- A. Privacy residue (independent detectors + O(N + L) indexed lookup + exact assigned-PSN PAN context)
    ident, inst_vals = _harvest_independent_identifiers(inp)
    ident_idx = _GramIndex(ident)
    inst_idx = _GramIndex(inst_vals)
    pat = Counter()
    resid_files = Counter()
    inst_preserved = 0
    channels = {
        "report.json": SHA_HEX.sub("", rep_text),
        "records.jsonl": rj_text,
        "file names": "\n".join(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()),
    }
    for rel_out, pf in sorted(parsed_cache.items()):
        channels[rel_out] = pf.text
    for p in sorted(san_root.rglob("*")) if san_root.is_dir() else ():
        if p.is_file():
            rel_key = "sanitized/" + p.relative_to(san_root).as_posix()
            if rel_key not in channels:
                channels[rel_key] = p.read_text(encoding="utf-8", errors="replace")

    def _mask_assigned_psn(m: re.Match) -> str:
        tok = m.group(0)
        return " " if tok in assigned_psns else tok

    _CONTAM_LINE = re.compile(r"(?i)(?:\bpatient\s*[:\-]\s*(?!PSN-)[A-Z][a-z]+)")
    for name, text in channels.items():
        tx = UUID.sub(" ", with_decoded_extras(text))
        tx_pan = _PSN_EXACT_TOKEN.sub(_mask_assigned_psn, tx) if (assigned_psns and "PSN-" in tx) else tx
        for label, rx, src_t in (("phone", PHONE, tx), ("aadhaar", AADHAAR, tx), ("ABHA", ABHA, tx), ("email", EMAIL, tx), ("PAN", PAN, tx_pan)):
            hits_rx = rx.findall(src_t)
            if label in ("aadhaar", "ABHA"):
                hits_rx = [h for h in hits_rx if not _COMPACT_TS.fullmatch(re.sub(r"\D", "", h))]
            n = len(hits_rx)
            if n:
                pat[label] += n
                resid_files[name] += n
        low = norm(tx)
        hits = sum(1 for v in ident_idx.find_hits(low) if not _only_in_staff_context(v, low))
        if hits:
            pat["input identity value"] += hits
            resid_files[name] += hits
        if inst_vals:
            matched_inst = inst_idx.find_hits(low)
            if matched_inst:
                # Never whitelist institutional text if direct PII/patient identity co-occurs on the same line
                contam = 0
                for line in tx.splitlines():
                    ln = norm(line)
                    line_pan = _PSN_EXACT_TOKEN.sub(_mask_assigned_psn, line) if (assigned_psns and "PSN-" in line) else line
                    if any(v in ln for v in matched_inst) and (
                        PHONE.search(line) or AADHAAR.search(line) or ABHA.search(line)
                        or PAN.search(line_pan) or _CONTAM_LINE.search(line)
                    ):
                        contam += 1
                if contam:
                    pat["institutional_contaminated"] += contam
                    resid_files[name] += contam
                else:
                    inst_preserved += len(matched_inst)
    R["privacy"] = {
        "channels_scanned": len(channels),
        "independent_identity_values_from_input": len(ident),
        "institutional_entities_distinguished": inst_preserved,
        "residual_pattern_hits": dict(pat),
        "files_with_residue": len(resid_files),
    }
    if pat:
        R["residual_risks"].append(
            f"{sum(pat.values())} residual identifier-pattern hits in {len(resid_files)} "
            f"channels (may include false positives such as clinical numbers); review before release"
        )
    R["checks"]["privacy"] = _make_check(
        "FAIL" if pat else ("PASS" if channels else "SKIPPED"),
        len(channels) - len(resid_files),
        len(channels),
        "Zero identifier hits across decoded sanitized, key, metadata, and filename channels (with institutional role separation)",
    )

    # ---------------- B. Field/occurrence-aware clinical & role-aware temporal integrity
    kept_cat = Counter()
    tot_cat = Counter()
    t_ok = t_fail = t_skip = t_inconc = 0
    note_t_ok = note_t_fail = 0
    recs_by_file: dict[str, list[dict]] = {}
    for r in recs:
        recs_by_file.setdefault(r["file"], []).append(r)
    patient_deltas: dict[str, set[int]] = {}
    for p, e in used_entries:
        if not e or e.get("status") != "sanitized":
            continue
        out_rel = e["output"]
        if not (out / out_rel).is_file():
            continue
        pf = parsed_cache.get(out_rel) or _ParsedOutputFile(out / out_rel)
        ipf = in_parsed_cache.get(p)
        if ipf is None:
            ipf = _ParsedOutputFile(p, raw_decode=True)
            in_parsed_cache[p] = ipf
        it = ipf.text
        in_counts = _extract_clinical_counts(it)
        out_counts = _extract_clinical_counts(pf.text)
        for (label, expr), icnt in in_counts.items():
            tot_cat[label] += icnt
            kept_cat[label] += min(icnt, out_counts.get((label, expr), 0))

        # Infer date order (DMY vs MDY) on full file before stripping DOB roles
        file_mdy = _infer_mdy(it) or _infer_mdy(pf.text)
        suf = p.suffix.lower()
        if suf in (".json", ".csv", ".tsv", ".jsonl", ".ndjson"):
            file_recs = recs_by_file.get(out_rel, [])
            if file_recs:
                for rec in file_recs:
                    in_txt, ok_in = ipf.resolve_record(str(rec.get("loc", "")), skip_dob=True)
                    out_txt, ok_out = pf.resolve_record(str(rec.get("out") or rec.get("loc") or ""), skip_dob=True)
                    if not (ok_in and ok_out):
                        continue
                    di = dates_in(_DOB_LINE.sub("", in_txt), mdy=file_mdy)
                    do = dates_in(_DOB_LINE.sub("", out_txt), mdy=file_mdy)
                    if len(di) == 1 and len(do) == 1 and rec.get("patient"):
                        o1, o2 = ordinal(di[0]), ordinal(do[0])
                        if o1 is not None and o2 is not None:
                            patient_deltas.setdefault(str(rec["patient"]), set()).add(o2 - o1)
                    elif len(di) >= 2:
                        if len(di) != len(do):
                            t_inconc += 1
                        else:
                            oi = [ordinal(d) for d in di]
                            oo = [ordinal(d) for d in do]
                            if None in oi or None in oo:
                                t_inconc += 1
                            else:
                                deltas = {oo[k] - oi[k] for k in range(len(oi))}
                                if len(deltas) == 1:
                                    t_ok += 1
                                    if rec.get("patient"):
                                        patient_deltas.setdefault(str(rec["patient"]), set()).update(deltas)
                                else:
                                    t_fail += 1
        elif suf in (".txt", ".md", ".hl7", ".er7", ".log", ".note", ".text"):
            di = dates_in(_DOB_LINE.sub("", it), mdy=file_mdy)
            do = dates_in(_DOB_LINE.sub("", pf.text), mdy=file_mdy)
            if len(di) < 2:
                t_skip += 1
            elif len(di) != len(do):
                t_inconc += 1
            else:
                oi = [ordinal(d) for d in di]
                oo = [ordinal(d) for d in do]
                if None in oi or None in oo:
                    t_inconc += 1
                else:
                    if all((oi[k] - oi[0]) == (oo[k] - oo[0]) for k in range(len(oi))):
                        t_ok += 1
                        note_t_ok += 1
                    else:
                        t_fail += 1
                        note_t_fail += 1

    cross_ok = sum(1 for ds in patient_deltas.values() if len(ds) == 1)
    cross_fail = sum(1 for ds in patient_deltas.values() if len(ds) > 1)
    t_fail += cross_fail

    tot_clin = sum(tot_cat.values())
    kept_clin = sum(kept_cat.values())
    clin_pct = round(100 * kept_clin / tot_clin, 2) if tot_clin else None
    t_eligible = t_ok + t_fail
    note_eligible = note_t_ok + note_t_fail
    R["clinical"] = {
        "protected_values": {k: f"{kept_cat[k]}/{tot_cat[k]}" for k in tot_cat},
        "protected_values_kept_pct": clin_pct,
        "occurrence_totals": f"{kept_clin}/{tot_clin}",
        "notes_with_intervals_preserved": f"{note_t_ok}/{note_eligible}" if note_eligible else f"0/0 (skipped:{t_skip}, inconclusive:{t_inconc})",
    }
    R["temporal"] = {
        "intervals_passed": t_ok,
        "intervals_failed": t_fail,
        "cross_record_patient_chronology": f"{cross_ok}/{cross_ok + cross_fail}" if (cross_ok + cross_fail) else "0/0 (N/A)",
        "skipped_under_2_dates": t_skip,
        "inconclusive_unparseable_or_count_mismatch": t_inconc,
        "fhir_dates_valid": f"{fhir_dates_ok}/{fhir_dates_tot}" if fhir_dates_tot else "0/0 (N/A)",
    }
    lost = tot_clin - kept_clin
    if lost:
        R["residual_risks"].append(
            f"{lost} protected clinical occurrences not preserved in sanitized output "
            f"(occurrence-aware multiset check)"
        )
    if t_fail:
        R["residual_risks"].append(f"{t_fail} document/patient date interval checks failed chronological offset preservation")
    if fhir_dates_ok < fhir_dates_tot:
        R["residual_risks"].append(f"{fhir_dates_tot - fhir_dates_ok} invalid FHIR R4 date/dateTime values")

    R["checks"]["clinical"] = _make_check(
        "SKIPPED" if tot_clin == 0 else ("PASS" if lost == 0 else "FAIL"),
        kept_clin,
        tot_clin,
        "Occurrence-aware preservation of medications, doses, frequencies, BP, labs, ICD-10, and staff",
    )
    if t_fail > 0 or fhir_dates_ok < fhir_dates_tot:
        temp_st = "FAIL"
    elif (t_eligible + cross_ok + fhir_dates_tot) > 0:
        temp_st = "WARNING" if t_inconc > 0 else "PASS"
    elif t_inconc > 0:
        temp_st = "INCONCLUSIVE"
    else:
        temp_st = "SKIPPED"
    R["checks"]["temporal"] = _make_check(
        temp_st,
        t_ok + cross_ok + fhir_dates_ok,
        t_eligible + cross_ok + fhir_dates_tot,
        f"Per-record & cross-record role-aware temporal + FHIR date checks (skipped={t_skip}, inconclusive={t_inconc})",
    )

    # ---------------- C. Record-level identity verification (exact loc/out resolution)
    out_resolved = out.resolve()
    linked = [r for r in recs if r.get("patient")]
    loc_valid = 0
    exact_placed = 0
    for r in linked:
        rf = r["file"]
        pf = parsed_cache.get(rf)
        if pf is None:
            cand = (out / rf).resolve()
            if not cand.is_relative_to(out_resolved):
                continue
            pf = _ParsedOutputFile(cand)
            parsed_cache[rf] = pf
        target_loc = str(r.get("out") or r.get("loc") or "")
        rec_text, found = pf.resolve_record(target_loc)
        if found:
            loc_valid += 1
            if str(r["patient"]) in rec_text:
                exact_placed += 1

    psns = Counter(r["patient"] for r in linked)
    bad_format = sum(1 for p_ in psns if not PSN.fullmatch(p_))
    missing_rec = len(linked) - exact_placed
    R["identity"] = {
        "records": len(recs),
        "records_linked": len(linked),
        "distinct_pseudonyms": len(psns),
        "record_locators_resolved": f"{loc_valid}/{len(linked)}",
        "pseudonym_present_in_exact_record": f"{exact_placed}/{len(linked)}",
        "pseudonym_present_in_exported_file": f"{exact_placed}/{len(linked)}",
        "pseudonym_placement_errors": missing_rec,
        "pseudonym_format_violations": bad_format,
        "largest_cluster_records": max(psns.values()) if psns else 0,
    }
    if missing_rec:
        R["residual_risks"].append(f"{missing_rec} linked records missing exact record-level pseudonym placement at loc/out")
    if bad_format:
        R["residual_risks"].append(f"{bad_format} pseudonyms violated contract format PSN-[0-9A-Z]{{6,16}}")

    R["checks"]["identity"] = _make_check(
        "SKIPPED" if not linked else ("PASS" if (missing_rec == 0 and bad_format == 0) else "FAIL"),
        exact_placed,
        len(linked),
        "Exact record-level (CSV row / RFC 6901 pointer / doc) pseudonym placement check",
    )

    statuses = [c["status"] for c in R["checks"].values()]
    if "FAIL" in statuses:
        R["verdict"] = "FAIL"
    elif "INCONCLUSIVE" in statuses or "WARNING" in statuses or R["residual_risks"]:
        R["verdict"] = "WARNING"
    elif "PASS" in statuses:
        R["verdict"] = "PASS"
    else:
        R["verdict"] = "SKIPPED"
    R["engine"] = {"timing_s": rep.get("timing", {}).get("seconds"), "peak_rss_mb": rep.get("resources", {}).get("peak_rss_mb")}
    R["audit_seconds"] = round(time.monotonic() - t0, 2)
    return R


def render_html(R: dict, metrics: dict | None) -> str:
    def table(d):
        return "<table>" + "".join(
            f"<tr><th>{html.escape(str(k).replace('_', ' '))}</th><td>{html.escape(str(v))}</td></tr>"
            for k, v in d.items()
        ) + "</table>"

    sec = [
        ("Summary · Release Verdict", {"assurance_version": R.get("assurance_version", "3.0"), "verdict": R.get("verdict", "SKIPPED")}),
        ("E · Structural Integrity", R["structural"]),
        ("A · Privacy Residue (Independent Decoded Channels)", R["privacy"]),
        ("B · Field/Occurrence Clinical Integrity", R["clinical"]),
        ("C · Role-Aware Temporal & FHIR Chronology", R.get("temporal", {})),
        ("D · Record-Level Identity Integrity", R["identity"]),
        ("Assurance 3.0 Check States", {k: f"{v['status']} ({v['coverage']})" for k, v in R.get("checks", {}).items()}),
        ("Engine Resources", R["engine"]),
    ]
    risks = "".join(f"<li>{html.escape(x)}</li>" for x in R["residual_risks"]) or "<li>No residual risks flagged by these checks.</li>"
    dev = ""
    if metrics:
        p = metrics.get("privacy", {})
        dev = ("<h2>Development metrics (synthetic ground truth, local harness, NOT official)</h2>" + table({
            "estimated total (local)": metrics.get("estimate", {}).get("est_total"),
            "leak rate (truth)": metrics.get("detection", {}).get("leak_mean"),
            "linking F0.5 / false merges": f"{metrics.get('identity', {}).get('f05')} / {metrics.get('identity', {}).get('false_merge_pairs')}",
            "clinical probes kept": metrics.get("utility", {}).get("clinical_probes"),
            "local attacker: profile re-id A4 (vs raw)": p.get("components_relative_to_raw", {}).get("A4_profile_reid"),
            "local attacker: targeted A5 (vs raw)": p.get("components_relative_to_raw", {}).get("A5_targeted"),
        }))
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VEIL Privacy Passport 3.0 — Team The Aevos</title>
<style>
:root{{--bg:#070b12;--fg:#e6edf7;--mut:#92a4bf;--line:#1e2d45;--warn:#f59e0b;--ok:#10b981}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 ui-sans-serif,system-ui,sans-serif;max-width:920px;margin:32px auto;padding:0 18px}}
h1{{font-size:25px;margin:0;color:#34d399}} h2{{font-size:16.5px;margin:24px 0 8px;color:#f1f5f9}} .sub{{color:var(--mut)}}
table{{border-collapse:collapse;width:100%}} th,td{{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--mut);font-weight:500;width:45%}} ul{{padding-left:20px}} .note{{color:var(--mut);font-size:13px}}
</style>
<h1>VEIL Privacy Passport 3.0</h1><div class="sub">Team The Aevos · Hide the identity. Preserve the medicine. · Truth-free verification by tools/veil_passport.py</div>
{''.join(f'<h2>{html.escape(t)}</h2>' + table(d) for t, d in sec)}
<h2>Residual risks &amp; verification alerts</h2><ul>{risks}</ul>
{dev}
<h2>Scope &amp; Disclaimers</h2>
<p class="note">Sections A–E require zero ground truth and inspect the exact input/output release artifact. PASS/FAIL/WARNING/SKIPPED/INCONCLUSIVE states report observed coverage over eligible items. Absence of residual pattern hits is evidence, never proof of anonymity or regulatory certification. Official evaluator results are external and unknown.</p>
</html>"""


def main() -> int:
    ap = argparse.ArgumentParser(description="VEIL Privacy Passport 3.0 (offline release-assurance audit)")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--metrics", help="optional harness metrics.json (synthetic-truth development metrics)")
    ap.add_argument("--json")
    ap.add_argument("--html")
    a = ap.parse_args()
    R = audit(Path(a.input), Path(a.output))
    metrics = json.loads(Path(a.metrics).read_text()) if a.metrics else None
    if a.json:
        Path(a.json).write_text(json.dumps(R, indent=2), encoding="utf-8")
    if a.html:
        Path(a.html).write_text(render_html(R, metrics), encoding="utf-8")
    print(json.dumps({k: R[k] for k in ("structural", "privacy", "clinical", "temporal", "identity", "checks")}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
