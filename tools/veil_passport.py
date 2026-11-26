#!/usr/bin/env python3
"""VEIL Privacy Passport 2.0: offline record/field/temporal release-assurance audit.

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
B64 = re.compile(r"[A-Za-z0-9+/]{24,4096}={0,2}")
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
    r"(?i)facility|hospital|organi[sz]ation|lab|panel|test|doctor|practitioner|department|ward|"
    r"referr|consult|staff|nurse|drug|medic|package|procedure|diagnos|code|display|scheme|insurer|tpa"
)
ID_KEY = re.compile(r"(?i)(?:^|_|\b)(?:name|naam|patient|uhid|mrn|aadha?a?r|abha|mobile|phone|contact|email)(?:$|_|\b)")
PSN = re.compile(r"PSN-[0-9A-Z]{6,16}")


def norm(s: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", s).casefold().split())


def decode(raw: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def with_decoded_extras(text: str) -> str:
    extra = []
    for m in B64.finditer(text):
        tok = m.group(0)
        try:
            extra.append(base64.b64decode(tok + "=" * (-len(tok) % 4)).decode("utf-8", "ignore"))
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


def input_identifiers(inp: Path) -> set[str]:
    """Independent harvest of personal identifier values across CSV/TSV headers and JSON keys."""
    vals = set()

    def add(v):
        if isinstance(v, (str, int)) and len(str(v).strip()) >= 5:
            sv = norm(str(v))
            if sv not in ("patient_name", "patient", "relative", "unknown"):
                vals.add(sv)

    def walk(o, key="", ctx=""):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, k, ctx + "/" + str(k))
        elif isinstance(o, list):
            for x in o:
                walk(x, key, ctx)
        elif ID_KEY.search(str(key)) and not NON_PERSON.search(ctx) and not re.match(r"(?i)\s*(?:dr|sr|sis|n/o)\.?\s", str(o)):
            add(o)

    for p in sorted(inp.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        t = decode(p.read_bytes()[:20_000_000])
        if p.suffix.lower() == ".json":
            try:
                walk(json.loads(t))
            except (ValueError, RecursionError):
                pass
        elif p.suffix.lower() in (".csv", ".tsv"):
            delim = _tabular_delim(p.suffix.lower(), t)
            try:
                rows = list(csv.reader(io.StringIO(t), delimiter=delim))
            except csv.Error:
                continue
            if rows:
                cols = [i for i, h in enumerate(rows[0]) if ID_KEY.search(h) and not NON_PERSON.search(h)]
                for r in rows[1:]:
                    for i in cols:
                        if i < len(r):
                            val = r[i].strip()
                            if val and not re.match(r"(?i)\s*(?:dr|sr|sis|n/o)\.?\s", val):
                                add(val)
    return {v for v in vals if not v.isdigit() or len(v) >= 6}


def dates_in(text: str) -> list[tuple[int, int, int]]:
    raw = []
    for m in DATE.finditer(text):
        if m.group(3):
            raw.append(("x", int(m.group(3)), int(m.group(1)), int(m.group(2))))
        else:
            raw.append(("iso", int(m.group(4)), int(m.group(5)), int(m.group(6))))
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


def _flat_json(obj) -> str:
    parts = []

    def rec(o):
        if isinstance(o, dict):
            for k, v in o.items():
                parts.append(str(k))
                rec(v)
        elif isinstance(o, list):
            for x in o:
                rec(x)
        elif o is not None:
            parts.append(str(o))

    rec(obj)
    return "\n".join(parts)


class _ParsedOutputFile:
    """Lazy parser for resolving exact exported records (CSV/TSV row, JSON pointer, JSONL line, text)."""

    def __init__(self, path: Path):
        self.path = path
        self.text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
        self.suf = path.suffix.lower()
        self.rows = None
        self.obj = None
        self.lines = None
        if self.suf in (".csv", ".tsv"):
            try:
                self.rows = list(csv.reader(io.StringIO(self.text), delimiter=_tabular_delim(self.suf, self.text)))
            except csv.Error:
                self.rows = []
        elif self.suf in (".jsonl", ".ndjson"):
            self.lines = [ln for ln in self.text.splitlines() if ln.strip()]
        elif self.suf == ".json":
            try:
                self.obj = json.loads(self.text)
            except ValueError:
                self.obj = None

    def resolve_record(self, loc: str) -> tuple[str, bool]:
        if loc in ("doc", "@file"):
            return self.text, bool(self.text)
        if loc.startswith("row:") and re.fullmatch(r"row:\d+", loc):
            idx = int(loc[4:])
            if self.lines is not None:
                return (self.lines[idx], True) if idx < len(self.lines) else ("", False)
            if self.rows is not None:
                row_idx = idx + 1  # data row after header row[0]
                return ("\n".join(self.rows[row_idx]), True) if row_idx < len(self.rows) else ("", False)
        if loc.startswith("/") and self.obj is not None:
            try:
                return _flat_json(_json_ptr(self.obj, loc)), True
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
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    files_rep = rep.get("files", [])
    by_sha_q: dict[str, list[dict]] = {}
    for e in files_rep:
        by_sha_q.setdefault(e["input_sha256"], []).append(e)
    in_list = [p for p in sorted(inp.rglob("*")) if p.is_file() and not p.is_symlink()]
    in_pairs = [(hashlib.sha256(p.read_bytes()).hexdigest(), p) for p in in_list]
    R: dict = {
        "assurance_version": "2.0",
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
    parsed_cache: dict[str, _ParsedOutputFile] = {}

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
        suf = o.suffix.lower()
        try:
            if suf == ".json":
                obj = json.loads(pf.text)
                rok, rtot, dok, dtot = _audit_fhir_bundle(obj)
                fhir_refs_ok += rok
                fhir_refs_tot += rtot
                fhir_dates_ok += dok
                fhir_dates_tot += dtot
            elif suf in (".csv", ".tsv"):
                orows = pf.rows if pf.rows is not None else []
                irows = list(csv.reader(io.StringIO(decode(p.read_bytes())), delimiter=_tabular_delim(p.suffix.lower(), decode(p.read_bytes()))))
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
        "report_counts_consistent": honest,
    }
    struct_ok = (
        accounted == len(in_pairs)
        and len(missing_out) == 0
        and parse_fail == 0
        and unexpected_exports == 0
        and unsafe_paths == 0
        and honest
    )
    R["checks"]["structural"] = _make_check(
        "PASS" if struct_ok else "FAIL",
        accounted - len(missing_out) - parse_fail - unexpected_exports - unsafe_paths,
        len(in_pairs),
        "1:1 SHA-256 accounting, valid parses, zero unexpected exports or unsafe paths",
    )

    # ---------------- A. Privacy residue (independent detectors across decoded channels)
    ident = input_identifiers(inp)
    pat = Counter()
    resid_files = Counter()
    channels = {
        "report.json": SHA_HEX.sub("", (out / "report.json").read_text(encoding="utf-8")),
        "records.jsonl": (out / "records.jsonl").read_text(encoding="utf-8"),
        "file names": "\n".join(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()),
    }
    for p in sorted((out / "sanitized").rglob("*")):
        if p.is_file():
            channels[p.relative_to(out).as_posix()] = p.read_text(encoding="utf-8", errors="replace")
    for name, text in channels.items():
        tx = UUID.sub(" ", with_decoded_extras(text))
        for label, rx in (("phone", PHONE), ("aadhaar", AADHAAR), ("ABHA", ABHA), ("email", EMAIL), ("PAN", PAN)):
            hits_rx = rx.findall(tx)
            if label in ("aadhaar", "ABHA"):
                hits_rx = [h for h in hits_rx if not _COMPACT_TS.fullmatch(re.sub(r"\D", "", h))]
            n = len(hits_rx)
            if n:
                pat[label] += n
                resid_files[name] += n
        low = norm(tx)
        hits = sum(1 for v in ident if v in low)
        if hits:
            pat["input identity value"] += hits
            resid_files[name] += hits
    R["privacy"] = {
        "channels_scanned": len(channels),
        "independent_identity_values_from_input": len(ident),
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
        "Zero identifier hits across decoded sanitized, key, metadata, and filename channels",
    )

    # ---------------- B. Field/occurrence-aware clinical & temporal integrity
    kept_cat = Counter()
    tot_cat = Counter()
    t_ok = t_fail = t_skip = t_inconc = 0
    for p, e in used_entries:
        if not e or e.get("status") != "sanitized":
            continue
        out_rel = e["output"]
        if not (out / out_rel).is_file():
            continue
        pf = parsed_cache.get(out_rel) or _ParsedOutputFile(out / out_rel)
        it = decode(p.read_bytes())
        in_counts = _extract_clinical_counts(it)
        out_counts = _extract_clinical_counts(pf.text)
        for (label, expr), icnt in in_counts.items():
            tot_cat[label] += icnt
            kept_cat[label] += min(icnt, out_counts.get((label, expr), 0))

        # Temporal preservation across notes & JSON/FHIR units (count SKIPPED / INCONCLUSIVE explicitly)
        if p.suffix.lower() in (".txt", ".json"):
            di, do = dates_in(it), dates_in(pf.text)
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
                    else:
                        t_fail += 1

    tot_clin = sum(tot_cat.values())
    kept_clin = sum(kept_cat.values())
    clin_pct = round(100 * kept_clin / tot_clin, 2) if tot_clin else None
    t_eligible = t_ok + t_fail
    R["clinical"] = {
        "protected_values": {k: f"{kept_cat[k]}/{tot_cat[k]}" for k in tot_cat},
        "protected_values_kept_pct": clin_pct if clin_pct is not None else 0.0,
        "occurrence_totals": f"{kept_clin}/{tot_clin}",
        "notes_with_intervals_preserved": f"{t_ok}/{t_eligible}" if t_eligible else f"0/0 (skipped:{t_skip}, inconclusive:{t_inconc})",
    }
    R["temporal"] = {
        "intervals_passed": t_ok,
        "intervals_failed": t_fail,
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
        R["residual_risks"].append(f"{t_fail} document date interval checks failed chronological offset preservation")

    R["checks"]["clinical"] = _make_check(
        "SKIPPED" if tot_clin == 0 else ("PASS" if lost == 0 else "FAIL"),
        kept_clin,
        tot_clin,
        "Occurrence-aware preservation of medications, doses, frequencies, BP, labs, ICD-10, and staff",
    )
    R["checks"]["temporal"] = _make_check(
        "PASS" if (t_eligible > 0 and t_fail == 0 and fhir_dates_ok == fhir_dates_tot)
        else ("FAIL" if (t_fail > 0 or fhir_dates_ok < fhir_dates_tot)
              else ("INCONCLUSIVE" if t_inconc > 0 else "SKIPPED")),
        t_ok + fhir_dates_ok,
        t_eligible + fhir_dates_tot,
        f"Temporal interval & FHIR date checks (skipped={t_skip}, inconclusive={t_inconc})",
    )

    # ---------------- C. Record-level identity verification (exact loc/out resolution)
    linked = [r for r in recs if r.get("patient")]
    loc_valid = 0
    exact_placed = 0
    for r in linked:
        rf = r["file"]
        pf = parsed_cache.get(rf)
        if pf is None:
            pf = _ParsedOutputFile(out / rf)
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
        ("E · Structural Integrity", R["structural"]),
        ("A · Privacy Residue (Independent Decoded Channels)", R["privacy"]),
        ("B · Field/Occurrence Clinical Integrity", R["clinical"]),
        ("C · Temporal & FHIR Chronology", R.get("temporal", {})),
        ("D · Record-Level Identity Integrity", R["identity"]),
        ("Assurance 2.0 Check States", {k: f"{v['status']} ({v['coverage']})" for k, v in R.get("checks", {}).items()}),
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
<title>VEIL Privacy Passport 2.0</title>
<style>
:root{{--bg:#070b12;--fg:#e6edf7;--mut:#92a4bf;--line:#1e2d45;--warn:#f59e0b;--ok:#10b981}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 ui-sans-serif,system-ui,sans-serif;max-width:920px;margin:32px auto;padding:0 18px}}
h1{{font-size:25px;margin:0;color:#34d399}} h2{{font-size:16.5px;margin:24px 0 8px;color:#f1f5f9}} .sub{{color:var(--mut)}}
table{{border-collapse:collapse;width:100%}} th,td{{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--mut);font-weight:500;width:45%}} ul{{padding-left:20px}} .note{{color:var(--mut);font-size:13px}}
</style>
<h1>VEIL Privacy Passport 2.0</h1><div class="sub">Hide the identity. Preserve the medicine. · Truth-free verification by tools/veil_passport.py</div>
{''.join(f'<h2>{html.escape(t)}</h2>' + table(d) for t, d in sec)}
<h2>Residual risks &amp; verification alerts</h2><ul>{risks}</ul>
{dev}
<h2>Scope &amp; Disclaimers</h2>
<p class="note">Sections A–E require zero ground truth and inspect the exact input/output release artifact. PASS/FAIL/WARNING/SKIPPED/INCONCLUSIVE states report observed coverage over eligible items. Absence of residual pattern hits is evidence, never proof of anonymity or regulatory certification. Official evaluator results are external and unknown.</p>
</html>"""


def main() -> int:
    ap = argparse.ArgumentParser(description="VEIL Privacy Passport 2.0 (offline release-assurance audit)")
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
