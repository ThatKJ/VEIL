#!/usr/bin/env python3
"""VEIL Privacy Passport: an offline release-assurance audit of one VEIL release.

Development / demo tool only. It is NOT imported by main.py and is not needed at evaluation time.

    python3 tools/veil_passport.py --input <input dir> --output <VEIL output dir> [--metrics harness_metrics.json] \
        [--html passport.html] [--json passport.json]

Every number in the Passport is measured by this script on the given input/output pair. It runs four groups
of checks that need NO ground truth (privacy residue, clinical integrity, identity integrity, structural
integrity). Optional development metrics (synthetic truth) and local attacker estimates are only shown if a
harness metrics file is supplied, and they are labelled as such. The Passport never prints patient values:
only counts and file-relative locations.

A clean Passport is evidence, not proof: it cannot show the absence of every possible identifier.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import csv
import hashlib
import html
import io
import json
import re
import sys
import time
import unicodedata
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------- independent detectors (not VEIL's own rules)
PHONE = re.compile(r"(?<![\w\-])(?:\+?91[\s\-.]?)?[6-9]\d{2}[\s\-.]?\d{3}[\s\-.]?\d{4}(?!\d)")
AADHAAR = re.compile(r"(?<![\w\-])[2-9]\d{3}[\s\-.]?\d{4}[\s\-.]?\d{4}(?![\w\-])")
EMAIL = re.compile(r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+")
PAN = re.compile(r"(?<![A-Z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Z0-9])")
B64 = re.compile(r"[A-Za-z0-9+/]{24,4096}={0,2}")
DATE = re.compile(r"(?<!\d)(\d{1,2})[/\-.](\d{1,2})[/\-.]((?:19|20)\d{2})(?!\d)|(?<!\d)((?:19|20)\d{2})-(\d{2})-(\d{2})(?!\d)")
CLINICAL = [
    ("blood pressure", re.compile(r"(?i)\bBP\s*[:\-]?\s*\d{2,3}\s*/\s*\d{2,3}")),
    ("dose", re.compile(r"(?i)\b\d+(?:\.\d+)?\s*(?:mg|mcg|ml|iu|units?)\b")),
    ("lab value", re.compile(r"(?i)\b\d+(?:\.\d+)?\s*(?:mg/dl|g/dl|mmol/l|/cumm|u/l|iu/l|ng/ml|%)")),
    ("frequency", re.compile(r"\b[0-4]-[0-4]-[0-4]\b")),
    ("ICD-10 code", re.compile(r"\b[A-TV-Z]\d{2}\.\d{1,2}\b")),
]
NON_PERSON = re.compile(r"(?i)facility|hospital|organi[sz]ation|lab|panel|test|doctor|practitioner|department|ward|"
                        r"referr|consult|staff|nurse|drug|medic|package|procedure|diagnos|code|display|scheme|insurer|tpa")
ID_KEY = re.compile(r"(?i)(?:^|_|\b)(?:name|naam|patient|uhid|mrn|aadha?a?r|abha|mobile|phone|contact|email)(?:$|_|\b)")
PSN = re.compile(r"PSN-[0-9A-Z]{6}")


def norm(s: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", s).casefold().split())


def decode(raw: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def with_b64(text: str) -> str:
    extra = []
    for m in B64.finditer(text):
        tok = m.group(0)
        try:
            extra.append(base64.b64decode(tok + "=" * (-len(tok) % 4)).decode("utf-8", "ignore"))
        except (binascii.Error, ValueError):
            pass
    return text + "\n" + "\n".join(extra)


def input_identifiers(inp: Path) -> set[str]:
    """Independent harvest: values under identity-looking CSV headers / JSON keys in the INPUT."""
    vals = set()

    def add(v):
        if isinstance(v, (str, int)) and len(str(v).strip()) >= 5:
            vals.add(norm(str(v)))

    def walk(o, key="", ctx=""):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, k, ctx + "/" + str(k))
        elif isinstance(o, list):
            for x in o:
                walk(x, key, ctx)
        elif ID_KEY.search(str(key)) and not NON_PERSON.search(ctx) and not re.match(r"(?i)\s*dr\.?\s", str(o)):
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
            try:
                rows = list(csv.reader(io.StringIO(t), delimiter="\t" if p.suffix.lower() == ".tsv" else ","))
            except csv.Error:
                continue
            if rows:
                cols = [i for i, h in enumerate(rows[0]) if ID_KEY.search(h) and not NON_PERSON.search(h)]
                for r in rows[1:]:
                    for i in cols:
                        if i < len(r):
                            add(r[i])
    vals = {v for v in vals if not v.isdigit() or len(v) >= 6}
    # Institution names and recurring labels appear across many files; a patient's identifiers do not.
    texts = [norm(decode(p.read_bytes()[:5_000_000])) for p in sorted(inp.rglob("*")) if p.is_file() and not p.is_symlink()]
    limit = max(10, len(texts) // 20)
    return {v for v in vals if sum(1 for t in texts if v in t) <= limit}


def dates_in(text: str) -> list[tuple[int, int, int]]:
    """(year, month, day) with ONE day/month order per document (as a human reader would)."""
    raw = []
    for m in DATE.finditer(text):
        if m.group(3):
            raw.append(("x", int(m.group(3)), int(m.group(1)), int(m.group(2))))
        else:
            raw.append(("iso", int(m.group(4)), int(m.group(5)), int(m.group(6))))
    mdy = any(k == "x" and b > 12 for k, y, a, b in raw) and not any(k == "x" and a > 12 for k, y, a, b in raw)
    return [(y, a, b) if k == "iso" else ((y, a, b) if mdy else (y, b, a)) for k, y, a, b in raw]


def ordinal(d):
    import datetime as dt
    try:
        return dt.date(*d).toordinal()
    except ValueError:
        return None


def audit(inp: Path, out: Path) -> dict:
    t0 = time.monotonic()
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    by_sha = {e["input_sha256"]: e for e in rep.get("files", [])}
    inputs = {hashlib.sha256(p.read_bytes()).hexdigest(): p for p in sorted(inp.rglob("*")) if p.is_file() and not p.is_symlink()}
    R = {"privacy": {}, "clinical": {}, "identity": {}, "structural": {}, "residual_risks": []}

    # ---------------- D. structural integrity
    accounted = sum(1 for s in inputs if s in by_sha)
    exported = [e for e in rep["files"] if e.get("status") == "sanitized"]
    missing_out = [e for e in exported if not (out / e["output"]).is_file()]
    parse_ok = parse_fail = 0
    row_match = row_total = 0
    for s, p in inputs.items():
        e = by_sha.get(s)
        if not e or e.get("status") != "sanitized":
            continue
        o = out / e["output"]
        if not o.is_file():
            continue
        ot = o.read_text(encoding="utf-8", errors="replace")
        suf = o.suffix.lower()
        try:
            if suf == ".json":
                json.loads(ot)
            elif suf in (".csv", ".tsv"):
                d = "\t" if suf == ".tsv" else ","
                orows = list(csv.reader(io.StringIO(ot), delimiter=d))
                irows = list(csv.reader(io.StringIO(decode(p.read_bytes())), delimiter=d))
                row_total += 1
                row_match += len(orows) == len(irows)
            parse_ok += 1
        except (ValueError, csv.Error):
            parse_fail += 1
    counts = rep.get("counts", {})
    honest = (counts.get("files_total") == len(rep["files"]) and counts.get("files_sanitized") == len(exported)
              and counts.get("records_processed") == len(recs))
    R["structural"] = {
        "input_files": len(inputs), "accounted_in_report": accounted, "exported": len(exported),
        "quarantined": sum(1 for e in rep["files"] if e.get("status") == "quarantined"),
        "declared_outputs_missing": len(missing_out), "outputs_parse_ok": parse_ok, "outputs_parse_fail": parse_fail,
        "tables_row_count_preserved": f"{row_match}/{row_total}", "report_counts_consistent": honest,
    }

    # ---------------- A. privacy residue (independent detectors + independent input harvest)
    ident = input_identifiers(inp)
    pat = Counter()
    resid_files = Counter()
    channels = {"report.json": (out / "report.json").read_text(encoding="utf-8"),
                "records.jsonl": (out / "records.jsonl").read_text(encoding="utf-8"),
                "file names": "\n".join(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())}
    for p in sorted((out / "sanitized").rglob("*")):
        if p.is_file():
            channels[p.relative_to(out).as_posix()] = p.read_text(encoding="utf-8", errors="replace")
    for name, text in channels.items():
        tx = UUID.sub(" ", with_b64(text))
        for label, rx in (("phone", PHONE), ("aadhaar", AADHAAR), ("email", EMAIL), ("PAN", PAN)):
            n = len(rx.findall(tx))
            if n:
                pat[label] += n
                resid_files[name] += n
        low = norm(tx)
        hits = sum(1 for v in ident if v in low)
        if hits:
            pat["input identity value"] += hits
            resid_files[name] += hits
    R["privacy"] = {"channels_scanned": len(channels), "independent_identity_values_from_input": len(ident),
                    "residual_pattern_hits": dict(pat), "files_with_residue": len(resid_files)}
    if pat:
        R["residual_risks"].append(f"{sum(pat.values())} residual identifier-pattern hits in {len(resid_files)} "
                                   f"channels (may include false positives such as clinical numbers); review before release")

    # ---------------- B. clinical integrity + temporal consistency (per exported file)
    kept = Counter()
    total = Counter()
    t_ok = t_total = 0
    for s, p in inputs.items():
        e = by_sha.get(s)
        if not e or e.get("status") != "sanitized" or not (out / e["output"]).is_file():
            continue
        it = decode(p.read_bytes())
        ot = norm((out / e["output"]).read_text(encoding="utf-8", errors="replace"))
        for label, rx in CLINICAL:
            for m in rx.finditer(it):
                total[label] += 1
                kept[label] += norm(m.group(0)) in ot
        if p.suffix.lower() in (".txt",):                     # one patient per note: intervals must survive
            di, do = dates_in(it), dates_in((out / e["output"]).read_text(encoding="utf-8", errors="replace"))
            if len(di) >= 2 and len(di) == len(do):
                oi = [ordinal(d) for d in di]
                oo = [ordinal(d) for d in do]
                if None not in oi and None not in oo:
                    t_total += 1
                    t_ok += all((oi[k] - oi[0]) == (oo[k] - oo[0]) for k in range(len(oi)))
    R["clinical"] = {"protected_values": {k: f"{kept[k]}/{total[k]}" for k in total},
                     "protected_values_kept_pct": round(100 * sum(kept.values()) / max(1, sum(total.values())), 2),
                     "notes_with_intervals_preserved": f"{t_ok}/{t_total}"}
    lost = sum(total.values()) - sum(kept.values())
    if lost:
        R["residual_risks"].append(f"{lost} protected clinical expressions not found verbatim in output "
                                   f"(may be re-formatted dates/ages or genuine loss)")

    # ---------------- C. identity integrity
    linked = [r for r in recs if r.get("patient")]
    placed = 0
    cache = {}
    for r in linked:
        f = out / r["file"]
        if r["file"] not in cache:
            cache[r["file"]] = f.read_text(encoding="utf-8", errors="replace") if f.is_file() else ""
        placed += r["patient"] in cache[r["file"]]
    psns = Counter(r["patient"] for r in linked)
    bad_format = sum(1 for p_ in psns if not PSN.fullmatch(p_))
    R["identity"] = {"records": len(recs), "records_linked": len(linked), "distinct_pseudonyms": len(psns),
                     "pseudonym_present_in_exported_file": f"{placed}/{len(linked)}",
                     "pseudonym_format_violations": bad_format,
                     "largest_cluster_records": max(psns.values()) if psns else 0}
    if placed < len(linked):
        R["residual_risks"].append(f"{len(linked) - placed} linked records whose pseudonym is not in the exported file")

    R["engine"] = {"timing_s": rep.get("timing", {}).get("seconds"), "peak_rss_mb": rep.get("resources", {}).get("peak_rss_mb")}
    R["audit_seconds"] = round(time.monotonic() - t0, 2)
    return R


def render_html(R: dict, metrics: dict | None) -> str:
    def table(d):
        return "<table>" + "".join(f"<tr><th>{html.escape(str(k).replace('_', ' '))}</th><td>{html.escape(str(v))}</td></tr>"
                                   for k, v in d.items()) + "</table>"
    sec = [("D · Structural integrity", R["structural"]), ("A · Privacy residue (independent detectors)", R["privacy"]),
           ("B · Clinical & temporal integrity", R["clinical"]), ("C · Identity integrity", R["identity"]),
           ("Engine resources", R["engine"])]
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
            "local attacker: targeted A5 (vs raw)": p.get("components_relative_to_raw", {}).get("A5_targeted")}))
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VEIL Privacy Passport</title>
<style>
:root{{--bg:#fbfaf7;--fg:#1c1b19;--mut:#6b675f;--line:#e4e0d6;--warn:#9a4b00;--ok:#2f6b3a}}
@media (prefers-color-scheme:dark){{:root{{--bg:#151413;--fg:#ece8df;--mut:#a39d92;--line:#2e2b27;--warn:#f0a35c;--ok:#7fc58b}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 ui-sans-serif,system-ui,sans-serif;max-width:900px;margin:32px auto;padding:0 16px}}
h1{{font-size:26px;margin:0}} h2{{font-size:17px;margin:28px 0 8px}} .sub{{color:var(--mut)}}
table{{border-collapse:collapse;width:100%}} th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--mut);font-weight:500;width:45%}} ul{{padding-left:20px}} .note{{color:var(--mut);font-size:13px}}
</style>
<h1>VEIL Privacy Passport</h1><div class="sub">Hide the identity. Preserve the medicine. · measured on this release by tools/veil_passport.py</div>
{''.join(f'<h2>{html.escape(t)}</h2>' + table(d) for t, d in sec)}
<h2>Residual risks detected</h2><ul>{risks}</ul>
{dev}
<h2>What this does not show</h2>
<p class="note">Sections A–D need no ground truth and are computed from this input/output pair only. Pattern hits can include
false positives (clinical numbers). Absence of hits is not proof of anonymity. Development metrics and attacker estimates,
when shown, come from a local re-implementation on synthetic data. The official evaluator's results are unknown.</p>
</html>"""


def main() -> int:
    ap = argparse.ArgumentParser(description="VEIL Privacy Passport (offline release-assurance audit)")
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
    print(json.dumps({k: R[k] for k in ("structural", "privacy", "clinical", "identity")}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
