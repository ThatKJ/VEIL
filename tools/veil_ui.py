#!/usr/bin/env python3
"""VEIL — Clinical Privacy Command Center (offline local web UI server).

Zero third-party dependencies (Python 3.10+ stdlib only). Reuses the frozen
rakshak engine, tools/veil_passport.py, and demo/sample_hospital/ without
modifying main.py or raksha.toml evaluation behavior.

Usage:
    python3 tools/veil_ui.py --demo --open
    python3 tools/veil_ui.py --port 8765 --demo
"""
from __future__ import annotations

import argparse
import atexit
import base64
import binascii
import csv
import datetime as dt
import hashlib
import http.server
import io
import json
import os
import posixpath
import re
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import webbrowser
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = ROOT / "web"
DEMO_DIR = ROOT / "demo" / "sample_hospital"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import veil_passport as VP  # noqa: E402
from rakshak import linker as LNK  # noqa: E402
from rakshak import pipeline as PL  # noqa: E402
from rakshak import privacy as PRV  # noqa: E402

MAX_UPLOAD_FILES = 64
MAX_UPLOAD_BYTES = 16 * 1024 * 1024
MAX_PREVIEW_BYTES = 256 * 1024

TAG_PATTERN = re.compile(
    r"\[(?:NAME|RELATIVE|PHONE|AADHAAR|ABHA|PAN|EMAIL|ID|INSURANCE|PIN|VILLAGE|DISTRICT|DATE|AGE|REDACTED)\]"
)
PSN_PATTERN = re.compile(r"\bPSN-[0-9A-Z]{6,16}\b")
STAFF_PATTERN = re.compile(r"\b(?:Dr\.|N/O|DEO)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}")
EXACT_PIN_PATTERN = re.compile(r"(?<!\d)[1-8]\d{5}(?!\s*/\s*cumm|\d)")
AGE_BAND_PATTERN = re.compile(r"\b\d{1,2}-\d{2,3}\b")

HISTORICAL_BENCHMARKS = {
    "team": "The Aevos",
    "checkpoint": "CHAMPION (main, built on frozen known-good-11 / 69530e8)",
    "disclaimer": (
        "Measured offline using the local synthetic harness and re-implemented attacker "
        "(NOT official competition evaluation; H20/H21/H2/s9_C are reclassified diagnostic datasets)."
    ),
    "runs": [
        {"dataset": "dev", "type": "Official Practice", "score": "92.31 (local w/ perf)", "leak_pct": "0.0% (check_dev 0/3230)", "false_merges": 0, "canaries": "0/4"},
        {"dataset": "chaos_dev", "type": "Dev Synthetic", "score": "93.01 (local w/ perf)", "leak_pct": "0.0% (truth)", "false_merges": 0, "canaries": "0/3"},
        {"dataset": "chaos_holdout2", "type": "Diag (FM 11 -> 0)", "score": "95.20 (local w/ perf)", "leak_pct": "0.1% (truth)", "false_merges": 0, "canaries": "0/4"},
        {"dataset": "chaos_holdout18", "type": "Diag Assam/Odisha", "score": "87.22 (+0.77 vs kg9)", "leak_pct": "0.0% (truth)", "false_merges": 0, "canaries": "0/4"},
        {"dataset": "chaos_holdout19", "type": "Diag Karnataka+JSONL", "score": "93.54 (+1.18 vs kg9)", "leak_pct": "0.7% (truth)", "false_merges": 0, "canaries": "0/4"},
        {"dataset": "chaos_holdout20", "type": "Diag Haryana/EAV", "score": "86.07 (local w/ perf)", "leak_pct": "0.1% (truth)", "false_merges": 0, "canaries": "0/4"},
        {"dataset": "chaos_holdout21", "type": "Diag Kerala/Malayalam", "score": "89.20 (local w/ perf)", "leak_pct": "0.2% (truth)", "false_merges": 0, "canaries": "0/4"},
        {"dataset": "4_blind_suites", "type": "Frozen Unseen (9601..9604)", "score": "89.96 mean (min 84.23)", "leak_pct": "0.01% - 0.11%", "false_merges": 0, "canaries": "0/16"},
    ],
    "scalability": [
        {"workload": "100k repeat (500p)", "records": "100,000", "wall_s": 10.384, "peak_rss_mb": 461.2, "throughput": "9,630 rows/s"},
        {"workload": "100k unique (100kp)", "records": "100,000", "wall_s": 12.378, "peak_rss_mb": 516.9, "throughput": "8,079 rows/s"},
        {"workload": "250k mixed (1,252 files)", "records": "188,750", "wall_s": 53.738, "peak_rss_mb": 732.6, "throughput": "3,512 rows/s"},
        {"workload": "500k repeat (50kp)", "records": "500,000", "wall_s": 55.589, "peak_rss_mb": 1766.6, "throughput": "8,995 rows/s"},
        {"workload": "1M repeat (100kp)", "records": "1,000,000", "wall_s": 113.157, "peak_rss_mb": 3206.6, "throughput": "8,837 rows/s"},
        {"workload": "1M unique (1M pts)", "records": "1,000,000", "wall_s": 128.927, "peak_rss_mb": 3176.2, "throughput": "7,756 rows/s"},
        {"workload": "1.25M mixed (6,252 files)", "records": "943,750", "wall_s": 682.755, "peak_rss_mb": 2928.4, "throughput": "1,382 rows/s"},
    ],
    "scale": {"records": "1,000,000 x 1,000,000", "seconds": 128.927, "peak_rss_mb": 3176.2},
    "checks": {"unit_tests": "41/41 OK", "official_checker": "READY TO SUBMIT (CONTRACT OK)"},
}


class ServerState:
    def __init__(self, workdir: Path):
        self.workdir = workdir
        self.lock = threading.Lock()
        self.jobs: dict[str, dict] = {}
        self.active: dict | None = None
        self.active_inp: Path | None = None
        self.active_upload_bytes: dict[str, bytes] | None = None
        self.active_out: Path | None = None
        self.active_secret: str = "veil-command-center-demo-key"
        self.active_policy_mode: str = "adaptive"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_rel(raw_path: str) -> str | None:
    norm = raw_path.replace("\\", "/").lstrip("/")
    cleaned = posixpath.normpath(norm)
    if not cleaned or cleaned in (".", "..") or cleaned.startswith("../") or cleaned.startswith("/"):
        return None
    parts = [p for p in cleaned.split("/") if p]
    if any(p in (".", "..") for p in parts):
        return None
    return "/".join(parts)


def _format_of(rel: str, raw: bytes) -> str:
    ext = Path(rel).suffix.lower()
    if ext == ".json":
        return "JSON"
    if ext == ".jsonl":
        return "JSONL"
    if ext == ".tsv":
        return "TSV"
    if ext == ".csv":
        return "CSV"
    if ext == ".txt":
        sample = VP.decode(raw[:1024])
        if sample.startswith("MSH|"):
            return "HL7 v2"
        if "-----BEGIN STRUCTURED-----" in sample:
            return "Hybrid Note"
        return "Clinical Note"
    return "Binary / Unsupported"


def _run_subprocess_engine(inp: Path, out: Path, secret: str, policy_mode: str) -> tuple[float, str]:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "RAKSHA_SECRET": secret}
    if policy_mode in ("mask", "fixed"):
        env["RAKSHAK_EXPERIMENT"] = "1"
        env["RAKSHAK_P_QI_MODE"] = policy_mode
    elif policy_mode == "adaptive":
        env.pop("RAKSHAK_EXPERIMENT", None)
        env.pop("RAKSHAK_P_QI_MODE", None)
    t0 = time.monotonic()
    res = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return round(time.monotonic() - t0, 3), res.stdout.strip()


def _detect_scripts(ev: dict) -> list[str]:
    scripts = set()
    joined = " ".join(ev.get("names_raw", []))
    if any("\u0900" <= ch <= "\u097F" for ch in joined):
        scripts.add("Devanagari")
    if any("\u0D00" <= ch <= "\u0D7F" for ch in joined):
        scripts.add("Malayalam")
    if any("\u0B80" <= ch <= "\u0BFF" for ch in joined):
        scripts.add("Tamil")
    if any("A" <= ch <= "Z" or "a" <= ch <= "z" for ch in joined) or not scripts:
        scripts.add("Latin")
    return sorted(scripts)


def _analyze_identity_and_qi(inp: Path, out: Path, policy_mode: str) -> tuple[dict, list[dict], dict]:
    """Build PII-safe patient identity graph, pairwise decisions, and real QI class metrics."""
    pol_path = ROOT / "config" / "policy.yaml"
    old_exp = os.environ.get("RAKSHAK_EXPERIMENT")
    old_mode = os.environ.get("RAKSHAK_P_QI_MODE")
    try:
        if policy_mode in ("mask", "fixed"):
            os.environ["RAKSHAK_EXPERIMENT"] = "1"
            os.environ["RAKSHAK_P_QI_MODE"] = policy_mode
        else:
            os.environ.pop("RAKSHAK_EXPERIMENT", None)
            os.environ.pop("RAKSHAK_P_QI_MODE", None)
        policy = PL.load_policy(pol_path)
    finally:
        if old_exp is None:
            os.environ.pop("RAKSHAK_EXPERIMENT", None)
        else:
            os.environ["RAKSHAK_EXPERIMENT"] = old_exp
        if old_mode is None:
            os.environ.pop("RAKSHAK_P_QI_MODE", None)
        else:
            os.environ["RAKSHAK_P_QI_MODE"] = old_mode

    H = PL.Harvest()
    jobs = []
    paths = [p for p in inp.rglob("*") if p.is_file() and not p.is_symlink()]
    for path in sorted(paths, key=lambda p: p.relative_to(inp).as_posix()):
        rel = path.relative_to(inp).as_posix()
        job = PL.FileJob(rel, path.read_bytes())
        PL.pass1(job, H)
        jobs.append(job)

    recs = [r for j in jobs for r in j.recs]
    date_orders = {j.rel: j.order for j in jobs}
    for r in recs:
        if r.ev["dob"]:
            d = PL.parse_date(r.ev["dob"], date_orders[r.file])
            r.ev["dob"] = d.isoformat() if d else None

    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    sha_to_out = {e["input_sha256"]: e.get("output") for e in rep.get("files", [])}
    out_to_in = {}
    for j in jobs:
        of = sha_to_out.get(j.sha)
        if of:
            out_to_in[of] = j.rel

    rec_psn_map: dict[tuple[str, str], str | None] = {}
    for line in (out / "records.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        rec_psn_map[(row["file"], row["loc"])] = row.get("patient")

    # Attach exact output PSN from records.jsonl so graph matches actual release 100%
    out_rel_by_in = {j.rel: sha_to_out.get(j.sha) for j in jobs}
    rec_info = []
    groups_by_psn: dict[str, list] = defaultdict(list)
    cluster_objs: dict[str, LNK.Cluster] = {}

    for idx, r in enumerate(recs):
        if r.loc.startswith("@"):
            continue
        out_f = out_rel_by_in.get(r.file)
        psn = rec_psn_map.get((out_f, r.loc)) if out_f else None
        if not psn and out_f:
            psn = rec_psn_map.get((out_f, "doc"))
        r.pid = psn
        if psn:
            r.key = psn
            groups_by_psn[psn].append(r)
            cl = LNK.Cluster(idx, r.ev)
            if psn not in cluster_objs:
                cluster_objs[psn] = cl
            else:
                cluster_objs[psn].absorb(cl)
        signals = []
        if any(str(i).startswith(("M:", "U:")) for i in r.ev["ids"]):
            signals.append("UHID/MRN")
        if any(str(i).startswith("A:") for i in r.ev["ids"]):
            signals.append("Aadhaar")
        if any(str(i).startswith(("B:", "N:")) for i in r.ev["ids"]):
            signals.append("ABHA/PAN")
        if r.ev["phones"]:
            signals.append("Mobile")
        if r.ev["names"]:
            signals.append("Name")
        if r.ev["dob"]:
            signals.append("DOB")
        if r.ev["rel"]:
            signals.append("Relative")
        if r.ev.get("conds"):
            signals.append("Clinical/ICD")
        rec_info.append({
            "idx": idx,
            "node_id": f"rec_{idx}",
            "psn": psn,
            "file": r.file,
            "sanitized_file": out_f,
            "loc": r.loc,
            "format": _format_of(r.file, next((j.raw for j in jobs if j.rel == r.file), b"")),
            "scripts": _detect_scripts({"names_raw": [" ".join(toks) for toks in r.ev["names"]]}),
            "signals": signals,
            "cl": LNK.Cluster(idx, r.ev),
            "ev": r.ev,
        })

    # Also capture raw-script presence from input text per file
    raw_scripts_by_file = {}
    for j in jobs:
        if j.status == "sanitized":
            txt = j.text or VP.decode(j.raw)
            sc = []
            if any("A" <= ch <= "Z" or "a" <= ch <= "z" for ch in txt):
                sc.append("Latin")
            if any("\u0900" <= ch <= "\u097F" for ch in txt):
                sc.append("Devanagari")
            if any("\u0D00" <= ch <= "\u0D7F" for ch in txt):
                sc.append("Malayalam")
            raw_scripts_by_file[j.rel] = sc or ["Latin"]
    for item in rec_info:
        item["scripts"] = raw_scripts_by_file.get(item["file"], item["scripts"])

    plan = PRV.plan(groups_by_psn, policy)
    qi_stats = _compute_qi_metrics(groups_by_psn, plan)

    # Build PII-safe clusters & edges
    nodes_clusters = []
    for psn, members in sorted(groups_by_psn.items()):
        rule = plan.rule(psn)
        ages = [m.ev["age"] for m in members if m.ev["age"] is not None]
        bf = plan.band_fn(psn)
        age_band = bf(max(ages)) if ages else "N/A"
        files = sorted({m.file for m in members})
        scripts = sorted({s for f in files for s in raw_scripts_by_file.get(f, ["Latin"])})
        cond_tags = sorted({c for m in members for c in m.ev.get("conds", set())})
        nodes_clusters.append({
            "id": psn,
            "psn": psn,
            "record_count": len(members),
            "files": files,
            "scripts": scripts,
            "age_band": age_band,
            "qi_reason": rule.reason,
            "qi_band_years": rule.band,
            "qi_pin": rule.pin,
            "qi_district": rule.dist,
            "condition_codes": cond_tags[:5],
        })

    nodes_records = [
        {
            "id": r["node_id"],
            "psn": r["psn"],
            "file": r["file"],
            "sanitized_file": r["sanitized_file"],
            "loc": r["loc"],
            "format": r["format"],
            "scripts": r["scripts"],
            "signals": r["signals"],
        }
        for r in rec_info
    ]

    decisions = []
    matched_edges = []
    seen_pairs = set()

    # 1. Matched links within each patient cluster across files/formats
    by_psn_recs: dict[str, list[dict]] = defaultdict(list)
    for r in rec_info:
        if r["psn"]:
            by_psn_recs[r["psn"]].append(r)

    for psn, items in sorted(by_psn_recs.items()):
        if len(items) < 2:
            continue
        anchor = items[0]
        for other in items[1:]:
            if other["file"] == anchor["file"] and other["loc"] == anchor["loc"]:
                continue
            shared_ids = anchor["ev"]["ids"] & other["ev"]["ids"]
            shared_phones = anchor["ev"]["phones"] & other["ev"]["phones"]
            shared_names = bool(LNK._name_compatible(anchor["cl"], other["cl"]) and anchor["cl"].names and other["cl"].names)
            evidence = []
            if shared_ids:
                evidence.append("Shared primary ID (MRN/UHID/Aadhaar)")
            if shared_phones:
                evidence.append("Matching verified mobile")
            if shared_names:
                if set(anchor["scripts"]) != set(other["scripts"]):
                    evidence.append("Cross-script name skeleton alignment")
                else:
                    evidence.append("Name skeleton match")
            if anchor["cl"].dobs and other["cl"].dobs and (anchor["cl"].dobs & other["cl"].dobs):
                evidence.append("DOB agreement")
            if not evidence:
                evidence.append("Transitive cluster support (multiple channels)")
            edge = {
                "source": anchor["node_id"],
                "target": other["node_id"],
                "psn": psn,
                "decision": "matched",
                "summary": f"{anchor['file']} ({anchor['loc']}) -> {other['file']} ({other['loc']})",
                "evidence": evidence,
                "veto": None,
            }
            matched_edges.append(edge)
            # Only add cross-file matches to decision table to keep table clear & punchy
            if anchor["file"] != other["file"]:
                decisions.append({
                    "pair_id": f"{psn}:{len(decisions)}",
                    "left": f"{psn} · {anchor['file']} ({anchor['loc']})",
                    "right": f"{psn} · {other['file']} ({other['loc']})",
                    "decision": "matched",
                    "rule": " · ".join(evidence),
                    "scripts": sorted(set(anchor["scripts"]) | set(other["scripts"])),
                })

    # 2. Rejected & ambiguous pairs across distinct clusters (never exposing raw PII!)
    psn_list = sorted(cluster_objs.keys())
    for i, pa in enumerate(psn_list):
        ca = cluster_objs[pa]
        for pb in psn_list[i + 1:]:
            cb = cluster_objs[pb]
            pair_key = (pa, pb)
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            # Check whether surface similarity exists (shared name token, family id, phone, village, or district)
            toks_a = {t for nk in ca.names for t in nk if len(t) >= 2}
            toks_b = {t for nk in cb.names for t in nk if len(t) >= 2}
            shared_name_toks = bool(toks_a & toks_b)
            shared_surname = any(nk_a and nk_b and nk_a[-1] == nk_b[-1] for nk_a in ca.names for nk_b in cb.names)
            shared_vill = bool(ca.villages & cb.villages)
            shared_id_raw = bool(ca.ids & cb.ids)
            is_comp = LNK.compatible(ca, cb)

            if not (shared_name_toks or shared_surname or shared_vill or shared_id_raw):
                continue

            veto_reasons = []
            if len(ca.genders | cb.genders) > 1:
                veto_reasons.append("Gender mismatch")
            if ca.dobs and cb.dobs and not (ca.dobs & cb.dobs):
                veto_reasons.append("Contradicting DOB")
            if not LNK._ages_ok(ca, cb):
                if ca.ages and cb.ages:
                    adiff = min(abs(x - y) for x in ca.ages for y in cb.ages)
                    veto_reasons.append(f"Age delta {adiff}y (> 2y limit)")
                else:
                    veto_reasons.append("Age range incompatibility")
            if not LNK._name_compatible(ca, cb):
                veto_reasons.append("Given-name / family token conflict")
            for pref, label in (("A:", "Contradicting Aadhaar"), ("B:", "Contradicting ABHA"), ("N:", "Contradicting PAN")):
                xa = {x for x in ca.ids if x.startswith(pref)}
                xb = {x for x in cb.ids if x.startswith(pref)}
                if xa and xb and not (xa & xb):
                    veto_reasons.append(label)
            if ca.rels and cb.rels and LNK._rel_match(ca.rels, cb.rels) == 0:
                veto_reasons.append("Different attendant/relative token")

            if not is_comp or veto_reasons:
                decision_kind = "rejected"
                surface = []
                if shared_name_toks:
                    surface.append("identical/overlapping name skeleton")
                elif shared_surname:
                    surface.append("shared family surname")
                if shared_id_raw:
                    surface.append("shared household/scheme ID")
                if shared_vill:
                    surface.append("same locality")
                rule_txt = f"Cannot-link veto ({', '.join(veto_reasons)}) despite {' + '.join(surface) or 'surface proximity'}"
            else:
                decision_kind = "ambiguous"
                rule_txt = "Shared locality/name token only — held separate pending secondary corroboration"

            rep_a = by_psn_recs[pa][0]["node_id"]
            rep_b = by_psn_recs[pb][0]["node_id"]
            matched_edges.append({
                "source": rep_a,
                "target": rep_b,
                "psn": f"{pa} != {pb}",
                "decision": decision_kind,
                "summary": f"{pa} vs {pb}",
                "evidence": [],
                "veto": rule_txt,
            })
            decisions.append({
                "pair_id": f"pair:{pa}:{pb}",
                "left": f"{pa} ({by_psn_recs[pa][0]['file']})",
                "right": f"{pb} ({by_psn_recs[pb][0]['file']})",
                "decision": decision_kind,
                "rule": rule_txt,
                "scripts": sorted(set(by_psn_recs[pa][0]["scripts"]) | set(by_psn_recs[pb][0]["scripts"])),
            })

    # Unlinked reference documents (patient=None) also listed cleanly as ambiguous/unassigned info
    unlinked_nodes = [r for r in rec_info if r["psn"] is None]
    for r in unlinked_nodes:
        decisions.append({
            "pair_id": f"ref:{r['node_id']}",
            "left": f"{r['file']} ({r['loc']})",
            "right": "Clinical Reference Pool",
            "decision": "ambiguous",
            "rule": "No patient entity present — preserved unlinked as non-patient clinical protocol",
            "scripts": r["scripts"],
        })

    graph = {
        "clusters": nodes_clusters,
        "records": nodes_records,
        "edges": matched_edges,
    }
    return graph, decisions, qi_stats


def _compute_qi_metrics(groups_by_psn: dict[str, list], plan: PRV.Plan) -> dict:
    """Measure real release equivalence-class sizes (k) after applying the chosen QI plan."""
    n_patients = len(groups_by_psn)
    cells = Counter()
    patient_reasons = Counter()
    exact_age_patients = 0
    pin_kept_patients = 0
    dist_kept_patients = 0
    dist_dropped_patients = 0
    band_10y_patients = 0

    for psn, members in groups_by_psn.items():
        prof = PRV._profile(members)
        rule = plan.rule(psn)
        patient_reasons[rule.reason] += 1
        if rule.band <= 1:
            exact_age_patients += 1
        if rule.band >= 10:
            band_10y_patients += 1
        if rule.pin != "drop":
            pin_kept_patients += 1
        if rule.dist == "keep" and prof["dist"]:
            dist_kept_patients += 1
        elif rule.dist == "drop" and prof["dist"]:
            dist_dropped_patients += 1
        age_cell = prof["age"] // max(1, rule.band) if prof["age"] is not None else None
        dist_cell = prof["dist"] if rule.dist == "keep" else None
        birth_cell = prof["birth"] if rule.dob == "shift" else None
        cells[(dist_cell, prof["g"], age_cell, birth_cell)] += 1

    singletons = sum(v for v in cells.values() if v == 1)
    k_lt_5 = sum(v for v in cells.values() if v < 5)
    min_k = min(cells.values()) if cells else 0
    avg_k = round(n_patients / max(1, len(cells)), 2) if cells else 0.0
    max_risk_pct = round(100.0 / max(1, min_k), 1) if cells else 0.0
    avg_risk_pct = round(100.0 * len(cells) / max(1, n_patients), 1) if n_patients else 0.0
    return {
        "patients": n_patients,
        "equivalence_classes": len(cells),
        "singleton_k1_patients": singletons,
        "under_k5_patients": k_lt_5,
        "min_k": min_k,
        "avg_k": avg_k,
        "prosecutor_max_risk_pct": max_risk_pct,
        "prosecutor_avg_risk_pct": avg_risk_pct,
        "exact_age_patients": exact_age_patients,
        "pin_kept_patients": pin_kept_patients,
        "district_kept_patients": dist_kept_patients,
        "district_dropped_patients": dist_dropped_patients,
        "band_10y_patients": band_10y_patients,
        "rule_breakdown": dict(patient_reasons),
    }


def _run_privacy_arena(inp: Path, arena_root: Path, secret: str) -> list[dict]:
    """Run main.py under all 3 QI policies (mask, fixed, adaptive) on the active input."""
    specs = [
        ("mask", "Direct Masking Only", "Masks direct IDs but keeps exact ages, 6-digit PINs, and locations."),
        ("fixed", "Fixed QI Policy", "Uniform 5-year age bands and shifted dates across all patients identically."),
        ("adaptive", "VEIL Adaptive (Default)", "Pools patient profiles cross-hospital; escalates singletons, rare ICDs & seniors >=80y."),
    ]
    rows = []
    for mode, label, summary in specs:
        out_dir = arena_root / f"arena_{mode}"
        dt_s, _ = _run_subprocess_engine(inp, out_dir, secret, mode)
        passport = VP.audit(inp, out_dir)
        _, _, qi_stats = _analyze_identity_and_qi(inp, out_dir, mode)
        san_texts = [
            p.read_text(encoding="utf-8", errors="replace")
            for p in (out_dir / "sanitized").rglob("*")
            if p.is_file()
        ]
        joined = "\n".join(san_texts)
        exact_pins_left = len(EXACT_PIN_PATTERN.findall(joined))
        age_bands_used = len(AGE_BAND_PATTERN.findall(joined))
        rep = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
        rows.append({
            "mode": mode,
            "label": label,
            "summary": summary,
            "runtime_s": dt_s,
            "records_linked": rep["counts"]["records_linked"],
            "identifiers_detected": rep["counts"]["identifiers_detected"],
            "clinical_kept_pct": passport["clinical"]["protected_values_kept_pct"],
            "intervals_preserved": passport["clinical"]["notes_with_intervals_preserved"],
            "residual_hits": sum(passport["privacy"]["residual_pattern_hits"].values()),
            "exact_pins_visible": exact_pins_left,
            "age_bands_applied": age_bands_used,
            "qi": qi_stats,
        })
    return rows


def _extract_before_after_and_clinical(inp: Path, out: Path) -> tuple[list[dict], dict, list[dict]]:
    """Pair input files to sanitized outputs, extract PII transformation tags and LOS clinical probes."""
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    by_sha = {e["input_sha256"]: e for e in rep.get("files", [])}
    file_pairs = []
    timeline_checks = []
    agg_tags = Counter()
    agg_psns = Counter()
    staff_kept = set()
    clinical_samples = []
    seen_clinical = set()

    clinical_extractors = [
        ("Blood Pressure", re.compile(r"(?i)\bBP\s*[:\-]?\s*\d{2,3}\s*/\s*\d{2,3}(?:\s*mmHg)?")),
        ("Medication Dose", re.compile(r"(?i)(?:Tab\.|Inj\.|Cap\.|ORS)?\s*[A-Za-z]{3,20}\s+\d+(?:\.\d+)?\s*(?:mg|mcg|ml|iu)\b|\b\d+(?:\.\d+)?\s*(?:mg|mcg|ml|iu)\b")),
        ("Lab / Platelet", re.compile(r"(?i)(?:Hemoglobin|HbA1c|Platelet\s+count|Serum\s+[A-Za-z]+|Creatinine|Temperature)?\s*,?\s*\d+(?:\.\d+)?\s*(?:mg/dL|g/dL|mmol/L|/cumm|mcg/dL|%|F)\b")),
        ("Dosing Schedule", re.compile(r"\b[0-4]-[0-4]-[0-4]\b")),
        ("ICD-10 Code", re.compile(r"\b[A-TV-Z]\d{2}\.\d{1,2}\b")),
    ]

    for p in sorted(inp.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        rel = p.relative_to(inp).as_posix()
        raw = p.read_bytes()
        sha = _sha256_bytes(raw)
        entry = by_sha.get(sha, {})
        status = entry.get("status", "unknown")
        out_rel = entry.get("output")
        reason = entry.get("reason")
        fmt = _format_of(rel, raw)

        if status == "quarantined":
            file_pairs.append({
                "input_rel": rel,
                "output_rel": None,
                "status": "quarantined",
                "reason": reason or "unsupported_format",
                "format": fmt,
                "sha256_short": sha[:12],
                "bytes_in": len(raw),
                "bytes_out": 0,
                "input_text": f"[BINARY / UNSUPPORTED PAYLOAD QUARANTINED]\nFile: {rel}\nSize: {len(raw)} bytes\nSHA-256: {sha}\nMagic prefix hex: {raw[:24].hex(' ')}",
                "output_text": f"[QUARANTINED — NOT EXPORTED TO sanitized/]\nReason: {reason or 'unsupported_format'}",
                "tag_counts": {},
                "psns": [],
                "staff_preserved": [],
            })
            continue

        out_path = (out / out_rel) if out_rel else None
        out_txt = out_path.read_text(encoding="utf-8", errors="replace") if (out_path and out_path.is_file()) else ""
        in_txt = VP.decode(raw)
        in_preview = in_txt[:MAX_PREVIEW_BYTES] + ("\n... [truncated preview]" if len(in_txt) > MAX_PREVIEW_BYTES else "")
        out_preview = out_txt[:MAX_PREVIEW_BYTES] + ("\n... [truncated preview]" if len(out_txt) > MAX_PREVIEW_BYTES else "")

        tags = Counter(TAG_PATTERN.findall(out_txt))
        psns = Counter(PSN_PATTERN.findall(out_txt))
        staff = sorted(set(STAFF_PATTERN.findall(out_txt)))
        agg_tags.update(tags)
        agg_psns.update(psns)
        staff_kept.update(staff)

        # Temporal preservation check for narrative notes
        if p.suffix.lower() == ".txt":
            di = VP.dates_in(in_txt)
            do = VP.dates_in(out_txt)
            if len(di) >= 2 and len(di) == len(do):
                oi = [VP.ordinal(d) for d in di]
                oo = [VP.ordinal(d) for d in do]
                if None not in oi and None not in oo:
                    in_span = oi[-1] - oi[0]
                    out_span = oo[-1] - oo[0]
                    shift = oo[0] - oi[0]
                    timeline_checks.append({
                        "file": rel,
                        "output_file": out_rel,
                        "input_dates": [f"{d[0]:04d}-{d[1]:02d}-{d[2]:02d}" for d in di],
                        "output_dates": [f"{d[0]:04d}-{d[1]:02d}-{d[2]:02d}" for d in do],
                        "input_los_days": in_span,
                        "output_los_days": out_span,
                        "los_delta_days": abs(out_span - in_span),
                        "patient_shift_days": shift,
                        "preserved": all((oi[k] - oi[0]) == (oo[k] - oo[0]) for k in range(len(oi))),
                    })

        # Sample clinical probes kept verbatim input -> output
        out_norm = VP.norm(out_txt)
        for cat, rx in clinical_extractors:
            for m in rx.finditer(in_txt):
                val = " ".join(m.group(0).split()).strip(".,;")
                if not val or val in seen_clinical:
                    continue
                seen_clinical.add(val)
                if len(clinical_samples) < 18:
                    clinical_samples.append({
                        "category": cat,
                        "file": rel,
                        "value": val,
                        "preserved": VP.norm(val) in out_norm,
                    })

        file_pairs.append({
            "input_rel": rel,
            "output_rel": out_rel,
            "status": status,
            "reason": reason,
            "format": fmt,
            "sha256_short": sha[:12],
            "bytes_in": len(raw),
            "bytes_out": len(out_txt.encode("utf-8")),
            "input_text": in_preview,
            "output_text": out_preview,
            "tag_counts": dict(tags),
            "psns": sorted(psns.keys()),
            "staff_preserved": staff,
        })

    transformations = [
        {"token": k, "count": v}
        for k, v in agg_tags.most_common()
    ]
    clinical_summary = {
        "timeline_intervals": timeline_checks,
        "staff_preserved": sorted(staff_kept),
        "samples": clinical_samples,
        "psn_tokens_total": sum(agg_psns.values()),
    }
    return file_pairs, clinical_summary, transformations


def _build_full_payload(
    inp: Path,
    out: Path,
    arena_root: Path,
    secret: str,
    policy_mode: str,
    mode_label: str,
    progress_cb=None,
) -> dict:
    def emit(pct: int, stage: str):
        if progress_cb:
            progress_cb(pct, stage)

    emit(10, "Discovering & hashing input channels")
    emit(28, "Running frozen VEIL engine pipeline")
    runtime_s, engine_stdout = _run_subprocess_engine(inp, out, secret, policy_mode)

    emit(50, "Auditing Privacy Passport & residue channels")
    passport = VP.audit(inp, out)
    passport_html = VP.render_html(passport, None)

    emit(68, "Constructing cross-hospital identity graph & veto decisions")
    graph, decisions, qi_stats = _analyze_identity_and_qi(inp, out, policy_mode)

    emit(84, "Benchmarking Privacy Arena (Mask vs Fixed vs Adaptive)")
    arena = _run_privacy_arena(inp, arena_root, secret)

    emit(95, "Extracting before/after diffs & clinical temporal integrity")
    file_pairs, clinical_detail, transformations = _extract_before_after_and_clinical(inp, out)

    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    emit(100, "Complete")
    return {
        "run_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "dataset_label": mode_label,
        "policy_mode": policy_mode,
        "runtime_s": runtime_s,
        "engine_stdout": engine_stdout,
        "report": rep,
        "passport": passport,
        "passport_html": passport_html,
        "corrupted_passport": None,
        "verification_history": [
            {
                "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S UTC"),
                "event": "Initial Assurance 3.0 Audit",
                "status": "PASS" if not passport["residual_risks"] else "FAIL",
                "summary": f"{passport['identity']['pseudonym_present_in_exact_record']} exact records · {passport['clinical']['occurrence_totals']} clinical · 0 residual hits"
                if not passport["residual_risks"]
                else "; ".join(passport["residual_risks"]),
            }
        ],
        "qi_stats": qi_stats,
        "identity_graph": graph,
        "identity_decisions": decisions,
        "privacy_arena": arena,
        "file_pairs": file_pairs,
        "transformations": transformations,
        "clinical_detail": clinical_detail,
        "historical_benchmarks": HISTORICAL_BENCHMARKS,
    }


def _stage_uploaded_files(files: list[dict], dest: Path) -> dict[str, bytes]:
    if not files or len(files) > MAX_UPLOAD_FILES:
        raise ValueError(f"Expected 1 to {MAX_UPLOAD_FILES} files")
    total_bytes = 0
    mem_files: dict[str, bytes] = {}
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    for item in files:
        rel = _safe_rel(str(item.get("path", "")))
        if not rel:
            raise ValueError("Invalid relative file path")
        b64 = item.get("content_b64")
        if isinstance(b64, str):
            try:
                raw = base64.b64decode(b64, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError(f"Invalid base64 payload for {rel}") from exc
        else:
            raw = str(item.get("text", "")).encode("utf-8")
        total_bytes += len(raw)
        if total_bytes > MAX_UPLOAD_BYTES:
            raise ValueError("Uploaded dataset exceeds 16 MB limit")
        target = (dest / rel).resolve()
        if not target.is_relative_to(dest.resolve()):
            raise ValueError("Unsafe upload path")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        mem_files[rel] = raw
    return mem_files


def _materialize_mem_files(mem_files: dict[str, bytes], dest: Path) -> None:
    for rel, raw in mem_files.items():
        target = (dest / rel).resolve()
        if target.is_relative_to(dest.resolve()):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)


def _create_zip_bytes(out: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(out.rglob("*")):
            if p.is_file():
                rel = p.relative_to(out).as_posix()
                if rel.startswith(("sanitized/",)) or rel in ("report.json", "records.jsonl"):
                    zf.write(p, arcname=rel)
    return buf.getvalue()


def make_handler(state: ServerState):
    class VeilHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args) -> None:
            return

        def _send(self, code: int, body: bytes, ctype: str, extra_headers: dict[str, str] | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, code: int, payload: dict) -> None:
            self._send(code, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_UPLOAD_BYTES * 2:
                raise ValueError("Invalid JSON request length")
            raw = self.rfile.read(length)
            obj = json.loads(raw.decode("utf-8"))
            if not isinstance(obj, dict):
                raise ValueError("Expected JSON object")
            return obj

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            if path in ("/", "/index.html", "/styles.css", "/app.js"):
                rel = "index.html" if path == "/" else path.lstrip("/")
                target = (WEB_DIR / rel).resolve()
                if not target.is_relative_to(WEB_DIR.resolve()) or not target.is_file():
                    self._send_json(404, {"error": "Static asset not found"})
                    return
                ctype = {
                    ".html": "text/html; charset=utf-8",
                    ".css": "text/css; charset=utf-8",
                    ".js": "application/javascript; charset=utf-8",
                }.get(target.suffix, "application/octet-stream")
                self._send(200, target.read_bytes(), ctype)
                return

            if path == "/api/health":
                self._send_json(200, {"ok": True, "demo_available": DEMO_DIR.is_dir()})
                return

            if path == "/api/state":
                with state.lock:
                    if not state.active:
                        self._send_json(200, {
                            "ready": False,
                            "demo_available": DEMO_DIR.is_dir(),
                            "historical_benchmarks": HISTORICAL_BENCHMARKS,
                        })
                        return
                    payload = {k: v for k, v in state.active.items() if k != "passport_html"}
                    payload["ready"] = True
                    payload["demo_available"] = DEMO_DIR.is_dir()
                    self._send_json(200, payload)
                return

            if path.startswith("/api/status/"):
                job_id = path.split("/api/status/", 1)[1]
                with state.lock:
                    job = state.jobs.get(job_id)
                    if not job:
                        self._send_json(404, {"error": "Job not found"})
                        return
                    self._send_json(200, dict(job))
                return

            if path == "/api/passport/html":
                with state.lock:
                    active = state.active
                    if not active:
                        self._send_json(404, {"error": "No active run"})
                        return
                    corrupted = active.get("corrupted_passport")
                    if urllib.parse.parse_qs(parsed.query).get("variant") == ["corrupt"] and corrupted:
                        html_txt = corrupted["html"]
                        fname = "veil_privacy_passport_DEFECT.html"
                    else:
                        html_txt = active["passport_html"]
                        fname = "veil_privacy_passport.html"
                self._send(
                    200,
                    html_txt.encode("utf-8"),
                    "text/html; charset=utf-8",
                    {"Content-Disposition": f'attachment; filename="{fname}"'},
                )
                return

            if path == "/api/passport/json":
                with state.lock:
                    active = state.active
                    if not active:
                        self._send_json(404, {"error": "No active run"})
                        return
                    data = active["corrupted_passport"]["audit"] if (
                        urllib.parse.parse_qs(parsed.query).get("variant") == ["corrupt"]
                        and active.get("corrupted_passport")
                    ) else active["passport"]
                self._send(
                    200,
                    json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8"),
                    "application/json; charset=utf-8",
                    {"Content-Disposition": 'attachment; filename="veil_privacy_passport.json"'},
                )
                return

            if path == "/api/download/zip":
                with state.lock:
                    out = state.active_out
                    if not out or not out.is_dir():
                        self._send_json(404, {"error": "No sanitized release available"})
                        return
                    zbytes = _create_zip_bytes(out)
                self._send(
                    200,
                    zbytes,
                    "application/zip",
                    {"Content-Disposition": 'attachment; filename="veil_sanitized_release.zip"'},
                )
                return

            self._send_json(404, {"error": "Not found"})

        def do_POST(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            if path == "/api/run":
                try:
                    req = self._read_json()
                except ValueError as exc:
                    self._send_json(400, {"error": str(exc)})
                    return

                mode = str(req.get("mode", "demo"))
                policy_mode = str(req.get("policy", "adaptive"))
                if policy_mode not in ("adaptive", "fixed", "mask"):
                    self._send_json(400, {"error": "Invalid policy mode"})
                    return
                secret = str(req.get("secret") or "veil-command-center-demo-key")[:128]

                job_id = hashlib.sha256(f"{time.time_ns()}-{os.getpid()}".encode()).hexdigest()[:12]
                run_dir = state.workdir / f"job_{job_id}"
                inp_dir = run_dir / "input"
                out_dir = run_dir / "output"
                arena_dir = run_dir / "arena"

                upload_mem: dict[str, bytes] | None = None
                try:
                    if mode == "demo":
                        if not DEMO_DIR.is_dir():
                            raise ValueError("Bundled demo/sample_hospital directory missing")
                        shutil.copytree(DEMO_DIR, inp_dir)
                        label = str(req.get("label") or "Synthetic Multi-Hospital Bundle (demo/sample_hospital)")
                    elif mode == "upload":
                        upload_mem = _stage_uploaded_files(req.get("files", []), inp_dir)
                        label = str(req.get("label") or "Uploaded Synthetic Hospital Dataset")
                    else:
                        raise ValueError("mode must be 'demo' or 'upload'")
                except ValueError as exc:
                    self._send_json(400, {"error": str(exc)})
                    return

                with state.lock:
                    state.jobs[job_id] = {
                        "job_id": job_id,
                        "status": "running",
                        "progress": 5,
                        "stage": "Queued VEIL execution",
                        "error": None,
                    }

                def worker():
                    def progress(pct: int, stage: str):
                        with state.lock:
                            if job_id in state.jobs:
                                state.jobs[job_id]["progress"] = pct
                                state.jobs[job_id]["stage"] = stage

                    try:
                        payload = _build_full_payload(
                            inp_dir, out_dir, arena_dir, secret, policy_mode, label, progress_cb=progress
                        )
                        with state.lock:
                            state.active = payload
                            state.active_inp = inp_dir if mode == "demo" else None
                            state.active_upload_bytes = upload_mem
                            state.active_out = out_dir
                            state.active_secret = secret
                            state.active_policy_mode = policy_mode
                            state.jobs[job_id]["status"] = "completed"
                            state.jobs[job_id]["progress"] = 100
                            state.jobs[job_id]["stage"] = "Complete"
                    except Exception as exc:  # noqa: BLE001
                        with state.lock:
                            state.jobs[job_id]["status"] = "failed"
                            state.jobs[job_id]["error"] = str(exc)
                    finally:
                        if mode == "upload" and inp_dir.exists():
                            shutil.rmtree(inp_dir, ignore_errors=True)
                        if arena_dir.exists():
                            shutil.rmtree(arena_dir, ignore_errors=True)

                if req.get("sync"):
                    worker()
                    with state.lock:
                        self._send_json(200, state.jobs[job_id])
                else:
                    threading.Thread(target=worker, daemon=True).start()
                    self._send_json(202, {"job_id": job_id, "status": "running"})
                return

            if path == "/api/passport/corrupt":
                with state.lock:
                    if (not state.active_inp and not state.active_upload_bytes) or not state.active_out or not state.active:
                        self._send_json(400, {"error": "Run VEIL first before testing defect detection"})
                        return
                    inp = state.active_inp
                    upload_mem = state.active_upload_bytes
                    out = state.active_out
                    bad_dir = out.parent / "output_corrupted"
                    if bad_dir.exists():
                        shutil.rmtree(bad_dir)
                    shutil.copytree(out, bad_dir)
                    txt_cands = sorted((bad_dir / "sanitized").rglob("*.txt"))
                    target = next((p for p in txt_cands if re.search(r"\d+\s*mg", p.read_text(encoding="utf-8", errors="replace"))), None)
                    if target is None and txt_cands:
                        target = txt_cands[0]
                    if target is None:
                        target = bad_dir / "sanitized" / "injected_defect.txt"
                        target.write_text("Tab. Paracetamol 550 mg\nCall 9876501234\n", encoding="utf-8")
                    else:
                        orig_t = target.read_text(encoding="utf-8", errors="replace")
                        mut_t = re.sub(r"(\d+)\s*mg", lambda m: f"{int(m.group(1)) + 50} mg", orig_t, count=1)
                        target.write_text(mut_t + "\nCall 9876501234\n", encoding="utf-8")
                    if inp is not None:
                        R_bad = VP.audit(inp, bad_dir)
                    else:
                        with tempfile.TemporaryDirectory(prefix="veil_ui_ephem_") as td:
                            tp = Path(td)
                            _materialize_mem_files(upload_mem or {}, tp)
                            R_bad = VP.audit(tp, bad_dir)
                    bad_html = VP.render_html(R_bad, None)
                    state.active["corrupted_passport"] = {
                        "target_file": target.relative_to(bad_dir).as_posix(),
                        "mutation": "Altered dosage (+50 mg) and injected unmasked contact number into release artifact.",
                        "audit": R_bad,
                        "html": bad_html,
                    }
                    state.active.setdefault("verification_history", []).insert(0, {
                        "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S UTC"),
                        "event": "Synthetic Fault Injection",
                        "status": "FAIL",
                        "summary": f"{state.active['corrupted_passport']['target_file']}: " + "; ".join(R_bad["residual_risks"]),
                    })
                    self._send_json(200, {
                        "status": "defect_detected",
                        "corrupted_passport": {
                            "target_file": state.active["corrupted_passport"]["target_file"],
                            "mutation": state.active["corrupted_passport"]["mutation"],
                            "audit": R_bad,
                        },
                        "verification_history": state.active["verification_history"],
                    })
                return

            if path == "/api/passport/repair":
                with state.lock:
                    if (not state.active_inp and not state.active_upload_bytes) or not state.active_out or not state.active:
                        self._send_json(400, {"error": "No active run to repair"})
                        return
                    inp = state.active_inp
                    upload_mem = state.active_upload_bytes
                    out = state.active_out
                    secret = state.active_secret
                    policy_mode = state.active_policy_mode
                    if inp is not None:
                        runtime_s, _ = _run_subprocess_engine(inp, out, secret, policy_mode)
                        R_ok = VP.audit(inp, out)
                    else:
                        with tempfile.TemporaryDirectory(prefix="veil_ui_ephem_") as td:
                            tp = Path(td)
                            _materialize_mem_files(upload_mem or {}, tp)
                            runtime_s, _ = _run_subprocess_engine(tp, out, secret, policy_mode)
                            R_ok = VP.audit(tp, out)
                    state.active["passport"] = R_ok
                    state.active["passport_html"] = VP.render_html(R_ok, None)
                    state.active["corrupted_passport"] = None
                    state.active["runtime_s"] = runtime_s
                    state.active.setdefault("verification_history", []).insert(0, {
                        "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S UTC"),
                        "event": "VEIL Clean Re-run & Repair",
                        "status": "PASS" if not R_ok["residual_risks"] else "FAIL",
                        "summary": f"{R_ok['identity']['pseudonym_present_in_exact_record']} exact records · {R_ok['clinical']['occurrence_totals']} clinical · repaired in {runtime_s}s",
                    })
                    self._send_json(200, {
                        "status": "repaired",
                        "passport": R_ok,
                        "runtime_s": runtime_s,
                        "verification_history": state.active["verification_history"],
                    })
                return

            self._send_json(404, {"error": "Not found"})

    return VeilHandler


class ReusableThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def create_server(host: str = "127.0.0.1", port: int = 8765, preload_demo: bool = False, workdir: Path | None = None):
    wd = workdir or Path(tempfile.mkdtemp(prefix="veil_ui_"))
    wd.mkdir(parents=True, exist_ok=True)
    if workdir is None:
        atexit.register(lambda: shutil.rmtree(wd, ignore_errors=True))
    state = ServerState(wd)
    if preload_demo and DEMO_DIR.is_dir():
        run_dir = wd / "job_initial_demo"
        inp = run_dir / "input"
        out = run_dir / "output"
        arena = run_dir / "arena"
        shutil.copytree(DEMO_DIR, inp)
        payload = _build_full_payload(
            inp, out, arena, state.active_secret, "adaptive", "Synthetic Multi-Hospital Bundle (demo/sample_hospital)"
        )
        state.active = payload
        state.active_inp = inp
        state.active_out = out
    srv = ReusableThreadingHTTPServer((host, port), make_handler(state))
    return srv, state


def main() -> int:
    ap = argparse.ArgumentParser(description="VEIL — Clinical Privacy Command Center (offline local UI)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--demo", action="store_true", help="Pre-run VEIL on demo/sample_hospital on startup")
    ap.add_argument("--open", action="store_true", help="Open browser tab automatically")
    args = ap.parse_args()

    srv, _ = create_server(host=args.host, port=args.port, preload_demo=args.demo)
    actual_port = srv.server_address[1]
    url = f"http://{args.host}:{actual_port}/"
    print(f"VEIL Clinical Privacy Command Center running offline at {url}", flush=True)
    if args.open:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down VEIL server.")
    finally:
        srv.shutdown()
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
