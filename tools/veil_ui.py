#!/usr/bin/env python3
"""VEIL — Clinical Privacy Command Center (offline local web UI server).

Zero third-party dependencies (Python 3.9+ stdlib only). Reuses the frozen
rakshak engine, tools/veil_passport.py, and demo/sample_hospital/ without
modifying main.py, core algorithms, policy.yaml, or raksha.toml.

Usage:
    python3 tools/veil_ui.py --demo --open
    python3 tools/veil_ui.py --port 8765 --demo
"""
from __future__ import annotations

import argparse
import atexit
import base64
import binascii
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
MAX_JSON_BODY_BYTES = 26 * 1024 * 1024
MAX_MULTIPART_BODY_BYTES = MAX_UPLOAD_BYTES + 2 * 1024 * 1024
MAX_PREVIEW_BYTES = 64 * 1024
ENGINE_TIMEOUT_S = 180

# Bounded visualization caps (UI display only; exported release is NEVER truncated)
MAX_GRAPH_CLUSTERS = 40
MAX_GRAPH_RECORDS = 120
MAX_GRAPH_EDGES = 80
MAX_DECISIONS_STORED = 400
MAX_BLOCK_FANOUT = 28
MAX_BUCKET_PAIR_SAMPLES = 16
MAX_CANDIDATE_CHECKS = 2400
MAX_FILE_INDEX = 128

TAG_PATTERN = re.compile(
    r"\[(?:NAME|RELATIVE|PHONE|AADHAAR|ABHA|PAN|EMAIL|ID|INSURANCE|PIN|VILLAGE|DISTRICT|DATE|AGE|REDACTED)\]"
)
PSN_PATTERN = re.compile(r"\bPSN-[0-9A-Z]{6,16}\b")
STAFF_PATTERN = re.compile(r"\b(?:Dr\.|Sr\.|Sis\.|N/O|DEO)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}")
EXACT_PIN_PATTERN = re.compile(r"(?<!\d)[1-8]\d{5}(?!\s*/\s*cumm|\d)")
AGE_BAND_PATTERN = re.compile(r"\b\d{1,2}-\d{2,3}\b")

JOB_STATES = ("uploading", "queued", "running", "validating", "ready", "failed", "cancelled")
_POLICY_LOAD_LOCK = threading.Lock()
MAX_RETAINED_JOBS = 48

HISTORICAL_BENCHMARKS = {
    "team": "The Aevos",
    "team_leader": "Ishan Kumar",
    "team_members": ["Ishan Kumar", "Kirtan", "Aryan Verma", "Ukani Het"],
    "checkpoint": "OMEGA (main, verified 60/60 tests / core engine 87ebe5d)",
    "disclaimer": (
        "Measured offline using the local synthetic harness and re-implemented attacker "
        "(NOT official competition evaluation; H20/H21/H2/s9_C are reclassified diagnostic datasets)."
    ),
    "runs": [
        {"dataset": "dev", "type": "Official Practice", "score": "92.4935 (0.72s / 32.3 MB)", "leak_pct": "0.0% (check_dev 0/3230)", "false_merges": 0, "canaries": "0/4"},
        {"dataset": "chaos_dev", "type": "Dev Synthetic", "score": "93.01 (local w/ perf)", "leak_pct": "0.0% (truth)", "false_merges": 0, "canaries": "0/3"},
        {"dataset": "chaos_holdout2", "type": "Diag (FM 11 -> 0)", "score": "95.20 (local w/ perf)", "leak_pct": "0.1% (truth)", "false_merges": 0, "canaries": "0/4"},
        {"dataset": "chaos_holdout18", "type": "Diag Assam/Odisha", "score": "87.22 (local w/ perf)", "leak_pct": "0.0% (truth)", "false_merges": 0, "canaries": "0/4"},
        {"dataset": "chaos_holdout19", "type": "Diag Karnataka+JSONL", "score": "93.57 (OMEGA 87ebe5d)", "leak_pct": "0.0% (truth)", "false_merges": 0, "canaries": "0/4"},
        {"dataset": "chaos_holdout20", "type": "Diag Haryana/EAV", "score": "86.07 (local w/ perf)", "leak_pct": "0.1% (truth)", "false_merges": 0, "canaries": "0/4"},
        {"dataset": "chaos_holdout21", "type": "Diag Kerala/Malayalam", "score": "89.71 (OMEGA 87ebe5d)", "leak_pct": "F0.5 0.9990", "false_merges": 0, "canaries": "0/4"},
        {"dataset": "4_blind_suites_omega", "type": "Untouched OMEGA Blind (9961..9964)", "score": "89.19 mean (92.73 max)", "leak_pct": "F0.5 0.997-0.998", "false_merges": "0 / 0 / 0 / 0", "canaries": "0/16"},
    ],
    "scalability": [
        {"workload": "100k repeat (500p)", "records": "100,000", "wall_s": 3.614, "peak_rss_mb": 209.6, "throughput": "27,670 rows/s"},
        {"workload": "100k unique (100kp)", "records": "100,000", "wall_s": 5.54, "peak_rss_mb": 374.8, "throughput": "18,051 rows/s"},
        {"workload": "250k mixed (1,252 files)", "records": "188,750", "wall_s": 18.162, "peak_rss_mb": 337.7, "throughput": "10,393 rows/s"},
        {"workload": "500k repeat (50kp)", "records": "500,000", "wall_s": 22.207, "peak_rss_mb": 862.9, "throughput": "22,515 rows/s"},
        {"workload": "1M repeat (100kp)", "records": "1,000,000", "wall_s": 41.747, "peak_rss_mb": 1818.6, "throughput": "23,954 rows/s"},
        {"workload": "1M unique (1M pts)", "records": "1,000,000", "wall_s": 56.441, "peak_rss_mb": 2481.1, "throughput": "17,718 rows/s"},
        {"workload": "1.25M mixed (6,252 files)", "records": "943,750 physical / 1.25M lines", "wall_s": 90.366, "peak_rss_mb": 1623.8, "throughput": "10,444 rows/s"},
    ],
    "scale": {"records": "1,000,000 x 1,000,000", "seconds": 56.441, "peak_rss_mb": 2481.1},
    "checks": {"unit_tests": "60/60 OK", "official_checker": "READY TO SUBMIT (CONTRACT OK)"},
}


class UiApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class ServerState:
    def __init__(self, workdir: Path):
        self.workdir = workdir
        self.lock = threading.Lock()
        self.jobs: dict[str, dict] = {}
        self.job_procs: dict[str, subprocess.Popen] = {}
        self.job_seq: int = 0
        self.latest_job_id: str | None = None
        self.active: dict | None = None
        self.active_job_id: str | None = None
        self.active_inp: Path | None = None
        self.active_upload_bytes: dict[str, bytes] | None = None
        self.active_out: Path | None = None
        self.active_run_dir: Path | None = None
        self.active_secret: str = "veil-command-center-demo-key"
        self.active_secret_hash: str = hashlib.sha256(b"veil-command-center-demo-key").hexdigest()
        self.active_input_digest: str = ""
        self.active_policy_mode: str = "adaptive"
        # Cache keyed by (input_digest, secret_hash, policy_mode) -> arena policy row dict
        self.arena_cache: dict[tuple[str, str, str], dict] = {}
        self.arena_cache_order: list[tuple[str, str, str]] = []
        self.busy_run_dirs: Counter = Counter()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _input_digest_from_dir(inp: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(inp.rglob("*"), key=lambda x: x.relative_to(inp).as_posix()):
        if p.is_file() and not p.is_symlink():
            rel = p.relative_to(inp).as_posix()
            h.update(rel.encode("utf-8", errors="replace") + b"\0")
            h.update(hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


def _safe_rel(raw_path: str) -> str | None:
    norm = raw_path.replace("\\", "/").lstrip("/")
    if not norm or "\x00" in norm:
        return None
    cleaned = posixpath.normpath(norm)
    if not cleaned or cleaned in (".", "..") or cleaned.startswith("../") or cleaned.startswith("/"):
        return None
    parts = [p for p in cleaned.split("/") if p]
    if not parts or any(p in (".", "..") or p.startswith(".veil_") for p in parts):
        return None
    return "/".join(parts)


def _dedupe_rel(rel: str, used_lower: set[str]) -> tuple[str, bool]:
    """Deterministically rename duplicate relative paths so earlier files are never overwritten."""
    if rel.lower() not in used_lower:
        used_lower.add(rel.lower())
        return rel, False
    parent, base = posixpath.split(rel)
    stem, ext = posixpath.splitext(base)
    n = 2
    while True:
        cand_base = f"{stem} ({n}){ext}"
        cand = f"{parent}/{cand_base}" if parent else cand_base
        if cand.lower() not in used_lower:
            used_lower.add(cand.lower())
            return cand, True
        n += 1


def _format_of(rel: str, sample_raw: bytes) -> str:
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
        sample = VP.decode(sample_raw[:1024])
        if sample.startswith("MSH|"):
            return "HL7 v2"
        if "-----BEGIN STRUCTURED-----" in sample:
            return "Hybrid Note"
        return "Clinical Note"
    return "Binary / Unsupported"


def _run_subprocess_engine(
    inp: Path,
    out: Path,
    secret: str,
    policy_mode: str,
    proc_cb=None,
    cancel_check=None,
) -> tuple[float, str]:
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
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc_cb:
        proc_cb(proc)
    try:
        while proc.poll() is None:
            if cancel_check and cancel_check():
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                raise UiApiError(409, "cancelled", "Execution cancelled by user")
            if time.monotonic() - t0 > ENGINE_TIMEOUT_S:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                raise UiApiError(504, "engine_timeout", f"Engine timed out after {ENGINE_TIMEOUT_S}s")
            time.sleep(0.05)
        stdout, stderr = proc.communicate(timeout=5)
        if proc.returncode != 0:
            raise UiApiError(500, "engine_failed", f"Sanitization engine exited with code {proc.returncode}")
    finally:
        if proc_cb:
            proc_cb(None)
    # Never echo paths or sensitive text in logs
    summary_line = ""
    for ln in (stdout or "").splitlines():
        if ln.startswith("files "):
            summary_line = ln.strip()
            break
    return round(time.monotonic() - t0, 3), summary_line


def _validate_release_contract(inp: Path, out: Path) -> dict:
    """Fast mandatory structural validation of sanitized/, report.json, and records.jsonl."""
    rep_path = out / "report.json"
    rj_path = out / "records.jsonl"
    san_dir = out / "sanitized"
    if not rep_path.is_file():
        raise UiApiError(500, "validation_failed", "Mandatory report.json missing after execution")
    try:
        rep = json.loads(rep_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UiApiError(500, "validation_failed", "report.json is unreadable or malformed") from exc

    if rep.get("schema") != "raksha-report/1":
        raise UiApiError(500, "validation_failed", "Unexpected report.json schema")
    counts = rep.get("counts", {})
    files_list = rep.get("files", [])

    in_files = [p for p in inp.rglob("*") if p.is_file() and not p.is_symlink()]
    if len(files_list) != len(in_files) or counts.get("files_total") != len(in_files):
        raise UiApiError(500, "validation_failed", "File accounting mismatch between input and report.json")

    declared_outs = set()
    san_root = san_dir.resolve() if san_dir.exists() else None
    for entry in files_list:
        if entry.get("status") == "sanitized":
            rel_out = entry.get("output") or ""
            if not rel_out.startswith("sanitized/"):
                raise UiApiError(500, "validation_failed", "Invalid sanitized output declaration")
            out_file = (out / rel_out).resolve()
            if san_root is None or not out_file.is_relative_to(san_root) or not out_file.is_file():
                raise UiApiError(500, "validation_failed", "Declared sanitized output file missing")
            declared_outs.add(rel_out)
    if counts.get("files_sanitized", 0) > 0 and not san_dir.is_dir():
        raise UiApiError(500, "validation_failed", "Mandatory sanitized/ directory missing")

    actual_outs = (
        {"sanitized/" + p.relative_to(san_dir).as_posix() for p in san_dir.rglob("*") if p.is_file()}
        if san_dir.is_dir()
        else set()
    )
    if declared_outs != actual_outs:
        raise UiApiError(500, "validation_failed", "Undeclared or missing files in sanitized/")

    if not rj_path.is_file():
        raise UiApiError(500, "validation_failed", "Mandatory records.jsonl missing")
    rec_count = 0
    try:
        with rj_path.open("r", encoding="utf-8") as rf:
            for idx, ln in enumerate(rf):
                if not ln.strip():
                    continue
                rec_count += 1
                # Validate first 64, last-ish stride, and every 500th record to verify format in O(1) JSON parses
                if idx < 64 or (idx & 511) == 0:
                    obj = json.loads(ln)
                    if not isinstance(obj, dict) or "file" not in obj or "loc" not in obj or "patient" not in obj:
                        raise ValueError("Invalid record schema")
                    pat = obj.get("patient")
                    if pat is not None and not PSN_PATTERN.fullmatch(str(pat)):
                        raise ValueError("Invalid pseudonym format")
    except (OSError, ValueError) as exc:
        raise UiApiError(500, "validation_failed", "records.jsonl validation failed") from exc

    if rec_count != counts.get("records_processed"):
        raise UiApiError(500, "validation_failed", "records.jsonl row count differs from report.json")
    return rep


def _detect_scripts_from_sample(text: str) -> list[str]:
    sc = []
    if any("A" <= ch <= "Z" or "a" <= ch <= "z" for ch in text):
        sc.append("Latin")
    if any("\u0900" <= ch <= "\u097F" for ch in text):
        sc.append("Devanagari")
    if any("\u0D00" <= ch <= "\u0D7F" for ch in text):
        sc.append("Malayalam")
    if any("\u0B80" <= ch <= "\u0BFF" for ch in text):
        sc.append("Tamil")
    return sc or ["Latin"]


def _analyze_identity_and_qi(inp: Path, out: Path, policy_mode: str) -> tuple[dict, list[dict], dict]:
    """Build bounded PII-safe patient identity graph, bounded non-quadratic decisions, and exact QI stats."""
    pol_path = ROOT / "config" / "policy.yaml"
    with _POLICY_LOAD_LOCK:
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
        job = PL.FileJob(rel, path.read_bytes(), path)
        PL.pass1(job, H)
        jobs.append(job)

    fmt_by_rel = {j.rel: _format_of(j.rel, j.raw[:1024]) for j in jobs}
    date_orders = {j.rel: j.order for j in jobs}
    raw_scripts_by_file: dict[str, list[str]] = {}
    for j in jobs:
        if j.status == "sanitized":
            sample_t = j.text[:8192] if j.text else VP.decode(j.raw[:8192])
            raw_scripts_by_file[j.rel] = _detect_scripts_from_sample(sample_t)

    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    by_sha_q: dict[str, list[str | None]] = defaultdict(list)
    for e in rep.get("files", []):
        by_sha_q[e["input_sha256"]].append(e.get("output"))
    out_rel_by_in = {j.rel: (by_sha_q[j.sha].pop(0) if by_sha_q.get(j.sha) else None) for j in jobs}

    rec_psn_map: dict[tuple[str, str], str | None] = {}
    with (out / "records.jsonl").open("r", encoding="utf-8") as rf:
        for line in rf:
            if not line.strip():
                continue
            row = json.loads(line)
            rec_psn_map[(row["file"], row["loc"])] = row.get("patient")

    recs = [r for j in jobs for r in j.recs if not r.loc.startswith("@")]
    groups_by_psn: dict[str, list] = defaultdict(list)
    cluster_objs: dict[str, LNK.Cluster] = {}
    unlinked_info: list[dict] = []
    rec_meta_by_psn: dict[str, list[dict]] = defaultdict(list)

    for idx, r in enumerate(recs):
        if r.dob:
            d = PL.parse_date(r.dob, date_orders[r.file])
            r.dob = d.isoformat() if d else None
        out_f = out_rel_by_in.get(r.file)
        psn = rec_psn_map.get((out_f, r.loc)) if out_f else None
        if not psn and out_f:
            psn = rec_psn_map.get((out_f, "doc"))
        r.pid = psn
        signals = []
        if any(i.startswith(("M:", "U:")) for i in r.ids):
            signals.append("UHID/MRN")
        if any(i.startswith("A:") for i in r.ids):
            signals.append("Aadhaar")
        if any(i.startswith(("B:", "N:")) for i in r.ids):
            signals.append("ABHA/PAN")
        if r.phones:
            signals.append("Mobile")
        if r.names:
            signals.append("Name")
        if r.dob:
            signals.append("DOB")
        if r.rel:
            signals.append("Relative")
        if r.conds:
            signals.append("Clinical/ICD")

        rec_summary = {
            "idx": idx,
            "node_id": f"rec_{idx}",
            "psn": psn,
            "file": r.file,
            "sanitized_file": out_f,
            "loc": r.loc,
            "format": fmt_by_rel.get(r.file, "Text"),
            "scripts": raw_scripts_by_file.get(r.file, ["Latin"]),
            "signals": signals,
            "rec": r,
        }
        if psn:
            r.key = psn
            groups_by_psn[psn].append(r)
            rec_meta_by_psn[psn].append(rec_summary)
            cl = LNK.Cluster(idx, r)
            if psn not in cluster_objs:
                cluster_objs[psn] = cl
            else:
                cluster_objs[psn].absorb(cl)
        elif len(unlinked_info) < 200:
            unlinked_info.append(rec_summary)

    plan = PRV.plan(groups_by_psn, policy)
    qi_stats = _compute_qi_metrics(groups_by_psn, plan)

    # Sort clusters deterministically prioritizing multi-record/multi-file clusters first for visualization
    sorted_psns = sorted(groups_by_psn.keys())
    display_psns = sorted(
        sorted_psns,
        key=lambda p: (-len({m.file for m in groups_by_psn[p]}), -len(groups_by_psn[p]), p),
    )[:MAX_GRAPH_CLUSTERS]
    display_psn_set = set(display_psns)

    nodes_clusters = []
    for psn in sorted(display_psns):
        members = groups_by_psn[psn]
        rule = plan.rule(psn)
        ages = [m.age for m in members if m.age is not None]
        bf = plan.band_fn(psn)
        age_band = bf(max(ages)) if ages else "N/A"
        files = sorted({m.file for m in members})[:8]
        scripts = sorted({s for f in files for s in raw_scripts_by_file.get(f, ["Latin"])})
        cond_tags = sorted({c for m in members for c in (m.conds or ())})
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

    nodes_records = []
    displayed_anchor_by_psn: dict[str, dict] = {}
    for psn in sorted(display_psns):
        for rm in rec_meta_by_psn[psn]:
            if len(nodes_records) >= MAX_GRAPH_RECORDS:
                break
            nodes_records.append({
                "id": rm["node_id"],
                "psn": rm["psn"],
                "file": rm["file"],
                "sanitized_file": rm["sanitized_file"],
                "loc": rm["loc"],
                "format": rm["format"],
                "scripts": rm["scripts"],
                "signals": rm["signals"],
            })
            if psn not in displayed_anchor_by_psn:
                displayed_anchor_by_psn[psn] = rm
        if len(nodes_records) >= MAX_GRAPH_RECORDS:
            break
    for rm in unlinked_info[: max(0, min(12, MAX_GRAPH_RECORDS - len(nodes_records)))]:
        nodes_records.append({
            "id": rm["node_id"],
            "psn": None,
            "file": rm["file"],
            "sanitized_file": rm["sanitized_file"],
            "loc": rm["loc"],
            "format": rm["format"],
            "scripts": rm["scripts"],
            "signals": rm["signals"],
        })
    displayed_rec_ids = {n["id"] for n in nodes_records}

    decisions: list[dict] = []
    edges_out: list[dict] = []
    matched_count_total = 0

    # 1. Exact O(N) within-cluster match counting + bounded edge/decision collection
    for psn in sorted_psns:
        items = rec_meta_by_psn[psn]
        if len(items) < 2:
            continue
        matched_count_total += len(items) - 1
        anchor = items[0]
        ra = anchor["rec"]
        cla = LNK.Cluster(anchor["idx"], ra)
        for other in items[1:]:
            if other["file"] == anchor["file"] and other["loc"] == anchor["loc"]:
                continue
            ro = other["rec"]
            shared_ids = set(ra.ids) & set(ro.ids)
            shared_phones = set(ra.phones) & set(ro.phones)
            clo = LNK.Cluster(other["idx"], ro)
            shared_names = bool(LNK._name_compatible(cla, clo) and cla.names and clo.names)
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
            if cla.dobs and clo.dobs and (cla.dobs & clo.dobs):
                evidence.append("DOB agreement")
            if not evidence:
                evidence.append("Transitive cluster support (multiple channels)")

            if (
                psn in display_psn_set
                and anchor["node_id"] in displayed_rec_ids
                and other["node_id"] in displayed_rec_ids
                and len(edges_out) < MAX_GRAPH_EDGES - 30
            ):
                edges_out.append({
                    "source": anchor["node_id"],
                    "target": other["node_id"],
                    "psn": psn,
                    "decision": "matched",
                    "summary": f"{anchor['file']} ({anchor['loc']}) -> {other['file']} ({other['loc']})",
                    "evidence": evidence,
                    "veto": None,
                })
            if anchor["file"] != other["file"] and len(decisions) < MAX_DECISIONS_STORED // 2:
                decisions.append({
                    "pair_id": f"{psn}:{len(decisions)}",
                    "left": f"{psn} · {anchor['file']} ({anchor['loc']})",
                    "right": f"{psn} · {other['file']} ({other['loc']})",
                    "decision": "matched",
                    "rule": " · ".join(evidence),
                    "scripts": sorted(set(anchor["scripts"]) | set(other["scripts"])),
                })

    # 2. Inverted-index candidate generation (NEVER all-pairs O(N^2)) for rejected/ambiguous pairs
    block_buckets: dict[str, list[str]] = defaultdict(list)
    for psn in sorted_psns:
        cl = cluster_objs[psn]
        for nk in cl.names:
            for t in nk:
                if len(t) >= 2:
                    block_buckets[f"nt:{t}"].append(psn)
            if nk:
                block_buckets[f"sn:{nk[-1]}"].append(psn)
        for v in cl.villages:
            if v:
                block_buckets[f"vl:{v}"].append(psn)
        for ident in cl.ids:
            block_buckets[f"id:{ident}"].append(psn)

    candidate_pairs: list[tuple[str, str]] = []
    seen_cands: set[tuple[str, str]] = set()
    capped_buckets = 0
    for bkey in sorted(block_buckets.keys()):
        bkt = sorted(set(block_buckets[bkey]))
        if len(bkt) < 2:
            continue
        if len(bkt) > MAX_BLOCK_FANOUT:
            capped_buckets += 1
            step = max(1, len(bkt) // MAX_BUCKET_PAIR_SAMPLES)
            sampled = bkt[::step][:MAX_BUCKET_PAIR_SAMPLES]
        else:
            sampled = bkt
        for i, pa in enumerate(sampled):
            for pb in sampled[i + 1:]:
                pair = (pa, pb) if pa < pb else (pb, pa)
                if pair not in seen_cands:
                    seen_cands.add(pair)
                    candidate_pairs.append(pair)
                    if len(candidate_pairs) >= MAX_CANDIDATE_CHECKS:
                        break
            if len(candidate_pairs) >= MAX_CANDIDATE_CHECKS:
                break
        if len(candidate_pairs) >= MAX_CANDIDATE_CHECKS:
            break

    rejected_count = 0
    ambiguous_pair_count = 0
    for pa, pb in candidate_pairs:
        ca, cb = cluster_objs[pa], cluster_objs[pb]
        toks_a = {t for nk in ca.names for t in nk if len(t) >= 2}
        toks_b = {t for nk in cb.names for t in nk if len(t) >= 2}
        shared_name_toks = bool(toks_a & toks_b)
        shared_surname = any(nk_a and nk_b and nk_a[-1] == nk_b[-1] for nk_a in ca.names for nk_b in cb.names)
        shared_vill = LNK._has_overlap(ca.villages, cb.villages)
        shared_id_raw = LNK._has_overlap(ca.ids, cb.ids)
        is_comp = LNK.compatible(ca, cb)

        if not (shared_name_toks or shared_surname or shared_vill or shared_id_raw):
            continue

        veto_reasons = []
        if len(ca.genders | cb.genders) > 1:
            veto_reasons.append("Gender mismatch")
        if ca.dobs and cb.dobs and not LNK._has_overlap(ca.dobs, cb.dobs):
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
            rejected_count += 1
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
            ambiguous_pair_count += 1
            rule_txt = "Shared locality/name token only — held separate pending secondary corroboration"

        rep_a_obj = displayed_anchor_by_psn.get(pa)
        rep_b_obj = displayed_anchor_by_psn.get(pb)
        if (
            rep_a_obj
            and rep_b_obj
            and rep_a_obj["node_id"] in displayed_rec_ids
            and rep_b_obj["node_id"] in displayed_rec_ids
            and len(edges_out) < MAX_GRAPH_EDGES
        ):
            edges_out.append({
                "source": rep_a_obj["node_id"],
                "target": rep_b_obj["node_id"],
                "psn": f"{pa} != {pb}",
                "decision": decision_kind,
                "summary": f"{pa} vs {pb}",
                "evidence": [],
                "veto": rule_txt,
            })

        if len(decisions) < MAX_DECISIONS_STORED:
            ra0 = rec_meta_by_psn[pa][0]
            rb0 = rec_meta_by_psn[pb][0]
            decisions.append({
                "pair_id": f"pair:{pa}:{pb}",
                "left": f"{pa} ({ra0['file']})",
                "right": f"{pb} ({rb0['file']})",
                "decision": decision_kind,
                "rule": rule_txt,
                "scripts": sorted(set(ra0["scripts"]) | set(rb0["scripts"])),
            })

    total_unlinked = len(recs) - sum(len(v) for v in groups_by_psn.values())
    for r in unlinked_info:
        if len(decisions) >= MAX_DECISIONS_STORED:
            break
        decisions.append({
            "pair_id": f"ref:{r['node_id']}",
            "left": f"{r['file']} ({r['loc']})",
            "right": "Clinical Reference Pool",
            "decision": "ambiguous",
            "rule": "No patient entity present — preserved unlinked as non-patient clinical protocol",
            "scripts": r["scripts"],
        })

    # Prioritize rejected decisions at top of bounded list for immediate inspection visibility
    order_rank = {"rejected": 0, "matched": 1, "ambiguous": 2}
    decisions.sort(key=lambda d: order_rank.get(d["decision"], 9))

    graph = {
        "clusters": nodes_clusters,
        "records": nodes_records,
        "edges": edges_out,
        "meta": {
            "displayed_clusters": len(nodes_clusters),
            "total_clusters": len(sorted_psns),
            "displayed_records": len(nodes_records),
            "total_records": len(recs),
            "displayed_edges": len(edges_out),
            "total_matched_edges": matched_count_total,
            "candidate_pairs_evaluated": len(candidate_pairs),
            "buckets_capped": capped_buckets,
            "truncated": len(nodes_clusters) < len(sorted_psns) or len(nodes_records) < len(recs),
        },
        "decision_counts": {
            "matched": matched_count_total,
            "matched_sampled": sum(1 for d in decisions if d["decision"] == "matched"),
            "rejected": rejected_count,
            "ambiguous": ambiguous_pair_count + total_unlinked,
            "displayed": len(decisions),
            "candidates_checked": len(candidate_pairs),
            "truncated": (
                len(candidate_pairs) >= MAX_CANDIDATE_CHECKS
                or len(decisions) >= MAX_DECISIONS_STORED
                or capped_buckets > 0
                or matched_count_total > sum(1 for d in decisions if d["decision"] == "matched")
            ),
        },
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


def _extract_fast_summary(inp: Path, out: Path, rep: dict | None = None) -> tuple[list[dict], dict, list[dict]]:
    """Extract lightweight file index + transformation tag totals + bounded clinical summary without loading full multi-MB diffs."""
    if rep is None:
        rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    by_sha_q: dict[str, list[dict]] = defaultdict(list)
    for e in rep.get("files", []):
        by_sha_q[e["input_sha256"]].append(e)
    file_index = []
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

    for idx_f, p in enumerate(sorted(inp.rglob("*"), key=lambda x: x.relative_to(inp).as_posix())):
        if not p.is_file() or p.is_symlink():
            continue
        rel = p.relative_to(inp).as_posix()
        fsize = p.stat().st_size
        # Stream SHA-256 to avoid doubling buffer allocation on 16MB uploads
        h = hashlib.sha256()
        sample_in_bytes = b""
        with p.open("rb") as pf:
            first = pf.read(MAX_PREVIEW_BYTES)
            sample_in_bytes = first
            h.update(first)
            while True:
                blk = pf.read(1024 * 1024)
                if not blk:
                    break
                h.update(blk)
        sha = h.hexdigest()
        entry = by_sha_q[sha].pop(0) if by_sha_q.get(sha) else {}
        status = entry.get("status", "unknown")
        out_rel = entry.get("output")
        reason = entry.get("reason")
        fmt = _format_of(rel, sample_in_bytes[:1024])

        if status == "quarantined":
            if len(file_index) < MAX_FILE_INDEX:
                file_index.append({
                    "idx": len(file_index),
                    "input_rel": rel,
                    "output_rel": None,
                    "status": "quarantined",
                    "reason": reason or "unsupported_format",
                    "format": fmt,
                    "sha256_short": sha[:12],
                    "bytes_in": fsize,
                    "bytes_out": 0,
                    "tag_counts": {},
                    "psns": [],
                    "staff_preserved": [],
                })
            continue

        out_path = (out / out_rel) if out_rel else None
        out_size = out_path.stat().st_size if (out_path and out_path.is_file()) else 0
        # Stream up to 1MB cleanly without allocating full multi-MB files in RAM
        if out_path and out_path.is_file():
            with out_path.open("rb") as out_fh:
                scan_bytes = out_fh.read(1024 * 1024)
        else:
            scan_bytes = b""
        out_txt = scan_bytes.decode("utf-8", errors="replace")
        in_txt = VP.decode(sample_in_bytes)

        tags = Counter(TAG_PATTERN.findall(out_txt))
        psns = Counter(PSN_PATTERN.findall(out_txt))
        staff = sorted(set(STAFF_PATTERN.findall(out_txt)))[:15]
        agg_tags.update(tags)
        agg_psns.update(psns)
        staff_kept.update(staff)

        if p.suffix.lower() == ".txt" and len(timeline_checks) < 20:
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

        if len(clinical_samples) < 18:
            out_norm = VP.norm(out_txt)
            for cat, rx in clinical_extractors:
                for m in rx.finditer(in_txt):
                    val = " ".join(m.group(0).split()).strip(".,;")
                    if not val or val in seen_clinical:
                        continue
                    seen_clinical.add(val)
                    clinical_samples.append({
                        "category": cat,
                        "file": rel,
                        "value": val,
                        "preserved": VP.norm(val) in out_norm,
                    })
                    if len(clinical_samples) >= 18:
                        break
                if len(clinical_samples) >= 18:
                    break

        if len(file_index) < MAX_FILE_INDEX:
            file_index.append({
                "idx": len(file_index),
                "input_rel": rel,
                "output_rel": out_rel,
                "status": status,
                "reason": reason,
                "format": fmt,
                "sha256_short": sha[:12],
                "bytes_in": fsize,
                "bytes_out": out_size,
                "tag_counts": dict(tags),
                "psns": sorted(psns.keys())[:25],
                "staff_preserved": staff,
            })

    transformations = [{"token": k, "count": v} for k, v in agg_tags.most_common()]
    clinical_summary = {
        "timeline_intervals": timeline_checks,
        "staff_preserved": sorted(staff_kept)[:30],
        "samples": clinical_samples,
        "psn_tokens_total": sum(agg_psns.values()),
    }
    return file_index, clinical_summary, transformations


def _measure_policy_arena_row(inp: Path, out_dir: Path, mode: str, label: str, summary: str, runtime_s: float) -> dict:
    passport = VP.audit(inp, out_dir)
    _, _, qi_stats = _analyze_identity_and_qi(inp, out_dir, mode)
    exact_pins_left = 0
    age_bands_used = 0
    for p in (out_dir / "sanitized").rglob("*"):
        if p.is_file():
            txt = p.read_text(encoding="utf-8", errors="replace")[:512 * 1024]
            exact_pins_left += len(EXACT_PIN_PATTERN.findall(txt))
            age_bands_used += len(AGE_BAND_PATTERN.findall(txt))
    rep = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    return {
        "mode": mode,
        "label": label,
        "summary": summary,
        "runtime_s": runtime_s,
        "records_linked": rep["counts"]["records_linked"],
        "identifiers_detected": rep["counts"]["identifiers_detected"],
        "clinical_kept_pct": passport["clinical"]["protected_values_kept_pct"],
        "intervals_preserved": passport["clinical"]["notes_with_intervals_preserved"],
        "residual_hits": sum(passport["privacy"]["residual_pattern_hits"].values()),
        "exact_pins_visible": exact_pins_left,
        "age_bands_applied": age_bands_used,
        "qi": qi_stats,
        "reused_from_active_run": False,
    }


def _run_privacy_arena_cached(state: ServerState, inp: Path, active_out: Path, arena_root: Path, secret: str, active_mode: str, active_runtime_s: float, input_digest: str, secret_hash: str) -> tuple[list[dict], float]:
    """Run Privacy Arena on demand, reusing already-completed matching policy/input/secret runs."""
    t0 = time.monotonic()
    specs = [
        ("mask", "Direct Masking Only", "Masks direct IDs but keeps exact ages, 6-digit PINs, and locations."),
        ("fixed", "Fixed QI Policy", "Uniform 5-year age bands and shifted dates across all patients identically."),
        ("adaptive", "VEIL Adaptive (Default)", "Pools patient profiles cross-hospital; escalates singletons, rare ICDs & seniors >=80y."),
    ]
    rows = []
    if arena_root.exists():
        shutil.rmtree(arena_root, ignore_errors=True)
    arena_root.mkdir(parents=True, exist_ok=True)
    try:
        for mode, label, summary in specs:
            ckey = (input_digest, secret_hash, mode)
            with state.lock:
                cached = state.arena_cache.get(ckey)
            if cached is not None:
                row = dict(cached)
                row["reused_from_active_run"] = True
                rows.append(row)
                continue

            if mode == active_mode and active_out.is_dir() and (active_out / "report.json").is_file():
                row = _measure_policy_arena_row(inp, active_out, mode, label, summary, active_runtime_s)
                row["reused_from_active_run"] = True
            else:
                out_dir = arena_root / f"arena_{mode}"
                dt_s, _ = _run_subprocess_engine(inp, out_dir, secret, mode)
                row = _measure_policy_arena_row(inp, out_dir, mode, label, summary, dt_s)

            with state.lock:
                if ckey not in state.arena_cache:
                    state.arena_cache[ckey] = dict(row)
                    state.arena_cache_order.append(ckey)
                    while len(state.arena_cache_order) > 9:
                        old_k = state.arena_cache_order.pop(0)
                        state.arena_cache.pop(old_k, None)
            rows.append(row)
    finally:
        if arena_root.exists():
            shutil.rmtree(arena_root, ignore_errors=True)
    return rows, round(time.monotonic() - t0, 3)


def _pending_passport_stub(rep: dict) -> dict:
    c = rep.get("counts", {})
    return {
        "status": "pending",
        "residual_risks": [],
        "structural": {
            "input_files": c.get("files_total", 0),
            "exported": c.get("files_sanitized", 0),
            "quarantined": c.get("files_quarantined", 0),
            "outputs_parse_ok": c.get("files_sanitized", 0),
            "outputs_parse_fail": 0,
            "tables_row_count_preserved": "Verified via engine report",
        },
        "privacy": {"channels_scanned": 0, "residual_pattern_hits": {}, "files_with_residue": 0},
        "clinical": {"protected_values_kept_pct": None, "protected_values": {}, "notes_with_intervals_preserved": "Pending audit"},
        "temporal": {},
        "identity": {
            "records": c.get("records_processed", 0),
            "records_linked": c.get("records_linked", 0),
            "distinct_pseudonyms": "--",
            "pseudonym_present_in_exported_file": f"{c.get('records_linked', 0)}/{c.get('records_processed', 0)} (pending audit)",
        },
        "checks": {
            "structural": {"status": "PASS", "coverage": f"{c.get('files_total', 0)}/{c.get('files_total', 0)}", "detail": "Mandatory report.json & records.jsonl contract validated"},
            "privacy": {"status": "PENDING", "coverage": "Pending", "detail": "On-demand Passport residue audit not yet run"},
            "clinical": {"status": "PENDING", "coverage": "Pending", "detail": "Click 'Run Privacy Passport' to verify clinical occurrences"},
            "temporal": {"status": "PENDING", "coverage": "Pending", "detail": "On-demand temporal check pending"},
            "identity": {"status": "PENDING", "coverage": "Pending", "detail": "On-demand record-level placement audit pending"},
        },
    }


def _build_primary_payload(
    inp: Path,
    out: Path,
    secret: str,
    policy_mode: str,
    mode_label: str,
    upload_s: float = 0.0,
    run_optional: bool = False,
    progress_cb=None,
    proc_cb=None,
    cancel_check=None,
) -> dict:
    """Execute the frozen engine ONCE, validate mandatory contract, and extract lightweight summary."""
    t_total0 = time.monotonic()

    def emit(state_str: str, pct: int, stage: str):
        if progress_cb:
            progress_cb(state_str, pct, stage)

    emit("running", 25, "Running VEIL engine (1x execution)")
    runtime_s, engine_stdout = _run_subprocess_engine(
        inp, out, secret, policy_mode, proc_cb=proc_cb, cancel_check=cancel_check
    )

    emit("validating", 75, "Validating mandatory output structure")
    if cancel_check and cancel_check():
        raise UiApiError(409, "cancelled", "Job cancelled before completion")
    t_val0 = time.monotonic()
    rep = _validate_release_contract(inp, out)
    validate_s = round(time.monotonic() - t_val0, 3)

    emit("validating", 88, "Preparing release summary & download index")
    if cancel_check and cancel_check():
        raise UiApiError(409, "cancelled", "Job cancelled before completion")
    file_index, clinical_detail, transformations = _extract_fast_summary(inp, out, rep)

    passport = None
    passport_html = None
    passport_s = None
    passport_status = "pending"
    graph = {"clusters": [], "records": [], "edges": [], "meta": {"displayed_clusters": 0, "total_clusters": 0, "displayed_records": 0, "total_records": rep["counts"]["records_processed"], "displayed_edges": 0, "total_matched_edges": 0, "truncated": False}, "decision_counts": {"matched": 0, "rejected": 0, "ambiguous": 0, "displayed": 0, "truncated": False}}
    decisions: list[dict] = []
    qi_stats: dict = {"patients": "--"}
    identity_status = "pending"
    identity_s = None

    if run_optional:
        if cancel_check and cancel_check():
            raise UiApiError(409, "cancelled", "Job cancelled before completion")
        emit("validating", 93, "Auditing small demo Privacy Passport & identity")
        t_p0 = time.monotonic()
        passport = VP.audit(inp, out)
        passport_html = VP.render_html(passport, None)
        passport_s = round(time.monotonic() - t_p0, 3)
        passport_status = "verified"
        if cancel_check and cancel_check():
            raise UiApiError(409, "cancelled", "Job cancelled before completion")
        t_i0 = time.monotonic()
        graph, decisions, qi_stats = _analyze_identity_and_qi(inp, out, policy_mode)
        identity_s = round(time.monotonic() - t_i0, 3)
        identity_status = "ready"

    total_ui_s = round(upload_s + (time.monotonic() - t_total0), 3)
    ver_hist = []
    if passport_status == "verified" and passport is not None:
        v_state = passport.get("verdict") or ("PASS" if not passport["residual_risks"] else "FAIL")
        ver_hist.append({
            "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S UTC"),
            "event": "Initial Assurance 3.0 Audit",
            "status": v_state,
            "summary": f"{passport['identity']['pseudonym_present_in_exact_record']} exact records · {passport['clinical']['occurrence_totals']} clinical · {v_state}"
            if not passport["residual_risks"]
            else "; ".join(passport["residual_risks"]),
        })
    else:
        ver_hist.append({
            "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S UTC"),
            "event": "Mandatory Output Contract Validation (1x Run)",
            "status": "PENDING",
            "summary": f"{rep['counts']['files_sanitized']}/{rep['counts']['files_total']} files · {rep['counts']['records_processed']} records validated in {validate_s}s; deep Passport audit pending on demand",
        })

    return {
        "run_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "dataset_label": mode_label,
        "policy_mode": policy_mode,
        "engine_executions": 1,
        "runtime_s": runtime_s,
        "timings": {
            "upload_staging_s": upload_s,
            "engine_runtime_s": runtime_s,
            "validation_s": validate_s,
            "passport_s": passport_s,
            "identity_s": identity_s,
            "arena_s": None,
            "total_ui_s": total_ui_s,
        },
        "engine_stdout": engine_stdout,
        "report": rep,
        "passport_status": passport_status,
        "passport": passport if passport is not None else _pending_passport_stub(rep),
        "passport_html": passport_html,
        "corrupted_passport": None,
        "verification_history": ver_hist,
        "identity_status": identity_status,
        "qi_stats": qi_stats,
        "identity_graph": graph,
        "identity_decisions": decisions,
        "arena_status": "pending",
        "privacy_arena": [],
        "file_pairs": file_index,
        "transformations": transformations,
        "clinical_detail": clinical_detail,
        "historical_benchmarks": HISTORICAL_BENCHMARKS,
    }


def _stage_uploaded_files(files: list[dict], dest: Path) -> tuple[dict[str, bytes], list[dict]]:
    if not isinstance(files, list) or not files or len(files) > MAX_UPLOAD_FILES:
        raise UiApiError(400, "file_count_exceeded", f"Expected 1 to {MAX_UPLOAD_FILES} uploaded files")
    total_bytes = 0
    mem_files: dict[str, bytes] = {}
    staged_meta: list[dict] = []
    used_lower: set[str] = set()
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    dest_root = dest.resolve()

    for item in files:
        if not isinstance(item, dict):
            raise UiApiError(400, "invalid_file", "Malformed uploaded file entry")
        orig_rel = _safe_rel(str(item.get("path", "")))
        if not orig_rel:
            raise UiApiError(400, "invalid_file", "Invalid or unsafe relative file path")
        b64 = item.get("content_b64")
        if isinstance(b64, str):
            try:
                raw = base64.b64decode(b64, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise UiApiError(400, "invalid_file", "Invalid base64 upload payload") from exc
        else:
            raw_text = item.get("text")
            raw = ("" if raw_text is None else str(raw_text)).encode("utf-8")
        total_bytes += len(raw)
        if total_bytes > MAX_UPLOAD_BYTES:
            shutil.rmtree(dest, ignore_errors=True)
            raise UiApiError(413, "size_limit_exceeded", "Uploaded dataset exceeds 16 MB limit")
        rel, renamed = _dedupe_rel(orig_rel, used_lower)
        target = (dest / rel).resolve()
        if not target.is_relative_to(dest_root):
            shutil.rmtree(dest, ignore_errors=True)
            raise UiApiError(400, "invalid_file", "Unsafe upload target path")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        staged_meta.append({"orig": orig_rel, "path": rel, "renamed": renamed, "bytes": len(raw)})
    return mem_files, staged_meta


def _split_multipart_sections(raw_body: bytes, boundary: bytes) -> list[bytes]:
    """Split multipart payload strictly on RFC 2046 boundary lines (never matching mid-line data)."""
    marker = b"--" + boundary
    if not raw_body.startswith(marker):
        idx = raw_body.find(b"\r\n" + marker)
        if idx == -1:
            return []
        raw_body = raw_body[idx + 2 :]
    # Split only on boundary lines preceded by start or CRLF
    sections: list[bytes] = []
    pos = len(marker)
    while pos < len(raw_body):
        if raw_body[pos : pos + 2] == b"--":
            break
        if raw_body[pos : pos + 2] == b"\r\n":
            pos += 2
        nxt = raw_body.find(b"\r\n" + marker, pos)
        if nxt == -1:
            sections.append(raw_body[pos:])
            break
        sections.append(raw_body[pos:nxt])
        pos = nxt + 2 + len(marker)
    return sections


def _parse_multipart_upload(raw_body: bytes, content_type: str, dest: Path) -> tuple[dict, dict[str, bytes], list[dict]]:
    """Stdlib pure-Python multipart/form-data parser with deterministic dedupe & strict limits."""
    m = re.search(r'boundary=(?:"([^"]+)"|([^;\s]+))', content_type, re.I)
    if not m:
        raise UiApiError(400, "upload_error", "Missing multipart boundary header")
    boundary = (m.group(1) or m.group(2)).encode("latin-1")
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    dest_root = dest.resolve()

    fields: dict[str, str] = {}
    relpaths: list[str] = []
    file_parts: list[tuple[str, bytes]] = []
    staged_meta: list[dict] = []
    used_lower: set[str] = set()
    total_bytes = 0

    for part in _split_multipart_sections(raw_body, boundary):
        sep = part.find(b"\r\n\r\n")
        if sep == -1:
            continue
        hdr_blob = part[:sep].decode("utf-8", errors="replace")
        body = part[sep + 4 :]

        disp = ""
        for hline in hdr_blob.split("\r\n"):
            if hline.lower().startswith("content-disposition:"):
                disp = hline
                break
        nm = re.search(r'\bname="((?:\\.|[^"])*)"', disp)
        if not nm:
            continue
        field_name = nm.group(1).replace('\\"', '"')
        fnm = re.search(r'\bfilename="((?:\\.|[^"])*)"', disp)
        if fnm is None:
            val = body.decode("utf-8", errors="replace")
            if field_name == "relpaths":
                try:
                    parsed = json.loads(val)
                    if isinstance(parsed, list):
                        relpaths = [str(x) for x in parsed]
                except ValueError:
                    pass
            else:
                fields[field_name] = val
            continue
        if len(file_parts) >= MAX_UPLOAD_FILES:
            shutil.rmtree(dest, ignore_errors=True)
            raise UiApiError(400, "file_count_exceeded", f"Too many files: maximum is {MAX_UPLOAD_FILES}")
        total_bytes += len(body)
        if total_bytes > MAX_UPLOAD_BYTES:
            shutil.rmtree(dest, ignore_errors=True)
            raise UiApiError(413, "size_limit_exceeded", "Uploaded dataset exceeds 16 MB limit")
        file_parts.append((fnm.group(1).replace('\\"', '"'), body))

    for file_idx, (fn_raw, body) in enumerate(file_parts):
        raw_fn = relpaths[file_idx] if file_idx < len(relpaths) else fn_raw
        orig_rel = _safe_rel(raw_fn)
        if not orig_rel:
            shutil.rmtree(dest, ignore_errors=True)
            raise UiApiError(400, "invalid_file", "Invalid or unsafe uploaded filename")
        rel, renamed = _dedupe_rel(orig_rel, used_lower)
        target = (dest / rel).resolve()
        if not target.is_relative_to(dest_root):
            shutil.rmtree(dest, ignore_errors=True)
            raise UiApiError(400, "invalid_file", "Unsafe upload path")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        staged_meta.append({"orig": orig_rel, "path": rel, "renamed": renamed, "bytes": len(body)})

    if not staged_meta:
        shutil.rmtree(dest, ignore_errors=True)
        raise UiApiError(400, "invalid_file", "No uploaded files received")
    return fields, {}, staged_meta


def _materialize_mem_files(mem_files: dict[str, bytes], dest: Path) -> None:
    dest_root = dest.resolve()
    for rel, raw in mem_files.items():
        target = (dest / rel).resolve()
        if target.is_relative_to(dest_root):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)


def _build_spooled_zip(out: Path) -> tuple[tempfile.SpooledTemporaryFile, int]:
    sp = tempfile.SpooledTemporaryFile(max_size=2 * 1024 * 1024)
    with zipfile.ZipFile(sp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(out.rglob("*")):
            if p.is_file():
                rel = p.relative_to(out).as_posix()
                if rel.startswith(("sanitized/",)) or rel in ("report.json", "records.jsonl"):
                    zf.write(p, arcname=rel)
    size = sp.tell()
    sp.seek(0)
    return sp, size


def _acquire_busy_dir(state: ServerState, run_dir: Path | None) -> str | None:
    if run_dir is None:
        return None
    dname = run_dir.name
    with state.lock:
        state.busy_run_dirs[dname] += 1
    return dname


def _release_busy_dir(state: ServerState, dname: str | None) -> None:
    if not dname:
        return
    need_clean = False
    with state.lock:
        if state.busy_run_dirs.get(dname, 0) <= 1:
            state.busy_run_dirs.pop(dname, None)
            if state.active_run_dir is None or state.active_run_dir.name != dname:
                need_clean = True
        else:
            state.busy_run_dirs[dname] -= 1
    if need_clean:
        _cleanup_old_workdirs(state)


def _cleanup_old_workdirs(state: ServerState) -> None:
    """Keep only the active job workdir, busy dirs, and any actively running job workdirs cleanly."""
    with state.lock:
        keep_dirs = set()
        if state.active_run_dir is not None:
            keep_dirs.add(state.active_run_dir.name)
        for jid, jb in list(state.jobs.items()):
            if jb.get("status") in ("uploading", "queued", "running", "validating"):
                keep_dirs.add(f"job_{jid}")
        for dname, cnt in state.busy_run_dirs.items():
            if cnt > 0:
                keep_dirs.add(dname)
        # Bound retained terminal job metadata entries cleanly
        if len(state.jobs) > MAX_RETAINED_JOBS:
            done_keys = [
                k for k, v in state.jobs.items()
                if k != state.active_job_id and k != state.latest_job_id
                and v.get("status") in ("ready", "failed", "cancelled")
            ]
            for old_k in done_keys[: len(state.jobs) - MAX_RETAINED_JOBS]:
                state.jobs.pop(old_k, None)
    for p in state.workdir.glob("job_*"):
        if p.is_dir() and p.name not in keep_dirs:
            shutil.rmtree(p, ignore_errors=True)


DEMO_SECRET = "veil-command-center-demo-key"  # public, synthetic demo bundle only (reproducible demo)


def _ephemeral_secret() -> str:
    """Uploads without a secret get a random one-time key instead of the public demo key.
    It is never returned, logged or persisted; supply your own key for reproducible releases."""
    import secrets
    return secrets.token_urlsafe(32)


def _build_csp() -> str:
    import base64
    hashes = []
    idx = WEB_DIR / "index.html"
    if idx.is_file():
        for m in re.finditer(r"<script>(.*?)</script>", idx.read_text(encoding="utf-8"), re.S):
            hashes.append("'sha256-" + base64.b64encode(hashlib.sha256(m.group(1).encode("utf-8")).digest()).decode() + "'")
    # 'unsafe-eval' only for browser test automation (Playwright string predicates); VEIL never calls eval and
    # inline scripts stay blocked except the hashed appearance bootstrap.
    return ("default-src 'self'; script-src 'self' 'unsafe-eval' " + " ".join(hashes) + "; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")


_CSP = _build_csp()


def make_handler(state: ServerState):
    class VeilHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args) -> None:
            return

        def _send(self, code: int, body: bytes, ctype: str, extra_headers: dict[str, str] | None = None) -> None:
            if code >= 400:
                self.close_connection = True
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Content-Security-Policy", _CSP)
            if self.close_connection:
                self.send_header("Connection", "close")
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, code: int, payload: dict) -> None:
            try:
                encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            except (TypeError, ValueError):
                code = 500
                encoded = b'{"error":"Response serialization failure","error_code":"serialization_failed"}'
            self._send(code, encoded, "application/json; charset=utf-8")

        def _send_spooled(self, code: int, sp: tempfile.SpooledTemporaryFile, size: int, ctype: str, extra_headers: dict[str, str] | None = None) -> None:
            try:
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(size))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                if extra_headers:
                    for k, v in extra_headers.items():
                        self.send_header(k, v)
                self.end_headers()
                sp.seek(0)
                while True:
                    chunk = sp.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True
            finally:
                try:
                    sp.close()
                except Exception:
                    pass

        def _allowed_hostnames(self) -> set[str]:
            allowed = {"127.0.0.1", "localhost", "::1"}
            bind = str(self.server.server_address[0]).lower()
            if bind not in ("", "0.0.0.0", "::"):
                allowed.add(bind)
            return allowed

        def _check_host(self) -> None:
            """DNS-rebinding defence: only loopback (or the explicit bind address) may name this server."""
            host_hdr = (self.headers.get("Host") or "").strip().lower()
            try:
                hp = urllib.parse.urlsplit("//" + host_hdr)
                hostname, port = hp.hostname, hp.port
            except ValueError:
                hostname, port = None, None
            if not hostname or hostname not in self._allowed_hostnames() or (port is not None and port != self.server.server_address[1]):
                raise UiApiError(403, "forbidden_host", "Unexpected Host header")

        def _check_same_origin(self) -> None:
            origin = self.headers.get("Origin")
            if origin is None:
                return
            if origin.strip().lower() == "null":
                raise UiApiError(403, "forbidden_origin", "Cross-origin POST with null origin blocked")
            try:
                po = urllib.parse.urlsplit(origin.strip())
                ok = po.scheme == "http" and po.hostname in self._allowed_hostnames() and (po.port or 80) == self.server.server_address[1]
            except ValueError:
                ok = False
            if not ok:
                raise UiApiError(403, "forbidden_origin", "Cross-origin request blocked")

        def _read_body_exact(self, limit: int) -> bytes:
            te = (self.headers.get("Transfer-Encoding") or "").lower()
            if "chunked" in te:
                buf = bytearray()
                while True:
                    sz_line = self.rfile.readline(128)
                    if not sz_line:
                        raise UiApiError(400, "upload_error", "Malformed chunked request body")
                    sz_tok = sz_line.split(b";", 1)[0].strip()
                    try:
                        chunk_len = int(sz_tok, 16)
                    except ValueError as exc:
                        raise UiApiError(400, "upload_error", "Malformed chunk size") from exc
                    if chunk_len < 0:
                        raise UiApiError(400, "upload_error", "Negative chunk size")
                    if chunk_len == 0:
                        # Consume trailer headers until empty line
                        while True:
                            tr = self.rfile.readline(4096)
                            if not tr or tr in (b"\r\n", b"\n"):
                                break
                        break
                    if len(buf) + chunk_len > limit:
                        self.close_connection = True
                        raise UiApiError(413, "size_limit_exceeded", "Uploaded payload exceeds size limit (16 MB)")
                    data = self.rfile.read(chunk_len)
                    if len(data) != chunk_len:
                        raise UiApiError(400, "upload_error", "Truncated chunked upload")
                    buf.extend(data)
                    crlf = self.rfile.read(2)
                    if crlf not in (b"\r\n", b"\n"):
                        raise UiApiError(400, "upload_error", "Malformed chunk terminator")
                if not buf:
                    raise UiApiError(400, "upload_error", "Empty request body")
                return bytes(buf)
            raw_len = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_len)
            except ValueError as exc:
                raise UiApiError(400, "upload_error", "Malformed Content-Length header") from exc
            if length <= 0:
                raise UiApiError(400, "upload_error", "Empty request body")
            if length > limit:
                self.close_connection = True
                raise UiApiError(413, "size_limit_exceeded", "Uploaded payload exceeds size limit (16 MB)")
            chunks = []
            rem = length
            while rem > 0:
                blk = self.rfile.read(min(rem, 1024 * 1024))
                if not blk:
                    raise UiApiError(400, "upload_error", "Connection interrupted during upload")
                chunks.append(blk)
                rem -= len(blk)
            return b"".join(chunks)

        def do_GET(self) -> None:
            try:
                self._check_host()
            except UiApiError as exc:
                self._send_json(exc.status_code, {"error": exc.message, "error_code": exc.code})
                return
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
                with state.lock:
                    aj = state.active_job_id
                self._send_json(200, {"ok": True, "demo_available": DEMO_DIR.is_dir(), "active_job_id": aj})
                return

            if path == "/api/state":
                with state.lock:
                    active = state.active
                    aj = state.active_job_id
                    rj = None
                    lj = state.latest_job_id
                    if lj and state.jobs.get(lj, {}).get("status") in ("uploading", "queued", "running", "validating"):
                        rj = lj
                    if not active:
                        snap = {
                            "ready": False,
                            "active_job_id": aj,
                            "running_job_id": rj,
                            "demo_available": DEMO_DIR.is_dir(),
                            "historical_benchmarks": HISTORICAL_BENCHMARKS,
                        }
                    else:
                        snap = {k: v for k, v in active.items() if k != "passport_html"}
                        snap["ready"] = True
                        snap["active_job_id"] = aj
                        snap["running_job_id"] = rj
                        snap["demo_available"] = DEMO_DIR.is_dir()
                self._send_json(200, snap)
                return

            if path.startswith("/api/status/"):
                job_id = path.split("/api/status/", 1)[1]
                with state.lock:
                    job = state.jobs.get(job_id)
                    snap = dict(job) if job else None
                if snap is None:
                    self._send_json(404, {"error": "Job not found", "error_code": "job_not_found"})
                    return
                self._send_json(200, snap)
                return

            if path == "/api/diff":
                qs = urllib.parse.parse_qs(parsed.query)
                try:
                    fidx = int((qs.get("idx") or ["0"])[0])
                except ValueError:
                    self._send_json(400, {"error": "Invalid file index", "error_code": "bad_request"})
                    return
                busy_dname: str | None = None
                with state.lock:
                    active = state.active
                    inp = state.active_inp
                    upload_mem = state.active_upload_bytes
                    out = state.active_out
                    if active and out and state.active_run_dir is not None:
                        busy_dname = state.active_run_dir.name
                        state.busy_run_dirs[busy_dname] += 1
                if not active or not out or (not inp and not upload_mem):
                    _release_busy_dir(state, busy_dname)
                    self._send_json(404, {"error": "No active run"})
                    return
                try:
                    files = active.get("file_pairs") or []
                    if fidx < 0 or fidx >= len(files):
                        self._send_json(404, {"error": "File index out of range"})
                        return
                    meta = dict(files[fidx])
                    in_rel = meta["input_rel"]
                    out_rel = meta.get("output_rel")
                    in_txt = ""
                    out_txt = ""
                    if meta["status"] == "quarantined":
                        raw_sample = b""
                        if inp is not None and (inp / in_rel).is_file():
                            with (inp / in_rel).open("rb") as f:
                                raw_sample = f.read(64)
                        elif upload_mem and in_rel in upload_mem:
                            raw_sample = upload_mem[in_rel][:64]
                        in_txt = f"[BINARY / UNSUPPORTED PAYLOAD QUARANTINED]\nFile: {in_rel}\nSize: {meta['bytes_in']} bytes\nMagic prefix hex: {raw_sample[:24].hex(' ')}"
                        out_txt = f"[QUARANTINED — NOT EXPORTED TO sanitized/]\nReason: {meta.get('reason') or 'unsupported_format'}"
                    else:
                        if inp is not None and (inp / in_rel).is_file():
                            with (inp / in_rel).open("rb") as f:
                                raw_chunk = f.read(MAX_PREVIEW_BYTES + 1)
                        elif upload_mem and in_rel in upload_mem:
                            raw_chunk = upload_mem[in_rel][: MAX_PREVIEW_BYTES + 1]
                        else:
                            raw_chunk = b""
                        in_dec = VP.decode(raw_chunk[:MAX_PREVIEW_BYTES])
                        in_txt = in_dec + ("\n... [preview truncated; exported file untouched]" if len(raw_chunk) > MAX_PREVIEW_BYTES else "")
                        if out_rel and (out / out_rel).is_file():
                            with (out / out_rel).open("rb") as f:
                                out_chunk = f.read(MAX_PREVIEW_BYTES + 1)
                            out_dec = out_chunk[:MAX_PREVIEW_BYTES].decode("utf-8", errors="replace")
                            out_txt = out_dec + ("\n... [preview truncated; full file in Download ZIP]" if len(out_chunk) > MAX_PREVIEW_BYTES else "")
                    meta["input_text"] = in_txt
                    meta["output_text"] = out_txt
                    self._send_json(200, meta)
                finally:
                    _release_busy_dir(state, busy_dname)
                return

            if path == "/api/decisions":
                qs = urllib.parse.parse_qs(parsed.query)
                filt = (qs.get("filter") or ["all"])[0]
                try:
                    raw_page = (qs.get("page") or ["0"])[0]
                    raw_lim = (qs.get("limit") or ["50"])[0]
                    page_val = int(raw_page if raw_page != "" else "0")
                    lim_val = int(raw_lim if raw_lim != "" else "50")
                except ValueError:
                    self._send_json(400, {"error": "Invalid pagination parameter", "error_code": "bad_request"})
                    return
                page = max(0, page_val)
                limit = min(100, max(1, lim_val))
                with state.lock:
                    active = state.active
                    decs = list(active.get("identity_decisions", [])) if active else []
                    counts = dict(active.get("identity_graph", {}).get("decision_counts", {})) if active else {}
                filtered = [x for x in decs if filt == "all" or x.get("decision") == filt]
                start = page * limit
                self._send_json(200, {
                    "items": filtered[start : start + limit],
                    "total_filtered": len(filtered),
                    "page": page,
                    "limit": limit,
                    "decision_counts": counts,
                })
                return

            if path == "/api/passport/html":
                with state.lock:
                    active = state.active
                    inp = state.active_inp
                    upload_mem = state.active_upload_bytes
                    out = state.active_out
                    ajid = state.active_job_id
                    if not active or not out:
                        self._send_json(404, {"error": "No active run"})
                        return
                    corrupted = active.get("corrupted_passport")
                    is_corrupt = urllib.parse.parse_qs(parsed.query).get("variant") == ["corrupt"] and bool(corrupted)
                    html_txt = corrupted["html"] if is_corrupt else active.get("passport_html")
                if html_txt is None:
                    R_ok, html_txt = _ensure_passport_audited(state, inp, upload_mem, out, job_id=ajid)
                fname = "veil_privacy_passport_DEFECT.html" if urllib.parse.parse_qs(parsed.query).get("variant") == ["corrupt"] else "veil_privacy_passport.html"
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
                    inp = state.active_inp
                    upload_mem = state.active_upload_bytes
                    out = state.active_out
                    ajid = state.active_job_id
                    if not active or not out:
                        self._send_json(404, {"error": "No active run"})
                        return
                    corrupted = active.get("corrupted_passport")
                    is_corrupt = urllib.parse.parse_qs(parsed.query).get("variant") == ["corrupt"] and bool(corrupted)
                    data = corrupted["audit"] if is_corrupt else (active["passport"] if active.get("passport_status") == "verified" else None)
                if data is None:
                    data, _ = _ensure_passport_audited(state, inp, upload_mem, out, job_id=ajid)
                self._send(
                    200,
                    json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8"),
                    "application/json; charset=utf-8",
                    {"Content-Disposition": 'attachment; filename="veil_privacy_passport.json"'},
                )
                return

            if path == "/api/download/zip":
                busy_dname: str | None = None
                with state.lock:
                    out = state.active_out
                    if out and state.active_run_dir is not None:
                        busy_dname = state.active_run_dir.name
                        state.busy_run_dirs[busy_dname] += 1
                if not out or not out.is_dir():
                    _release_busy_dir(state, busy_dname)
                    self._send_json(404, {"error": "No sanitized release available"})
                    return
                try:
                    sp, zsize = _build_spooled_zip(out)
                except Exception:
                    _release_busy_dir(state, busy_dname)
                    raise
                try:
                    self._send_spooled(
                        200,
                        sp,
                        zsize,
                        "application/zip",
                        {"Content-Disposition": 'attachment; filename="veil_sanitized_release.zip"'},
                    )
                finally:
                    _release_busy_dir(state, busy_dname)
                return

            self._send_json(404, {"error": "Not found"})

        def do_POST(self) -> None:
            try:
                self._check_host()
                self._check_same_origin()
            except UiApiError as exc:
                self._send_json(exc.status_code, {"error": exc.message, "error_code": exc.code})
                return
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            if path.startswith("/api/cancel/"):
                job_id = path.split("/api/cancel/", 1)[1]
                with state.lock:
                    jb = state.jobs.get(job_id)
                    if not jb:
                        self._send_json(404, {"error": "Job not found", "error_code": "job_not_found"})
                        return
                    if jb["status"] in ("uploading", "queued", "running", "validating"):
                        jb["status"] = "cancelled"
                        jb["stage"] = "Cancelled by user"
                        jb["error_code"] = "cancelled"
                        proc = state.job_procs.get(job_id)
                    else:
                        proc = None
                    cur_status = jb["status"]
                if proc is not None and proc.poll() is None:
                    try:
                        proc.terminate()
                    except OSError:
                        pass
                self._send_json(200, {"job_id": job_id, "status": cur_status})
                return

            if path == "/api/run":
                t_up0 = time.monotonic()
                ctype = self.headers.get("Content-Type", "")
                job_id = hashlib.sha256(f"{time.time_ns()}-{os.getpid()}-{threading.get_ident()}".encode()).hexdigest()[:12]
                run_dir = state.workdir / f"job_{job_id}"
                inp_dir = run_dir / "input"
                out_dir = run_dir / "output"

                upload_mem: dict[str, bytes] | None = None
                staged_meta: list[dict] = []
                sync_flag = False
                run_optional = False
                try:
                    if ctype.lower().startswith("multipart/form-data"):
                        raw_body = self._read_body_exact(MAX_MULTIPART_BODY_BYTES)
                        fields, upload_mem, staged_meta = _parse_multipart_upload(raw_body, ctype, inp_dir)
                        mode = str(fields.get("mode", "upload"))
                        policy_mode = str(fields.get("policy", "adaptive"))
                        secret = str(fields.get("secret") or "")[:128] or _ephemeral_secret()
                        label = str(fields.get("label") or f"Uploaded Synthetic Dataset ({len(staged_meta)} files)")
                        sync_flag = str(fields.get("sync", "")).lower() in ("1", "true")
                        run_optional = str(fields.get("run_optional", "")).lower() in ("1", "true")
                    else:
                        raw_body = self._read_body_exact(MAX_JSON_BODY_BYTES)
                        try:
                            req = json.loads(raw_body.decode("utf-8"))
                        except (UnicodeDecodeError, ValueError) as exc:
                            raise UiApiError(400, "upload_error", "Malformed JSON upload payload") from exc
                        if not isinstance(req, dict):
                            raise UiApiError(400, "upload_error", "Expected JSON object")
                        mode = str(req.get("mode", "demo"))
                        policy_mode = str(req.get("policy", "adaptive"))
                        secret = str(req.get("secret") or "")[:128] or (DEMO_SECRET if mode == "demo" else _ephemeral_secret())
                        sync_flag = bool(req.get("sync"))
                        run_optional = bool(req.get("run_optional", mode == "demo"))
                        if mode == "demo":
                            if not DEMO_DIR.is_dir():
                                raise UiApiError(400, "invalid_file", "Bundled demo/sample_hospital directory missing")
                            shutil.copytree(DEMO_DIR, inp_dir)
                            label = str(req.get("label") or "Synthetic Multi-Hospital Bundle (demo/sample_hospital)")
                        elif mode == "upload":
                            upload_mem, staged_meta = _stage_uploaded_files(req.get("files", []), inp_dir)
                            label = str(req.get("label") or f"Uploaded Synthetic Dataset ({len(staged_meta)} files)")
                        else:
                            raise UiApiError(400, "upload_error", "mode must be 'demo' or 'upload'")

                    if policy_mode not in ("adaptive", "fixed", "mask"):
                        raise UiApiError(400, "upload_error", "Invalid policy mode")
                    if not secret.strip():
                        raise UiApiError(400, "upload_error", "RAKSHA_SECRET must not be empty")
                except UiApiError as exc:
                    shutil.rmtree(run_dir, ignore_errors=True)
                    self._send_json(exc.status_code, {"error": exc.message, "error_code": exc.code})
                    return

                upload_s = round(time.monotonic() - t_up0, 3)
                input_digest = _input_digest_from_dir(inp_dir)
                secret_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()

                with state.lock:
                    state.job_seq += 1
                    my_seq = state.job_seq
                    state.latest_job_id = job_id
                    state.jobs[job_id] = {
                        "job_id": job_id,
                        "seq": my_seq,
                        "status": "queued",
                        "progress": 10,
                        "stage": "Staged input · queued for VEIL engine",
                        "error": None,
                        "error_code": None,
                        "staged_files": staged_meta,
                        "created_at": time.time(),
                        "engine_runtime_s": None,
                        "total_ui_s": None,
                    }

                def worker():
                    def is_cancelled() -> bool:
                        with state.lock:
                            jb = state.jobs.get(job_id)
                            return bool((jb and jb.get("status") == "cancelled") or my_seq < state.job_seq)

                    def set_proc(p):
                        with state.lock:
                            if p is None:
                                state.job_procs.pop(job_id, None)
                            else:
                                state.job_procs[job_id] = p

                    def progress(status_str: str, pct: int, stage: str):
                        with state.lock:
                            jb = state.jobs.get(job_id)
                            if jb and jb["status"] != "cancelled":
                                jb["status"] = status_str
                                jb["progress"] = pct
                                jb["stage"] = stage

                    became_active = False
                    try:
                        payload = _build_primary_payload(
                            inp_dir,
                            out_dir,
                            secret,
                            policy_mode,
                            label,
                            upload_s=upload_s,
                            run_optional=run_optional,
                            progress_cb=progress,
                            proc_cb=set_proc,
                            cancel_check=is_cancelled,
                        )
                        payload["job_id"] = job_id
                        payload["input_digest"] = input_digest
                        payload["staged_files"] = staged_meta

                        with state.lock:
                            jb = state.jobs.get(job_id)
                            if (jb and jb["status"] == "cancelled") or my_seq < state.job_seq:
                                raise UiApiError(409, "cancelled", "Job cancelled or superseded before completion")
                            state.active = payload
                            state.active_job_id = job_id
                            state.active_inp = inp_dir
                            state.active_upload_bytes = None
                            state.active_out = out_dir
                            state.active_run_dir = run_dir
                            state.active_secret = secret
                            state.active_secret_hash = secret_hash
                            state.active_input_digest = input_digest
                            state.active_policy_mode = policy_mode
                            state.jobs[job_id]["status"] = "ready"
                            state.jobs[job_id]["progress"] = 100
                            state.jobs[job_id]["stage"] = "Ready — sanitized release verified"
                            state.jobs[job_id]["engine_runtime_s"] = payload["runtime_s"]
                            state.jobs[job_id]["total_ui_s"] = payload["timings"]["total_ui_s"]
                            became_active = True
                        _cleanup_old_workdirs(state)
                    except UiApiError as exc:
                        with state.lock:
                            if job_id in state.jobs:
                                state.jobs[job_id]["status"] = "cancelled" if exc.code == "cancelled" else "failed"
                                state.jobs[job_id]["error"] = exc.message
                                state.jobs[job_id]["error_code"] = exc.code
                        shutil.rmtree(out_dir, ignore_errors=True)
                    except Exception:  # noqa: BLE001 - never leak internal exception text/paths
                        with state.lock:
                            if job_id in state.jobs:
                                state.jobs[job_id]["status"] = "failed"
                                state.jobs[job_id]["error"] = "Internal processing error during dataset sanitization"
                                state.jobs[job_id]["error_code"] = "engine_failed"
                        shutil.rmtree(out_dir, ignore_errors=True)
                    finally:
                        if not became_active:
                            shutil.rmtree(run_dir, ignore_errors=True)

                if sync_flag:
                    worker()
                    with state.lock:
                        snap = dict(state.jobs[job_id])
                    code = 200 if snap["status"] == "ready" else (504 if snap.get("error_code") == "engine_timeout" else 500)
                    self._send_json(code, snap)
                else:
                    threading.Thread(target=worker, daemon=True).start()
                    self._send_json(202, {"job_id": job_id, "status": "queued", "staged_files": staged_meta})
                return

            if path == "/api/passport/run":
                with state.lock:
                    active = state.active
                    inp = state.active_inp
                    upload_mem = state.active_upload_bytes
                    out = state.active_out
                    active_job_id = state.active_job_id
                if not active or not out or not (inp or upload_mem):
                    self._send_json(400, {"error": "Run VEIL first before running Privacy Passport"})
                    return
                t0 = time.monotonic()
                audit_res, _ = _ensure_passport_audited(state, inp, upload_mem, out, force=True, job_id=active_job_id)
                dt_s = round(time.monotonic() - t0, 3)
                with state.lock:
                    hist = list(state.active.get("verification_history", [])) if state.active else []
                    timings = dict(state.active.get("timings", {})) if state.active else {}
                self._send_json(200, {
                    "status": "verified",
                    "passport_status": "verified",
                    "passport": audit_res,
                    "passport_s": dt_s,
                    "timings": timings,
                    "verification_history": hist,
                })
                return

            if path == "/api/identity/run":
                busy_dname: str | None = None
                with state.lock:
                    active = state.active
                    inp = state.active_inp
                    upload_mem = state.active_upload_bytes
                    out = state.active_out
                    pmode = state.active_policy_mode
                    ajid = state.active_job_id
                    if active and out and (inp or upload_mem) and state.active_run_dir is not None:
                        busy_dname = state.active_run_dir.name
                        state.busy_run_dirs[busy_dname] += 1
                if not active or not out or not (inp or upload_mem):
                    _release_busy_dir(state, busy_dname)
                    self._send_json(400, {"error": "Run VEIL first before analyzing identity graph"})
                    return
                try:
                    t0 = time.monotonic()
                    if inp is not None:
                        graph, decisions, qi_stats = _analyze_identity_and_qi(inp, out, pmode)
                    else:
                        with tempfile.TemporaryDirectory(prefix="veil_ui_id_") as td:
                            tp = Path(td)
                            _materialize_mem_files(upload_mem or {}, tp)
                            graph, decisions, qi_stats = _analyze_identity_and_qi(tp, out, pmode)
                    dt_s = round(time.monotonic() - t0, 3)
                    with state.lock:
                        if state.active and state.active_job_id == ajid:
                            state.active["identity_graph"] = graph
                            state.active["identity_decisions"] = decisions
                            state.active["qi_stats"] = qi_stats
                            state.active["identity_status"] = "ready"
                            state.active.setdefault("timings", {})["identity_s"] = dt_s
                    self._send_json(200, {
                        "identity_status": "ready",
                        "identity_s": dt_s,
                        "identity_graph": graph,
                        "identity_decisions": decisions[:50],
                        "qi_stats": qi_stats,
                    })
                finally:
                    _release_busy_dir(state, busy_dname)
                return

            if path == "/api/arena/run":
                busy_dname = None
                with state.lock:
                    active = state.active
                    inp = state.active_inp
                    upload_mem = state.active_upload_bytes
                    out = state.active_out
                    secret = state.active_secret
                    secret_hash = state.active_secret_hash
                    input_digest = state.active_input_digest
                    pmode = state.active_policy_mode
                    runtime_s = float(active.get("runtime_s", 0.0)) if active else 0.0
                    ajid = state.active_job_id
                    if active and out and (inp or upload_mem) and state.active_run_dir is not None:
                        busy_dname = state.active_run_dir.name
                        state.busy_run_dirs[busy_dname] += 1
                if not active or not out or not (inp or upload_mem):
                    _release_busy_dir(state, busy_dname)
                    self._send_json(400, {"error": "Run VEIL first before benchmarking Privacy Arena"})
                    return
                try:
                    arena_dir = Path(tempfile.mkdtemp(prefix=f"arena_{ajid or 'cur'}_", dir=str(state.workdir)))
                    if inp is not None:
                        arena, arena_s = _run_privacy_arena_cached(state, inp, out, arena_dir, secret, pmode, runtime_s, input_digest, secret_hash)
                    else:
                        with tempfile.TemporaryDirectory(prefix="veil_ui_ar_") as td:
                            tp = Path(td)
                            _materialize_mem_files(upload_mem or {}, tp)
                            arena, arena_s = _run_privacy_arena_cached(state, tp, out, arena_dir, secret, pmode, runtime_s, input_digest, secret_hash)
                    with state.lock:
                        if state.active and state.active_job_id == ajid:
                            state.active["privacy_arena"] = arena
                            state.active["arena_status"] = "ready"
                            state.active.setdefault("timings", {})["arena_s"] = arena_s
                    self._send_json(200, {"arena_status": "ready", "arena_s": arena_s, "privacy_arena": arena})
                finally:
                    _release_busy_dir(state, busy_dname)
                return

            if path == "/api/passport/corrupt":
                busy_dname = None
                with state.lock:
                    active = state.active
                    inp = state.active_inp
                    upload_mem = state.active_upload_bytes
                    out = state.active_out
                    ajid = state.active_job_id
                    if active and out and (inp or upload_mem) and state.active_run_dir is not None:
                        busy_dname = state.active_run_dir.name
                        state.busy_run_dirs[busy_dname] += 1
                if (not inp and not upload_mem) or not out or not active:
                    _release_busy_dir(state, busy_dname)
                    self._send_json(400, {"error": "Run VEIL first before testing defect detection"})
                    return
                try:
                    bad_dir = out.parent / "output_corrupted"
                    if bad_dir.exists():
                        shutil.rmtree(bad_dir)
                    shutil.copytree(out, bad_dir)
                    (bad_dir / "sanitized").mkdir(parents=True, exist_ok=True)
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
                    corr_verdict = R_bad.get("verdict") or ("FAIL" if R_bad.get("residual_risks") else "WARNING")
                    corr_obj = {
                        "target_file": target.relative_to(bad_dir).as_posix(),
                        "mutation": "Altered dosage (+50 mg) and injected unmasked contact number into release artifact.",
                        "audit": R_bad,
                        "html": bad_html,
                    }
                    with state.lock:
                        if state.active and state.active_job_id == ajid:
                            state.active["corrupted_passport"] = corr_obj
                            state.active.setdefault("verification_history", []).insert(0, {
                                "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S UTC"),
                                "event": "Synthetic Fault Injection",
                                "status": corr_verdict,
                                "summary": f"{corr_obj['target_file']}: " + "; ".join(R_bad["residual_risks"]),
                            })
                            hist = list(state.active["verification_history"])
                        else:
                            hist = []
                    self._send_json(200, {
                        "status": "defect_detected",
                        "corrupted_passport": {
                            "target_file": corr_obj["target_file"],
                            "mutation": corr_obj["mutation"],
                            "audit": R_bad,
                        },
                        "verification_history": hist,
                    })
                finally:
                    _release_busy_dir(state, busy_dname)
                return

            if path == "/api/passport/repair":
                busy_dname = None
                with state.lock:
                    active = state.active
                    inp = state.active_inp
                    upload_mem = state.active_upload_bytes
                    out = state.active_out
                    secret = state.active_secret
                    policy_mode = state.active_policy_mode
                    ajid = state.active_job_id
                    if active and out and (inp or upload_mem) and state.active_run_dir is not None:
                        busy_dname = state.active_run_dir.name
                        state.busy_run_dirs[busy_dname] += 1
                if (not inp and not upload_mem) or not out or not active:
                    _release_busy_dir(state, busy_dname)
                    self._send_json(400, {"error": "No active run to repair"})
                    return
                try:
                    repair_out = Path(tempfile.mkdtemp(prefix="output_repair_", dir=str(out.parent)))
                    try:
                        if inp is not None:
                            runtime_s, _ = _run_subprocess_engine(inp, repair_out, secret, policy_mode)
                            rep_new = _validate_release_contract(inp, repair_out)
                            file_index, clinical_detail, transformations = _extract_fast_summary(inp, repair_out, rep_new)
                            R_ok = VP.audit(inp, repair_out)
                        else:
                            with tempfile.TemporaryDirectory(prefix="veil_ui_ephem_") as td:
                                tp = Path(td)
                                _materialize_mem_files(upload_mem or {}, tp)
                                runtime_s, _ = _run_subprocess_engine(tp, repair_out, secret, policy_mode)
                                rep_new = _validate_release_contract(tp, repair_out)
                                file_index, clinical_detail, transformations = _extract_fast_summary(tp, repair_out, rep_new)
                                R_ok = VP.audit(tp, repair_out)
                        old_backup = out.parent / f"output_old_{threading.get_ident()}"
                        if old_backup.exists():
                            shutil.rmtree(old_backup, ignore_errors=True)
                        if out.exists():
                            out.rename(old_backup)
                        repair_out.rename(out)
                        shutil.rmtree(old_backup, ignore_errors=True)
                    finally:
                        if repair_out.exists() and repair_out != out:
                            shutil.rmtree(repair_out, ignore_errors=True)
                    shutil.rmtree(out.parent / "output_corrupted", ignore_errors=True)
                    html_ok = VP.render_html(R_ok, None)
                    verdict_ok = R_ok.get("verdict") or ("PASS" if not R_ok["residual_risks"] else "FAIL")
                    with state.lock:
                        if state.active and state.active_job_id == ajid:
                            state.active["report"] = rep_new
                            state.active["file_pairs"] = file_index
                            state.active["clinical_detail"] = clinical_detail
                            state.active["transformations"] = transformations
                            state.active["passport"] = R_ok
                            state.active["passport_html"] = html_ok
                            state.active["passport_status"] = "verified"
                            state.active["corrupted_passport"] = None
                            state.active["runtime_s"] = runtime_s
                            state.active.setdefault("verification_history", []).insert(0, {
                                "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S UTC"),
                                "event": "VEIL Clean Re-run & Repair",
                                "status": verdict_ok,
                                "summary": f"{R_ok['identity']['pseudonym_present_in_exact_record']} exact records · {R_ok['clinical']['occurrence_totals']} clinical · {verdict_ok} · repaired in {runtime_s}s",
                            })
                            hist = list(state.active["verification_history"])
                        else:
                            hist = []
                    self._send_json(200, {
                        "status": "repaired",
                        "passport": R_ok,
                        "passport_status": "verified",
                        "runtime_s": runtime_s,
                        "verification_history": hist,
                    })
                finally:
                    _release_busy_dir(state, busy_dname)
                return

            self._send_json(404, {"error": "Not found"})

    return VeilHandler


def _ensure_passport_audited(state: ServerState, inp: Path | None, upload_mem: dict[str, bytes] | None, out: Path, force: bool = False, job_id: str | None = None) -> tuple[dict, str]:
    dname = out.parent.name
    with state.lock:
        if not force and state.active and state.active.get("passport_status") == "verified" and state.active.get("passport_html"):
            return state.active["passport"], state.active["passport_html"]
        state.busy_run_dirs[dname] += 1
    try:
        t0 = time.monotonic()
        if inp is not None:
            audit_res = VP.audit(inp, out)
        else:
            with tempfile.TemporaryDirectory(prefix="veil_ui_pp_") as td:
                tp = Path(td)
                _materialize_mem_files(upload_mem or {}, tp)
                audit_res = VP.audit(tp, out)
        html_res = VP.render_html(audit_res, None)
        dt_s = round(time.monotonic() - t0, 3)
        with state.lock:
            if state.active and (job_id is None or state.active_job_id == job_id):
                v_state = audit_res.get("verdict") or ("PASS" if not audit_res["residual_risks"] else "FAIL")
                state.active["passport"] = audit_res
                state.active["passport_html"] = html_res
                state.active["passport_status"] = "verified"
                state.active.setdefault("timings", {})["passport_s"] = dt_s
                state.active.setdefault("verification_history", []).insert(0, {
                    "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S UTC"),
                    "event": "On-Demand Assurance 3.0 Audit",
                    "status": v_state,
                    "summary": f"{audit_res['identity']['pseudonym_present_in_exact_record']} exact records · {audit_res['clinical']['occurrence_totals']} clinical · {v_state} · audited in {dt_s}s"
                    if not audit_res["residual_risks"]
                    else "; ".join(audit_res["residual_risks"]),
                })
        return audit_res, html_res
    finally:
        with state.lock:
            state.busy_run_dirs[dname] -= 1
            if state.busy_run_dirs[dname] <= 0:
                state.busy_run_dirs.pop(dname, None)


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
        shutil.copytree(DEMO_DIR, inp)
        payload = _build_primary_payload(
            inp, out, state.active_secret, "adaptive", "Synthetic Multi-Hospital Bundle (demo/sample_hospital)",
            run_optional=True,
        )
        input_digest = _input_digest_from_dir(inp)
        payload["job_id"] = "initial_demo"
        payload["input_digest"] = input_digest
        state.active = payload
        state.active_job_id = "initial_demo"
        state.active_inp = inp
        state.active_out = out
        state.active_run_dir = run_dir
        state.active_input_digest = input_digest
    srv = ReusableThreadingHTTPServer((host, port), make_handler(state))
    return srv, state


def main() -> int:
    ap = argparse.ArgumentParser(description="VEIL — Clinical Privacy Command Center (offline local UI)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--demo", action=argparse.BooleanOptionalAction, default=False, help="Pre-run VEIL on demo/sample_hospital on startup")
    ap.add_argument("--open", action=argparse.BooleanOptionalAction, default=False, help="Open browser tab automatically")
    args = ap.parse_args()

    srv, _ = create_server(host=args.host, port=args.port, preload_demo=args.demo)
    actual_port = srv.server_address[1]
    url = f"http://{args.host}:{actual_port}/"
    print(f"VEIL Clinical Privacy Command Center running offline at {url}", flush=True)
    if args.open:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    import signal

    def _graceful(signum, frame):  # SIGTERM/SIGHUP take the same path as Ctrl-C so atexit removes the private workdir
        raise KeyboardInterrupt

    for _sig in (signal.SIGTERM, getattr(signal, "SIGHUP", None)):
        if _sig is not None:
            signal.signal(_sig, _graceful)
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
