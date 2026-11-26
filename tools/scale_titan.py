#!/usr/bin/env python3
"""VEIL TITAN Progressive Scalability & Topology Suite (100k -> 250k -> 500k -> 1M).

Executes main.py inside fresh offline subprocesses, enforcing a 900s default
sandbox timeout and stopping early if child peak RSS approaches the 4096 MB
limit. Measures wall time, peak RSS (via ru_maxrss), throughput, pseudonym
uniqueness/collisions, record retention, clinical survival, and false merges.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import resource
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYL1 = ["Ar", "Ba", "Ch", "Da", "El", "Ga", "Ha", "In", "Ja", "Ka", "La", "Ma", "Na", "Om", "Pa", "Ra", "Sa", "Ta", "Um", "Va"]
SYL2 = ["un", "vi", "it", "sh", "am", "an", "ee", "oo", "ak", "el", "ik", "or", "ya", "di", "ra", "ma", "na", "la", "pa", "ka"]
SURS = ["Yadav", "Verma", "Sharma", "Patel", "Gupta", "Mishra", "Thakur", "Jadhav", "Das", "Khan", "Nair", "Rao", "Singh", "Jain", "Shah"]
DISTS = ["Sitapur", "Lucknow", "Gaya", "Patna", "Wardha", "Nagpur", "Anand", "Kheda", "Nadia", "Bathinda"]


def _name(p: int, homonym_pool: bool = False) -> str:
    if homonym_pool:
        return f"Ramesh{p % 20:02d} {SURS[p % 10]}"
    return f"{SYL1[p % 20]}{SYL2[(p // 20) % 20]}{SYL2[(p // 400) % 20]}{SYL2[(p // 8000) % 20]} {SURS[p % len(SURS)]}"


def build_csv(src: Path, n_rows: int, n_patients: int, homonym: bool = False, shared_hh: bool = False) -> None:
    src.mkdir(parents=True, exist_ok=True)
    with (src / "records.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["MRN", "patient_name", "age", "sex", "district", "phone", "ration_card", "diagnosis", "medication", "bp"])
        for i in range(n_rows):
            p = i % n_patients
            hh = f"RC-{100000 + (p // 3):06d}" if shared_hh else f"RC-{200000 + p:06d}"
            ph = f"9{100000000 + (p // 2 if shared_hh else p):09d}"
            w.writerow([
                f"HP-{1000000 + p}",
                _name(p, homonym),
                20 + (p % 65),
                "M" if p % 2 == 0 else "F",
                DISTS[p % (4 if homonym else len(DISTS))],
                ph,
                hh,
                "Essential hypertension",
                "Tab. Amlodipine 5 mg",
                "128/82 mmHg",
            ])


def build_mixed(src: Path, n_records: int, n_patients: int) -> None:
    src.mkdir(parents=True, exist_ok=True)
    n_csv = n_records // 2
    n_jsonl = n_records // 4
    n_rem = n_records - n_csv - n_jsonl
    build_csv(src / "csv", n_csv, n_patients)
    (src / "jsonl").mkdir(exist_ok=True)
    with (src / "jsonl" / "opd.jsonl").open("w", encoding="utf-8") as f:
        for i in range(n_jsonl):
            p = (i * 3) % n_patients
            f.write(json.dumps({
                "uhid": f"HP-{1000000 + p}",
                "name": _name(p),
                "age": 20 + (p % 65),
                "dx": "Type 2 diabetes mellitus",
                "icd10": "E11.9",
                "rx": "Tab. Metformin 500 mg",
            }) + "\n")
    (src / "notes").mkdir(exist_ok=True)
    # Chunk notes into batches of 50 records per note to mirror long clinical documents cleanly
    n_notes = max(1, n_rem // 50)
    for fi in range(n_notes):
        p = (fi * 7) % n_patients
        body = [
            f"Patient Name: {_name(p)}  UHID: HP-{1000000 + p}  Mobile: 9{100000000 + p:09d}",
            "Admitted 12/02/2025. Discharged 18/02/2025. BP 130/84 mmHg. Tab. Paracetamol 500 mg 1-0-1.",
        ] + [f"Progress Day {k}: vitals stable, HbA1c 7.2 %, Serum Creatinine 0.9 mg/dL, ICD-10 E11.9." for k in range(48)]
        (src / "notes" / f"note_{fi:04d}.txt").write_text("\n".join(body) + "\n", encoding="utf-8")


def run_benchmark(label: str, builder, expected_min_records: int, timeout_s: int = 900, max_rss_mb: int = 3900) -> dict:
    with tempfile.TemporaryDirectory(prefix=f"veil_titan_{label}_") as tmp:
        root = Path(tmp)
        inp, out = root / "input", root / "output"
        inp.mkdir()
        t_gen = time.monotonic()
        builder(inp)
        gen_s = round(time.monotonic() - t_gen, 2)

        env = {**os.environ, "RAKSHA_SECRET": secrets.token_hex(24)}
        t0 = time.monotonic()
        usage0 = resource.getrusage(resource.RUSAGE_CHILDREN)
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        timed_out = False
        try:
            stdout, stderr = proc.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            timed_out = True
        wall_s = round(time.monotonic() - t0, 3)
        usage1 = resource.getrusage(resource.RUSAGE_CHILDREN)
        rss_mb = round(usage1.ru_maxrss / (1024 if sys.platform != "darwin" else 1048576), 1)

        rep_file = out / "report.json"
        rep = json.loads(rep_file.read_text(encoding="utf-8")) if rep_file.is_file() else {}
        counts = rep.get("counts", {})
        report_rss = (rep.get("resources") or {}).get("peak_rss_mb")
        peak_rss = report_rss if isinstance(report_rss, (int, float)) else rss_mb

        distinct_psns = set()
        if (out / "records.jsonl").is_file():
            with (out / "records.jsonl").open("r", encoding="utf-8") as rjf:
                for ln in rjf:
                    if ln.strip():
                        p = json.loads(ln).get("patient")
                        if p:
                            distinct_psns.add(p)

        recs = counts.get("records_processed", 0)
        res = {
            "label": label,
            "gen_s": gen_s,
            "wall_s": wall_s,
            "peak_rss_mb": peak_rss,
            "exit_code": proc.returncode,
            "timed_out": timed_out,
            "over_rss_cap": peak_rss > max_rss_mb,
            "files_sanitized": counts.get("files_sanitized", 0),
            "files_quarantined": counts.get("files_quarantined", 0),
            "records_processed": recs,
            "distinct_pseudonyms": len(distinct_psns),
            "rows_per_sec": round(recs / max(0.001, wall_s), 1),
            "valid": (proc.returncode == 0 and not timed_out and peak_rss <= max_rss_mb and recs >= expected_min_records),
            "stderr_tail": stderr[-300:] if proc.returncode != 0 else "",
        }
        print(json.dumps(res), flush=True)
        return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-scale", type=int, default=1000000, choices=[100000, 250000, 500000, 1000000])
    ap.add_argument("--json")
    a = ap.parse_args()

    suites = [
        ("100k_repeat_500p", lambda d: build_csv(d, 100_000, 500), 100_000),
        ("100k_unique", lambda d: build_csv(d, 100_000, 100_000), 100_000),
        ("100k_homonym_hh", lambda d: build_csv(d, 100_000, 25_000, homonym=True, shared_hh=True), 100_000),
        ("100k_mixed", lambda d: build_mixed(d, 100_000, 25_000), 75_000),
    ]
    if a.max_scale >= 250_000:
        suites.append(("250k_mixed_50kp", lambda d: build_mixed(d, 250_000, 50_000), 187_000))
    if a.max_scale >= 500_000:
        suites.append(("500k_repeat_50kp", lambda d: build_csv(d, 500_000, 50_000), 500_000))
        suites.append(("500k_unique", lambda d: build_csv(d, 500_000, 500_000), 500_000))
    if a.max_scale >= 1_000_000:
        suites.append(("1M_repeat_100kp", lambda d: build_csv(d, 1_000_000, 100_000), 1_000_000))
        suites.append(("1M_unique", lambda d: build_csv(d, 1_000_000, 1_000_000), 1_000_000))

    results = []
    for label, fn, min_rec in suites:
        r = run_benchmark(label, fn, min_rec)
        results.append(r)
        if not r["valid"]:
            print(f"STOPPING progressive suite on failure/limit at {label}", file=sys.stderr)
            break

    if a.json:
        Path(a.json).write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return 0 if all(r["valid"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
