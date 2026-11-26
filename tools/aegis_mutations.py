#!/usr/bin/env python3
"""AEGIS verifier mutation test (dev-only; synthetic data; never part of the submission runtime).

    python3 tools/aegis_mutations.py --input <dataset input/> --release <clean VEIL output dir> --work <scratch dir>

Copies the clean release once per mutation into a separately labelled directory, injects exactly one
defect, and runs the Privacy Passport audit. The original release is never modified.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import veil_passport as VP  # noqa: E402


def _first(out: Path, pattern: str, ext: str):
    for p in sorted((out / "sanitized").rglob(f"*{ext}")):
        t = p.read_text(encoding="utf-8", errors="replace")
        m = re.search(pattern, t)
        if m:
            return p, t, m
    return None, None, None


def _append_txt(out: Path, line: str):
    p = sorted((out / "sanitized").rglob("*.txt"))[0]
    p.write_text(p.read_text(encoding="utf-8") + "\n" + line + "\n", encoding="utf-8")


def _records(out: Path):
    return (out / "records.jsonl").read_text(encoding="utf-8").splitlines()


def _write_records(out: Path, lines):
    (out / "records.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def m_pan(out, name):
    _append_txt(out, "PAN: ABCPD1234F")


def m_phone(out, name):
    _append_txt(out, "Call 9876501234")


def m_name(out, name):
    _append_txt(out, f"Seen with {name}")


def m_b64(out, name):
    _append_txt(out, "ref " + base64.b64encode(b"Mobile 9876501234").decode())


def m_dose(out, name):
    p, t, m = _first(out, r"(\d+)\s*mg\b", ".txt")
    p.write_text(t[: m.start(1)] + str(int(m.group(1)) + 50) + t[m.end(1):], encoding="utf-8")


def m_lab(out, name):
    p, t, m = _first(out, r"(\d+(?:\.\d+)?)\s*(?:g/dL|mg/dL|mmol/L)", ".txt")
    if p is None:
        p, t, m = _first(out, r"(\d+(?:\.\d+)?)\s*(?:g/dL|mg/dL|mmol/L)", ".csv")
    p.write_text(t[: m.start(1)] + str(round(float(m.group(1)) * 3 + 7, 1)) + t[m.end(1):], encoding="utf-8")


def m_duration(out, name):
    rx = r"\b(\d{2})-(\d{2})-(\d{4})\b"   # DD-MM-YYYY as used in the synthetic notes
    for p in sorted((out / "sanitized").rglob("*.txt")):
        t = p.read_text(encoding="utf-8")
        ds = list(re.finditer(rx, t))
        if len(ds) >= 2:
            m = ds[1]                                   # move the second (discharge) date: stay length changes
            day = int(m.group(1))
            nd = f"{day - 2:02d}" if day > 3 else f"{day + 2:02d}"
            p.write_text(t[: m.start(1)] + nd + t[m.end(1):], encoding="utf-8")
            return
    raise RuntimeError("no multi-date note")


def m_wrong_psn(out, name):
    lines = _records(out)
    recs = [json.loads(x) for x in lines]
    psns = sorted({r["patient"] for r in recs if r["patient"]})
    for i, r in enumerate(recs):
        if r["patient"]:
            r["patient"] = next(p for p in psns if p != r["patient"])
            lines[i] = json.dumps(r)
            break
    _write_records(out, lines)


def m_locator(out, name):
    lines = _records(out)
    for i, x in enumerate(lines):
        r = json.loads(x)
        if r["patient"] and r["loc"].startswith("row:"):
            r["loc"] = "row:99999"
            lines[i] = json.dumps(r)
            break
    _write_records(out, lines)


def m_missing(out, name):
    lines = _records(out)
    i = next(i for i, x in enumerate(lines) if json.loads(x)["patient"])
    _write_records(out, lines[:i] + lines[i + 1:])


def m_duplicate(out, name):
    lines = _records(out)
    i = next(i for i, x in enumerate(lines) if json.loads(x)["patient"])
    _write_records(out, lines + [lines[i]])


def m_fhir_ref(out, name):
    for p in sorted((out / "sanitized").rglob("*.json")):
        t = p.read_text(encoding="utf-8")
        m = re.search(r'"reference"\s*:\s*"([^"]+)"', t)
        if m and "resourceType" in t:
            p.write_text(t[: m.start(1)] + "urn:uuid:00000000-dead-beef-0000-000000000000" + t[m.end(1):], encoding="utf-8")
            return
    raise RuntimeError("no FHIR reference")


def m_extra_file(out, name):
    (out / "sanitized" / "unexpected_extra.txt").write_text("BP 120/80\n", encoding="utf-8")


def m_report_count(out, name):
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    rep["counts"]["records_processed"] += 1
    (out / "report.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")


def m_malformed(out, name):
    p = sorted((out / "sanitized").rglob("*.json"))[0]
    t = p.read_text(encoding="utf-8")
    p.write_text(t[: len(t) // 2], encoding="utf-8")


def m_dob_unshifted(out, name):
    """Genuine leak: put a patient's ORIGINAL birth date back into its sanitized DOB cell."""
    import csv, io
    inp = Path(os.environ["AEGIS_INPUT"])
    for o in sorted((out / "sanitized").rglob("*.csv")):
        rel = o.relative_to(out / "sanitized")
        src = inp / rel
        if not src.is_file():
            continue
        irows = list(csv.reader(io.StringIO(src.read_text(encoding="utf-8-sig", errors="replace"))))
        orows = list(csv.reader(io.StringIO(o.read_text(encoding="utf-8"))))
        if not irows or len(irows) != len(orows):
            continue
        for ci, h in enumerate(irows[0]):
            if re.search(r"(?i)\bdob\b|birth", h):
                for ri in range(1, len(irows)):
                    if ci < len(irows[ri]) and irows[ri][ci].strip() and ci < len(orows[ri]):
                        orows[ri][ci] = irows[ri][ci]
                        buf = io.StringIO(); csv.writer(buf, lineterminator="\n").writerows(orows)
                        o.write_text(buf.getvalue(), encoding="utf-8")
                        return
    raise RuntimeError("no aligned DOB column")


MUTATIONS = [
    ("PAN identifier", m_pan, "privacy"), ("phone number", m_phone, "privacy"), ("patient name", m_name, "privacy"),
    ("base64-encoded phone", m_b64, "privacy"), ("medication dose", m_dose, "clinical"), ("lab value", m_lab, "clinical"),
    ("clinical duration", m_duration, "temporal"), ("wrong pseudonym", m_wrong_psn, "identity"),
    ("broken locator", m_locator, "identity"), ("missing record", m_missing, "identity|structural"),
    ("duplicated record", m_duplicate, "identity|structural"), ("broken FHIR reference", m_fhir_ref, "structural"),
    ("unexpected output file", m_extra_file, "structural"), ("inaccurate report count", m_report_count, "structural"),
    ("malformed output", m_malformed, "structural"),
    ("unshifted birth date", m_dob_unshifted, "privacy"),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--release", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--name", required=True, help="a synthetic patient name present in the input")
    a = ap.parse_args()
    inp, rel, work = Path(a.input), Path(a.release), Path(a.work)
    os.environ["AEGIS_INPUT"] = str(inp)
    work.mkdir(parents=True, exist_ok=True)
    clean = VP.audit(inp, rel)
    fails = {k: c["status"] for k, c in clean["checks"].items() if c["status"] != "PASS"}
    print(f"CLEAN CONTROL  verdict={clean['verdict']}  non-pass={fails or 'none'}  risks={len(clean['residual_risks'])}")
    caught = 0
    for i, (label, fn, expect) in enumerate(MUTATIONS, 1):
        dst = work / f"MUTANT_{i:02d}_{re.sub(r'[^a-z]+', '_', label)}"
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(rel, dst)
        try:
            fn(dst, a.name)
        except Exception as exc:  # noqa: BLE001
            print(f"{i:02d} {label:24} SKIPPED (fixture lacks target: {exc})")
            continue
        try:
            R = VP.audit(inp, dst)
        except Exception as exc:  # noqa: BLE001
            print(f"{i:02d} {label:24} AUDIT ERROR {type(exc).__name__}")
            continue
        bad = sorted(k for k, c in R["checks"].items() if c["status"] in ("FAIL", "WARNING", "INCONCLUSIVE"))
        hit = R["verdict"] != "PASS"
        right = any(b in expect.split("|") for b in bad)
        caught += hit
        print(f"{i:02d} {label:24} verdict={R['verdict']:7} pillars={','.join(bad) or '-':28} expected={expect:20} {'DETECTED' if hit else 'MISSED'}{'' if right or not hit else ' (other pillar)'}")
    print(f"\n{caught}/{len(MUTATIONS)} mutations changed the verdict from PASS")
    assert rel.exists()
    return 0


if __name__ == "__main__":
    sys.exit(main())
