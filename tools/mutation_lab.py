#!/usr/bin/env python3
"""VEIL TITAN Adversarial Mutation Laboratory (dev-only test generator & invariant auditor).

Generates diverse semantic variants across encodings, CSV dialects, header/column aliases,
mixed Indic scripts & digits, HTML/URL/Base64/Hex hidden channels, stacked/EAV/nested schemas,
zero-width obfuscation, homonyms, shared household IDs, clinical/ID number collisions, long
clinical notes, and malformed binary traps with independent ground truth.
"""
from __future__ import annotations

import base64
import csv
import datetime as dt
import io
import json
import os
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import veil_passport as VP  # noqa: E402

DEVA_TRANS = str.maketrans("0123456789", "०१२३४५६७८९")


def generate_mutation_suite(inp: Path, variant: str = "standard") -> dict:
    """Create a rich, multi-channel synthetic hospital input tree and return independent ground truth."""
    inp.mkdir(parents=True, exist_ok=True)
    # 5 independent synthetic truth patients (canonical truth independent of VEIL)
    patients = {
        "PT_ARJUN": {
            "name_en": "Arjun Verma",
            "name_deva": "अर्जुन वर्मा",
            "uhid": "UH-91-1001",
            "aadhaar": "4123 7781 9024",
            "phone": "9812345670",
            "dob": dt.date(1980, 4, 15),
            "age": 45,
            "gender": "M",
            "district": "Lucknow",
            "pin": "226001",
        },
        "PT_MEERA_1": {
            "name_en": "Meera Nair",
            "name_ml": "മീര നായര",
            "uhid": "UH-91-2001",
            "aadhaar": "5234 8891 1029",
            "phone": "9822211100",
            "dob": dt.date(1991, 9, 8),
            "age": 34,
            "gender": "F",
            "district": "Kozhikode",
            "pin": "673001",
            "relative": "D/O Balan Nair",
        },
        "PT_MEERA_2": {
            "name_en": "Meera Nair",  # Homonym trap!
            "uhid": "UH-91-2002",
            "aadhaar": "6345 9901 2038",
            "phone": "9833344455",
            "dob": dt.date(1962, 11, 20),
            "age": 63,
            "gender": "F",
            "district": "Kozhikode",
            "pin": "673002",
            "relative": "W/O Soman Nair",
        },
        "PT_HH_SON": {
            "name_en": "Rohan Sharma",
            "uhid": "UH-91-3001",
            "phone": "9844455566",
            "household_ration": "RC-55667788",
            "dob": dt.date(1998, 2, 12),
            "age": 28,
            "gender": "M",
            "district": "Sitapur",
            "pin": "261001",
        },
        "PT_HH_MOTHER": {
            "name_en": "Sunita Sharma",  # Shares ration_card + village with Rohan Sharma
            "uhid": "UH-91-3002",
            "phone": "9855566677",
            "household_ration": "RC-55667788",
            "dob": dt.date(1968, 7, 19),
            "age": 57,
            "gender": "F",
            "district": "Sitapur",
            "pin": "261001",
            "icd": "E83.0",  # Rare disease escalation
        },
    }

    # 1. Dialect, encoding & column-permutation mutation on registration table
    reg_dir = inp / "reg"
    reg_dir.mkdir()
    p1 = patients["PT_ARJUN"]
    m1 = patients["PT_MEERA_1"]
    m2 = patients["PT_MEERA_2"]
    h1 = patients["PT_HH_SON"]
    h2 = patients["PT_HH_MOTHER"]

    if variant == "mutated":
        delim = ";"
        enc = "utf-16-le"
        bom = b"\xff\xfe"
        cols = ["RationCard", "District", "Mobile", "DOB", "Sex", "Age", "Patient_Name", "UHID", "PIN"]
        fmt_date = lambda d: d.strftime("%d.%m.%Y").translate(DEVA_TRANS)
    else:
        delim = ","
        enc = "utf-8"
        bom = b"\xef\xbb\xbf"
        cols = ["UHID", "Patient_Name", "Age", "Gender", "DOB", "Mobile", "District", "PIN", "Ration_Card"]
        fmt_date = lambda d: d.strftime("%d/%m/%Y")

    rows = [cols]
    for pt in (p1, m1, m2, h1, h2):
        # Inject zero-width joiner obfuscation in mutated variant
        nm = ("Arjun\u200b Verma" if variant == "mutated" and pt is p1 else pt["name_en"])
        if variant == "mutated":
            rows.append([
                pt.get("household_ration", "RC-000111"), pt["district"], pt["phone"],
                fmt_date(pt["dob"]), pt["gender"], str(pt["age"]), nm, pt["uhid"], pt["pin"],
            ])
        else:
            rows.append([
                pt["uhid"], nm, str(pt["age"]), pt["gender"],
                fmt_date(pt["dob"]), pt["phone"], pt["district"], pt["pin"], pt.get("household_ration", "RC-000111"),
            ])
    buf = io.StringIO()
    csv.writer(buf, delimiter=delim).writerows(rows)
    (reg_dir / "admissions.csv").write_bytes(bom + buf.getvalue().encode(enc))

    # 2. Mixed scripts + coded/stringified JSON + encoded HTML/URL/Base64/Hex attachments
    opd_dir = inp / "opd"
    opd_dir.mkdir()
    secret_payload = base64.b64encode(f"Patient: {p1['name_en']} | Aadhaar: {p1['aadhaar']}".encode()).decode()
    hex_payload = f"Mobile {m1['phone']}".encode().hex()
    visits_obj = {
        "column_codes": {"c1": "op_no", "c2": "patient_name", "c3": "mobile", "c4": "aadhaar", "c5": "diagnosis", "c6": "icd10"},
        "records": [
            json.dumps({
                "c1": p1["uhid"],
                "c2": unicodedata.normalize("NFKD", p1["name_deva"]),
                "c3": p1["phone"],
                "c4": p1["aadhaar"],
                "c5": "Type 2 diabetes mellitus",
                "c6": "E11.9",
                "attachment_b64": secret_payload,
            }, ensure_ascii=False),
            json.dumps({
                "c1": m1["uhid"],
                "c2": m1["name_ml"],
                "c3": m1["phone"],
                "c4": m1["aadhaar"],
                "c5": "Hypertension",
                "c6": "I10",
                "trace_hex": hex_payload,
            }, ensure_ascii=False),
            json.dumps({
                "c1": m2["uhid"],
                "c2": m2["name_en"],
                "c3": m2["phone"],
                "c4": m2["aadhaar"],
                "c5": "Osteoarthritis",
                "c6": "M19.9",
            }, ensure_ascii=False),
        ],
    }
    (opd_dir / "visits.json").write_text(json.dumps(visits_obj, ensure_ascii=False, indent=2), encoding="utf-8")

    # 3. Long clinical note + HTML entities + URL tel/wa.me + leap year chronology + platelet/PIN collision
    notes_dir = inp / "notes"
    notes_dir.mkdir()
    filler = "\n".join(
        f"Day {k}: Vitals stable BP 124/78 mmHg; Platelet count 226001 /cumm; HbA1c 6.8 %; Tab. Metformin 500 mg 1-0-1."
        for k in range(1, 25)
    )
    note_txt = (
        f"Patient Name: {p1['name_en']}    UHID: {p1['uhid']}\n"
        f"Admitted: 28/02/2024. Discharged: 05/03/2024.\n"  # Spans 2024 leap day (6-day LOS)
        f"Attending: Dr. Anand Kulkarni; Nursing: N/O Priya Menon\n"
        f"Contact portal: https://wa.me/91{p1['phone']} | call tel:{p1['phone']}\n"
        f"HTML tag note: &#65;&#114;&#106;&#117;&#110;\n"
        f"{filler}\n"
        f"-----BEGIN STRUCTURED-----\n"
        + json.dumps({"uhid": p1["uhid"], "patient_name": p1["name_en"], "pin": p1["pin"], "los_days": 6})
        + "\n-----END STRUCTURED-----\n"
    )
    (notes_dir / "arjun_long_note.txt").write_text(note_txt, encoding="utf-8")

    # 4. EAV CSV + clean clinical note + binary/deeply-nested malformed safety traps
    lab_dir = inp / "lab"
    lab_dir.mkdir()
    with (lab_dir / "eav_panel.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["UHID", "Attribute", "Value", "Date"])
        w.writerow([h2["uhid"], "Hemoglobin", "11.4 g/dL", "2024-02-29"])  # Valid leap year ISO date
        w.writerow([h2["uhid"], "ICD10", h2["icd"], "2024-02-29"])
        w.writerow([h1["uhid"], "Platelet count", "261001 /cumm", "2024-02-29"])  # Numeric match with PIN 261001!

    sec_dir = inp / "quarantine_test"
    sec_dir.mkdir()
    (sec_dir / "corrupt.bin").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00invalid_scan_payload")
    deep_json = "{" * 90 + '"a": 1' + "}" * 90
    (sec_dir / "too_deep.json").write_text(deep_json, encoding="utf-8")

    return {"patients": patients, "variant": variant}


def verify_semantic_invariants(inp: Path, out: Path, meta: dict) -> dict:
    """Assert security, linkage, clinical, temporal, and Assurance 3.0 invariants without fixed bytes."""
    passport = VP.audit(inp, out)
    pts = meta["patients"]
    rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    by_sha = {e["input_sha256"]: e for e in rep["files"]}
    recs = {}
    for ln in (out / "records.jsonl").read_text(encoding="utf-8").splitlines():
        if ln.strip():
            r = json.loads(ln)
            recs[(r["file"], r["loc"])] = r.get("patient")

    # Identify output filenames cleanly via SHA-256
    reg_out = by_sha[VP.hashlib.sha256((inp / "reg" / "admissions.csv").read_bytes()).hexdigest()]["output"]
    visits_out = by_sha[VP.hashlib.sha256((inp / "opd" / "visits.json").read_bytes()).hexdigest()]["output"]
    note_out = by_sha[VP.hashlib.sha256((inp / "notes" / "arjun_long_note.txt").read_bytes()).hexdigest()]["output"]
    eav_out = by_sha[VP.hashlib.sha256((inp / "lab" / "eav_panel.csv").read_bytes()).hexdigest()]["output"]

    psn_arjun_reg = recs[(reg_out, "row:0")]
    psn_meera1_reg = recs[(reg_out, "row:1")]
    psn_meera2_reg = recs[(reg_out, "row:2")]
    psn_rohan_reg = recs[(reg_out, "row:3")]
    psn_sunita_reg = recs[(reg_out, "row:4")]

    psn_arjun_json = recs[(visits_out, "/records/0")]
    psn_meera1_json = recs[(visits_out, "/records/1")]
    psn_meera2_json = recs[(visits_out, "/records/2")]
    psn_arjun_note = recs[(note_out, "doc")]
    psn_sunita_eav = recs[(eav_out, "row:0")]
    psn_rohan_eav = recs[(eav_out, "row:2")]

    checks = {
        "quarantined_malformed": rep["counts"]["files_quarantined"] == 2,
        "zero_residual_hits": not passport["privacy"]["residual_pattern_hits"],
        "arjun_linked_across_script_dialect_note": len({psn_arjun_reg, psn_arjun_json, psn_arjun_note}) == 1 and psn_arjun_reg is not None,
        "meera1_linked_across_malayalam": psn_meera1_reg == psn_meera1_json and psn_meera1_reg is not None,
        "meera2_linked": psn_meera2_reg == psn_meera2_json and psn_meera2_reg is not None,
        "homonyms_never_merged": psn_meera1_reg != psn_meera2_reg,
        "household_ration_never_merged": psn_rohan_reg != psn_sunita_reg,
        "eav_linked_correctly": psn_sunita_eav == psn_sunita_reg and psn_rohan_eav == psn_rohan_reg,
        "platelet_226001_preserved": "226001 /cumm" in (out / note_out).read_text(encoding="utf-8"),
        "platelet_261001_preserved": "261001 /cumm" in (out / eav_out).read_text(encoding="utf-8"),
        "leap_los_preserved": passport["temporal"]["intervals_failed"] == 0 and passport["temporal"]["intervals_passed"] >= 1,
        "clinical_100pct": passport["clinical"]["protected_values_kept_pct"] == 100.0,
        "passport_record_identity_pass": passport["checks"]["identity"]["status"] == "PASS",
        "passport_structural_pass": passport["checks"]["structural"]["status"] == "PASS",
    }
    return {"variant": meta["variant"], "checks": checks, "all_passed": all(checks.values()), "passport": passport}


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="veil_mutlab_") as td:
        for variant in ("standard", "mutated"):
            inp = Path(td) / f"in_{variant}"
            out = Path(td) / f"out_{variant}"
            meta = generate_mutation_suite(inp, variant)
            env = {**os.environ, "RAKSHA_SECRET": "mutation-lab-secret-01"}
            subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                           env=env, check=True, capture_output=True)
            res = verify_semantic_invariants(inp, out, meta)
            print(json.dumps({"variant": variant, "all_passed": res["all_passed"], "checks": res["checks"]}))
            if not res["all_passed"]:
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
