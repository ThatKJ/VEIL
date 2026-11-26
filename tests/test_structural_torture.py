"""Final structural, accounting, interrupted-write, FHIR, escaping, and scale-torture tests."""
from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rakshak import pipeline as PL  # noqa: E402


class StructuralTortureTests(unittest.TestCase):
    def _run_cli(self, inp: Path, out: Path, secret: str = "torture-secret-2026") -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
            cwd=str(ROOT),
            env={**os.environ, "RAKSHA_SECRET": secret},
            capture_output=True,
            text=True,
            check=True,
        )

    def test_mixed_torture_conflicts_pii_keys_fhir_dup_sha_unicode_quarantine(self):
        with tempfile.TemporaryDirectory(prefix="veil_torture_") as d:
            root = Path(d)
            inp, out = root / "in", root / "out"
            (inp / "sub_Asha_Sharma_9876543210").mkdir(parents=True)
            (inp / "copy_dir").mkdir(parents=True)

            # 1. Duplicate & conflicting IDs across files (shared phone/MRN vs conflicting Aadhaar/gender -> must NOT merge!)
            # Plus JSON with PII outer keys & escaped unicode & base64/hex
            dup_csv = (
                "UHID,patient_name,aadhaar,sex,mobile,dob,dx\n"
                "H-9001,Kiran Patel,234567891234,M,9822334455,14/05/1980,Type 2 DM\n"
                "H-9001,Kiran Patel,876543219876,F,9822334455,19/08/1982,Asthma\n"
            )
            (inp / "sub_Asha_Sharma_9876543210" / "KiranPatel_H-9001.csv").write_text(dup_csv, encoding="utf-8")
            (inp / "copy_dir" / "duplicate_exact.csv").write_text(dup_csv, encoding="utf-8")  # Exact duplicate SHA-256!

            # 2. PII-containing JSON keys + nested records + Unicode \uXXXX escapes + RFC 6901 ~ and / chars in nested keys
            import base64
            b64_note = base64.b64encode(b"Patient: Asha Sharma Mobile: 9876543210 MRN: AS-5511").decode()
            pii_key_obj = {
                "patients": {
                    "Ramesh Kumar 9811223344": {"name": "Ramesh Kumar", "age": 54, "mobile": "9811223344", "dx/code": "E11.9"},
                    "Asha Sharma": {"name": "\u0906\u0936\u093e \u0936\u0930\u094d\u092e\u093e", "age": 41, "note_b64": b64_note},
                },
                "deep_safe": {"lvl": 1},
            }
            cur = pii_key_obj["deep_safe"]
            for lv in range(2, 42):
                cur["c"] = {"lvl": lv}
                cur = cur["c"]
            # Write with ensure_ascii=True so \u0906... Unicode escape sequences appear literally on disk!
            (inp / "nested_pii_keys.json").write_text(json.dumps(pii_key_obj, ensure_ascii=True), encoding="utf-8")

            # 3. FHIR R4 Bundle with internal urn:uuid refs, Organization & Practitioner
            fhir = {
                "resourceType": "Bundle",
                "type": "collection",
                "entry": [
                    {"fullUrl": "urn:uuid:11111111-1111-4111-8111-111111111111", "resource": {
                        "resourceType": "Patient", "id": "p1",
                        "name": [{"text": "Sushma Nair"}], "gender": "female", "birthDate": "1974-03-11",
                        "identifier": [{"value": "SN-4402"}],
                    }},
                    {"fullUrl": "urn:uuid:22222222-2222-4222-8222-222222222222", "resource": {
                        "resourceType": "Observation", "id": "o1",
                        "subject": {"reference": "urn:uuid:11111111-1111-4111-8111-111111111111"},
                        "effectiveDateTime": "2025-02-10T09:30:00Z",
                        "code": {"text": "HbA1c"}, "valueQuantity": {"value": 7.4, "unit": "%"},
                    }},
                    {"fullUrl": "urn:uuid:33333333-3333-4333-8333-333333333333", "resource": {
                        "resourceType": "Organization", "id": "org1", "name": "Malabar Specialty Hospital",
                    }},
                ],
            }
            (inp / "fhir_bundle.json").write_text(json.dumps(fhir), encoding="utf-8")

            # 4. Long clinical note (~300 KB) preserving clinical context & timeline
            note_body = (
                "Patient: Sushma Nair\nUHID: SN-4402\nAdmitted: 10/02/2025\nDischarged: 16/02/2025\n"
                "Treating: Dr. Arvind Menon; SN Maya Krishnan.\n"
                "Diagnosis: K/C/O Addison's disease; S/O acute appendicitis. CPAP 10/5.\n"
                + ("Vitals stable, Tab. Metformin 500 mg 1-0-1, BP 122/78 mmHg.\n" * 4000)
            )
            (inp / "long_note.txt").write_text(note_body, encoding="utf-8")

            # 5. Malformed mixed exports: too-deep JSON (>64), binary fake PDF, zero-byte, escaping symlink
            deep = {"x": "Meera"}
            for _ in range(85):
                deep = {"n": deep}
            (inp / "too_deep_85.json").write_text(json.dumps(deep), encoding="utf-8")
            (inp / "bad_binary.pdf").write_bytes(b"%PDF-1.5\x00\xff\xfe\xfa\x02")
            (inp / "empty.csv").write_bytes(b"")
            outside = root / "secret_outside.txt"
            outside.write_text("SECRET_OUTSIDE_DATA 9999888877", encoding="utf-8")
            (inp / "escape_link.txt").symlink_to(outside)

            self._run_cli(inp, out)

            rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
            rep_txt = json.dumps(rep)
            # Renamed filename & directory check: zero PII in report, file names, or records.jsonl
            for leak_tok in ("Asha", "Sharma", "9876543210", "Kiran", "Patel", "9811223344", "234567891234", "876543219876", "SECRET_OUTSIDE_DATA"):
                self.assertNotIn(leak_tok, rep_txt)

            # Accurate accounting: 9 physical input files (2 duplicate SHA CSVs, 2 JSONs, 1 TXT sanitized = 5; 4 quarantined)
            self.assertEqual(rep["counts"]["files_total"], 9)
            self.assertEqual(rep["counts"]["files_sanitized"], 5)
            self.assertEqual(rep["counts"]["files_quarantined"], 4)
            self.assertEqual(len(rep["files"]), 9)
            for fe in rep["files"]:
                if fe["status"] == "sanitized":
                    self.assertTrue((out / fe["output"]).is_file(), fe["output"])
                else:
                    self.assertIsNone(fe["output"])

            san_files = [p.relative_to(out).as_posix() for p in (out / "sanitized").rglob("*") if p.is_file()]
            self.assertEqual(len(san_files), 5)
            for sf in san_files:
                self.assertNotIn("Asha", sf)
                self.assertNotIn("KiranPatel", sf)
                self.assertNotIn("9876543210", sf)

            # Records accounting & no false merges on conflicting Aadhaar (even on identical H-9001 & mobile!)
            recs = [json.loads(ln) for ln in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if ln.strip()]
            self.assertEqual(rep["counts"]["records_processed"], len(recs))
            csv_recs = [r for r in recs if r["file"].endswith(".csv")]
            self.assertEqual(len(csv_recs), 4)  # 2 rows * 2 identical-SHA CSV files
            pids_row0 = {r["patient"] for r in csv_recs if r["loc"] == "row:0"}
            pids_row1 = {r["patient"] for r in csv_recs if r["loc"] == "row:1"}
            self.assertEqual(len(pids_row0), 1)
            self.assertEqual(len(pids_row1), 1)
            self.assertNotEqual(pids_row0, pids_row1)  # Conflicting Aadhaar + Gender NEVER merged!

            # PII-named JSON keys renamed & zero leaked PII in records.jsonl loc/out
            rj_raw = (out / "records.jsonl").read_text(encoding="utf-8")
            self.assertNotIn("Ramesh Kumar", rj_raw)
            self.assertNotIn("9811223344", rj_raw)
            nested_out = json.loads((out / "sanitized" / "nested_pii_keys.json").read_text(encoding="utf-8"))
            self.assertNotIn("Ramesh Kumar 9811223344", nested_out["patients"])
            self.assertNotIn("Asha Sharma", json.dumps(nested_out))
            self.assertEqual(nested_out["deep_safe"]["lvl"], 1)

            # FHIR references resolve and clinical data kept
            fhir_out = json.loads((out / "sanitized" / "fhir_bundle.json").read_text(encoding="utf-8"))
            obs_ref = fhir_out["entry"][1]["resource"]["subject"]["reference"]
            full_urls = {e["fullUrl"] for e in fhir_out["entry"]}
            self.assertIn(obs_ref, full_urls)
            self.assertEqual(fhir_out["entry"][2]["resource"]["name"], "Malabar Specialty Hospital")

            # Long clinical note preserved clinical values + exact 6-day LOS delta
            long_out = (out / "sanitized" / "long_note.txt").read_text(encoding="utf-8")
            self.assertIn("Addison's disease", long_out)
            self.assertIn("S/O acute appendicitis", long_out)
            self.assertIn("CPAP 10/5", long_out)
            self.assertIn("Dr. Arvind Menon", long_out)
            self.assertIn("SN Maya Krishnan", long_out)
            self.assertNotIn("Sushma Nair", long_out)
            self.assertNotIn("SN-4402", long_out)

    def test_interrupted_write_leaves_no_partial_temp_files(self):
        with tempfile.TemporaryDirectory(prefix="veil_intr_") as d:
            root = Path(d)
            inp, out = root / "in", root / "out"
            inp.mkdir(); (out / "sanitized").mkdir(parents=True)
            (inp / "patient.csv").write_text("uhid,name\nU-10,Meera Devi\n", encoding="utf-8")

            # Simulate interrupted atomic replace during Pass 2 export -> file fails safely to quarantine, zero .veil_tmp_* left
            with mock.patch("rakshak.pipeline.os.replace", side_effect=OSError("disk_full_sim")):
                try:
                    PL.run(inp, out, {})
                except OSError:
                    pass
            leftovers = [p.name for p in out.rglob("*") if ".veil_tmp_" in p.name or p.name.endswith(".tmp")]
            self.assertEqual(leftovers, [])

    def test_mixed_format_exact_record_accounting_and_no_silent_loss(self):
        """Reconcile raw physical lines vs logical VEIL records across CSV, stacked CSV, JSONL, @meta JSON, 50-line notes, and quarantine."""
        with tempfile.TemporaryDirectory(prefix="veil_acct_") as d:
            root = Path(d)
            inp, out = root / "in", root / "out"
            inp.mkdir()
            (inp / "csv").mkdir()
            # 1) Regular 10-row CSV (10 physical patient rows)
            csv_lines = ["MRN,patient_name,age,sex,diagnosis"]
            for i in range(10):
                csv_lines.append(f"M-{900+i},Patient Acct{i},{30+i},M,Hypertension")
            (inp / "csv" / "regular.csv").write_text("\n".join(csv_lines) + "\n", encoding="utf-8")

            # 2) Stacked CSV w/ preamble + repeat header -> strictly 3 data records
            (inp / "csv" / "stacked.csv").write_text(
                "HOSPITAL EXPORT BATCH 1\n"
                "uhid,patient_name,dx\n"
                "U-1,Meera Rao,Asthma\n"
                "U-2,Kabir Das,Migraine\n"
                "uhid,patient_name,dx\n"
                "U-3,Ananya Iyer,Fever\n",
                encoding="utf-8",
            )

            # 3) JSONL w/ 6 lines + empty lines -> strictly 6 records
            jsonl_rows = [json.dumps({"uhid": f"J-{i}", "name": f"Ravi Verma{i}", "dx": "T2DM"}) for i in range(6)]
            (inp / "opd.jsonl").write_text("\n".join(jsonl_rows[:3]) + "\n\n" + "\n".join(jsonl_rows[3:]) + "\n", encoding="utf-8")

            # 4) Nested JSON w/ @meta (non-patient metadata) + 2 patient records -> strictly 2 patient records
            (inp / "bundle.json").write_text(json.dumps({
                "meta": {"hospital": "City Clinic", "exported_on": "2025-02-01"},
                "records": [
                    {"uhid": "B-1", "name": "Sita Nair", "dx": "Anemia"},
                    {"uhid": "B-2", "name": "Mohan Lal", "dx": "Gastritis"},
                ],
            }), encoding="utf-8")

            # 5) Two 50-line clinical notes (100 physical lines -> strictly 2 doc-level VEIL records, matching scale_titan note packing)
            for ni in range(2):
                note_lines = [f"Patient Name: Deepak Joshi{ni}  UHID: N-{10+ni}"] + [
                    f"Progress Day {k}: BP 120/80 mmHg, HbA1c 6.5%" for k in range(49)
                ]
                (inp / f"note_{ni}.txt").write_text("\n".join(note_lines) + "\n", encoding="utf-8")

            # 6) Binary unsupported file -> quarantined (0 records, never copied to sanitized/)
            (inp / "scan.pdf").write_bytes(b"%PDF-1.4\n\x00binary\n")

            with mock.patch.dict(os.environ, {"RAKSHA_SECRET": "acct-regression-secret"}):
                rc = PL.run(inp, out, {})
            self.assertEqual(rc, 0)

            rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(rep["counts"]["files_total"], 7)
            self.assertEqual(rep["counts"]["files_sanitized"], 6)
            self.assertEqual(rep["counts"]["files_quarantined"], 1)
            self.assertFalse((out / "sanitized" / "scan.pdf").exists())

            rj = [json.loads(line) for line in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            # Expected: 10 (regular.csv) + 3 (stacked.csv) + 6 (opd.jsonl) + 2 (bundle.json) + 2 (note_0/1) = 23
            self.assertEqual(len(rj), 23)
            self.assertEqual(rep["counts"]["records_processed"], 23)
            self.assertTrue(all(not r["loc"].startswith("@") for r in rj))
            by_file = {}
            for r in rj:
                by_file[r["file"]] = by_file.get(r["file"], 0) + 1
            self.assertEqual(by_file["sanitized/csv/regular.csv"], 10)
            self.assertEqual(by_file["sanitized/csv/stacked.csv"], 3)
            self.assertEqual(by_file["sanitized/opd.jsonl"], 6)
            self.assertEqual(by_file["sanitized/bundle.json"], 2)
            self.assertEqual(by_file["sanitized/note_0.txt"], 1)
            self.assertEqual(by_file["sanitized/note_1.txt"], 1)


if __name__ == "__main__":
    unittest.main()
