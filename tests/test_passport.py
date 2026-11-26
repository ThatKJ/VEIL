import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import veil_passport as V  # noqa: E402


class PassportTests(unittest.TestCase):
    def test_clean_release_passes_and_injected_defect_is_caught(self):
        with tempfile.TemporaryDirectory() as d:
            inp, out = Path(d) / "in", Path(d) / "out"
            inp.mkdir()
            (inp / "reg.csv").write_text("UHID,Patient Name,Mobile\nAB-1001,Meera Devi Rajput,9876501234\n", encoding="utf-8")
            (inp / "note.txt").write_text("Patient Name: Meera Devi Rajput\nUHID: AB-1001\nAdmitted 03/02/2026, discharged 09/02/2026.\n"
                                          "Tab Metformin 500 mg BD. BP 130/80. HbA1c 7.2 %\n", encoding="utf-8")
            subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                           check=True, capture_output=True, env={**os.environ, "RAKSHA_SECRET": "t" * 32})
            clean = V.audit(inp, out)
            self.assertEqual(clean["privacy"]["residual_pattern_hits"], {})
            self.assertEqual(clean["clinical"]["protected_values_kept_pct"], 100.0)
            self.assertTrue(clean["structural"]["report_counts_consistent"])
            note = next((out / "sanitized").glob("note*.txt"))
            note.write_text(note.read_text(encoding="utf-8").replace("500 mg", "550 mg") + "\nCall 9876501234\n", encoding="utf-8")
            bad = V.audit(inp, out)
            self.assertGreaterEqual(bad["privacy"]["residual_pattern_hits"].get("phone", 0), 1)
            self.assertLess(bad["clinical"]["protected_values_kept_pct"], 100.0)
            self.assertEqual(len(bad["residual_risks"]), 2)

    def test_duplicate_sha_physical_files_counted_individually(self):
        with tempfile.TemporaryDirectory() as d:
            inp, out = Path(d) / "in", Path(d) / "out"
            (inp / "sub").mkdir(parents=True)
            csv_body = "UHID,Patient Name,Mobile\nAB-2001,Kavitha Ramesh,9876543210\n"
            (inp / "reg.csv").write_text(csv_body, encoding="utf-8")
            (inp / "sub" / "reg_copy.csv").write_text(csv_body, encoding="utf-8")
            subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                           check=True, capture_output=True, env={**os.environ, "RAKSHA_SECRET": "t" * 32})
            clean = V.audit(inp, out)
            st = clean["structural"]
            self.assertEqual(st["input_files"], 2)
            self.assertEqual(st["accounted_in_report"], 2)
            self.assertEqual(st["exported"], 2)
            self.assertTrue(st["report_counts_consistent"])
            rendered = json.dumps(clean) + V.render_html(clean, None)
            self.assertNotIn("Kavitha Ramesh", rendered)
            self.assertNotIn("9876543210", rendered)

    def test_assurance3_institutional_discrimination_and_cross_record_temporal(self):
        with tempfile.TemporaryDirectory() as d:
            inp, out = Path(d) / "in", Path(d) / "out"
            inp.mkdir()
            (inp / "fhir.json").write_text(json.dumps({
                "resourceType": "Bundle",
                "type": "collection",
                "entry": [
                    {"fullUrl": "Patient/1", "resource": {"resourceType": "Patient", "id": "1",
                        "name": [{"text": "Asha Kumari"}], "birthDate": "1985-04-12",
                        "identifier": [{"value": "UH-7701"}]}},
                    {"fullUrl": "Organization/1", "resource": {"resourceType": "Organization", "id": "1",
                        "name": "Arogya Seva Sadan"}},
                ],
            }), encoding="utf-8")
            (inp / "visits.csv").write_text(
                "uhid,patient_name,visit_date\n"
                "UH-7701,Asha Kumari,10/01/2026\n"
                "UH-7701,Asha Kumari,20/01/2026\n",
                encoding="utf-8",
            )
            subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                           check=True, capture_output=True, env={**os.environ, "RAKSHA_SECRET": "a3-test-secret"})
            clean = V.audit(inp, out)
            self.assertEqual(clean["assurance_version"], "3.0")
            self.assertEqual(clean["verdict"], "PASS")
            self.assertEqual(clean["privacy"]["residual_pattern_hits"], {})
            self.assertGreaterEqual(clean["privacy"]["institutional_entities_distinguished"], 1)
            self.assertEqual(clean["checks"]["temporal"]["status"], "PASS")

            # Contaminating institutional name with an unredacted patient ID/name on same line must FAIL
            fhir_out = next((out / "sanitized").glob("fhir*.json"))
            raw_txt = fhir_out.read_text(encoding="utf-8")
            fhir_out.write_text(raw_txt.replace("Arogya Seva Sadan", "Arogya Seva Sadan Patient: Rahul Verma 9811223344"), encoding="utf-8")
            contam = V.audit(inp, out)
            self.assertEqual(contam["checks"]["privacy"]["status"], "FAIL")
            self.assertGreaterEqual(contam["privacy"]["residual_pattern_hits"].get("institutional_contaminated", 0), 1)
            self.assertEqual(contam["verdict"], "FAIL")

            # Restoring clean JSON and corrupting ONE row's date shift must FAIL temporal chronology
            fhir_out.write_text(raw_txt, encoding="utf-8")
            csv_out = next((out / "sanitized").glob("visits*.csv"))
            lines = csv_out.read_text(encoding="utf-8").splitlines()
            lines[2] = re.sub(r"\d{2}/\d{2}/\d{4}", "01/01/2028", lines[2])
            csv_out.write_text("\n".join(lines) + "\n", encoding="utf-8")
            bad_t = V.audit(inp, out)
            self.assertEqual(bad_t["checks"]["temporal"]["status"], "FAIL")
            self.assertEqual(bad_t["verdict"], "FAIL")

    def test_omega_honest_verdict_parse_fail_and_jsonl_harvest(self):
        """Assurance 3.0 handles 0-clinical N/A, JSONL harvest, malformed output fail & path traversal."""
        with tempfile.TemporaryDirectory() as d:
            inp, out = Path(d) / "in", Path(d) / "out"
            inp.mkdir()
            (inp / "roster.jsonl").write_text(
                json.dumps({"patient_name": "Deepak Kulkarni", "uhid": "DK-991", "mobile": "9820012345"}) + "\n",
                encoding="utf-8",
            )
            subprocess.run(
                [sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                check=True,
                capture_output=True,
                env={**os.environ, "RAKSHA_SECRET": "omega-pp-test"},
            )
            clean = V.audit(inp, out)
            self.assertIsNone(clean["clinical"]["protected_values_kept_pct"])
            self.assertGreaterEqual(clean["privacy"]["independent_identity_values_from_input"], 1)
            self.assertNotIn(clean["verdict"], ("FAIL",))

            # Corrupt output JSONL -> outputs_parse_fail >= 1 and verdict == FAIL
            out_jsonl = next((out / "sanitized").glob("roster*.jsonl"))
            saved = out_jsonl.read_text(encoding="utf-8")
            out_jsonl.write_text("{broken json\n", encoding="utf-8")
            bad = V.audit(inp, out)
            self.assertGreaterEqual(bad["structural"]["outputs_parse_fail"], 1)
            self.assertEqual(bad["checks"]["structural"]["status"], "FAIL")
            self.assertEqual(bad["verdict"], "FAIL")

            # Restore clean JSONL and verify records.jsonl path traversal triggers structural failure
            out_jsonl.write_text(saved, encoding="utf-8")
            rj = out / "records.jsonl"
            rj_orig = rj.read_text(encoding="utf-8")
            rj_obj = json.loads(rj_orig.splitlines()[0])
            rj_obj["file"] = "../../outside.jsonl"
            rj.write_text(json.dumps(rj_obj) + "\n", encoding="utf-8")
            trav = V.audit(inp, out)
            self.assertEqual(trav["verdict"], "FAIL")


if __name__ == "__main__":
    unittest.main()
