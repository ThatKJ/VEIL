import csv
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rakshak.lexicon import deva_to_latin, skel
from rakshak.pipeline import load_policy, run


class RegressionTests(unittest.TestCase):
    def _run_cli(self, inp: Path, out: Path, secret: str | None = None):
        env = {**os.environ, "RAKSHA_SECRET": secret or secrets.token_hex(24)}
        subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / "main.py"),
             "--input", str(inp), "--output", str(out)],
            check=True, capture_output=True, env=env,
        )

    def test_lab_dict_of_dicts_preserves_test_names_and_links_patient(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out = root / "input", root / "out"
            inp.mkdir()
            (inp / "report.json").write_text(json.dumps({
                "patient": {"MR No": "PID#B-04329", "naam": "Kavi Toma", "mobile": "9876-543-210"},
                "tests": {
                    "T1": {"name": "Haemoglobin", "result": "13.7", "unit": "g/dL"},
                    "T2": {"name": "Serum Creatinine", "result": "1.6", "unit": "mg/dL"},
                },
                "collected": "20230822",
            }), encoding="utf-8")
            (inp / "note.txt").write_text(
                "Dardi: Kavi Toma\nMR No:- PID#B-04329\nRiport: Serum Creatinine 1.6 mg/dL, Haemoglobin 13.7 g/dL\n",
                encoding="utf-8",
            )
            self._run_cli(inp, out)
            san_json = json.loads((out / "sanitized" / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(san_json["tests"]["T1"]["name"], "Haemoglobin")
            self.assertEqual(san_json["tests"]["T2"]["name"], "Serum Creatinine")
            self.assertNotEqual(san_json["collected"], "20230822")
            san_note = (out / "sanitized" / "note.txt").read_text(encoding="utf-8")
            self.assertIn("Serum Creatinine", san_note)
            self.assertIn("Haemoglobin", san_note)
            recs = [json.loads(line) for line in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(recs), 2)
            self.assertTrue(all(r["patient"] for r in recs))
            self.assertEqual(recs[0]["patient"], recs[1]["patient"])

    def test_multi_indic_transliteration_and_scrubbing(self):
        # Devanagari, Gurmukhi, and Bengali forms of a synthetic name should share skeleton
        self.assertEqual(skel("साहाश"), skel("ਸਾਹਾਸ਼"))
        self.assertEqual(skel("साहाश"), skel("সাহাশ"))
        self.assertTrue(deva_to_latin("यखा"))
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out = root / "input", root / "out"
            inp.mkdir()
            (inp / "ds.txt").write_text(
                "मरीज दा नाम: यखा बिस्वास\n"
                "ਨਾਮ: ਯਖਾ ਬਿਸ੍ਵਾਸ\n"
                "उमर: ੧੫ साल\n"
                "एम.आर. नं.: IP.23.16401\n"
                "फोन नं.: ੮੪੫੪੭੩੭੩੫੧\n",
                encoding="utf-8",
            )
            (inp / "opd.json").write_text(json.dumps({
                "meta": {"report_link": "https://his.example/opd?mr=IP.23.16401&fmt=json"},
                "visits": {"V0001": {"dardi": {"mr": "IP.23.16401", "naam": "Yakha Biswas", "phone": "+91(84547)37351"}}},
            }), encoding="utf-8")
            self._run_cli(inp, out)
            san_ds = (out / "sanitized" / "ds.txt").read_text(encoding="utf-8")
            self.assertNotIn("ਯਖਾ", san_ds)
            self.assertNotIn("੮੪੫੪੭੩੭੩੫੧", san_ds)
            self.assertIn("10-19", san_ds)
            self.assertIn("मरीज दा नाम:", san_ds)
            san_opd = (out / "sanitized" / "opd.json").read_text(encoding="utf-8")
            self.assertNotIn("16401", san_opd)
            recs = [json.loads(line) for line in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(recs[0]["patient"], recs[1]["patient"])

    def test_canaries_mojibake_cr_only_and_malformed_quarantine(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out = root / "input", root / "out"
            inp.mkdir()
            (inp / "claim.json").write_text(json.dumps({
                "claim": "CLM-1",
                "attachments": [{"file": "Fuqix_Zaxoq_consent.pdf", "pages": 2}],
            }), encoding="utf-8")
            (inp / "portal.log").write_text(
                "GET https://portal.example/report?patient=Xazhex+Zuzhiq&lang=gu 200\n",
                encoding="utf-8",
            )
            (inp / "mojibake.txt").write_bytes(
                "Dardi: नुभुन वोहरा\nBP 150/90\n".encode("utf-8").decode("latin-1").encode("utf-8")
            )
            (inp / "cr_only.csv").write_bytes(b"MRN,Name,Age\rIP.23.10001,Kavi Toma,30\r")
            (inp / "bad_quote.csv").write_text('MRN,Name\n1,"unterminated', encoding="utf-8")
            self._run_cli(inp, out)
            self.assertNotIn("Fuqix", (out / "sanitized" / "claim.json").read_text(encoding="utf-8"))
            self.assertNotIn("Xazhex", (out / "sanitized" / "portal.log").read_text(encoding="utf-8"))
            moji = (out / "sanitized" / "mojibake.txt").read_text(encoding="utf-8")
            self.assertNotIn("नुभुन", moji)
            self.assertNotIn("à¤", moji)
            self.assertIn("BP 150/90", moji)
            cr = (out / "sanitized" / "cr_only.csv").read_text(encoding="utf-8")
            self.assertNotIn("Kavi Toma", cr)
            self.assertFalse((out / "sanitized" / "bad_quote.csv").exists())
            rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(rep["counts"]["files_quarantined"], 1)


if __name__ == "__main__":
    unittest.main()
