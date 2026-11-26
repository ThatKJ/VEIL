import json
import os
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


if __name__ == "__main__":
    unittest.main()
