import csv
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest


class PatientIdsTest(unittest.TestCase):
    def test_rejected_shared_identifier_cannot_rejoin_patients_at_export(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp = root / "input"
            inp.mkdir()
            with (inp / "register.csv").open("w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["MRN", "Name", "DOB", "Age"])
                w.writerows([["ZZ-123456", "Kavi Toma", "1982-01-10", "44"],
                             ["ZZ-123456", "Vina Tora", "2001-03-11", "25"],
                             ["ZZ-123456", "Kavi Toma", "1982-01-10", "44"]])
            out = root / "out"
            subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / "main.py"),
                            "--input", str(inp), "--output", str(out)], check=True,
                           capture_output=True, env={**os.environ, "RAKSHA_SECRET": secrets.token_hex(24)})
            ids = [json.loads(line)["patient"] for line in (out / "records.jsonl").read_text().splitlines()]
            self.assertTrue(all(ids))
            self.assertEqual(ids[0], ids[2])
            self.assertNotEqual(ids[0], ids[1])
