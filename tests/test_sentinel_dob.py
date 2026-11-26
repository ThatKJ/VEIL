"""SENTINEL: birth dates in unfamiliar formats/labels are never exported unchanged; the Passport detects a
genuinely unshifted DOB cell and does not flag correctly shifted ones (dates generated independently)."""
from __future__ import annotations

import csv
import io
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import veil_passport as VP  # noqa: E402

FORMATS = [("%d/%m/%Y", "DOB"), ("%d-%m-%Y", "Date of Birth"), ("%Y-%m-%d", "Birth Date"),
           ("%d.%m.%Y", "Janam Tithi"), ("%Y/%m/%d", "D.O.B.")]


class TestSentinelDob(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rng = random.Random(20261127)
        cls.td = Path(tempfile.mkdtemp(prefix="sentinel_dob_"))
        cls.inp, cls.out = cls.td / "input", cls.td / "output"
        cls.inp.mkdir()
        cls.files = {}
        for k, (fmt, header) in enumerate(FORMATS):
            rows = [["UHID", "Patient Name", "Gender", header, "Reg Date"]]
            for i in range(12):
                dob = date(1940, 1, 1) + timedelta(days=rng.randrange(0, 30000))
                reg = date(2024, 1, 1) + timedelta(days=rng.randrange(0, 600))
                rows.append([f"HX{k}-{40000 + i}", f"Patient{k}{i} Test{i}", "F" if i % 2 else "M",
                             dob.strftime(fmt), reg.strftime("%d/%m/%Y")])
            buf = io.StringIO()
            csv.writer(buf, lineterminator="\n").writerows(rows)
            name = f"reg_{k}.csv"
            (cls.inp / name).write_text(buf.getvalue(), encoding="utf-8")
            cls.files[name] = rows
        env = {**os.environ, "RAKSHA_SECRET": "sentinel-dob-test"}
        subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(cls.inp), "--output", str(cls.out)],
                       check=True, env=env, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td, ignore_errors=True)

    def _out_rows(self, name):
        rep = json.loads((self.out / "report.json").read_text(encoding="utf-8"))
        import hashlib
        sha = hashlib.sha256((self.inp / name).read_bytes()).hexdigest()
        rel = next(f["output"] for f in rep["files"] if f["input_sha256"] == sha)
        return list(csv.reader(io.StringIO((self.out / rel).read_text(encoding="utf-8")))), self.out / rel

    def test_engine_never_exports_an_unchanged_birth_date(self):
        for name, rows in self.files.items():
            orows, _ = self._out_rows(name)
            self.assertEqual(len(orows), len(rows), name)
            for r_in, r_out in zip(rows[1:], orows[1:]):
                self.assertNotEqual(r_in[3], r_out[3], f"{name}: DOB {r_in[3]} exported unchanged")

    def test_passport_flags_only_a_genuinely_unshifted_dob_cell(self):
        clean = VP.audit(self.inp, self.out)
        self.assertEqual(clean["privacy"]["residual_pattern_hits"].get("unshifted birth date", 0), 0)
        bad = self.td / "mutant"
        shutil.copytree(self.out, bad)
        name = "reg_0.csv"
        orows, path = self._out_rows(name)
        path = bad / path.relative_to(self.out)
        orows[3][3] = self.files[name][3][3]                 # put one original DOB back
        buf = io.StringIO()
        csv.writer(buf, lineterminator="\n").writerows(orows)
        path.write_text(buf.getvalue(), encoding="utf-8")
        R = VP.audit(self.inp, bad)
        self.assertEqual(R["privacy"]["residual_pattern_hits"].get("unshifted birth date"), 1)
        self.assertNotEqual(R["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
