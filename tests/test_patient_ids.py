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

    def test_pseudonym_entropy_secret_and_order_independence(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from rakshak import engine as E  # noqa: E402

        orig_secret = E.SECRET
        try:
            E.SECRET = b"secret-alpha-001"
            p1 = E.pseudonym("M:UHID1001")
            p2 = E.pseudonym("M:UHID1001")
            p3 = E.pseudonym("M:UHID1002")
            self.assertEqual(p1, p2)
            self.assertNotEqual(p1, p3)
            self.assertRegex(p1, r"^PSN-[0-9A-Z]{10}$")
            self.assertNotEqual(p1[4:], E.opaque("fname", "M:UHID1001", 10))

            # Changing secret must change the pseudonym
            E.SECRET = b"secret-beta-002"
            p_diff = E.pseudonym("M:UHID1001")
            self.assertNotEqual(p1, p_diff)

            # High-cardinality uniqueness: 200,000 keys must produce 0 collisions under 50-bit base32
            seen = {E.pseudonym(f"M:PAT-{i:07d}") for i in range(200_000)}
            self.assertEqual(len(seen), 200_000)
        finally:
            E.SECRET = orig_secret

        # Order-independence across shuffled input row order
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp1, inp2 = root / "in1", root / "in2"
            inp1.mkdir(); inp2.mkdir()
            rows = [
                ["Z-101", "Asha Devi", "1985-05-01", "41"],
                ["Z-102", "Ravi Kumar", "1978-07-12", "48"],
                ["Z-103", "Meera Nair", "1990-11-23", "36"],
            ]
            for idx, rlist in enumerate((rows, list(reversed(rows))), 1):
                inp = inp1 if idx == 1 else inp2
                with (inp / "reg.csv").open("w", newline="") as f:
                    w = csv.writer(f)
                    w.writerow(["MRN", "Name", "DOB", "Age"])
                    w.writerows(rlist)
            out1, out2 = root / "out1", root / "out2"
            env = {**os.environ, "RAKSHA_SECRET": "order-invariant-key"}
            main_py = str(Path(__file__).resolve().parents[1] / "main.py")
            subprocess.run([sys.executable, main_py, "--input", str(inp1), "--output", str(out1)], check=True, capture_output=True, env=env)
            subprocess.run([sys.executable, main_py, "--input", str(inp2), "--output", str(out2)], check=True, capture_output=True, env=env)
            m1 = [json.loads(l)["patient"] for l in (out1 / "records.jsonl").read_text().splitlines() if l.strip()]
            m2 = [json.loads(l)["patient"] for l in (out2 / "records.jsonl").read_text().splitlines() if l.strip()]
            self.assertEqual(m1, list(reversed(m2)))
