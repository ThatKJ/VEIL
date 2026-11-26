"""Adversarial mutation & Assurance 3.0 record/field/temporal tests."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import mutation_lab as ML  # noqa: E402
import veil_passport as VP  # noqa: E402


class AdversarialMutationAndPassport2Tests(unittest.TestCase):
    def test_semantic_variants_preserve_identity_and_medicine(self):
        with tempfile.TemporaryDirectory(prefix="veil_mut_test_") as td:
            env = {**os.environ, "RAKSHA_SECRET": "titan-mutation-test-key"}
            for variant in ("standard", "mutated"):
                inp = Path(td) / f"in_{variant}"
                out = Path(td) / f"out_{variant}"
                meta = ML.generate_mutation_suite(inp, variant)
                subprocess.run(
                    [sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                    env=env, check=True, capture_output=True,
                )
                res = ML.verify_semantic_invariants(inp, out, meta)
                for cname, ok in res["checks"].items():
                    self.assertTrue(ok, f"{variant} failed check {cname}: {res['checks']}")

    def test_passport2_catches_misplaced_record_psn_and_duplicate_clinical_loss(self):
        with tempfile.TemporaryDirectory(prefix="veil_p2_strict_") as td:
            inp, out = Path(td) / "in", Path(td) / "out"
            inp.mkdir()
            (inp / "patients.csv").write_text(
                "UHID,Patient Name,Mobile\n"
                "U-101,Anita Verma,9811112222\n"
                "U-102,Sunil Verma,9811113333\n",
                encoding="utf-8",
            )
            (inp / "notes.txt").write_text(
                "Patient Name: Anita Verma\nUHID: U-101\n"
                "Prescribed Tab. Paracetamol 500 mg morning and Tab. Paracetamol 500 mg night.\n",
                encoding="utf-8",
            )
            subprocess.run(
                [sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                env={**os.environ, "RAKSHA_SECRET": "p2-strict-key"}, check=True, capture_output=True,
            )
            clean = VP.audit(inp, out)
            self.assertEqual(clean["checks"]["identity"]["status"], "PASS")
            self.assertEqual(clean["checks"]["clinical"]["status"], "PASS")
            self.assertEqual(clean["checks"]["temporal"]["status"], "SKIPPED")  # notes.txt has <2 dates

            # 1) Occurrence-aware check: dropping ONE of two identical '500 mg' doses must FAIL clinical check!
            note_p = next((out / "sanitized").glob("*.txt"))
            t = note_p.read_text(encoding="utf-8")
            idx = t.rfind("500 mg")
            note_p.write_text(t[:idx] + "000 mg" + t[idx + 6:], encoding="utf-8")
            after_loss = VP.audit(inp, out)
            self.assertLess(after_loss["clinical"]["protected_values_kept_pct"], 100.0)
            self.assertEqual(after_loss["checks"]["clinical"]["status"], "FAIL")

            # 2) Record-level check: swap PSN in records.jsonl row:0 <-> row:1 (stays in same file, wrong row!)
            rj = out / "records.jsonl"
            lines = [json.loads(l) for l in rj.read_text(encoding="utf-8").splitlines() if l.strip()]
            csv_rows = [r for r in lines if r["file"].endswith(".csv")]
            self.assertEqual(len(csv_rows), 2)
            csv_rows[0]["patient"], csv_rows[1]["patient"] = csv_rows[1]["patient"], csv_rows[0]["patient"]
            rj.write_text("\n".join(json.dumps(r) for r in lines) + "\n", encoding="utf-8")
            after_swap = VP.audit(inp, out)
            self.assertEqual(after_swap["identity"]["pseudonym_placement_errors"], 2)
            self.assertEqual(after_swap["checks"]["identity"]["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
