"""APEX regression, adversarial mutation, format-dialect, and 2-CPU determinism tests."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import veil_passport as VP  # noqa: E402


class ApexAdversarialTests(unittest.TestCase):
    def _run_cli(self, inp: Path, out: Path, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        env = {**os.environ, "RAKSHA_SECRET": "apex-test-secret-2026"}
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )

    def test_mareez_lab_blocks_homonym_separation_and_row_alignment(self):
        with tempfile.TemporaryDirectory(prefix="veil_apex_mareez_") as td:
            inp, out = Path(td) / "in", Path(td) / "out"
            inp.mkdir()
            lab_csv = (
                "LAB EXPORT,Apex General Aspatal,,,,\n"
                "MAREEZ,KHAADEE KADIAN,13092025,UHID,40475-MSA-25,41\n"
                "Test,Nateeja,Maap,,,\n"
                "Haemoglobin,7.5,g/dL,,,\n"
                "Report karta,Dr. Yaachat Dalal,,,,\n"
                "\n"
                "MAREEZ,KHAADEE KADIAN,16082025,UHID,40484-MSA-25,47\n"
                "Test,Nateeja,Maap,,,\n"
                "HbA1c,10.4,%,,,\n"
                "Report karta,Dr. Dhirish Jamwal,,,,\n"
            )
            (inp / "lab_blocks.csv").write_text(lab_csv, encoding="utf-8")
            self._run_cli(inp, out)

            san = (out / "sanitized" / "lab_blocks.csv").read_text(encoding="utf-8")
            self.assertNotIn("KHAADEE", san)
            self.assertNotIn("40475-MSA-25", san)
            self.assertNotIn("40484-MSA-25", san)
            self.assertIn("Apex General Aspatal", san)
            self.assertIn("Haemoglobin,7.5,g/dL", san)
            self.assertIn("HbA1c,10.4,%", san)
            self.assertIn("Dr. Yaachat Dalal", san)
            self.assertIn("Dr. Dhirish Jamwal", san)

            recs = {
                r["loc"]: r["patient"]
                for r in (json.loads(ln) for ln in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if ln.strip())
            }
            p1 = recs.get("row:0")
            p2 = recs.get("row:5")
            self.assertIsNotNone(p1)
            self.assertIsNotNone(p2)
            self.assertNotEqual(p1, p2)

    def test_pipe_packed_kv_message_header_and_first_line_protocol(self):
        with tempfile.TemporaryDirectory(prefix="veil_apex_pipekv_") as td:
            inp, out = Path(td) / "in", Path(td) / "out"
            inp.mkdir()
            opd_json = {
                "hospital": "Meham Sarvjanik Aspatal",
                "opd_register": {
                    "02072025": [
                        {
                            "parchi": 1,
                            "packed": "bimaar=Bhebhun Langeh|uhid=40547-MSA-25|fone=7818 21 0390",
                            "doctor": "Dr. Shijuyet Manhas",
                            "shikayat": "C/O loose stools x 7 days",
                            "nidan": {"text": "Acute gastroenteritis", "icd10": "A09"},
                            "dawai": ["Metformin 500 mg OD"],
                        }
                    ]
                },
            }
            fhir_msg = {
                "resourceType": "Bundle",
                "type": "message",
                "entry": [
                    {
                        "resource": {
                            "resourceType": "MessageHeader",
                            "id": "mh1",
                            "source": {"name": "Meham Sarvjanik Aspatal"},
                        }
                    },
                    {
                        "resource": {
                            "resourceType": "Patient",
                            "id": "p1",
                            "identifier": [{"value": "40547-MSA-25"}],
                            "name": [{"text": "Bhebhun Langeh"}],
                        }
                    },
                ],
            }
            proto_txt = (
                "STANDARD PROTOCOL\n"
                "First-line antipyretic: Tab. Paracetamol 500 mg 1-0-1 x 3 days.\n"
            )
            (inp / "opd_packed.json").write_text(json.dumps(opd_json), encoding="utf-8")
            (inp / "fhir_msg.json").write_text(json.dumps(fhir_msg), encoding="utf-8")
            (inp / "protocol.txt").write_text(proto_txt, encoding="utf-8")

            self._run_cli(inp, out)

            opd_san = (out / "sanitized" / "opd_packed.json").read_text(encoding="utf-8")
            for leak in ("Bhebhun", "Langeh", "40547-MSA-25", "7818 21 0390"):
                self.assertNotIn(leak, opd_san)
            self.assertIn("Meham Sarvjanik Aspatal", opd_san)
            self.assertIn("Dr. Shijuyet Manhas", opd_san)
            self.assertIn("Metformin 500 mg OD", opd_san)

            proto_san = (out / "sanitized" / "protocol.txt").read_text(encoding="utf-8")
            self.assertIn("Tab. Paracetamol 500 mg 1-0-1 x 3 days.", proto_san)

            recs = [json.loads(ln) for ln in (out / "records.jsonl").read_text(encoding="utf-8").splitlines() if ln.strip()]
            opd_rec = next(r for r in recs if r["file"] == "sanitized/opd_packed.json")
            fhir_pt = next(r for r in recs if r["file"] == "sanitized/fhir_msg.json" and r["patient"] is not None)
            self.assertIsNotNone(opd_rec["patient"])
            self.assertEqual(opd_rec["patient"], fhir_pt["patient"])

    def test_kin_honorifics_std_landline_cont_row_family_hx_and_negative_age(self):
        with tempfile.TemporaryDirectory(prefix="veil_apex_kin_") as td:
            inp, out = Path(td) / "in", Path(td) / "out"
            inp.mkdir()
            screen_csv = (
                "UHID,Rogiya hesaru,Tande/Ganda hesaru,Umar,family_hx_dm,family_hx_htn,dx\n"
                "KR-101,Nadaf D. Daayal,Dulish Nadaf avara maga,-2,Y,N,Hypertension\n"
                ",Veedu Fon: 0496-2541234,,,,,\n"
            )
            wa_txt = (
                "Patient Name: Goli didi\n"
                "Attendant: Kamal Bhaiya\n"
                "Complaint: Fever x 2 days. BP 118/76 mmHg.\n"
            )
            (inp / "screening.csv").write_text(screen_csv, encoding="utf-8")
            (inp / "wa_note.txt").write_text(wa_txt, encoding="utf-8")

            self._run_cli(inp, out)

            sc_san = (out / "sanitized" / "screening.csv").read_text(encoding="utf-8")
            for leak in ("Nadaf", "Daayal", "Dulish", "0496-2541234"):
                self.assertNotIn(leak, sc_san)
            self.assertIn(",Y,N,Hypertension", sc_san)
            # Negative pediatric age remains negative-banded rather than drifting positive.
            self.assertRegex(sc_san, r"-\d+")

            wa_san = (out / "sanitized" / "wa_note.txt").read_text(encoding="utf-8")
            self.assertNotIn("Goli", wa_san)
            self.assertNotIn("Kamal Bhaiya", wa_san)
            self.assertIn("PSN-", wa_san)
            self.assertIn("[RELATIVE]", wa_san)
            self.assertIn("BP 118/76 mmHg", wa_san)

    def test_bounded_2cpu_fork_matches_1cpu_byte_for_byte(self):
        with tempfile.TemporaryDirectory(prefix="veil_apex_2cpu_") as td:
            root = Path(td)
            inp, out1, out2 = root / "in", root / "out1", root / "out2"
            inp.mkdir()
            # Exceeds 8 sanitized files & 1.5 MB threshold to exercise bounded 2-CPU LPT fork path.
            pad = "Vitals stable. Tab. Metformin 500 mg OD. BP 120/80 mmHg.\n" * 60
            for idx in range(10):
                pid = 2000 + idx
                txt = (
                    f"Patient Name: Ramesh Nair {pid if False else ''}\n"
                    f"UHID: APX-{pid}\n"
                    f"Mobile: 98{idx:02d}112233\n"
                    + pad
                    + f"Assessment: Type 2 DM (E11.9) on {10 + idx:02d}/05/2025.\n"
                )
                # Use distinct names across shards so Sweeper matches across split files too.
                txt = txt.replace("Ramesh Nair", f"Kaveri Menon{chr(65 + idx)}")
                (inp / f"note_{idx:02d}.txt").write_text(txt * 45, encoding="utf-8")
            total_bytes = sum(p.stat().st_size for p in inp.iterdir())
            self.assertGreater(total_bytes, 1_500_000)

            self._run_cli(inp, out1, {"RAKSHA_CPUS": "1"})
            self._run_cli(inp, out2, {"RAKSHA_CPUS": "2"})

            def _digest(d: Path) -> dict[str, str]:
                return {
                    fp.relative_to(d).as_posix(): hashlib.sha256(fp.read_bytes()).hexdigest()
                    for fp in sorted(d.rglob("*"))
                    if fp.is_file() and fp.name != "report.json"
                }

            self.assertEqual(_digest(out1), _digest(out2))
            rep1 = json.loads((out1 / "report.json").read_text(encoding="utf-8"))
            rep2 = json.loads((out2 / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(rep1["counts"], rep2["counts"])
            self.assertFalse(list((out2 / "sanitized").rglob(".veil_tmp_*")))

    def test_mutation_lab_passport_catches_injected_unmasked_leak(self):
        with tempfile.TemporaryDirectory(prefix="veil_apex_mut_") as td:
            inp, out = Path(td) / "in", Path(td) / "out"
            shutil.copytree(ROOT / "demo" / "sample_hospital", inp)
            self._run_cli(inp, out)
            clean_passport = VP.audit(inp, out)
            self.assertEqual(clean_passport["residual_risks"], [])

            # Mutate sanitized output to inject raw patient phone/name leakage and verify Passport catches it.
            target = out / "sanitized" / "opd" / "coded_visits.json"
            txt = target.read_text(encoding="utf-8")
            target.write_text(txt.replace("[PHONE]", "9876543210", 1), encoding="utf-8")
            mutated = VP.audit(inp, out)
            self.assertGreater(mutated["privacy"]["files_with_residue"], 0)
            self.assertTrue(mutated["residual_risks"])


if __name__ == "__main__":
    unittest.main()
