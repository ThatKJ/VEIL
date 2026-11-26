"""Phase VIII production security, adversarial encoding, symlink escape, ReDoS, and offline execution tests."""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class SecurityAndFuzzTests(unittest.TestCase):
    def _run_cli(self, inp: Path, out: Path, secret: str = "sec-test-key-xyz", extra_env: dict | None = None):
        env = dict(os.environ, RAKSHA_SECRET=secret, HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1")
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_symlink_escape_quarantined_and_never_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            outside = t / "outside_secret.txt"
            outside.write_text("TOP_SECRET_CANARY_OUTSIDE_TREE 9998887776", encoding="utf-8")
            inp, out = t / "in", t / "out"
            inp.mkdir()
            (inp / "normal.txt").write_text("Diagnosis: Essential hypertension\nBP: 130/80\n", encoding="utf-8")
            try:
                (inp / "escape.txt").symlink_to(outside)
            except OSError:
                self.skipTest("symlinks not supported in environment")
            res = self._run_cli(inp, out)
            self.assertEqual(res.returncode, 0, res.stderr)
            report = json.loads((out / "report.json").read_text())
            q = [f for f in report["files"] if f["status"] == "quarantined"]
            self.assertEqual(len(q), 1)
            self.assertEqual(q[0]["reason"], "unreadable")
            all_out = "\n".join(p.read_text(errors="ignore") for p in out.rglob("*") if p.is_file())
            self.assertNotIn("TOP_SECRET_CANARY_OUTSIDE_TREE", all_out)

    def test_filename_collision_and_path_traversal_contained(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            inp, out = t / "in", t / "out"
            (inp / "ward").mkdir(parents=True)
            # Two files whose scrubbed output filenames would collide if collision suffixing failed
            (inp / "ward" / "Arvind_Sharma_report.txt").write_text("Patient Name: Arvind Sharma\nDx: Fever\n", encoding="utf-8")
            (inp / "ward" / "Pankaj_Verma_report.txt").write_text("Patient Name: Pankaj Verma\nDx: Cough\n", encoding="utf-8")
            # Metadata attempting "../" traversal string inside JSON
            (inp / "meta_traversal.json").write_text(json.dumps({
                "meta": {"source_path": "../../etc/Arvind_Sharma_A-12345.csv"},
                "patient": {"name": "Arvind Sharma", "mrn": "A-12345"},
                "diagnosis": "Typhoid fever",
            }), encoding="utf-8")
            res = self._run_cli(inp, out)
            self.assertEqual(res.returncode, 0, res.stderr)
            san = (out / "sanitized").resolve()
            exported = [p for p in san.rglob("*") if p.is_file()]
            self.assertEqual(len(exported), 3)
            for p in exported:
                self.assertTrue(p.resolve().is_relative_to(san))
            meta_txt = (san / "meta_traversal.json").read_text(encoding="utf-8")
            json.loads(meta_txt)
            self.assertNotIn("Arvind Sharma", meta_txt)
            self.assertNotIn("Pankaj Verma", "\n".join(p.read_text(errors="ignore") for p in exported))

    def test_nested_encodings_b64_url_hex_and_binary_disguise(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            inp, out = t / "in", t / "out"
            inp.mkdir()
            raw_pii = "Patient: Zafar Qureshi, Phone: 9811223344, MRN: ZQ-778899"
            b64 = base64.b64encode(raw_pii.encode()).decode()
            url_pii = urllib.parse.quote("Kamlesh Yadav MRN KY-991122")
            hex_pii = b"Sunita Devi 9876501234".hex()
            (inp / "encoded_notes.json").write_text(json.dumps({
                "patient_name": "Zafar Qureshi",
                "mrn": "ZQ-778899",
                "ocr_blob": f"data:text/plain;base64,{b64}",
                "query_url": f"https://his.local/search?q={url_pii}",
                "hex_trace": hex_pii,
                "dx": "Essential hypertension",
            }), encoding="utf-8")
            (inp / "fake_pdf.pdf").write_bytes(b"%PDF-1.4\x00\xff\xfe\xfa\x01binary_junk")
            (inp / "corrupt.csv").write_bytes(b"name,age\nRamesh,35\n\x00\xff\xfeinvalid")
            (inp / "truncated.json").write_text('{"patient": "Ramesh", "dx": [1, 2', encoding="utf-8")
            res = self._run_cli(inp, out)
            self.assertEqual(res.returncode, 0, res.stderr)
            san_json = (out / "sanitized" / "encoded_notes.json").read_text(encoding="utf-8")
            parsed = json.loads(san_json)
            self.assertEqual(parsed["dx"], "Essential hypertension")
            for forbidden in ("Zafar", "Qureshi", "9811223344", "ZQ-778899", "Kamlesh", "KY-991122", "Sunita", "9876501234"):
                self.assertNotIn(forbidden, san_json)
            report = json.loads((out / "report.json").read_text())
            self.assertGreaterEqual(report["counts"]["files_quarantined"], 2)

    def test_5mb_clinical_payload_redos_latency_and_secret_hygiene(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            inp, out = t / "in", t / "out"
            inp.mkdir()
            secret = "UNIQUE_RAKSHA_SECRET_TOKEN_DO_NOT_LEAK"
            block = (
                "K/C/O Type 2 diabetes mellitus x 6 yrs. BP 126/82 mmHg. HbA1c 7.1%. "
                "Attendant (W/o Mr. Hariom Tiwari) gave consent. Dr. Kavita Joshi advised Tab Metformin 500 mg BD.\n"
            )
            # ~5 MB unstructured note with mixed clinical phrases and tricky boundaries
            big_text = "Patient Name: Mahesh Kulkarni\nMRN: MK-445566\n" + (block * 28000)
            self.assertGreater(len(big_text.encode()), 4_500_000)
            (inp / "massive_note.txt").write_text(big_text, encoding="utf-8")
            t0 = time.monotonic()
            res = self._run_cli(inp, out, secret=secret)
            dt = time.monotonic() - t0
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertLess(dt, 20.0, f"5MB payload took {dt:.2f}s")
            san_txt = (out / "sanitized" / "massive_note.txt").read_text(encoding="utf-8")
            self.assertNotIn("Mahesh Kulkarni", san_txt)
            self.assertNotIn("Hariom Tiwari", san_txt)
            self.assertIn("Dr. Kavita Joshi", san_txt)
            self.assertIn("Type 2 diabetes mellitus", san_txt)
            for p in out.rglob("*"):
                if p.is_file():
                    self.assertNotIn(secret.encode(), p.read_bytes())
            self.assertNotIn(secret, res.stdout + res.stderr)

    def test_network_blocked_offline_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            inp, out, hook = t / "in", t / "out", t / "pyhook"
            inp.mkdir(); hook.mkdir()
            (inp / "note.txt").write_text("Patient: Devendra Singh\nMRN: DS-101\nDx: Asthma\n", encoding="utf-8")
            (hook / "sitecustomize.py").write_text(
                "import socket\n"
                "def _deny(*a, **kw):\n"
                "    raise RuntimeError('OFFLINE_NETWORK_VIOLATION')\n"
                "socket.socket = _deny\n"
                "socket.create_connection = _deny\n",
                encoding="utf-8",
            )
            res = self._run_cli(inp, out, extra_env={"PYTHONPATH": f"{hook}{os.pathsep}{ROOT}"})
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertNotIn("OFFLINE_NETWORK_VIOLATION", res.stderr)
            self.assertNotIn("Devendra", (out / "sanitized" / "note.txt").read_text(encoding="utf-8"))

    def test_missing_or_empty_raksha_secret_fails_safely(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            inp, out = t / "in", t / "out"
            inp.mkdir()
            (inp / "note.txt").write_text("Patient: Devendra Singh\nMRN: DS-101\n", encoding="utf-8")
            for bad_env in (
                {k: v for k, v in os.environ.items() if k != "RAKSHA_SECRET"},
                {**os.environ, "RAKSHA_SECRET": ""},
                {**os.environ, "RAKSHA_SECRET": "   "},
            ):
                res = subprocess.run(
                    [sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                    cwd=str(ROOT), env=bad_env, capture_output=True, text=True,
                )
                self.assertNotEqual(res.returncode, 0)
                self.assertIn("RAKSHA_SECRET", res.stderr)
                self.assertFalse((out / "report.json").exists())


if __name__ == "__main__":
    unittest.main()
