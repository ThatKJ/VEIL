"""Contract, CleverCSV dialect, FHIR R4 structure, metamorphic, and fuzz tests."""
import json
import os
from pathlib import Path
import random
import re
import secrets
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rakshak.engine import sniff_delim

MAIN = Path(__file__).resolve().parents[1] / "main.py"
FHIR_DATE_RX = re.compile(r"^\d{4}(?:-\d{2}(?:-\d{2})?)?$")


def _run_cli(inp: Path, out: Path, secret: str) -> None:
    env = {**os.environ, "RAKSHA_SECRET": secret, "OMP_NUM_THREADS": "2"}
    subprocess.run(
        [sys.executable, str(MAIN), "--input", str(inp), "--output", str(out)],
        check=True, capture_output=True, env=env,
    )


def _validate_fhir_r4_bundle(bundle: dict) -> list[str]:
    """Structural checks modeled on HL7 FHIR R4 Bundle / Patient / Clinical resources."""
    errs = []
    if bundle.get("resourceType") != "Bundle":
        errs.append("root resourceType != Bundle")
    if bundle.get("type") not in {"document", "message", "transaction", "transaction-response",
                                  "batch", "batch-response", "history", "searchset", "collection"}:
        errs.append(f"invalid Bundle.type: {bundle.get('type')!r}")
    entries = bundle.get("entry")
    if not isinstance(entries, list):
        return errs + ["Bundle.entry not a list"]
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("resource"), dict):
            errs.append(f"entry[{idx}] missing resource object")
            continue
        res = entry["resource"]
        rt = res.get("resourceType")
        if not rt:
            errs.append(f"entry[{idx}] missing resourceType")
        if rt == "Patient":
            if "birthDate" in res and not FHIR_DATE_RX.fullmatch(str(res["birthDate"])):
                errs.append(f"entry[{idx}] invalid Patient.birthDate: {res['birthDate']!r}")
            if "gender" in res and res["gender"] not in {"male", "female", "other", "unknown"}:
                errs.append(f"entry[{idx}] invalid Patient.gender: {res['gender']!r}")
    return errs


class GeneralizationAndContractsTests(unittest.TestCase):
    def test_clevercsv_dialects_preamble_quotes_and_multiline(self):
        csv_text = (
            "Hospital Audit Export — Ward B\n"
            "Generated for QA\n"
            "MRN|Name|Notes|District|Age\n"
            'IP-1019|Zolap Qemir|"Admitted, stable; BP 120/80\nFollowup 7d"|Hardoi|42\n'
            'IP-1029|Vunex Tolar|"C/O fever|cough; prescribed Tab Paracetamol"|Hardoi|41\n'
        )
        self.assertEqual(sniff_delim(csv_text, ".csv"), "|")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out = root / "input", root / "out"
            inp.mkdir()
            (inp / "export_pipe.csv").write_text(csv_text, encoding="utf-8")
            (inp / "utf16.txt").write_bytes(
                "Patient: Zolap Qemir\nMRN: IP-1019\nDiagnosis: Dengue\n".encode("utf-16")
            )
            _run_cli(inp, out, "secret-clevercsv-1234567890")
            san_csv = (out / "sanitized" / "export_pipe.csv").read_text(encoding="utf-8")
            self.assertNotIn("Zolap", san_csv)
            self.assertNotIn("Vunex", san_csv)
            self.assertIn("BP 120/80", san_csv)
            self.assertIn("Tab Paracetamol", san_csv)
            recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()]
            z_pids = {r["patient"] for r in recs if r["patient"]}
            # Zolap in csv + utf16.txt share one pseudonym; Vunex gets its own
            self.assertEqual(len(z_pids), 2)

    def test_fhir_r4_structural_validity_under_escalation(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out = root / "input", root / "out"
            inp.mkdir()
            bundle = {
                "resourceType": "Bundle",
                "type": "collection",
                "entry": [
                    {
                        "resource": {
                            "resourceType": "Patient",
                            "id": "pat-1",
                            "identifier": [{"value": "UHID-77881"}],
                            "name": [{"text": "Qazek Buvim"}],
                            "gender": "female",
                            "birthDate": "1940-08-19",
                        }
                    },
                    {
                        "resource": {
                            "resourceType": "Observation",
                            "id": "obs-1",
                            "code": {"text": "HbA1c"},
                            "valueQuantity": {"value": 7.4, "unit": "%"},
                        }
                    },
                ],
            }
            (inp / "r4.json").write_text(json.dumps(bundle), encoding="utf-8")
            _run_cli(inp, out, "secret-fhir-1234567890")
            out_bundle = json.loads((out / "sanitized" / "r4.json").read_text(encoding="utf-8"))
            self.assertEqual(_validate_fhir_r4_bundle(out_bundle), [])
            self.assertNotIn("Qazek", json.dumps(out_bundle))
            self.assertEqual(out_bundle["entry"][1]["resource"]["valueQuantity"]["value"], 7.4)

    def test_metamorphic_filename_and_record_order_invariance(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp_a, inp_b = root / "a", root / "b"
            out_a, out_b = root / "oa", root / "ob"
            inp_a.mkdir(); inp_b.mkdir()
            rows = [
                {"mrn": "MR-11", "name": "Huvok Tamir", "dob": "1985-03-10", "age": 41, "diagnosis": "HTN"},
                {"mrn": "MR-12", "name": "Dapik Senor", "dob": "1986-04-11", "age": 40, "diagnosis": "DM2"},
            ]
            (inp_a / "reg.json").write_text(json.dumps({"patients": rows}), encoding="utf-8")
            (inp_b / "visit_log.json").write_text(json.dumps({"patients": list(reversed(rows))}, indent=4), encoding="utf-8")
            sec = "secret-meta-fixed-123456"
            _run_cli(inp_a, out_a, sec)
            _run_cli(inp_b, out_b, sec)
            pa = json.loads((out_a / "sanitized" / "reg.json").read_text())["patients"]
            pb = json.loads((out_b / "sanitized" / "visit_log.json").read_text())["patients"]
            self.assertEqual(pa[0]["name"], pb[1]["name"])
            self.assertEqual(pa[0]["dob"], pb[1]["dob"])
            self.assertEqual(pa[1]["name"], pb[0]["name"])
            self.assertEqual(pa[1]["dob"], pb[0]["dob"])

    def test_fuzz_malformed_deep_json_and_large_note_latency(self):
        rng = random.Random(20261126)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out = root / "input", root / "out"
            inp.mkdir()
            deep = {"x": 1}
            for _ in range(90):
                deep = {"nested": deep}
            (inp / "too_deep.json").write_text(json.dumps(deep), encoding="utf-8")
            (inp / "bad_utf8.txt").write_bytes(b"\xff\xfe\x00\xd8bad" + bytes(rng.randrange(0, 32) for _ in range(80)))
            (inp / "trunc.json").write_text('{"patient": {"name": "Foo', encoding="utf-8")
            (inp / "empty.csv").write_text("   \n\n", encoding="utf-8")
            # Long adversarial repetitive text without catastrophic backtracking
            (inp / "big_note.txt").write_text(
                "Patient: Mekul Zovap\n" + ("BP 120/80 HR 76 SpO2 98% Hb 13.2 g/dL. " * 2500),
                encoding="utf-8",
            )
            t0 = time.monotonic()
            _run_cli(inp, out, secrets.token_hex(24))
            elapsed = time.monotonic() - t0
            self.assertLess(elapsed, 5.0)
            rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertGreaterEqual(rep["counts"]["files_quarantined"], 3)
            self.assertEqual(rep["counts"]["files_sanitized"], 1)
            big = (out / "sanitized" / "big_note.txt").read_text(encoding="utf-8")
            self.assertNotIn("Mekul", big)
            self.assertIn("SpO2 98%", big)

    def test_homonyms_with_conflicting_relative_surnames_never_merge(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out = root / "input", root / "out"
            inp.mkdir()
            (inp / "p1.txt").write_text("Patient: Xuvip Poxak\nS/o Kamal Sharma\nAge: 35\n", encoding="utf-8")
            (inp / "p2.txt").write_text("Patient: Xuvip Poxak\nS/o Kamal Verma\nAge: 35\n", encoding="utf-8")
            _run_cli(inp, out, "secret-homonym-rel-12345")
            recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()]
            pids = [r["patient"] for r in recs]
            self.assertEqual(len(pids), 2)
            self.assertNotEqual(pids[0], pids[1])


if __name__ == "__main__":
    unittest.main()
