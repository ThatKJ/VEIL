"""Regression tests for Operation VEIL — OMEGA core engine, clinical, identity & security hardening."""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rakshak import engine as EN  # noqa: E402
from rakshak import linker as LK  # noqa: E402
from rakshak import pipeline as PL  # noqa: E402
from rakshak import scrub as S  # noqa: E402


class OmegaCoreHardeningTests(unittest.TestCase):
    def _run_cli(self, inp: Path, out: Path, secret: str = "omega-test-secret", hashseed: str | None = None) -> subprocess.CompletedProcess:
        env = {**os.environ, "RAKSHA_SECRET": secret}
        if hashseed is not None:
            env["PYTHONHASHSEED"] = hashseed
        return subprocess.run(
            [sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )

    def test_tokenset_ascii_digits_over_64_and_verify_text_determinism(self):
        H = EN.Harvest()
        for i in range(70):
            d = f"90000{i:04d}"
            H.id_digits.add(d)
            H.phones.add(d)
        H.id_digits.add("54321")
        sw = S.Sweeper(H)
        ctx = S.Ctx(H, "PSN-TEST123", 0, "dmy", (5, None), PL.Stats())
        res = S.scrub_text("ref 54321 and 900000012 note", ctx, sw)
        self.assertEqual(res, "ref [ID] and [ID] note")
        fname = PL.scrub_component("export_54321.csv", H, sw, "salt1")
        self.assertNotIn("54321", fname)

        # verify_text PYTHONHASHSEED determinism + sharp-s (.casefold expansion)
        crit = ["ramesh kumar", "kumar sharma"]
        idx = PL.build_verify_index(crit)
        out_a, hits_a = PL.verify_text("ß ramesh kumar sharma", crit, idx)
        self.assertEqual(out_a[:2], "ß ")
        self.assertGreaterEqual(hits_a, 1)
        code = (
            "import sys; sys.path.insert(0, %r); "
            "from rakshak import pipeline as PL; "
            "c = ['ramesh kumar', 'kumar sharma']; "
            "print(PL.verify_text('ramesh kumar sharma', c, PL.build_verify_index(c))[0])"
        ) % str(ROOT)
        r42 = subprocess.run([sys.executable, "-c", code], env={**os.environ, "PYTHONHASHSEED": "42"}, capture_output=True, text=True, check=True)
        r123 = subprocess.run([sys.executable, "-c", code], env={**os.environ, "PYTHONHASHSEED": "123"}, capture_output=True, text=True, check=True)
        self.assertEqual(r42.stdout.strip(), r123.stdout.strip())

    def test_sambandhi_family_id_ration_and_cont_row_no_false_merges(self):
        with tempfile.TemporaryDirectory() as d:
            inp, out = Path(d) / "in", Path(d) / "out"
            inp.mkdir()
            (inp / "nondani.ndjson").write_text(
                json.dumps({"uhid": "MDR-1", "hesaru": "Nashechee Nadaf", "sambandhi": {"relation": "hendati", "hesaru": "Romi Nadaf"}, "durawani": "9783294032", "linga": "F", "huttida_dinanka": "31/08/1985"}) + "\n"
                + json.dumps({"uhid": "SGP-2", "hesaru": "Romi Nadaf", "durawani": "9783294032"}) + "\n",
                encoding="utf-8",
            )
            (inp / "reg.csv").write_text(
                "OP Nambar,Rogiyude Peru,Prayam,Aan/Pen,Janana Theeyathi\n"
                "OP-101,Cheruvalli Hedha,44,Pen,20/08/1981\n"
                ",\"Thamasa sthalam: Cheruvalli (H), Malappuram Dt - 676680\",Fon: 9462-977371,Veedu Fon: 0496 4782810,Ration: 4621474987\n"
                "OP-102,Bhinabha Cheruvalli,50,Aan,26/09/1975\n"
                ",\"Thamasa sthalam: Cheruvalli (H), Malappuram Dt - 676680\",Fon: 9462-977371,Veedu Fon: 0496 4782810,Ration: 4621474987\n",
                encoding="utf-8",
            )
            self._run_cli(inp, out)
            recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()]
            by_key = {(r["file"], r["loc"]): r["patient"] for r in recs}
            # Spouse Nashechee vs Romi stay distinct even without DOB on SGP-2
            self.assertIsNotNone(by_key[("sanitized/nondani.ndjson", "row:0")])
            self.assertIsNotNone(by_key[("sanitized/nondani.ndjson", "row:1")])
            self.assertNotEqual(
                by_key[("sanitized/nondani.ndjson", "row:0")],
                by_key[("sanitized/nondani.ndjson", "row:1")],
            )
            # Continuation rows inherit their respective parent patient PSNs cleanly, never cross-merging
            p_hedha = by_key[("sanitized/reg.csv", "row:0")]
            p_hedha_cont = by_key[("sanitized/reg.csv", "row:1")]
            p_bhinabha = by_key[("sanitized/reg.csv", "row:2")]
            p_bhinabha_cont = by_key[("sanitized/reg.csv", "row:3")]
            self.assertEqual(p_hedha, p_hedha_cont)
            self.assertEqual(p_bhinabha, p_bhinabha_cont)
            self.assertNotEqual(p_hedha, p_bhinabha)
            reg_san = (out / "sanitized/reg.csv").read_text(encoding="utf-8")
            self.assertNotIn("4621474987", reg_san)
            self.assertNotIn("0496 4782810", reg_san)

    def test_struct_keys_non_fhir_rx_kin_tail_and_linker_vetoes(self):
        # _RX_KIN_TAIL extracts relative name (group 2), not "S/O"
        H = EN.Harvest()
        r = EN.Rec("a.csv", 0)
        PL.add_ev(r, H, "NAME", "Ramesh Kumar S/O Mohan Lal")
        self.assertEqual(r.rel, (("Mohan", "Lal"),))
        self.assertIn("mohan lal", H.full_names)

        # Non-FHIR JSON "id" & nested "type": {"patient_note": ...} are scrubbed
        with tempfile.TemporaryDirectory() as d:
            inp, out = Path(d) / "in", Path(d) / "out"
            inp.mkdir()
            (inp / "data.json").write_text(
                json.dumps({"patients": [{"id": "UHID-998877", "name": "Ramesh Kumar", "type": {"patient_note": "Ramesh Kumar 9876543210"}}]}),
                encoding="utf-8",
            )
            self._run_cli(inp, out)
            san = (out / "sanitized/data.json").read_text(encoding="utf-8")
            self.assertNotIn("UHID-998877", san)
            self.assertNotIn("9876543210", san)
            self.assertNotIn("Ramesh Kumar", san)

        # 0091 international Indian mobile links & scrubs while STD landline stays non-linking
        self.assertEqual(PL._mobile_core("00918210083972"), "8210083972")
        self.assertIsNone(PL._mobile_core("04964782810"))
        self.assertEqual(EN.classify_digits("0091-8210083972"), "PHONE")

        # Linker cluster veto on dob vs age+date mismatch, age chaining, and institutional emails
        self.assertFalse(PL._is_personal_email("reception@hospital.org"))
        self.assertFalse(PL._is_personal_email("info@clinic.in"))
        c_dob = LK.Cluster(0, {"names": [["Ramesh", "Kumar"]], "rel": [], "dob": "1980-01-01", "gender": "M", "age": None, "date": None, "village": None, "ids": (), "phones": ()})
        c_age = LK.Cluster(1, {"names": [["Ramesh", "Kumar"]], "rel": [], "dob": None, "gender": "M", "age": 20, "date": 2026, "village": None, "ids": (), "phones": ()})
        self.assertFalse(LK.compatible(c_dob, c_age))
        c_a = LK.Cluster(2, {"names": [["Sunil", "Verma"]], "rel": [], "dob": None, "gender": "M", "age": 25, "date": None, "village": None, "ids": (), "phones": ()})
        c_b = LK.Cluster(3, {"names": [["Sunil", "Verma"]], "rel": [], "dob": None, "gender": "M", "age": 27, "date": None, "village": None, "ids": (), "phones": ()})
        c_c = LK.Cluster(4, {"names": [["Sunil", "Verma"]], "rel": [], "dob": None, "gender": "M", "age": 33, "date": None, "village": None, "ids": (), "phones": ()})
        c_a.absorb(c_b)
        self.assertFalse(LK.compatible(c_a, c_c))

    def test_clinical_integrity_labs_wo_so_co_asha_deva_dr_age_band_and_eponym(self):
        H = EN.Harvest()
        H.add_name("ASHA DEVI")
        H.add_name("Bell")
        H.add_name("राकेश")
        sw = S.Sweeper(H)
        ctx = S.Ctx(H, "PSN-PAT99", 0, "dmy", (5, None), PL.Stats())
        note = (
            "Patient Name: ASHA DEVI\n"
            "Followed up by ASHA worker daily.\n"
            "डॉ. शर्मा ने राकेश को देखा\n"
            "Platelets 70000-90000 /cumm; IV NS 20 mEq/1000mL\n"
            "C/O Pedal edema and Dry cough. Chest clear W/O Crepitations.\n"
            "X-ray S/O Consolidation. Father: Farmer. Attendant: Self.\n"
            "Age 50-54 yrs. Dx: Bell palsy and Graves' disease.\n"
        )
        out = S.scrub_text(note, ctx, sw)
        self.assertNotIn("ASHA DEVI", out)
        self.assertIn("ASHA worker", out)
        self.assertIn("डॉ. शर्मा", out)
        self.assertNotIn("राकेश", out)
        self.assertIn("70000-90000 /cumm", out)
        self.assertIn("20 mEq/1000mL", out)
        self.assertIn("C/O Pedal edema", out)
        self.assertIn("W/O Crepitations", out)
        self.assertIn("S/O Consolidation", out)
        self.assertIn("Father: Farmer", out)
        self.assertIn("Attendant: Self", out)
        self.assertIn("Age 50-54 yrs", out)
        self.assertNotIn("50-54-54", out)
        self.assertIn("Bell palsy", out)
        self.assertIn("Graves' disease", out)
        # Bounds check against literal PUA chars
        self.assertIn("\uE000", S.scrub_text("test \uE000\uE109\uE001 text", ctx, sw))

    def test_hidden_abha_homoglyphs_diacritics_b64_hex_hl7_and_multipatient_fhir(self):
        with tempfile.TemporaryDirectory() as d:
            inp, out = Path(d) / "in", Path(d) / "out"
            inp.mkdir()
            b64_phone = base64.b64encode(b"9876543210").decode()
            long_hex = ("Patient: Ramesh Sharma Phone: 9876543210 " + ("clinical ok " * 14)).encode().hex()
            (inp / "राकेश_शर्मा.txt").write_text(
                f"Name: राकेश शर्मा\n"
                f"ABHA: ramesh.sharma@abdm\n"
                f"Alias: R\u03b1mesh Sharm\u0101\n"
                f"Pct: Ramesh%20Sharma\n"
                f"B64: {b64_phone}\n"
                f"Hex: {long_hex}\n",
                encoding="utf-8",
            )
            (inp / "adt_note.hl7").write_text(
                "MSH|^~\\&|HIS|H1|HUB|H1|202402100915||ADT^A04|53338764|P|2.5\r"
                "PID|1||MRN-8821||Sharma^Ramesh||19850412|M|||12MG Road^^Lucknow||9876543210\r",
                encoding="utf-8",
            )
            (inp / "deep_fake.txt").write_text(('{"a":' * 5000) + '1' + ('}' * 5000), encoding="utf-8")
            (inp / "multi.json").write_text(
                json.dumps({
                    "resourceType": "Bundle",
                    "type": "collection",
                    "entry": [
                        {"fullUrl": "urn:uuid:p1", "resource": {"resourceType": "Patient", "id": "p1", "name": [{"text": "Asha Patel"}], "birthDate": "1980", "identifier": [{"value": "UH-101"}]}},
                        {"fullUrl": "urn:uuid:e1", "resource": {"resourceType": "Encounter", "id": "e1", "subject": {"reference": "urn:uuid:p1"}, "period": {"start": "2024-05-10"}}},
                        {"fullUrl": "urn:uuid:p2", "resource": {"resourceType": "Patient", "id": "p2", "name": [{"text": "Vikram Verma"}], "birthDate": "1975-06-15", "identifier": [{"value": "UH-202"}]}},
                        {"fullUrl": "urn:uuid:e2", "resource": {"resourceType": "Encounter", "id": "e2", "subject": {"reference": "Patient/p2"}, "period": {"start": "2024-05-10"}}},
                    ],
                }),
                encoding="utf-8",
            )
            self._run_cli(inp, out)
            rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
            statuses = [f["status"] for f in rep["files"]]
            self.assertEqual(statuses.count("quarantined"), 1)  # deep_fake.txt only
            self.assertEqual(statuses.count("sanitized"), 3)
            # Devanagari filename scrubbed
            san_names = [p.name for p in (out / "sanitized").rglob("*") if p.is_file()]
            self.assertFalse(any("राकेश" in n or "शर्मा" in n for n in san_names))
            # Check text file leaks
            txt_out = next((out / "sanitized").glob("*.txt"))
            txt_body = txt_out.read_text(encoding="utf-8")
            for leaked in ("ramesh.sharma@abdm", "R\u03b1mesh", "Sharm\u0101", "Ramesh", b64_phone, "9876543210"):
                self.assertNotIn(leaked, txt_body)
            # Check HL7 processed cleanly & not corrupted with Patient: prefix before MSH|
            hl7_out = (out / "sanitized/adt_note.hl7").read_text(encoding="utf-8")
            self.assertTrue(hl7_out.startswith("MSH|"))
            self.assertNotIn("Sharma", hl7_out)
            # Check multi-patient FHIR Bundle shifted Encounters independently and kept YYYY birthDate
            bundle = json.loads((out / "sanitized/multi.json").read_text(encoding="utf-8"))
            self.assertEqual(bundle["entry"][0]["resource"]["birthDate"], "1980")
            self.assertNotEqual(
                bundle["entry"][1]["resource"]["period"]["start"],
                bundle["entry"][3]["resource"]["period"]["start"],
            )


if __name__ == "__main__":
    unittest.main()
