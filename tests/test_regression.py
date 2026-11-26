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

    def test_hl7_v2_adt_fields_are_structured_and_structure_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out = root / "input", root / "out"
            inp.mkdir()
            msg = ("MSH|^~\\&|HIS|H1|HUB|H1|202402100915||ADT^A04|53338764|P|2.5\r"
                   "EVN|A04|202402100915\r"
                   "PID|1||JDH25OP47912^^^JDH^MR~886964861767^^^UIDAI^NI||RABHA^Nashi||19241110|F|||"
                   "Gh. No. 21^Bhodush Ali^Dhupilmunda Dakhin^Sambalpur^AS^768073^IN||+918017094700^PRN^CP\r"
                   "NK1|1|RABHA^Kheebigir|SPO^spouse\r"
                   "PV1|1|O|OPD^^^JDH||||D565^Mara^Bhoi|||MED\r")
            (inp / "adt.txt").write_text(msg, encoding="utf-8", newline="")
            self._run_cli(inp, out)
            files = [p for p in (out / "sanitized").rglob("*") if p.is_file()]
            text = files[0].read_bytes().decode("utf-8")     # keep HL7 \r segment separators
            segs = text.split("\r")
            self.assertTrue(segs[0].startswith("MSH|^~\\&|HIS"))
            pid = next(x for x in segs if x.startswith("PID|")).split("|")
            self.assertEqual(len(pid), 14)                                  # field count preserved
            for raw in ("RABHA", "Nashi", "886964861767", "JDH25OP47912", "8017094700", "768073", "Dhupilmunda",
                        "Kheebigir", "19241110"):
                self.assertNotIn(raw, text)
            self.assertIn("D565^Mara^Bhoi", text)                          # attending doctor kept
            rows = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertTrue(rows[0]["patient"] and rows[0]["patient"] in text)

    def test_malformed_jsonl_rows_are_parsed_literally_and_linked(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out = root / "input", root / "out"
            inp.mkdir()
            (inp / "reg.ndjson").write_text(
                '// export v2\n'
                '{"uhid": "MDR24x34706", "hesaru": "Khorigi Kuruba", "durawani": "+91 640 622 8041"}\n'
                "{'uhid': 'MDR24x33949', 'hesaru': 'Khobiyish Hiremath', 'durawani': '+91 905 176 3028'}\n"
                '{"uhid": "MDR24x33950", "hesaru": "Yokhil Hiremath", note: \'kaagada\',}\n', encoding="utf-8")
            self._run_cli(inp, out)
            text = next(p for p in (out / "sanitized").rglob("*") if p.is_file()).read_text(encoding="utf-8")
            for raw in ("Khorigi", "Khobiyish", "Yokhil", "MDR24x33949", "9051763028", "905 176 3028"):
                self.assertNotIn(raw, text)
            self.assertIn("kaagada", text)
            rows = {r["loc"]: r["patient"] for r in map(json.loads, (out / "records.jsonl").read_text().splitlines())}
            for loc in ("row:1", "row:2", "row:3"):
                self.assertTrue(rows[loc] and rows[loc] in text, loc)

    def test_national_id_typo_is_not_a_conflict_but_different_ids_are(self):
        from rakshak.linker import _one_edit, compatible, Cluster
        base = {"names": [["Vakeneel", "Grewal"]], "rel": [], "ids": set(), "phones": set(), "dob": "1990-02-17",
                "age": 34, "gender": "M", "village": None}
        a = Cluster(0, {**base, "ids": {"A:845014968778"}})
        typo = Cluster(1, {**base, "ids": {"A:845104968778"}})        # adjacent transposition
        other = Cluster(2, {**base, "ids": {"A:923614118770"}})       # a different person's number
        self.assertTrue(_one_edit("845014968778", "845104968778"))
        self.assertTrue(compatible(a, typo))
        self.assertFalse(compatible(a, other))

    def test_schema_key_matching_patient_name_keeps_record_locators(self):
        """A patient called "Data" must not cause the structural key "data" to be renamed,
        which used to collapse every nested record to loc "doc" with patient null (H16)."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out = root / "input", root / "out"
            (inp / "reg").mkdir(parents=True)
            (inp / "reg" / "patients.csv").write_text(
                "UHID,Patient Name,Gender,Age,Mobile\n"
                "AYU-24-0101,Data Singh Bains,M,52,9876501234\n"
                "AYU-24-0102,Ruha Kaur Mann,F,33,9123409876\n", encoding="utf-8")
            visits = [{"pt": {"ref": "AYU-24-0101", "label": "Data Singh Bains"}, "consult": {"plan": ["Tab Metformin 500 mg BD"]}},
                      {"pt": {"ref": "AYU-24-0102", "label": "Ruha Kaur Mann"}, "consult": {"plan": ["Tab Iron 100 mg OD"]}}]
            (inp / "opd.json").write_text(json.dumps({
                "meta": {"tool": "sync"},
                "data": {"patientInfo": {"sessions": [{"tokens": visits}]}},
                "zainab_siddiqui": {"note": "index entry"}}), encoding="utf-8")
            (inp / "reg2.csv").write_text("UHID,Patient Name\nX-77881,Zainab Siddiqui\n", encoding="utf-8")
            self._run_cli(inp, out)
            sanitized = json.loads((out / "sanitized" / "opd.json").read_text(encoding="utf-8"))
            self.assertIn("data", sanitized)
            self.assertIn("patientInfo", sanitized["data"])
            self.assertNotIn("zainab_siddiqui", sanitized)          # a real full-name key is still renamed
            rows = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()]
            opd = {r["loc"]: r["patient"] for r in rows if r["file"] == "sanitized/opd.json"}
            self.assertIn("/data/patientInfo/sessions/0/tokens/0", opd)
            self.assertIn("/data/patientInfo/sessions/0/tokens/1", opd)
            self.assertTrue(all(opd[k] for k in opd if "/tokens/" in k))
            reg = {r["loc"]: r["patient"] for r in rows if r["file"].endswith("patients.csv")}
            self.assertEqual(opd["/data/patientInfo/sessions/0/tokens/0"], reg["row:0"])
            self.assertNotEqual(opd["/data/patientInfo/sessions/0/tokens/0"], opd["/data/patientInfo/sessions/0/tokens/1"])
            blob = "\n".join(p.read_text(encoding="utf-8") for p in out.rglob("*") if p.is_file())
            self.assertNotIn("Data Singh Bains", blob)
            self.assertNotIn("Zainab Siddiqui", blob)

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

    def test_phase7_doctor_relative_fhir_prekin_hidden_and_unlinked_shift(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out1, out2 = root / "input", root / "out1", root / "out2"
            inp.mkdir()
            (inp / "note_kin.txt").write_text(
                "Xuvip Poxak, W/o Beegan Baghel, 34 yrs/F, 12 Apr 2024\n"
                "Seen by Dr. Beegan Baghel\n",
                encoding="utf-8",
            )
            (inp / "note_kin2.txt").write_text(
                "Patient: Xuvip Poxak\n"
                "W/o Beegan\n"
                "Seen on 15 Apr 2024\n",
                encoding="utf-8",
            )
            (inp / "bundle.json").write_text(json.dumps({
                "resourceType": "Bundle",
                "type": "collection",
                "entry": [{
                    "resource": {
                        "resourceType": "Patient",
                        "id": "p1",
                        "name": [{"text": "Xuvip Poxak"}],
                        "gender": "female",
                        "birthDate": "1990-05-14",
                    }
                }, {
                    "resource": {
                        "resourceType": "Condition",
                        "code": {"text": "RareConditionXYZ"},
                    }
                }],
            }), encoding="utf-8")
            (inp / "lab_panel.json").write_text(json.dumps({
                "patient": {"name": "Xuvip Poxak", "dob": "14/05/1990"},
                "panels": [{"name": "CBC", "results": [{"test": "WBC", "result": "7200", "unit": "/uL"}]}],
            }), encoding="utf-8")
            (inp / "hidden.txt").write_text(
                "Patient: X\u200buvip Po\u0445ak\n"
                "Note: \\u0058\\u0075\\u0076\\u0069\\u0070\\u0020\\u0050\\u006f\\u0078\\u0061\\u006b\n"
                "Hex: " + b"Xuvip Poxak".hex() + "\n",
                encoding="utf-8",
            )
            (inp / "unlinked.txt").write_text("Unlinked clinic log: 03/04/2023\n", encoding="utf-8")
            self._run_cli(inp, out1, secret="secret-alpha-1234567890")
            self._run_cli(inp, out2, secret="secret-beta-0987654321")

            san_kin = (out1 / "sanitized" / "note_kin.txt").read_text(encoding="utf-8")
            self.assertIn("Dr. Beegan Baghel", san_kin)
            self.assertNotIn("Xuvip", san_kin)
            self.assertIn("[RELATIVE]", san_kin)

            san_fhir = json.loads((out1 / "sanitized" / "bundle.json").read_text(encoding="utf-8"))
            pat = san_fhir["entry"][0]["resource"]
            self.assertRegex(pat["birthDate"], r"^\d{4}-\d{2}-\d{2}$")
            self.assertNotEqual(pat["birthDate"], "1990-05-14")

            san_lab = json.loads((out1 / "sanitized" / "lab_panel.json").read_text(encoding="utf-8"))
            self.assertEqual(san_lab["panels"][0]["results"][0]["test"], "WBC")

            san_hid1 = (out1 / "sanitized" / "hidden.txt").read_text(encoding="utf-8")
            self.assertNotIn("Xuvip", san_hid1)
            self.assertNotIn("Poxak", san_hid1)
            self.assertNotIn(b"Xuvip Poxak".hex(), san_hid1)

            san_unl1 = (out1 / "sanitized" / "unlinked.txt").read_text(encoding="utf-8")
            san_unl2 = (out2 / "sanitized" / "unlinked.txt").read_text(encoding="utf-8")
            self.assertNotIn("03/04/2023", san_unl1)
            self.assertNotEqual(san_unl1, san_unl2)

            recs = [json.loads(l) for l in (out1 / "records.jsonl").read_text(encoding="utf-8").splitlines()]
            kin_pids = [r["patient"] for r in recs if r["file"] in ("sanitized/note_kin.txt", "sanitized/note_kin2.txt")]
            self.assertEqual(len(kin_pids), 2)
            self.assertTrue(all(kin_pids))
            self.assertEqual(len(set(kin_pids)), 1)
            dob_pids = [r["patient"] for r in recs if r["file"] in ("sanitized/bundle.json", "sanitized/lab_panel.json")]
            self.assertEqual(len(dob_pids), 2)
            self.assertTrue(all(dob_pids))
            self.assertEqual(len(set(dob_pids)), 1)

    def test_phase8_hindi_slicing_kin_age_village_header_and_lastupdated(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out1, out2 = root / "input", root / "out1", root / "out2"
            inp.mkdir()
            (inp / "hi.txt").write_text(
                "रोगी का नाम: श्री वोजिरा गुप्ता   आयु/लिंग: 9 वर्ष/म\n"
                "पुत्री बीगन राजभर\n",
                encoding="utf-8",
            )
            (inp / "rx.txt").write_text("Nm: Bheechoyel G.  Yr: 29  UHID BJS.24.12061\nPt: 30y | M\nमरीज़: (103 साल)\n", encoding="utf-8")
            (inp / "reg.csv").write_text(
                "UHID,Patient Name,Village/Mohalla,District,Age\n"
                "BJS.24.12061,Bheechoyel G.,Rampur,Barabanki,29\n",
                encoding="utf-8",
            )
            (inp / "meta_fhir.json").write_text(json.dumps({
                "resourceType": "Bundle",
                "type": "collection",
                "meta": {"lastUpdated": "2026-09-05T10:00:00+05:30"},
                "entry": [{"resource": {"resourceType": "Patient", "id": "p1", "name": [{"text": "Vojira Gupta"}]}}],
            }), encoding="utf-8")
            self._run_cli(inp, out1, secret="sec-p8-alpha-123456")
            self._run_cli(inp, out2, secret="sec-p8-beta-654321")

            hi = (out1 / "sanitized" / "hi.txt").read_text(encoding="utf-8")
            self.assertNotIn("ुप्ता", hi)
            self.assertNotIn("गुप्ता", hi)
            self.assertIn("पुत्री [RELATIVE]", hi)
            self.assertIn("0-9", hi)

            rx = (out1 / "sanitized" / "rx.txt").read_text(encoding="utf-8")
            self.assertIn("Yr: 20-29", rx)
            self.assertIn("30-39y", rx)
            self.assertIn("(85-119 साल)", rx)

            reg = (out1 / "sanitized" / "reg.csv").read_text(encoding="utf-8")
            self.assertTrue(reg.splitlines()[0].startswith("UHID,Patient Name,Village/Mohalla,District,Age"))

            f1 = json.loads((out1 / "sanitized" / "meta_fhir.json").read_text(encoding="utf-8"))
            f2 = json.loads((out2 / "sanitized" / "meta_fhir.json").read_text(encoding="utf-8"))
            self.assertRegex(f1["meta"]["lastUpdated"], r"^\d{4}-\d{2}-\d{2}T10:00:00\+05:30$")
            self.assertNotEqual(f1["meta"]["lastUpdated"], "2026-09-05T10:00:00+05:30")
            self.assertNotEqual(f1["meta"]["lastUpdated"], f2["meta"]["lastUpdated"])

    def test_phase8_nested_pairs_dotted_phone_and_deva_role(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out = root / "input", root / "out"
            inp.mkdir()
            (inp / "rpt.json").write_text(json.dumps({
                "rpt": [
                    ["Nm", "GOND Sogi Haajen"],
                    ["UHID", "BJS.24.11585"],
                    ["Ph#", "85880.61445"],
                    ["res", [["TSH", "7.51", "mIU/L"]]],
                ]
            }), encoding="utf-8")
            (inp / "ds_rel.txt").write_text(
                "Patient: Sogi Haajen Gond\n"
                "पोपुम ठाकुर (बेटा)\n"
                "W/o Baasutij. Follow-up at 7d\n"
                "Address: Tola Dhichir, Gali No. 16\n"
                "Ph# 85880.61445\n",
                encoding="utf-8",
            )
            self._run_cli(inp, out, secret="sec-pairs-123456")
            rpt_out = json.loads((out / "sanitized" / "rpt.json").read_text(encoding="utf-8"))
            keys_col = [row[0] for row in rpt_out["rpt"]]
            self.assertEqual(keys_col, ["Nm", "UHID", "Ph#", "res"])
            self.assertEqual(rpt_out["rpt"][3][1][0], ["TSH", "7.51", "mIU/L"])

            ds = (out / "sanitized" / "ds_rel.txt").read_text(encoding="utf-8")
            self.assertNotIn("पोपुम", ds)
            self.assertIn("(बेटा)", ds)
            self.assertIn("Follow-up", ds)
            self.assertNotIn("Dhichir", ds)
            self.assertNotIn("Gali No. 16", ds)

            recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(recs), 2)
            self.assertTrue(all(r["patient"] for r in recs))
            self.assertEqual(recs[0]["patient"], recs[1]["patient"])

    def test_phase8_iso_dob_short_surname_and_paren_kin(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out = root / "input", root / "out"
            inp.mkdir()
            (inp / "hi_dob.csv").write_text(
                "UHID,Name,DOB,Age\nAYU-H-12-0491,नापी झा,27 सितंबर 1951,74\n", encoding="utf-8"
            )
            (inp / "lab_init.csv").write_text(
                "Specimen,Client,Ref No,Test,Result\nS1,N. Jha,AYU-H-12-0491,TSH,4.2\nS2,N. Jha,AYU-H-12-0491,HbA1c,6.1\n",
                encoding="utf-8",
            )
            (inp / "card.json").write_text(json.dumps({
                "pt": {"name": "Naapee Jha", "dob": "27.09.1951", "mrn": "AYU-H-12-0491"}
            }), encoding="utf-8")
            (inp / "note_pkin.txt").write_text(
                "[22-Aug-25] mili: Godarosh (son of Mevish) - UTI followup.\n"
                "14:00 - K/C/O Bell's palsy. Attendant (W/o Rajesh Verma) informed about diet.\n",
                encoding="utf-8",
            )
            (inp / "opd_g.json").write_text(json.dumps({
                "patient": {"name": "Godarosh Mandal", "relative": "Mevish Mandal", "mrn": "M-99102"}
            }), encoding="utf-8")
            self._run_cli(inp, out, secret="sec-link8-123456")

            recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()]
            jha_pids = [r["patient"] for r in recs if r["file"] in ("sanitized/hi_dob.csv", "sanitized/lab_init.csv", "sanitized/card.json")]
            self.assertEqual(len(jha_pids), 4)
            self.assertTrue(all(jha_pids))
            self.assertEqual(len(set(jha_pids)), 1)

            g_pids = [r["patient"] for r in recs if r["file"] in ("sanitized/note_pkin.txt", "sanitized/opd_g.json")]
            self.assertEqual(len(g_pids), 2)
            self.assertTrue(all(g_pids))
            self.assertEqual(len(set(g_pids)), 1)
            npk = (out / "sanitized" / "note_pkin.txt").read_text(encoding="utf-8")
            self.assertNotIn("Godarosh", npk)
            self.assertNotIn("Mevish", npk)
            self.assertNotIn("Rajesh", npk)
            self.assertIn("K/C/O Bell's palsy", npk)

    def test_phase8_exportedfor_xhtml_url_id_and_begum_surname(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out = root / "input", root / "out"
            inp.mkdir()
            # 1. exportedFor metadata must never bypass scrub_text as DOCTOR; xhtml namespace must not inject fake MRN
            (inp / "opd.json").write_text(json.dumps({
                "meta": {"exportedFor": "query: naam=VariantFirstname UnseenSurname"},
                "tokens": [{"pt": {"ref": "AYU-H-55-0599", "label": "S.D. Begum"}, "dx": "Dengue fever"}],
            }), encoding="utf-8")
            # 2. Bundle with xmlns="http://www.w3.org/1999/xhtml" and surname "Begum"
            (inp / "fhir.json").write_text(json.dumps({
                "resourceType": "Bundle",
                "type": "collection",
                "entry": [{
                    "resource": {
                        "resourceType": "Patient",
                        "id": "p-begum",
                        "text": {"status": "generated", "div": "<div xmlns=\"http://www.w3.org/1999/xhtml\">Shidhaat Begum</div>"},
                        "name": [{"family": "Begum", "given": ["Shidhaat"]}],
                        "identifier": [{"value": "AYU-H-55-0599"}],
                    }
                }],
            }), encoding="utf-8")
            self._run_cli(inp, out, secret="sec-blindfix-9988")
            opd_out = (out / "sanitized" / "opd.json").read_text(encoding="utf-8")
            self.assertNotIn("VariantFirstname", opd_out)
            self.assertNotIn("UnseenSurname", opd_out)
            recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()]
            pids = [r["patient"] for r in recs if r["patient"]]
            self.assertEqual(len(pids), 2)
            self.assertEqual(len(set(pids)), 1)

    def test_phase9_family_phone_cross_script_village_byear_and_labharthi(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out = root / "input", root / "out"
            inp.mkdir()
            # Multi-member family phone: wife (Devanagari village, 2024 vs 2026 aging) & husband (same phone, different name)
            (inp / "reg.csv").write_text(
                "UHID,Patient Name,Gender,Age,DOB,Village,Mobile\n"
                "SNJ/26/001,Sukhwinder Kaur,F,41,22/01/1982,Durgamau Kalan,9876543210\n"
                "SNJ/26/002,Kuldeep Singh,M,46,10/03/1979,Durgamau Kalan,9876543210\n",
                encoding="utf-8",
            )
            (inp / "rx_wife.txt").write_text(
                "नाम: सुखविंदर कौर   आयु: 44 वर्ष\nग्राम: दुर्गामऊ कलां\nतारीख: 16/05/2026\nDiagnosis: Fever\n",
                encoding="utf-8",
            )
            (inp / "note_co.txt").write_text(
                "[16-Oct-25] opd: Meekan (C/o Chacheraj) - Iron deficiency anaemia followup.\n"
                "Number 89063-18163.\n",
                encoding="utf-8",
            )
            (inp / "batch.tsv").write_text(json.dumps([
                {"labharthi": "Meekan Kurian", "guardian": "Chacheraj Kurian", "mobile": "8906318163"}
            ]), encoding="utf-8")
            (inp / "whatsapp.txt").write_text(
                "14-Nov-24 9:27 pm - Nurse: Meekan di ka result normal, 89063-18163 pe batana\n"
                "Patient ko Dawa di.\n",
                encoding="utf-8",
            )
            self._run_cli(inp, out, secret="sec-phase9-check")
            recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()]
            by_file = {}
            for r in recs:
                by_file.setdefault(r["file"], []).append(r["patient"])
            # Wife linked across script, village transliteration, and 41->44 aging; husband stays distinct on same phone
            wife_reg = by_file["sanitized/reg.csv"][0]
            husb_reg = by_file["sanitized/reg.csv"][1]
            self.assertNotEqual(wife_reg, husb_reg)
            self.assertEqual(by_file["sanitized/rx_wife.txt"][0], wife_reg)
            # Note with (C/o Rel), WhatsApp "di ka", and "labharthi" JSON behind .tsv all link to one cluster
            meekan_pids = [
                by_file["sanitized/note_co.txt"][0],
                by_file["sanitized/batch.tsv"][0],
                by_file["sanitized/whatsapp.txt"][0],
            ]
            self.assertEqual(len(set(meekan_pids)), 1)
            self.assertTrue(meekan_pids[0])
            # "labharthi" field replaced by PSN (not [NAME]), ensuring pseudonym_consistency
            batch_out = (out / "sanitized" / "batch.tsv").read_text(encoding="utf-8")
            self.assertIn(meekan_pids[0], batch_out)
            # "Dawa di." never falsely treated as patient name
            wa_out = (out / "sanitized" / "whatsapp.txt").read_text(encoding="utf-8")
            self.assertIn("Dawa di", wa_out)

    def test_phase9_hyphenated_mrn_and_camelcase_filename_hygiene(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out = root / "input", root / "out"
            inp.mkdir()
            (inp / "DS-UPADHYAY-reema-R-2024-A-5670.txt").write_text(
                "Patient Name: Reema Upadhyay\nMRN: R/2024/A/5670\nDx: Typhoid fever\n", encoding="utf-8"
            )
            (inp / "MaheeAwasthi_CBC_17Mar.json").write_text(json.dumps({
                "patient": {"name": "Mahee Awasthi", "mrn": "KMC:2024:01112"},
                "results": [{"test": "Hb", "result": "11.5", "unit": "g/dL"}],
            }), encoding="utf-8")
            self._run_cli(inp, out, secret="sec-fname-hygiene")
            rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
            outs = [f["output"] for f in rep["files"] if f["status"] == "sanitized"]
            self.assertEqual(len(outs), 2)
            joined = "\n".join(outs) + "\n" + (out / "records.jsonl").read_text(encoding="utf-8")
            for leaked in ("UPADHYAY", "Upadhyay", "reema", "5670", "R-2024-A", "Mahee", "Awasthi"):
                self.assertNotIn(leaked, joined)

    def test_phase10_deva_apostrophe_dates_staff_and_canary_cues(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out1, out2 = root / "input", root / "out1", root / "out2"
            inp.mkdir()
            (inp / "summary.md").write_text(
                "| Rugir naam | चजादम भोई |\n"
                "| Jonmo tarikh | ०३/०९/२०१७ |\n"
                "| Bhorti | २५/०७/२०२५ |\n"
                "| Ruksot | २७/०७/२०२५ |\n"
                "| Admit2 | 29 Mar '25 |\n"
                "| Disch2 | 11 Apr '25 |\n"
                "<!-- copied from the chart of Fozu Xozor -->\n",
                encoding="utf-8",
            )
            (inp / "opd.json").write_text(json.dumps({
                "patient": {"name": "Chajadam Bhoi", "mrn": "BGH#25#49976"},
                "seen_by": {"doctor": "Dr. Beeda Pradhan", "assisted_by": {"role": "GNM", "name": "Sr. Puba Hazarika"}},
            }), encoding="utf-8")
            (inp / "merge.txt").write_bytes(
                b"MSH|^~\\&|HIS|H1|HUB|H1|20250902||ADT^A40|M1|P|2.5\r"
                b"PID|1||BGH#25#49976^^^H1^MR\r"
                b"MRG|OLD-4174^^^H1^MR\r"
                b"NTE|1||Duplicate chart of Foza Xuqen merged\r"
            )
            self._run_cli(inp, out1, secret="sec-p10-alpha-123")
            self._run_cli(inp, out2, secret="sec-p10-beta-456")

            md1 = (out1 / "sanitized" / "summary.md").read_text(encoding="utf-8")
            md2 = (out2 / "sanitized" / "summary.md").read_text(encoding="utf-8")
            for raw in ("०३/०९/२०१७", "२५/०७/२०२५", "२७/०७/२०२५", "29 Mar '25", "11 Apr '25", "Fozu Xozor"):
                self.assertNotIn(raw, md1)
            self.assertNotEqual(md1, md2)

            opd1 = (out1 / "sanitized" / "opd.json").read_text(encoding="utf-8")
            self.assertIn("Sr. Puba Hazarika", opd1)
            self.assertIn("Dr. Beeda Pradhan", opd1)

            hl7 = (out1 / "sanitized" / "merge.txt").read_bytes().decode("utf-8")
            self.assertNotIn("OLD-4174", hl7)
            self.assertNotIn("Foza Xuqen", hl7)

    def test_phase10_json_keyed_map_and_lenient_jsonl_bounds(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            inp, out = root / "input", root / "out"
            inp.mkdir()
            (inp / "alt_reg.csv").write_text("UHID,Patient Name\nALT-99881,Ramesh Sharma\n", encoding="utf-8")
            (inp / "visits.json").write_text(json.dumps({
                "visit_order": ["VC-UK97820"],
                "visits": {
                    "V001": {"uhid": "MR-100", "name": "Mohan Lal", "dx": "Fever"},
                    "VC-UK97820": {"uhid": "MR-105", "name": "Deepak Rao", "dx": "Sprain"},
                    "ALT-99881": {"uhid": "MR-101", "name": "Ramesh Sharma", "dx": "Cough"},
                    "H-88123": {"uhid": "MR-102", "name": "Kamla Devi", "dx": "Asthma"},
                    "Ramesh": {"uhid": "MR-103", "name": "Sohan Verma", "dx": "Cold"},
                    "ABCDE1234F": {"uhid": "MR-104", "name": "Anita Nair", "dx": "Rash"},
                }
            }), encoding="utf-8")
            deep_nest = '{"uhid": "M-DEEP", "name": "Raju Das", "x": ' + ('[' * 75) + '1' + (']' * 75) + '}'
            (inp / "mixed.jsonl").write_text(
                "{'uhid': 'J-101', 'hesaru': 'Kaveri Rao', note: 'Dx: fever, BP: 120/80',}\n"
                "{'uhid': 'J-102', 'hesaru': 'Bala Nair', 'tags': {'set_item'}, 'nested': {1: 'Bala Nair'}, 'big': " + ("1" * 120) + "}\n"
                + deep_nest + "\n",
                encoding="utf-8",
            )
            self._run_cli(inp, out, secret="sec-p10-bounds")
            san_v = (out / "sanitized" / "visits.json").read_text(encoding="utf-8")
            v_obj = json.loads(san_v)
            self.assertIn("V001", v_obj["visits"])
            self.assertIn("VC-UK97820", v_obj["visits"])
            for leaked_key in ("ALT-99881", "H-88123", "Ramesh", "ABCDE1234F"):
                self.assertNotIn(leaked_key, san_v)
            recs_txt = (out / "records.jsonl").read_text(encoding="utf-8")
            for leaked_key in ("ALT-99881", "H-88123", "Ramesh", "ABCDE1234F"):
                self.assertNotIn(leaked_key, recs_txt)

            mixed_lines = (out / "sanitized" / "mixed.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(mixed_lines), 3)
            row0 = json.loads(mixed_lines[0])
            self.assertEqual(row0["note"], "Dx: fever, BP: 120/80")
            self.assertNotIn("Bala Nair", mixed_lines[1])
            self.assertNotIn("Raju Das", mixed_lines[2])


if __name__ == "__main__":
    unittest.main()
