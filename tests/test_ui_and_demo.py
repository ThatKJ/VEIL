"""End-to-end tests for demo/sample_hospital/ and tools/veil_ui.py offline server."""
from __future__ import annotations

import base64
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import veil_passport as VP  # noqa: E402
import veil_ui as UI  # noqa: E402


class TestDemoAndUI(unittest.TestCase):
    def test_sample_hospital_demo_end_to_end(self):
        demo_inp = ROOT / "demo" / "sample_hospital"
        self.assertTrue(demo_inp.is_dir())
        with tempfile.TemporaryDirectory(prefix="veil_demo_test_") as td:
            out = Path(td) / "out"
            env = {**os.environ, "RAKSHA_SECRET": "test-demo-secret-key"}
            res = subprocess.run(
                [sys.executable, str(ROOT / "main.py"), "--input", str(demo_inp), "--output", str(out)],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("quarantined 1", res.stdout)

            passport = VP.audit(demo_inp, out)
            self.assertEqual(passport["structural"]["input_files"], 7)
            self.assertEqual(passport["structural"]["exported"], 6)
            self.assertEqual(passport["structural"]["quarantined"], 1)
            self.assertEqual(passport["privacy"]["residual_pattern_hits"], {})
            self.assertEqual(passport["privacy"]["files_with_residue"], 0)
            self.assertEqual(passport["clinical"]["protected_values_kept_pct"], 100.0)
            self.assertEqual(passport["clinical"]["notes_with_intervals_preserved"], "1/1")
            self.assertEqual(passport["identity"]["distinct_pseudonyms"], 5)

            recs = [
                json.loads(line)
                for line in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            by_file_loc = {(r["file"], r["loc"]): r["patient"] for r in recs}

            # Cross-script & multi-format linkage for SH-25-1001
            arjun_visits = by_file_loc[("sanitized/opd/coded_visits.json", "/visits/0")]
            arjun_tsv = by_file_loc[("sanitized/reg/admissions_super.tsv", "row:0")]
            arjun_lab = by_file_loc[("sanitized/lab/panel_eav.csv", "row:0")]
            self.assertIsNotNone(arjun_visits)
            self.assertEqual(arjun_visits, arjun_tsv)
            self.assertEqual(arjun_visits, arjun_lab)

            # Homonyms kept apart
            meera_34 = by_file_loc[("sanitized/reg/admissions_super.tsv", "row:1")]
            meera_62 = by_file_loc[("sanitized/reg/admissions_super.tsv", "row:2")]
            self.assertNotEqual(meera_34, meera_62)

            # Household ration-card sharers kept apart
            kavita = by_file_loc[("sanitized/reg/admissions_super.tsv", "row:3")]
            rohan = by_file_loc[("sanitized/reg/admissions_super.tsv", "row:4")]
            self.assertNotEqual(kavita, rohan)

    def test_ui_server_api_upload_corrupt_repair_and_exports(self):
        with tempfile.TemporaryDirectory(prefix="veil_ui_test_") as td:
            srv, _ = UI.create_server(host="127.0.0.1", port=0, preload_demo=True, workdir=Path(td))
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            base = f"http://127.0.0.1:{port}"
            try:
                # Static UI assets
                for asset, marker in (
                    ("/", "VEIL — Clinical Privacy Command Center"),
                    ("/styles.css", "--emerald"),
                    ("/app.js", "highlightSanitized"),
                ):
                    with urllib.request.urlopen(base + asset, timeout=5) as r:
                        self.assertEqual(r.status, 200)
                        self.assertIn(marker, r.read().decode("utf-8"))

                # State endpoint & zero raw PII in audit/graph/arena responses
                with urllib.request.urlopen(base + "/api/state", timeout=5) as r:
                    state = json.loads(r.read().decode("utf-8"))
                self.assertTrue(state["ready"])
                self.assertEqual(state["passport_status"], "verified")
                self.assertEqual(state["engine_executions"], 1)
                self.assertEqual(state["arena_status"], "pending")

                # On-demand Privacy Arena reuses the active 'adaptive' run cleanly
                req_arena = urllib.request.Request(base + "/api/arena/run", method="POST", data=b"{}")
                with urllib.request.urlopen(req_arena, timeout=20) as r:
                    arena_res = json.loads(r.read().decode("utf-8"))
                self.assertEqual(len(arena_res["privacy_arena"]), 3)
                adap_row = next(x for x in arena_res["privacy_arena"] if x["mode"] == "adaptive")
                self.assertTrue(adap_row["reused_from_active_run"])

                with urllib.request.urlopen(base + "/api/state", timeout=5) as r:
                    state = json.loads(r.read().decode("utf-8"))
                audit_blob = json.dumps({
                    "passport": state["passport"],
                    "identity_graph": state["identity_graph"],
                    "identity_decisions": state["identity_decisions"],
                    "privacy_arena": state["privacy_arena"],
                }, ensure_ascii=False)
                for pii in ("Arjun Verma", "अर्जुन वर्मा", "Meera Sharma", "Kavita Nair", "Rohan Nair", "9876501122", "629133048812"):
                    self.assertNotIn(pii, audit_blob)

                # Intentional synthetic defect + repair
                req_bad = urllib.request.Request(base + "/api/passport/corrupt", method="POST", data=b"{}")
                with urllib.request.urlopen(req_bad, timeout=10) as r:
                    bad = json.loads(r.read().decode("utf-8"))
                self.assertEqual(bad["status"], "defect_detected")
                self.assertTrue(len(bad["corrupted_passport"]["audit"]["residual_risks"]) >= 1)

                req_rep = urllib.request.Request(base + "/api/passport/repair", method="POST", data=b"{}")
                with urllib.request.urlopen(req_rep, timeout=10) as r:
                    rep = json.loads(r.read().decode("utf-8"))
                self.assertEqual(rep["status"], "repaired")
                self.assertEqual(rep["passport"]["residual_risks"], [])

                # Export HTML + JSON + ZIP
                with urllib.request.urlopen(base + "/api/passport/html", timeout=5) as r:
                    self.assertIn("VEIL Privacy Passport", r.read().decode("utf-8"))
                with urllib.request.urlopen(base + "/api/download/zip", timeout=5) as r:
                    zbytes = r.read()
                with zipfile.ZipFile(io.BytesIO(zbytes), "r") as zf:
                    names = set(zf.namelist())
                    self.assertIn("report.json", names)
                    self.assertIn("records.jsonl", names)
                    self.assertTrue(any(n.startswith("sanitized/") for n in names))

                # Path traversal protection on upload
                bad_upload = json.dumps({
                    "mode": "upload",
                    "files": [{"path": "../escape.txt", "content_b64": base64.b64encode(b"hi").decode()}],
                }).encode("utf-8")
                req_trav = urllib.request.Request(
                    base + "/api/run", method="POST", data=bad_upload,
                    headers={"Content-Type": "application/json"},
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req_trav, timeout=5)
                self.assertEqual(ctx.exception.code, 400)
                ctx.exception.close()

                # Valid synthetic upload via sync mode
                note_b64 = base64.b64encode(
                    b"Patient: Anita Das\nUHID: UHID-99881\nBP 118/76 mmHg\nTab. Amoxicillin 500 mg\n"
                ).decode()
                ok_upload = json.dumps({
                    "mode": "upload",
                    "sync": True,
                    "label": "Unit Upload Synth",
                    "files": [{"path": "opd/visit1.txt", "content_b64": note_b64}],
                }).encode("utf-8")
                req_ok = urllib.request.Request(
                    base + "/api/run", method="POST", data=ok_upload,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req_ok, timeout=15) as r:
                    done = json.loads(r.read().decode("utf-8"))
                self.assertEqual(done["status"], "ready")
                with urllib.request.urlopen(base + "/api/state", timeout=5) as r:
                    up_state = json.loads(r.read().decode("utf-8"))
                self.assertEqual(up_state["dataset_label"], "Unit Upload Synth")
                self.assertEqual(up_state["engine_executions"], 1)
                self.assertEqual(up_state["passport_status"], "pending")
                self.assertEqual(up_state["arena_status"], "pending")

                # Trigger on-demand Privacy Passport verification for uploaded dataset
                req_pp = urllib.request.Request(base + "/api/passport/run", method="POST", data=b"{}")
                with urllib.request.urlopen(req_pp, timeout=15) as r:
                    pp_res = json.loads(r.read().decode("utf-8"))
                self.assertEqual(pp_res["passport_status"], "verified")
                self.assertEqual(pp_res["passport"]["privacy"]["files_with_residue"], 0)
                shutil.rmtree(Path(td), ignore_errors=True)
            finally:
                srv.shutdown()
                srv.server_close()


if __name__ == "__main__":
    unittest.main()
