"""AEGIS regression tests: UI host/origin policy, security headers, demo-key isolation, verifier sensitivity."""
from __future__ import annotations

import base64
import http.client
import json
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import veil_passport as VP  # noqa: E402
import veil_ui as UI  # noqa: E402


class TestUiHostAndOrigin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp(prefix="aegis_ui_")
        cls.srv, _ = UI.create_server(host="127.0.0.1", port=0, preload_demo=True, workdir=Path(cls.td))
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.td, ignore_errors=True)

    def _req(self, method, path, headers=None, body=b""):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        c.putrequest(method, path, skip_host=True)
        for k, v in {"Host": f"127.0.0.1:{self.port}", **(headers or {})}.items():
            c.putheader(k, v)
        c.putheader("Content-Length", str(len(body)))
        c.endheaders(body)
        r = c.getresponse()
        data = r.read()
        hdrs = dict(r.getheaders())
        c.close()
        return r.status, data, hdrs

    def test_rebinding_host_rejected_on_every_sensitive_get(self):
        for path in ("/", "/api/state", "/api/diff?idx=0", "/api/passport/json", "/api/download/zip"):
            st, _, _ = self._req("GET", path, {"Host": f"evil.example:{self.port}"})
            self.assertEqual(st, 403, path)
        st, _, _ = self._req("GET", "/api/state", {"Host": "127.0.0.1:1"})
        self.assertEqual(st, 403)

    def test_loopback_hosts_allowed(self):
        for host in (f"127.0.0.1:{self.port}", f"localhost:{self.port}"):
            st, _, _ = self._req("GET", "/api/health", {"Host": host})
            self.assertEqual(st, 200, host)

    def test_cross_origin_post_rejected_even_with_matching_foreign_host(self):
        st, _, _ = self._req("POST", "/api/passport/run", {"Host": f"evil.example:{self.port}", "Origin": f"http://evil.example:{self.port}"})
        self.assertEqual(st, 403)
        st, _, _ = self._req("POST", "/api/passport/run", {"Origin": "http://evil.example"})
        self.assertEqual(st, 403)
        st, _, _ = self._req("POST", "/api/passport/run", {"Origin": "null"})
        self.assertEqual(st, 403)

    def test_same_origin_post_allowed_and_security_headers_present(self):
        st, _, h = self._req("POST", "/api/passport/run", {"Origin": f"http://localhost:{self.port}"})
        self.assertEqual(st, 200)
        st, _, h = self._req("GET", "/")
        self.assertEqual(h.get("X-Frame-Options"), "DENY")
        self.assertIn("frame-ancestors 'none'", h.get("Content-Security-Policy", ""))
        script_src = h["Content-Security-Policy"].split("script-src", 1)[1].split(";", 1)[0]
        self.assertNotIn("'unsafe-inline'", script_src)
        self.assertNotIn("'unsafe-eval'", script_src)

    def test_state_never_contains_secret(self):
        _, data, _ = self._req("GET", "/api/state")
        self.assertNotIn(UI.DEMO_SECRET.encode(), data)


class TestAbandonedWorkdirReaper(unittest.TestCase):
    def test_only_dead_owner_marked_veil_dirs_are_removed(self):
        import os
        root = Path(tempfile.mkdtemp(prefix="aegis_reap_"))
        try:
            dead, live, legacy, other = root / "veil_ui_dead", root / "veil_ui_live", root / "veil_ui_legacy", root / "other_dir"
            for d in (dead, live, legacy, other):
                (d / "job_x").mkdir(parents=True)
            (dead / UI._OWNER_MARKER).write_text(json.dumps({"pid": 2 ** 22 + 12345}), encoding="utf-8")
            (live / UI._OWNER_MARKER).write_text(json.dumps({"pid": os.getpid()}), encoding="utf-8")
            (other / UI._OWNER_MARKER).write_text(json.dumps({"pid": 2 ** 22 + 12345}), encoding="utf-8")
            self.assertEqual(UI._reap_abandoned_workdirs(root), 1)
            self.assertFalse(dead.exists())
            self.assertTrue(live.exists() and legacy.exists() and other.exists())
        finally:
            shutil.rmtree(root, ignore_errors=True)


class TestDemoKeyIsolation(unittest.TestCase):
    def test_ephemeral_secret_is_random_and_not_the_public_demo_key(self):
        a, b = UI._ephemeral_secret(), UI._ephemeral_secret()
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, UI.DEMO_SECRET)
        self.assertGreaterEqual(len(a), 32)


def _bundle(ref: str) -> dict:
    return {"resourceType": "Bundle", "entry": [
        {"fullUrl": "urn:uuid:p1", "resource": {"resourceType": "Patient", "id": "p1"}},
        {"fullUrl": "urn:uuid:o1", "resource": {"resourceType": "Observation", "id": "o1", "subject": {"reference": ref},
                                                "contained": [{"resourceType": "Device", "id": "d"}], "device": {"reference": "#d"}}},
    ]}


class TestPassportContextPairs(unittest.TestCase):
    """Same expression as legitimate clinical/institutional content (A) vs genuine synthetic patient PII (B)."""

    def test_harvest_separates_staff_medication_institution_from_patient(self):
        root = Path(tempfile.mkdtemp(prefix="aegis_pair_"))
        try:
            (root / "reg.csv").write_text(
                "patient_name,attending_name,medication_name,hospital_name\n"
                "Tusha Kuruba,SN Tusha Kuruba,Metformin 500 mg,Meham Sarvjanik Aspatal\n", encoding="utf-8")
            vals, inst = VP._harvest_independent_identifiers(root)
            self.assertIn("tusha kuruba", vals)                 # B: the patient is harvested
            self.assertNotIn("sn tusha kuruba", vals)           # A: staff-titled entry is not a patient identity
            self.assertNotIn("metformin 500 mg", vals)          # A: clinical expression
            self.assertIn("meham sarvjanik aspatal", inst)      # A: institution
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_clinician_context_ignored_but_bare_patient_mention_counts(self):
        self.assertTrue(VP._only_in_staff_context("tusha kuruba", VP.norm("Reviewed by SN Tusha Kuruba.")))
        self.assertTrue(VP._only_in_staff_context("anand shukla", VP.norm("Seen by Dr. Anand Shukla.")))
        self.assertFalse(VP._only_in_staff_context("tusha kuruba", VP.norm("Patient Tusha Kuruba admitted.")))
        self.assertFalse(VP._only_in_staff_context("anand shukla", VP.norm("Dr. Anand Shukla saw patient Anand Shukla.")))


class TestVerifierSensitivity(unittest.TestCase):
    def test_contained_reference_resolves_and_broken_reference_is_counted(self):
        self.assertEqual(VP._audit_fhir_bundle(_bundle("urn:uuid:p1"))[:2], (2, 2))
        self.assertEqual(VP._audit_fhir_bundle(_bundle("urn:uuid:gone"))[:2], (1, 2))

    def test_short_base64_payload_is_decoded_for_residue_scan(self):
        tok = base64.b64encode(b"9876501234").decode()
        self.assertGreaterEqual(len(tok), 16)
        self.assertIn("9876501234", VP.with_decoded_extras("ref " + tok))


if __name__ == "__main__":
    unittest.main()
