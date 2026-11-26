"""Comprehensive performance, multi-file, fault-injection, and Playwright browser tests for VEIL UI hotfix."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import veil_ui as UI  # noqa: E402


def _make_csv_bytes(n_rows: int, repeated: bool = False, prefix: str = "UH") -> bytes:
    lines = ["uhid,patient_name,age,gender,mobile,village,district,pin,diagnosis"]
    for i in range(n_rows):
        pid = (i % 50) if repeated else i
        lines.append(
            f"{prefix}-{100000 + pid},Ramesh Kumar{pid % 20} S{pid},{20 + (pid % 65)},M,{9000000000 + pid},Rampur,Sitapur,261001,Type 2 DM (E11.9)"
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _multipart_post(url: str, fields: dict[str, str], files: list[tuple[str, bytes]], timeout: int = 120) -> tuple[int, dict]:
    boundary = "----VeilHotfixBoundary987654"
    parts: list[bytes] = []
    for k, v in fields.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode("utf-8")
        )
    for rel, data in files:
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="{rel}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode("utf-8")
            + data
            + b"\r\n"
        )
    parts.append(f"--{boundary}--\r\n".encode("utf-8"))
    body = b"".join(parts)
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "Content-Length": str(len(body))},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        data = json.loads(exc.read().decode("utf-8"))
        return exc.code, data


class UiHotfixAndScaleTests(unittest.TestCase):
    def _poll_until_done(self, base: str, job_id: str, timeout: float = 120.0) -> dict:
        t0 = time.monotonic()
        while time.monotonic() - t0 < timeout:
            with urllib.request.urlopen(f"{base}/api/status/{job_id}", timeout=15) as r:
                st = json.loads(r.read().decode("utf-8"))
            if st["status"] in ("ready", "failed", "cancelled"):
                return st
            time.sleep(0.15)
        self.fail(f"Job {job_id} timed out after {timeout}s")

    def test_upload_scale_matrix_100_to_50k_single_engine_run_and_bounded_state(self):
        """Measure upload, 1x engine, validation, optional audit/identity, state size & ZIP accounting."""
        workloads = [
            ("100_unique", 100, False, True),
            ("1000_unique", 1000, False, True),
            ("5000_unique", 5000, False, True),
            ("5000_repeat50", 5000, True, False),
            ("10000_unique", 10000, False, True),
            ("25000_repeat50", 25000, True, False),
            ("50000_repeat50", 50000, True, False),
        ]
        metrics_log = []
        with tempfile.TemporaryDirectory(prefix="veil_ui_scale_") as td:
            srv, _ = UI.create_server("127.0.0.1", 0, preload_demo=False, workdir=Path(td))
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            base = f"http://127.0.0.1:{port}"
            try:
                for label, n_rows, rep_flag, run_opt in workloads:
                    raw = _make_csv_bytes(n_rows, repeated=rep_flag)
                    t0 = time.monotonic()
                    code, start = _multipart_post(
                        base + "/api/run",
                        {"mode": "upload", "policy": "adaptive", "secret": "scale-secret-2026", "label": label, "relpaths": json.dumps([f"reg/{label}.csv"])},
                        [(f"reg/{label}.csv", raw)],
                    )
                    self.assertEqual(code, 202, start)
                    st = self._poll_until_done(base, start["job_id"], timeout=120.0)
                    total_wall = round(time.monotonic() - t0, 3)
                    self.assertEqual(st["status"], "ready", f"{label} failed: {st}")

                    with urllib.request.urlopen(base + "/api/state", timeout=15) as r:
                        state_bytes = r.read()
                    state_json = json.loads(state_bytes.decode("utf-8"))
                    self.assertEqual(state_json["engine_executions"], 1)
                    self.assertEqual(state_json["passport_status"], "pending")
                    self.assertEqual(state_json["arena_status"], "pending")
                    self.assertEqual(state_json["report"]["counts"]["records_processed"], n_rows)
                    self.assertLess(len(state_bytes), 256 * 1024, f"/api/state bloated on {label}: {len(state_bytes)}")

                    # Verify ZIP contains all N sanitized records immediately without truncation
                    with urllib.request.urlopen(base + "/api/download/zip", timeout=30) as r:
                        zbytes = r.read()
                    with zipfile.ZipFile(io.BytesIO(zbytes), "r") as zf:
                        rec_lines = [ln for ln in zf.read("records.jsonl").decode("utf-8").splitlines() if ln.strip()]
                        self.assertEqual(len(rec_lines), n_rows)

                    opt_id_s = None
                    opt_pp_s = None
                    opt_arena_s = None
                    if run_opt and n_rows <= 10000:
                        req_id = urllib.request.Request(base + "/api/identity/run", method="POST", data=b"{}")
                        with urllib.request.urlopen(req_id, timeout=30) as r:
                            id_res = json.loads(r.read().decode("utf-8"))
                        opt_id_s = id_res["identity_s"]
                        g = id_res["identity_graph"]
                        self.assertLessEqual(len(g["clusters"]), UI.MAX_GRAPH_CLUSTERS)
                        self.assertLessEqual(len(g["records"]), UI.MAX_GRAPH_RECORDS)
                        self.assertLessEqual(len(g["edges"]), UI.MAX_GRAPH_EDGES)
                        self.assertEqual(g["meta"]["total_clusters"], n_rows)

                        req_pp = urllib.request.Request(base + "/api/passport/run", method="POST", data=b"{}")
                        with urllib.request.urlopen(req_pp, timeout=60) as r:
                            pp_res = json.loads(r.read().decode("utf-8"))
                        opt_pp_s = pp_res["passport_s"]
                        self.assertEqual(pp_res["passport_status"], "verified")
                        self.assertEqual(pp_res["passport"]["verdict"], "PASS")
                        self.assertEqual(pp_res["passport"]["clinical"]["protected_values_kept_pct"], 100.0)
                        self.assertEqual(pp_res["passport"]["identity"]["pseudonym_placement_errors"], 0)
                        self.assertEqual(pp_res["passport"]["privacy"]["residual_pattern_hits"], {})
                        self.assertEqual(pp_res["passport"]["privacy"]["files_with_residue"], 0)

                        if n_rows == 1000:
                            req_ar = urllib.request.Request(base + "/api/arena/run", method="POST", data=b"{}")
                            with urllib.request.urlopen(req_ar, timeout=60) as r:
                                ar_res = json.loads(r.read().decode("utf-8"))
                            opt_arena_s = ar_res["arena_s"]
                            adap = next(x for x in ar_res["privacy_arena"] if x["mode"] == "adaptive")
                            self.assertTrue(adap["reused_from_active_run"])

                    tim = state_json["timings"]
                    metrics_log.append({
                        "label": label,
                        "rows": n_rows,
                        "upload_s": tim["upload_staging_s"],
                        "engine_s": tim["engine_runtime_s"],
                        "validate_s": tim["validation_s"],
                        "total_ready_s": total_wall,
                        "state_kb": round(len(state_bytes) / 1024, 1),
                        "identity_s": opt_id_s,
                        "passport_s": opt_pp_s,
                        "arena_s": opt_arena_s,
                    })
                print("\nUI_SCALE_MATRIX:", json.dumps(metrics_log, indent=2), flush=True)
            finally:
                srv.shutdown()
                srv.server_close()

    def test_multifile_counts_duplicates_limits_quarantine_and_interrupted_requests(self):
        with tempfile.TemporaryDirectory(prefix="veil_ui_multi_") as td:
            srv, state = UI.create_server("127.0.0.1", 0, preload_demo=False, workdir=Path(td))
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            base = f"http://127.0.0.1:{port}"
            try:
                # 1. File counts: 1, 2, 10, 32, 64 files + duplicate filename dedupe + binary quarantine accounting
                for count in (1, 2, 10, 32, 64):
                    files = []
                    rels = []
                    for i in range(count):
                        # Include intentional duplicate filename on multi-file batches + malformed binary at last slot of 64
                        rel = "shared/visits.csv" if (count >= 2 and i in (0, 1)) else (
                            "bad/corrupt.pdf" if (count == 64 and i == 63) else f"ward_{i % 4}/batch_{i}.csv"
                        )
                        payload = b"%PDF-1.5\x00\xff\xfe" if rel.endswith(".pdf") else _make_csv_bytes(5, repeated=False, prefix=f"F{i}")
                        files.append((rel, payload))
                        rels.append(rel)
                    code, start = _multipart_post(
                        base + "/api/run",
                        {"mode": "upload", "policy": "adaptive", "secret": "multi-sec", "relpaths": json.dumps(rels)},
                        files,
                    )
                    self.assertEqual(code, 202, start)
                    st = self._poll_until_done(base, start["job_id"], timeout=60.0)
                    self.assertEqual(st["status"], "ready")
                    with urllib.request.urlopen(base + "/api/state", timeout=10) as r:
                        sj = json.loads(r.read().decode("utf-8"))
                    c = sj["report"]["counts"]
                    self.assertEqual(c["files_total"], count)
                    if count == 64:
                        self.assertEqual(c["files_sanitized"], 63)
                        self.assertEqual(c["files_quarantined"], 1)
                    else:
                        self.assertEqual(c["files_sanitized"], count)
                    # Duplicate "shared/visits.csv" -> kept both via "shared/visits (2).csv"
                    if count >= 2:
                        rels_out = {fp["input_rel"] for fp in sj["file_pairs"]}
                        self.assertIn("shared/visits.csv", rels_out)
                        self.assertIn("shared/visits (2).csv", rels_out)

                # 2. > 64 files cleanly rejected
                files65 = [(f"f_{i}.csv", b"uhid,patient_name\nU1,A B\n") for i in range(65)]
                code65, err65 = _multipart_post(base + "/api/run", {"mode": "upload", "secret": "s"}, files65)
                self.assertEqual(code65, 400)
                self.assertEqual(err65["error_code"], "file_count_exceeded")

                # 3. > 16 MB upload cleanly rejected without crashing keep-alive/fetch
                big_payload = b"A" * (UI.MAX_UPLOAD_BYTES + 1024)
                code_big, err_big = _multipart_post(base + "/api/run", {"mode": "upload", "secret": "s"}, [("huge.csv", big_payload)])
                self.assertEqual(code_big, 413)
                self.assertEqual(err_big["error_code"], "size_limit_exceeded")

                # 4. Path traversal rejected cleanly
                code_tr, err_tr = _multipart_post(base + "/api/run", {"mode": "upload", "secret": "s"}, [("../evil.txt", b"Patient: X")])
                self.assertEqual(code_tr, 400)
                self.assertEqual(err_tr["error_code"], "invalid_file")

                # 5. Interrupted TCP request does not crash or poison server
                with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                    sock.sendall(
                        b"POST /api/run HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 5000\r\n\r\n{\"mode\":\"upload\""
                    )
                with urllib.request.urlopen(base + "/api/health", timeout=5) as r:
                    self.assertTrue(json.loads(r.read().decode("utf-8"))["ok"])
            finally:
                srv.shutdown()
                srv.server_close()

    def test_real_browser_playwright_multifile_5k_upload_and_lazy_views(self):
        """Real headless Chromium test: incremental file selection, remove/clear, 5k upload & lazy views."""
        from playwright.sync_api import sync_playwright

        with tempfile.TemporaryDirectory(prefix="veil_pw_") as td:
            root = Path(td)
            f_dir = root / "fixtures"
            f_dir.mkdir()
            (f_dir / "batch_a.csv").write_bytes(_make_csv_bytes(25, prefix="BA"))
            (f_dir / "batch_b.csv").write_bytes(_make_csv_bytes(25, prefix="BB"))
            sub = f_dir / "dup"
            sub.mkdir()
            (sub / "batch_a.csv").write_bytes(_make_csv_bytes(10, prefix="DUP"))
            csv_5k = f_dir / "hospital_5k.csv"
            csv_5k.write_bytes(_make_csv_bytes(5000, repeated=False, prefix="H5K"))

            # Start server in real child subprocess so peak process RSS is isolated and realistic
            proc = subprocess.Popen(
                [sys.executable, str(ROOT / "tools" / "veil_ui.py"), "--host", "127.0.0.1", "--port", "0"],
                cwd=str(ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                url_line = ""
                t0 = time.monotonic()
                while time.monotonic() - t0 < 15.0:
                    ln = proc.stdout.readline()
                    if "http://127.0.0.1:" in ln:
                        url_line = ln.strip()
                        break
                m = re.search(r"http://127\.0\.0\.1:\d+/", url_line)
                self.assertIsNotNone(m, f"UI server failed to announce port: {url_line!r}")
                base_url = m.group(0)

                console_errors: list[str] = []
                page_errors: list[str] = []
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True)
                    page = browser.new_page()
                    page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
                    page.on("pageerror", lambda exc: page_errors.append(str(exc)))

                    page.goto(base_url, wait_until="networkidle")
                    page.click('button[data-view="runner"]')

                    # 1. Incremental selection preserves existing files + handles duplicate names cleanly
                    page.set_input_files("#file-input", [str(f_dir / "batch_a.csv")])
                    self.assertIn("1 / 64 files", page.text_content("#staged-stats-text"))

                    # Repeated selection of another file + exact duplicate filename "batch_a.csv"
                    page.set_input_files("#file-input", [str(f_dir / "batch_b.csv"), str(sub / "batch_a.csv")])
                    stats_txt = page.text_content("#staged-stats-text")
                    self.assertIn("3 / 64 files", stats_txt)
                    staged_html = page.inner_html("#staged-files-list")
                    self.assertIn("batch_a.csv", staged_html)
                    self.assertIn("batch_a (2).csv", staged_html)

                    # Remove 1 file -> 2/64, then Clear All -> hidden
                    page.click('[data-remove="0"]')
                    self.assertIn("2 / 64 files", page.text_content("#staged-stats-text"))
                    page.click("#btn-clear-staged")
                    self.assertTrue(page.is_hidden("#staged-summary-bar"))
                    self.assertTrue(page.is_disabled("#btn-run-uploaded"))

                    # 1b. Select & run 64 files in Chromium
                    b64_dir = f_dir / "batch64"
                    b64_dir.mkdir()
                    b64_paths = []
                    for bi in range(64):
                        fp = b64_dir / f"f_{bi:02d}.csv"
                        fp.write_bytes(_make_csv_bytes(2, prefix=f"B{bi}"))
                        b64_paths.append(str(fp))
                    page.set_input_files("#file-input", b64_paths)
                    self.assertIn("64 / 64 files", page.text_content("#staged-stats-text"))
                    page.click("#btn-run-uploaded")
                    page.wait_for_function(
                        "document.getElementById('runner-log').textContent.includes('64/64 files sanitized')",
                        timeout=30000,
                    )
                    page.click("#btn-clear-staged")

                    # 2. Upload 5,000-row CSV -> completes cleanly via single 1x engine execution!
                    page.set_input_files("#file-input", [str(csv_5k)])
                    self.assertIn("1 / 64 files", page.text_content("#staged-stats-text"))
                    t_ui0 = time.monotonic()
                    page.click("#btn-run-uploaded")
                    page.wait_for_function(
                        "document.getElementById('status-pill').textContent.includes('Sanitized Ready')",
                        timeout=30000,
                    )
                    browser_upload_to_ready_s = round(time.monotonic() - t_ui0, 3)

                    log_txt = page.text_content("#runner-log")
                    self.assertIn("1x engine run", log_txt)
                    self.assertIn("5000 records", log_txt)
                    self.assertNotIn("Failed to fetch", log_txt)
                    self.assertNotIn("Verified PASS", page.text_content("#status-pill"))

                    # 3. Verify lazy Diff Inspector works smoothly on 5,000 rows
                    page.click('button[data-view="inspector"]')
                    page.wait_for_function(
                        "document.getElementById('diff-output-pre').textContent.includes('PSN-')",
                        timeout=10000,
                    )

                    # 4. Verify bounded Identity Graph loads on demand without DOM freeze
                    page.click('button[data-view="graph"]')
                    t_g0 = time.monotonic()
                    page.click("#btn-run-identity")
                    page.wait_for_function(
                        "document.getElementById('graph-subset-badge').textContent.includes('of 5000 clusters')",
                        timeout=20000,
                    )
                    browser_graph_s = round(time.monotonic() - t_g0, 3)

                    # 5. Verify Privacy Passport runs cleanly on demand and reaches Verified PASS (0 false PAN hits!)
                    page.click('button[data-view="passport"]')
                    self.assertIn("VERIFICATION PENDING", page.text_content("#passport-banner"))
                    page.click("#btn-run-passport")
                    page.wait_for_function(
                        "document.getElementById('status-pill').textContent === 'Verified PASS'",
                        timeout=30000,
                    )
                    self.assertIn("5000/5000", page.text_content("#passport-pillars"))
                    self.assertIn("pseudonym placement errors0", page.text_content("#passport-pillars").lower())

                    # 6. Verify Privacy Arena on-demand & Inject Defect -> Detect -> Repair -> Reverify cycle
                    page.click('button[data-view="arena"]')
                    self.assertIn("On-Demand", page.text_content("#arena-status-badge"))
                    page.click("#btn-run-arena")
                    page.wait_for_function(
                        "document.getElementById('arena-status-badge').textContent === 'Measured Live'",
                        timeout=45000,
                    )
                    self.assertIn("VEIL Adaptive", page.text_content("#arena-table"))

                    page.click('button[data-view="passport"]')
                    page.click("#btn-corrupt-demo")
                    page.wait_for_function(
                        "document.getElementById('status-pill').textContent === 'Defect Caught!'",
                        timeout=30000,
                    )
                    self.assertIn("SYNTHETIC DEFECT CAUGHT", page.text_content("#passport-banner"))
                    page.click("#btn-repair-demo")
                    page.wait_for_function(
                        "document.getElementById('status-pill').textContent === 'Verified PASS'",
                        timeout=30000,
                    )

                    # 7. Upload 10,000-row unique CSV & verify full ZIP + Passport Verified PASS
                    csv_10k = f_dir / "hospital_10k.csv"
                    csv_10k.write_bytes(_make_csv_bytes(10000, repeated=False, prefix="H10K"))
                    page.click('button[data-view="runner"]')
                    page.click("#btn-clear-staged")
                    page.set_input_files("#file-input", [str(csv_10k)])
                    t_10k0 = time.monotonic()
                    page.click("#btn-run-uploaded")
                    page.wait_for_function(
                        "document.getElementById('runner-log').textContent.includes('10000 records')",
                        timeout=30000,
                    )
                    browser_10k_ready_s = round(time.monotonic() - t_10k0, 3)

                    with page.expect_download() as dl_info:
                        page.click("#btn-download-zip")
                    dl = dl_info.value
                    with zipfile.ZipFile(dl.path(), "r") as zf:
                        recs_10k = [ln for ln in zf.read("records.jsonl").decode("utf-8").splitlines() if ln.strip()]
                        self.assertEqual(len(recs_10k), 10000)

                    page.click('button[data-view="passport"]')
                    page.click("#btn-run-passport")
                    page.wait_for_function(
                        "document.getElementById('status-pill').textContent === 'Verified PASS'",
                        timeout=30000,
                    )

                    print(
                        f"\nPLAYWRIGHT_E2E: 5k_ready={browser_upload_to_ready_s}s, 10k_ready={browser_10k_ready_s}s, bounded_graph={browser_graph_s}s, console_errs={len(console_errors)}, page_errs={len(page_errors)}",
                        flush=True,
                    )
                    self.assertEqual(console_errors, [])
                    self.assertEqual(page_errors, [])
                    browser.close()
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                for pipe in (proc.stdout, proc.stderr):
                    if pipe is not None:
                        pipe.close()

    def test_passport_pan_assigned_psn_context_positive_and_negative(self):
        """Valid assigned PSNs matching PAN regex do not false-positive; adjacent/malformed/unassigned PANs fail."""
        import veil_passport as VP

        with tempfile.TemporaryDirectory(prefix="veil_pan_ctx_") as td:
            root = Path(td)
            inp, out = root / "in", root / "out"
            inp.mkdir()
            (out / "sanitized").mkdir(parents=True)
            # Clean input note (clinical only so clinical=PASS/SKIPPED, identity checked precisely)
            (inp / "note.txt").write_text("Diagnosis: Type 2 DM (E11.9)\nVitals: BP 120/80 mmHg\n", encoding="utf-8")
            sha_in = hashlib.sha256((inp / "note.txt").read_bytes()).hexdigest()
            psn_valid = "PSN-ABCDE1234F"  # matches PAN regex inside PSN token if unmasked!

            def _write_release(san_text: str):
                (out / "sanitized" / "note.txt").write_text(san_text, encoding="utf-8")
                rec_line = json.dumps({"file": "sanitized/note.txt", "loc": "doc", "patient": psn_valid}) + "\n"
                (out / "records.jsonl").write_text(rec_line, encoding="utf-8")
                rep = {
                    "schema": "raksha-report/1",
                    "files": [{"input_sha256": sha_in, "output": "sanitized/note.txt", "status": "sanitized"}],
                    "counts": {"files_total": 1, "files_sanitized": 1, "files_quarantined": 0, "records_processed": 1, "records_linked": 1},
                }
                (out / "report.json").write_text(json.dumps(rep), encoding="utf-8")

            # Positive 1: Exact assigned PSN token -> 0 false PAN hits -> PASS
            _write_release(f"Patient: {psn_valid}\nDiagnosis: Type 2 DM (E11.9)\nVitals: BP 120/80 mmHg\n")
            res_ok = VP.audit(inp, out)
            self.assertEqual(res_ok["privacy"]["residual_pattern_hits"], {})
            self.assertEqual(res_ok["verdict"], "PASS")

            # Negative 1: Genuine PAN adjacent to valid PSN -> PAN detected!
            _write_release(f"Patient: {psn_valid} ABCDE1234F\nDiagnosis: Type 2 DM (E11.9)\nVitals: BP 120/80 mmHg\n")
            res_adj = VP.audit(inp, out)
            self.assertEqual(res_adj["privacy"]["residual_pattern_hits"].get("PAN"), 1)
            self.assertEqual(res_adj["verdict"], "FAIL")

            # Negative 2: Genuine PAN inside malformed / non-boundary PSN-like / unassigned strings -> PAN detected!
            for bad_tok in (f"{psn_valid}-EXTRA", f"{psn_valid}_X", f"X_{psn_valid}", "PSN-ZXCVB9999Q"):
                _write_release(f"Patient: {psn_valid}\nRef: {bad_tok}\nDiagnosis: Type 2 DM (E11.9)\nVitals: BP 120/80 mmHg\n")
                res_bad = VP.audit(inp, out)
                self.assertEqual(res_bad["privacy"]["residual_pattern_hits"].get("PAN"), 1, f"Failed to flag malformed {bad_tok}")
                self.assertEqual(res_bad["verdict"], "FAIL")

            # Equivalence check: _GramIndex matches exact brute-force substring scan including short/long items
            samples = {"a1b2", "uh-100000", "ramesh kumar0 s12345", "9000012345"}
            text_norm = "note with uh-100000 and a1b2 and row:12345 and 9000012345"
            expected = sorted(s for s in samples if s in text_norm)
            got = sorted(VP._GramIndex(samples).find_hits(text_norm))
            self.assertEqual(got, expected)

    def test_optional_analysis_cannot_overwrite_newer_job(self):
        """Concurrent stale Job 1 optional audit must not clobber a newer active Job 2 release."""
        import veil_passport as VP

        with tempfile.TemporaryDirectory(prefix="veil_ui_iso_") as td:
            srv, state = UI.create_server("127.0.0.1", 0, preload_demo=False, workdir=Path(td))
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            base = f"http://127.0.0.1:{port}"
            try:
                # Run Job 1
                code1, s1 = _multipart_post(base + "/api/run", {"mode": "upload", "secret": "s1", "relpaths": json.dumps(["j1.csv"])}, [("j1.csv", _make_csv_bytes(10, prefix="J1"))])
                self.assertEqual(code1, 202)
                st1 = self._poll_until_done(base, s1["job_id"])
                self.assertEqual(st1["status"], "ready")
                j1_id = s1["job_id"]
                with state.lock:
                    j1_inp = state.active_inp
                    j1_out = state.active_out
                    self.assertIsNotNone(j1_inp)
                    self.assertIsNone(state.active_upload_bytes)

                # Start slow delayed Passport audit on Job 1 vs immediate Job 2 upload
                real_audit = VP.audit
                entered = threading.Event()
                release = threading.Event()

                def slow_audit(*a, **kw):
                    entered.set()
                    release.wait(timeout=5)
                    return real_audit(*a, **kw)

                t_stale = threading.Thread(
                    target=lambda: UI._ensure_passport_audited(state, j1_inp, None, j1_out, force=True, job_id=j1_id),
                    daemon=True,
                )
                VP.audit = slow_audit
                try:
                    t_stale.start()
                    self.assertTrue(entered.wait(timeout=3))
                    # Upload and complete Job 2 while Job 1's optional audit is in-flight!
                    code2, s2 = _multipart_post(base + "/api/run", {"mode": "upload", "secret": "s2", "label": "Job2Wins", "relpaths": json.dumps(["j2.csv"])}, [("j2.csv", _make_csv_bytes(20, prefix="J2"))])
                    self.assertEqual(code2, 202)
                    st2 = self._poll_until_done(base, s2["job_id"])
                    self.assertEqual(st2["status"], "ready")
                finally:
                    release.set()
                    t_stale.join(timeout=5)
                    VP.audit = real_audit

                with urllib.request.urlopen(base + "/api/state", timeout=5) as r:
                    cur_state = json.loads(r.read().decode("utf-8"))
                self.assertEqual(cur_state["dataset_label"], "Job2Wins")
                self.assertEqual(cur_state["active_job_id"], s2["job_id"])
                # Job 2 stays pending (was NOT overwritten by Job 1's stale 'verified' result!)
                self.assertEqual(cur_state["passport_status"], "pending")
                self.assertEqual(cur_state["report"]["counts"]["records_processed"], 20)
            finally:
                srv.shutdown()
                srv.server_close()

    def test_omega_ui_security_multipart_concurrency_and_repair(self):
        """Covers same-origin CSRF, bad query 400, RFC2046 multipart with relpaths-last & boundary-in-body, corrupt/repair on JSON-only upload, and ZIP streaming."""
        with tempfile.TemporaryDirectory(prefix="veil_omega_ui_") as td:
            srv, state = UI.create_server("127.0.0.1", 0, preload_demo=False, workdir=Path(td))
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            base = f"http://127.0.0.1:{port}"
            try:
                # 1. Cross-origin & null-origin POST blocked with 403
                for bad_origin in ("http://evil.example", "null"):
                    req = urllib.request.Request(
                        base + "/api/run",
                        data=b"{}",
                        headers={"Content-Type": "application/json", "Origin": bad_origin},
                        method="POST",
                    )
                    with self.assertRaises(urllib.error.HTTPError) as ctx:
                        urllib.request.urlopen(req, timeout=5)
                    self.assertEqual(ctx.exception.code, 403)

                # 2. Invalid pagination query -> 400
                with self.assertRaises(urllib.error.HTTPError) as ctx400:
                    urllib.request.urlopen(base + "/api/decisions?page=abc", timeout=5)
                self.assertEqual(ctx400.exception.code, 400)

                # 3. Multipart with "--boundary" inside payload AND relpaths placed AFTER files!
                boundary = "----VeilBoundaryXYZ"
                fhir_json = json.dumps({
                    "resourceType": "Patient",
                    "id": "p1",
                    "name": [{"text": "Meera Nair"}],
                    "birthDate": "1990-02-14",
                    "note": [{"text": f"Ref marker --{boundary} mid-body should not truncate"}],
                }).encode("utf-8")
                parts = [
                    f"--{boundary}\r\nContent-Disposition: form-data; name=\"mode\"\r\n\r\nupload\r\n".encode(),
                    f"--{boundary}\r\nContent-Disposition: form-data; name=\"secret\"\r\n\r\nomega-ui-key\r\n".encode(),
                    f"--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"ignored.json\"\r\nContent-Type: application/json\r\n\r\n".encode()
                    + fhir_json + b"\r\n",
                    f"--{boundary}\r\nContent-Disposition: form-data; name=\"relpaths\"\r\n\r\n[\"sub/fhir_patient.json\"]\r\n".encode(),
                    f"--{boundary}--\r\n".encode(),
                ]
                raw_mp = b"".join(parts)
                req_mp = urllib.request.Request(
                    base + "/api/run",
                    data=raw_mp,
                    headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "Origin": base},
                    method="POST",
                )
                with urllib.request.urlopen(req_mp, timeout=5) as resp:
                    self.assertEqual(resp.status, 202)
                    jid = json.loads(resp.read().decode("utf-8"))["job_id"]
                st = self._poll_until_done(base, jid)
                self.assertEqual(st["status"], "ready")

                with state.lock:
                    self.assertIsNotNone(state.active_inp)
                    self.assertIsNone(state.active_upload_bytes)
                    self.assertTrue((state.active_inp / "sub/fhir_patient.json").is_file())
                    self.assertIn("--" + boundary, (state.active_inp / "sub/fhir_patient.json").read_text(encoding="utf-8"))

                # 4. Corrupt & Repair on JSON-only upload (0 .txt files) + ZIP stream check
                req_c = urllib.request.Request(base + "/api/passport/corrupt", data=b"{}", headers={"Origin": base}, method="POST")
                with urllib.request.urlopen(req_c, timeout=10) as rc:
                    corr = json.loads(rc.read().decode("utf-8"))
                self.assertEqual(corr["status"], "defect_detected")
                self.assertEqual(corr["corrupted_passport"]["audit"]["verdict"], "FAIL")

                req_r = urllib.request.Request(base + "/api/passport/repair", data=b"{}", headers={"Origin": base}, method="POST")
                with urllib.request.urlopen(req_r, timeout=15) as rr:
                    rep_res = json.loads(rr.read().decode("utf-8"))
                self.assertEqual(rep_res["status"], "repaired")
                self.assertNotEqual(rep_res["passport"]["verdict"], "FAIL")

                with urllib.request.urlopen(base + "/api/download/zip", timeout=10) as rz:
                    zraw = rz.read()
                with zipfile.ZipFile(io.BytesIO(zraw), "r") as zf:
                    names = set(zf.namelist())
                    self.assertIn("report.json", names)
                    self.assertIn("records.jsonl", names)
                    self.assertNotIn("sanitized/injected_defect.txt", names)
            finally:
                srv.shutdown()
                srv.server_close()

    def test_omega_playwright_all_views_e2e(self):
        """Drive real Chromium across all 7 UI tabs, multi-file staging append, corrupt/repair & error-free console."""
        from playwright.sync_api import sync_playwright

        with tempfile.TemporaryDirectory(prefix="veil_omega_pw_") as td:
            srv, _ = UI.create_server("127.0.0.1", 0, preload_demo=False, workdir=Path(td))
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            base = f"http://127.0.0.1:{port}/"
            try:
                f1 = Path(td) / "ward_a.csv"
                f2 = Path(td) / "ward_note.txt"
                f1.write_text("uhid,patient_name,age,mobile\nUH-501,Ramesh Iyer,45,9876543210\n", encoding="utf-8")
                f2.write_text(
                    "Patient Name: Ramesh Iyer\nUHID: UH-501\nAdmitted 02/03/2026, discharged 08/03/2026.\n"
                    "BP 130/80 mmHg. Tab. Metformin 500 mg BD.\n",
                    encoding="utf-8",
                )

                with sync_playwright() as pw:
                    try:
                        browser = pw.chromium.launch(headless=True)
                    except Exception as exc:
                        self.skipTest(f"Chromium unavailable: {exc}")
                    page = browser.new_page(viewport={"width": 1440, "height": 900})
                    errors = []
                    page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
                    page.on("console", lambda m: errors.append(f"console.{m.type}: {m.text}") if m.type == "error" else None)

                    page.goto(base, wait_until="networkidle")
                    # Before run, download button is disabled
                    self.assertEqual(page.get_attribute("#btn-download-zip", "aria-disabled"), "true")

                    # Switch to Upload & Run and stage TWO sequential files without overwriting the first
                    page.click('button[data-view="runner"]')
                    page.set_input_files("#file-input", str(f1))
                    page.set_input_files("#file-input", str(f2))
                    staged_text = page.text_content("#staged-files-list") or ""
                    self.assertIn("ward_a.csv", staged_text)
                    self.assertIn("ward_note.txt", staged_text)

                    page.click("#btn-run-uploaded")
                    page.wait_for_function(
                        "() => document.querySelector('#status-pill')?.textContent.includes('Sanitized Ready')",
                        timeout=30000,
                    )
                    self.assertEqual(page.get_attribute("#btn-download-zip", "aria-disabled"), "false")

                    # Visit every remaining tab & exercise on-demand controls
                    page.click('button[data-view="inspector"]')
                    page.wait_for_function(
                        "() => (document.querySelector('#diff-output-pre')?.textContent || '').includes('PSN-')",
                        timeout=10000,
                    )

                    page.click('button[data-view="graph"]')
                    page.click("#btn-run-identity")
                    page.wait_for_function(
                        "() => (document.querySelector('#graph-subset-badge')?.textContent || '').includes('clusters')",
                        timeout=15000,
                    )

                    page.click('button[data-view="arena"]')
                    page.click("#btn-run-arena")
                    page.wait_for_function(
                        "() => (document.querySelector('#arena-status-badge')?.textContent || '') === 'Measured Live'",
                        timeout=30000,
                    )

                    page.click('button[data-view="clinical"]')
                    clin_txt = page.text_content("#view-clinical") or ""
                    self.assertIn("500 mg", clin_txt)

                    page.click('button[data-view="passport"]')
                    page.click("#btn-run-passport")
                    page.wait_for_function(
                        "() => (document.querySelector('#passport-banner')?.textContent || '').includes('RELEASE AUDIT PASSED')",
                        timeout=15000,
                    )

                    # Inject defect -> export link gets ?variant=corrupt, repair clears it
                    page.click("#btn-corrupt-demo")
                    page.wait_for_function(
                        "() => (document.querySelector('#passport-banner')?.textContent || '').includes('SYNTHETIC DEFECT CAUGHT')",
                        timeout=10000,
                    )
                    self.assertIn("?variant=corrupt", page.get_attribute("#btn-export-passport-html", "href") or "")

                    page.click("#btn-repair-demo")
                    page.wait_for_function(
                        "() => (document.querySelector('#passport-banner')?.textContent || '').includes('RELEASE AUDIT PASSED')",
                        timeout=20000,
                    )
                    self.assertNotIn("?variant=corrupt", page.get_attribute("#btn-export-passport-html", "href") or "")

                    body_txt = page.inner_text("body")
                    self.assertNotIn("NaN", body_txt)
                    self.assertNotIn("undefined", body_txt)
                    self.assertEqual(errors, [])
                    browser.close()
            finally:
                srv.shutdown()
                srv.server_close()


if __name__ == "__main__":
    unittest.main()
