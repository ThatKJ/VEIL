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
                        self.assertEqual(pp_res["passport"]["clinical"]["protected_values_kept_pct"], 100.0)
                        self.assertEqual(pp_res["passport"]["identity"]["pseudonym_placement_errors"], 0)
                        real_leaks = {k: v for k, v in pp_res["passport"]["privacy"]["residual_pattern_hits"].items() if k != "PAN"}
                        self.assertEqual(real_leaks, {})

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

                    # 5. Verify Privacy Passport runs cleanly on demand and clears PENDING state
                    page.click('button[data-view="passport"]')
                    self.assertIn("VERIFICATION PENDING", page.text_content("#passport-banner"))
                    page.click("#btn-run-passport")
                    page.wait_for_function(
                        "document.getElementById('status-pill').textContent !== 'Sanitized Ready · Audit Pending' && !document.getElementById('passport-banner').textContent.includes('VERIFICATION PENDING')",
                        timeout=30000,
                    )
                    self.assertIn(page.text_content("#status-pill"), ("Verified PASS", "Review Risks"))
                    self.assertIn("5000/5000", page.text_content("#passport-pillars"))
                    self.assertIn("pseudonym placement errors0", page.text_content("#passport-pillars").lower())

                    print(
                        f"\nPLAYWRIGHT_5K: upload_to_ready={browser_upload_to_ready_s}s, bounded_graph_render={browser_graph_s}s, console_errs={len(console_errors)}, page_errs={len(page_errors)}",
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


if __name__ == "__main__":
    unittest.main()
