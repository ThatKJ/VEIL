#!/usr/bin/env python3
"""VEIL frontend journeys (frontend-only test, synthetic data, offline).

    python3 web/tests/journeys.py [--rows 50000] [--shots DIR]

Starts its own UI server on a free port with a fresh work dir, drives Chromium with Playwright and
checks real outcomes (job status, counts, downloads), not just visible buttons. Never touches the
backend code; it only calls tools/veil_ui.py the way a user would.
"""
from __future__ import annotations

import argparse
import io
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}{('  · ' + detail) if detail else ''}", flush=True)


def csv_bytes(n: int, prefix: str) -> bytes:
    lines = ["uhid,patient_name,age,gender,mobile,village,district,pin,diagnosis"]
    for i in range(n):
        lines.append(f"{prefix}-{100000 + i},Sunita Devi{i % 20} K{i},{20 + i % 65},F,{9100000000 + i},Rampur,Sitapur,261001,Type 2 DM (E11.9)")
    return ("\n".join(lines) + "\n").encode()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server(port: int, home: Path) -> subprocess.Popen:
    env = {**os.environ, "TMPDIR": str(home)}
    p = subprocess.Popen([sys.executable, str(ROOT / "tools" / "veil_ui.py"), "--port", str(port)], cwd=str(home),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    t0 = time.time()
    while time.time() - t0 < 15:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return p
        except OSError:
            time.sleep(0.15)
    raise RuntimeError("UI server did not start")


def no_overflow(page) -> bool:
    return page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=50000)
    ap.add_argument("--shots", default="")
    a = ap.parse_args()
    shots = Path(a.shots) if a.shots else None
    if shots:
        shots.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="veil_journeys_") as td:
        td = Path(td)
        port = free_port()
        base = f"http://127.0.0.1:{port}/"
        srv = start_server(port, td)
        errors: list[str] = []
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch()
                ctx = browser.new_context(viewport={"width": 1440, "height": 900}, accept_downloads=True)
                page = ctx.new_page()
                page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
                page.on("pageerror", lambda e: errors.append(str(e)))

                # ---- Journey A: first-time user
                page.goto(base, wait_until="networkidle")
                check("A empty state shows import + demo", page.is_visible("#overview-empty") and page.is_visible("#btn-empty-demo"))
                check("A download disabled before a release", page.get_attribute("#btn-download-zip", "aria-disabled") == "true")
                page.click('button[data-view="passport"]')
                check("A views explain missing data", page.is_visible("#view-passport [data-needs-data]"))
                page.click('button[data-view="overview"]')
                if shots:
                    page.wait_for_timeout(600)
                    page.screenshot(path=str(shots / "empty-state.png"), full_page=True)
                page.click("#btn-empty-demo")
                page.wait_for_function("document.getElementById('status-pill').textContent.includes('Verified PASS') || document.getElementById('status-pill').textContent.includes('Sanitized Ready')", timeout=60000)
                check("A demo run reaches a release state", True, page.text_content("#status-pill"))
                check("A file-count badge shows release size", page.text_content("#nav-file-count").strip().isdigit())
                with page.expect_download() as dl:
                    page.click("#btn-download-zip")
                with zipfile.ZipFile(dl.value.path()) as zf:
                    names = zf.namelist()
                check("A ZIP holds report.json + records.jsonl + sanitized/", "report.json" in names and "records.jsonl" in names and any(n.startswith("sanitized/") for n in names))

                # ---- Journey E (part 1): run arena on the demo
                page.click('button[data-view="arena"]')
                page.click("#btn-run-arena")
                page.wait_for_function("document.getElementById('arena-status-badge').textContent === 'Measured Live'", timeout=60000)
                check("E arena measured on demo", "VEIL Adaptive" in page.text_content("#arena-table"))

                # ---- Journey F: invalid uploads
                page.click('button[data-view="runner"]')
                many = td / "many"
                many.mkdir()
                paths = []
                for i in range(65):
                    fp = many / f"f{i:02d}.csv"
                    fp.write_bytes(csv_bytes(2, f"M{i}"))
                    paths.append(str(fp))
                page.set_input_files("#file-input", paths)
                msg = page.text_content("#upload-validation-msg") or ""
                check("F 65 files rejected with a clear message", "limit is 64" in msg and page.is_hidden("#staged-summary-bar"), msg[:80])
                big = td / "big.csv"
                big.write_bytes(b"x" * (17 * 1024 * 1024))
                page.set_input_files("#file-input", [str(big)])
                msg = page.text_content("#upload-validation-msg") or ""
                check("F >16 MB rejected before upload", "16 MB" in msg, msg[:80])
                check("F secret field not prefilled with the public demo key", page.input_value("#secret-input") == "")
                page.fill("#secret-input", "journey-secret")

                # ---- Journey C: large dataset + reload mid-job (F reconnection)
                big_csv = td / f"hospital_{a.rows}.csv"
                big_csv.write_bytes(csv_bytes(a.rows, "L"))
                page.set_input_files("#file-input", [str(big_csv)])
                t0 = time.time()
                page.click("#btn-run-uploaded")
                page.wait_for_function("['Queued','Running…','Validating…'].includes(document.getElementById('status-pill').textContent) || document.getElementById('status-pill').textContent.includes('Sanitized Ready')", timeout=60000)
                saved = page.evaluate("sessionStorage.getItem('veil_active_job_id')")
                page.reload(wait_until="domcontentloaded")
                page.wait_for_function(f"document.getElementById('runner-log').textContent.includes('{a.rows} records')", timeout=180000)
                ready_s = round(time.time() - t0, 2)
                check("C/F reload mid-job resumes and completes", True, f"{a.rows} rows ready in {ready_s}s (job {saved or 'already done'})")
                check("C status is honest before audit", "Sanitized Ready" in page.text_content("#status-pill"), page.text_content("#status-pill"))

                # Journey E (part 2): stale arena must not persist for the new dataset
                page.click('button[data-view="arena"]')
                check("E arena reset for new dataset", page.text_content("#arena-status-badge") == "On-Demand")

                page.click('button[data-view="inspector"]')
                page.wait_for_function("document.getElementById('diff-output-pre').textContent.includes('PSN-')", timeout=20000)
                trunc_visible = page.is_visible("#diff-trunc-note")
                check("C inspector shows bounded preview", trunc_visible, "truncation note visible")
                page.click('button[data-view="graph"]')
                t1 = time.time()
                page.click("#btn-run-identity")
                page.wait_for_function(f"document.getElementById('graph-subset-badge').textContent.includes('of {a.rows} clusters')", timeout=120000)
                nodes = page.evaluate("document.querySelectorAll('#identity-svg *').length")
                check("C bounded identity graph", nodes < 400, f"{round(time.time() - t1, 2)}s, {nodes} SVG nodes, {page.text_content('#graph-subset-badge')}")
                page.click('button[data-view="passport"]')
                check("C passport pending before audit", "VERIFICATION PENDING" in page.text_content("#passport-banner"))
                t2 = time.time()
                page.click("#btn-run-passport")
                page.wait_for_function("!document.getElementById('btn-run-passport').disabled", timeout=180000)
                check("C passport verdict shown", True, f"{round(time.time() - t2, 2)}s → {page.text_content('#status-pill')}")
                check("C pillars show the full denominator", f"{a.rows}/{a.rows}" in page.text_content("#passport-pillars"))
                with page.expect_download(timeout=120000) as dl:
                    page.click("#btn-download-zip")
                with zipfile.ZipFile(dl.value.path()) as zf:
                    recs = [ln for ln in zf.read("records.jsonl").decode().splitlines() if ln.strip()]
                check("C ZIP complete", len(recs) == a.rows, f"{len(recs)} records")

                # ---- Journey D: defect → detect → repair → reverify
                page.click("#btn-corrupt-demo")
                page.wait_for_function("document.getElementById('status-pill').textContent === 'Defect Caught!'", timeout=120000)
                check("D defect caught and labelled as demo copy", "SYNTHETIC DEFECT CAUGHT" in page.text_content("#passport-banner") and page.is_visible("#sheet-defect"))
                check("D defect export links point to the defect variant", "variant=corrupt" in (page.get_attribute("#btn-export-passport-html", "href") or ""))
                page.click("#btn-repair-demo")
                page.wait_for_function("document.getElementById('status-pill').textContent !== 'Repairing Release...' && document.getElementById('status-pill').textContent !== 'Defect Caught!'", timeout=180000)
                check("D repair reverifies", page.is_hidden("#sheet-defect"), page.text_content("#status-pill"))
                if shots:
                    page.wait_for_timeout(1200)
                    page.screenshot(path=str(shots / "passport-after-repair.png"), full_page=True)

                # ---- Journey G: keyboard, rail, appearance
                page.goto(base + "#/overview", wait_until="networkidle")
                page.reload(wait_until="networkidle")
                page.keyboard.press("Tab")
                check("G first Tab reaches skip link", page.evaluate("document.activeElement.classList.contains('skip-link')"))
                page.keyboard.press("Enter")
                check("G skip link moves focus to main without changing view", page.evaluate("document.activeElement.id === 'main'") and page.is_visible("#view-overview"))
                page.focus('button[data-view="clinical"]')
                page.keyboard.press("Enter")
                check("G Enter on nav switches view", page.is_visible("#view-clinical") and page.text_content("#view-title") == "Clinical integrity")
                page.click("#btn-rail")
                page.reload(wait_until="networkidle")
                check("G rail preference persists", page.evaluate("document.getElementById('app-shell').classList.contains('rail')"))
                page.click('button[data-view="passport"]')
                check("G nav usable in rail mode", page.is_visible("#view-passport"))
                if shots:
                    page.wait_for_timeout(900)
                    page.screenshot(path=str(shots / "rail-mode.png"))
                page.click("#btn-rail")
                page.click('.appearance-opt[data-appearance="dark"]')
                page.reload(wait_until="networkidle")
                check("G dark appearance persists", page.evaluate("document.documentElement.dataset.theme === 'dark'"))
                page.click('.appearance-opt[data-appearance="system"]')
                ctx.close()

                # Reduced motion + narrow widths
                for w, h in ((1280, 800), (1024, 768), (768, 1024), (390, 844)):
                    c2 = browser.new_context(viewport={"width": w, "height": h}, reduced_motion="reduce")
                    p2 = c2.new_page()
                    p2.on("pageerror", lambda e: errors.append(str(e)))
                    p2.goto(base, wait_until="networkidle")
                    bad = []
                    for v in ("overview", "runner", "inspector", "graph", "arena", "clinical", "passport"):
                        if w <= 860:
                            p2.click("#btn-menu")
                            p2.wait_for_selector("#sidebar.open")
                            p2.click(f'button[data-view="{v}"]')
                            p2.wait_for_timeout(250)
                            if p2.evaluate("document.getElementById('sidebar').classList.contains('open')"):
                                bad.append(f"{v}:drawer-stuck")
                        else:
                            p2.click(f'button[data-view="{v}"]')
                        p2.wait_for_timeout(150)
                        if not no_overflow(p2):
                            bad.append(f"{v}:overflow")
                        if shots and w in (390, 768) and v in ("overview", "passport", "runner"):
                            p2.screenshot(path=str(shots / f"{v}-{w}.png"), full_page=True)
                    check(f"G {w}px: all views reachable, no horizontal overflow", not bad, ", ".join(bad))
                    c2.close()

                # ---- Journey F: server unavailable
                c3 = browser.new_context(viewport={"width": 1280, "height": 800})
                p3 = c3.new_page()
                p3.goto(base + "#/passport", wait_until="networkidle")
                srv.terminate()
                srv.wait(timeout=5)
                p3.click("#btn-run-passport")
                p3.wait_for_selector(".toast[data-tone='fail']", timeout=10000)
                check("F server down → actionable error, no crash", "Audit failed to run" in p3.text_content(".toast[data-tone='fail']"))
                if shots:
                    p3.screenshot(path=str(shots / "error-state.png"))
                c3.close()
                browser.close()
        finally:
            if srv.poll() is None:
                srv.terminate()
        real_errors = [e for e in errors if "Failed to load resource" not in e and "ERR_CONNECTION_REFUSED" not in e]
        check("No console/page errors during journeys", not real_errors, "; ".join(real_errors[:3]))

    failed = [n for n, ok, _ in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
