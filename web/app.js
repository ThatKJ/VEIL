(() => {
  "use strict";

  // Limits mirror tools/veil_ui.py (MAX_UPLOAD_FILES, MAX_UPLOAD_BYTES). The server enforces them too.
  const MAX_UPLOAD_FILES = 64;
  const MAX_UPLOAD_BYTES = 16 * 1024 * 1024;
  const DECISIONS_PAGE_LIMIT = 50;
  const MAX_FOCUS_RECORDS = 24; // records drawn around one pseudonym hub (the rest are listed as "+N more")
  const VIEWS = ["overview", "runner", "inspector", "graph", "arena", "clinical", "passport"];
  const VIEW_TITLES = {
    overview: "Overview",
    runner: "Import & run",
    inspector: "Record inspector",
    graph: "Identity",
    arena: "Privacy arena",
    clinical: "Clinical integrity",
    passport: "Privacy Passport",
  };
  const IN_FLIGHT = ["uploading", "queued", "running", "validating"];

  const state = {
    data: null,
    activeView: "overview",
    selectedFileIdx: 0,
    selectedCluster: null,
    decisionFilter: "all",
    decisionPage: 0,
    stagedFiles: [], // [{ id, path, origPath, renamed, size, file }]
    activeJobId: null,
    isSubmitting: false,
    diffCache: new Map(),
    renderedViews: new Set(),
    decisionsReq: 0,
  };

  const $ = (id) => document.getElementById(id);

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // Sanitized output is escaped first, then known VEIL tokens are wrapped. Never executes uploaded content.
  function highlightSanitized(text) {
    let out = esc(text);
    out = out.replace(/\[(NAME|RELATIVE|PHONE|AADHAAR|ABHA|PAN|EMAIL|ID|INSURANCE|PIN|VILLAGE|DISTRICT|DATE|AGE|REDACTED)\]/g, '<span class="tok-tag">[$1]</span>');
    out = out.replace(/\bPSN-[0-9A-Z]{6,16}\b/g, '<span class="tok-psn">$&</span>');
    out = out.replace(/\b(?:Dr\.|Sr\.|Sis\.|N\/O|DEO)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}/g, '<span class="tok-staff">$&</span>');
    return out;
  }

  function fmtBytes(bytes) {
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  const fmtInt = (n) => (typeof n === "number" ? n.toLocaleString("en-US") : esc(n ?? "—"));
  const fmtSec = (s) => (s == null ? "—" : `${s}s`);
  function ratioParts(r) {
    const m = String(r ?? "").match(/^(\d+)\s*\/\s*(\d+)/);
    return m ? [Number(m[1]), Number(m[2])] : null;
  }
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  const ICON = {
    check: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 10.5l3.2 3.2L15 6.8"/></svg>',
    alert: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M10 5v6M10 14.5v.1"/></svg>',
    x: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M6 6l8 8m0-8l-8 8"/></svg>',
    clock: '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="6"/><path d="M10 7v3.4l2.2 1.4"/></svg>',
    dash: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M6 10h8"/></svg>',
  };
  const use = (id, cls = "ico") => `<svg class="${cls}" aria-hidden="true"><use href="#${id}"/></svg>`;

  // ---------- Toasts (replace blocking alert dialogs) ----------
  function toast(message, tone = "info", ms = 5200) {
    const host = $("toasts");
    const el = document.createElement("div");
    el.className = "toast";
    el.dataset.tone = tone;
    el.setAttribute("role", tone === "fail" ? "alert" : "status");
    el.innerHTML = `<span>${esc(message)}</span><button type="button" aria-label="Dismiss">${use("i-x")}</button>`;
    el.querySelector("button").addEventListener("click", () => el.remove());
    host.appendChild(el);
    while (host.children.length > 4) host.firstElementChild.remove();
    if (ms) setTimeout(() => el.remove(), ms);
  }

  function setBusy(btn, busy, busyLabel) {
    if (!btn) return;
    if (busy) {
      btn.dataset.label = btn.dataset.label || btn.innerHTML;
      btn.disabled = true;
      btn.setAttribute("aria-busy", "true");
      if (busyLabel) btn.textContent = busyLabel;
    } else {
      btn.disabled = false;
      btn.removeAttribute("aria-busy");
      if (btn.dataset.label) btn.innerHTML = btn.dataset.label;
      delete btn.dataset.label;
    }
  }

  // ---------- Appearance (local preference only) ----------
  function applyAppearance(mode) {
    const root = document.documentElement;
    if (mode === "light" || mode === "dark") root.setAttribute("data-theme", mode);
    else root.removeAttribute("data-theme");
    document.querySelectorAll(".appearance-opt").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.appearance === mode)));
    try {
      if (mode === "system") localStorage.removeItem("veil_appearance");
      else localStorage.setItem("veil_appearance", mode);
    } catch {
      /* storage unavailable: the choice applies to this page only */
    }
  }
  (function initAppearance() {
    let saved = "system";
    try {
      saved = localStorage.getItem("veil_appearance") || "system";
    } catch {
      saved = "system";
    }
    document.querySelectorAll(".appearance-opt").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.appearance === saved)));
    document.querySelector(".appearance").addEventListener("click", (e) => {
      const b = e.target.closest(".appearance-opt");
      if (b) applyAppearance(b.dataset.appearance);
    });
    document.querySelector(".appearance").addEventListener("keydown", (e) => {
      if (!["ArrowLeft", "ArrowRight"].includes(e.key)) return;
      const opts = [...document.querySelectorAll(".appearance-opt")];
      const i = opts.findIndex((o) => o.getAttribute("aria-checked") === "true");
      const n = opts[(i + (e.key === "ArrowRight" ? 1 : opts.length - 1)) % opts.length];
      applyAppearance(n.dataset.appearance);
      n.focus();
      e.preventDefault();
    });
  })();

  // ---------- Navigation (lazy view rendering, hash deep links, mobile drawer) ----------
  const sidebar = $("sidebar");
  const scrim = $("scrim");
  function setDrawer(open) {
    sidebar.classList.toggle("open", open);
    scrim.hidden = !open;
    $("btn-menu").setAttribute("aria-expanded", String(open));
    if (open) sidebar.querySelector(".nav-item.active")?.focus();
  }
  $("btn-menu").addEventListener("click", () => setDrawer(!sidebar.classList.contains("open")));
  scrim.addEventListener("click", () => setDrawer(false));
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && sidebar.classList.contains("open")) {
      setDrawer(false);
      $("btn-menu").focus();
    }
  });

  // Sliding pill: follows the active item; when a child of Analysis is active the pill rests on the
  // parent row and the child gets the light pill, as in the source-list reference.
  const indicator = $("nav-indicator");
  function placeIndicator() {
    const nav = $("nav");
    const active = nav.querySelector(`.nav-item[data-view="${state.activeView}"]`);
    if (!active) return;
    const target = active.classList.contains("nav-child") ? $("nav-analysis") : active;
    nav.querySelectorAll(".on-pill").forEach((el) => el.classList.remove("on-pill"));
    target.classList.add("on-pill");
    const nr = nav.getBoundingClientRect();
    const tr = target.getBoundingClientRect();
    if (!tr.height) return;
    indicator.style.transform = `translate(${tr.left - nr.left}px, ${tr.top - nr.top}px)`;
    indicator.style.width = `${tr.width}px`;
    indicator.style.height = `${tr.height}px`;
    indicator.classList.add("ready");
  }
  function trackIndicator(ms = 560) {
    const end = performance.now() + ms;
    const step = () => { placeIndicator(); if (performance.now() < end) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  }
  if ("ResizeObserver" in window) new ResizeObserver(() => placeIndicator()).observe($("nav"));
  window.addEventListener("resize", () => placeIndicator());

  function setGroupOpen(open) {
    const wrap = $("grp-analysis-wrap");
    if ((wrap.dataset.open === "true") === open) return;
    wrap.dataset.open = String(open);
    $("nav-analysis").setAttribute("aria-expanded", String(open));
    wrap.querySelectorAll(".nav-child").forEach((b) => { b.tabIndex = open ? 0 : -1; });
    trackIndicator();
  }
  $("nav-analysis").addEventListener("click", () => setGroupOpen($("grp-analysis-wrap").dataset.open !== "true"));

  function setRail(on) {
    $("app-shell").classList.toggle("rail", on);
    $("btn-rail").setAttribute("aria-pressed", String(on));
    $("btn-rail").setAttribute("aria-label", on ? "Expand sidebar" : "Collapse sidebar");
    $("btn-rail").title = on ? "Expand sidebar" : "Collapse sidebar";
    try { localStorage.setItem("veil_rail", on ? "1" : "0"); } catch { /* per-page only */ }
    trackIndicator(700);
  }
  $("btn-rail").addEventListener("click", () => setRail(!$("app-shell").classList.contains("rail")));
  try { if (localStorage.getItem("veil_rail") === "1") setRail(true); } catch { /* default expanded */ }

  function setView(target, { updateHash = true } = {}) {
    if (!VIEWS.includes(target)) target = "overview";
    state.activeView = target;
    document.querySelectorAll(".nav-item").forEach((b) => {
      const on = b.dataset.view === target;
      b.classList.toggle("active", on);
      if (on) b.setAttribute("aria-current", "page");
      else b.removeAttribute("aria-current");
    });
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
    $(`view-${target}`).classList.add("active");
    const h1 = $("view-title");
    if (h1.textContent !== VIEW_TITLES[target]) {
      h1.textContent = VIEW_TITLES[target];
      h1.classList.remove("swap");
      void h1.offsetWidth; // restart the title transition
      h1.classList.add("swap");
    }
    if (["graph", "arena", "clinical"].includes(target)) setGroupOpen(true);
    placeIndicator();
    document.title = `${VIEW_TITLES[target]} — VEIL`;
    if (updateHash && location.hash !== `#/${target}`) history.replaceState(null, "", `#/${target}`);
    if (state.data && state.data.ready && !state.renderedViews.has(target)) renderView(target, state.data);
    if (sidebar.classList.contains("open")) setDrawer(false);
  }

  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => setView(btn.dataset.view));
  });
  document.addEventListener("click", (e) => {
    const g = e.target.closest("[data-goto]");
    if (g) {
      e.preventDefault();
      setView(g.dataset.goto);
      $("main").focus({ preventScroll: true });
    }
  });
  window.addEventListener("hashchange", () => {
    const m = location.hash.match(/^#\/(\w+)/);
    if (m) setView(m[1], { updateHash: false }); // other anchors (e.g. the skip link) are not routes
  });
  document.querySelector(".skip-link").addEventListener("click", (e) => {
    e.preventDefault();
    $("main").focus();
  });

  // ---------- API ----------
  async function apiFetchJson(url, opts = {}) {
    let res;
    try {
      res = await fetch(url, opts);
    } catch {
      const err = new Error("Server unreachable or connection interrupted");
      err.code = "server_unavailable";
      err.isNetwork = true;
      throw err;
    }
    let body = {};
    const txt = await res.text();
    try {
      body = txt ? JSON.parse(txt) : {};
    } catch {
      const err = new Error(`Malformed server response (HTTP ${res.status})`);
      err.code = "serialization_failed";
      throw err;
    }
    if (!res.ok) {
      const err = new Error(body.error || `Request failed (HTTP ${res.status})`);
      err.code = body.error_code || (res.status === 413 ? "size_limit_exceeded" : "server_error");
      err.status = res.status;
      throw err;
    }
    return body;
  }

  // Status pill: text is part of the UI contract ("Verified PASS", "Defect Caught!", "Sanitized Ready…").
  function setStatus(label, tone = "idle") {
    const el = $("status-pill");
    const changed = el.dataset.tone !== tone;
    el.textContent = label;
    el.dataset.tone = tone;
    if (changed) { el.classList.remove("flash"); void el.offsetWidth; el.classList.add("flash"); }
    const ns = $("nav-passport-state");
    if (ns) ns.dataset.tone = tone === "ok" || tone === "warn" || tone === "fail" ? tone : "";
  }

  function setRunControlsBusy(busy) {
    state.isSubmitting = busy;
    $("btn-quick-demo").disabled = busy;
    $("btn-run-demo").disabled = busy;
    $("btn-empty-demo").disabled = busy;
    $("btn-run-uploaded").disabled = busy || state.stagedFiles.length === 0;
    $("nav-run-dot").classList.toggle("live", busy);
    $("btn-clear-staged").disabled = busy;
    fi.disabled = busy;
    dz.setAttribute("aria-disabled", String(busy));
    dz.classList.toggle("locked", busy);
    document.querySelectorAll(".staged-rm").forEach((b) => { b.disabled = busy; });
  }

  function setStages(status) {
    const order = ["uploading", "queued", "running", "validating", "ready"];
    const idx = order.indexOf(status);
    document.querySelectorAll("#run-stages li").forEach((li, i) => {
      li.classList.remove("done", "now", "bad");
      if (status === "failed" || status === "cancelled") {
        if (li.dataset.stage === "ready") li.classList.add("bad");
        return;
      }
      if (idx < 0) return;
      if (i < idx || status === "ready") li.classList.add("done");
      else if (i === idx) li.classList.add("now");
    });
  }

  function showProgress(pct, stage, showCancel = false) {
    $("progress-panel").classList.remove("hidden");
    $("progress-pct").textContent = `${pct}%`;
    $("progress-stage").textContent = stage;
    $("progress-fill").style.transform = `scaleX(${Math.max(0, Math.min(100, pct)) / 100})`;
    $("progress-bar").setAttribute("aria-valuenow", String(pct));
    $("btn-cancel-job").classList.toggle("hidden", !showCancel);
  }

  function hideProgress() {
    $("progress-panel").classList.add("hidden");
    $("btn-cancel-job").classList.add("hidden");
  }

  function saveActiveJobId(jid) {
    state.activeJobId = jid;
    try {
      if (jid) sessionStorage.setItem("veil_active_job_id", jid);
      else sessionStorage.removeItem("veil_active_job_id");
    } catch {
      // ignore storage unavailability
    }
  }

  function getSavedJobId() {
    try {
      return sessionStorage.getItem("veil_active_job_id");
    } catch {
      return null;
    }
  }

  function renderTimingsLine(timings) {
    const el = $("runner-timings");
    if (!el || !timings) return;
    const parts = [
      timings.upload_staging_s != null ? `Staging ${timings.upload_staging_s}s` : null,
      timings.engine_runtime_s != null ? `Engine ${timings.engine_runtime_s}s (1 run)` : null,
      timings.validation_s != null ? `Validation ${timings.validation_s}s` : null,
      timings.total_ui_s != null ? `Total ${timings.total_ui_s}s` : null,
      timings.passport_s != null ? `Audit ${timings.passport_s}s` : null,
      timings.arena_s != null ? `Arena ${timings.arena_s}s` : null,
    ].filter(Boolean);
    el.textContent = parts.join(" · ");
  }

  // Adaptive status polling with bounded transient-failure retry. A network blip never marks a live job failed.
  async function pollJob(jobId, logEl) {
    saveActiveJobId(jobId);
    $("btn-reconnect-job").classList.add("hidden");
    $("runner-done").classList.add("hidden");
    setRunControlsBusy(true);
    let delayMs = 350;
    let consecutiveNetFails = 0;

    while (state.activeJobId === jobId) {
      let st;
      try {
        st = await apiFetchJson(`/api/status/${encodeURIComponent(jobId)}`);
        consecutiveNetFails = 0;
      } catch (err) {
        if (err.isNetwork && consecutiveNetFails < 8) {
          consecutiveNetFails += 1;
          const wait = Math.min(4000, Math.round(500 * Math.pow(1.5, consecutiveNetFails - 1)));
          setStatus(`Reconnecting (${consecutiveNetFails}/8)…`, "warn");
          if (logEl) logEl.textContent = `Connection to the local server dropped while job ${jobId} was running. Retrying in ${(wait / 1000).toFixed(1)}s; the job keeps running on the server.`;
          await sleep(wait);
          continue;
        }
        hideProgress();
        setRunControlsBusy(false);
        if (err.code === "job_not_found") {
          saveActiveJobId(null);
          setStatus("Job no longer available", "warn");
          if (logEl) logEl.textContent = "The server no longer knows this job (it may have restarted). Start a new run.";
          return;
        }
        setStatus(err.code === "server_unavailable" ? "Server Unavailable" : "Polling Error", "fail");
        if (logEl) logEl.textContent = `Lost contact with the server (${err.code || "network"}): ${err.message}. Use “Reconnect to job” once the server is back; the job may still be running.`;
        $("btn-reconnect-job").classList.remove("hidden");
        return;
      }

      const stageTxt = st.stage || st.status || "Running";
      setStages(st.status);
      if (IN_FLIGHT.includes(st.status)) setStatus(st.status === "queued" ? "Queued" : st.status === "validating" ? "Validating…" : "Running…", "busy");
      showProgress(st.progress ?? 0, stageTxt, ["queued", "running", "validating"].includes(st.status));
      if (logEl) logEl.textContent = `${stageTxt} (${st.progress ?? 0}%)`;

      if (st.status === "ready") {
        saveActiveJobId(null);
        hideProgress();
        setRunControlsBusy(false);
        state.diffCache.clear();
        state.selectedFileIdx = 0;
        state.selectedCluster = null;
        state.decisionPage = 0;
        await loadState({ resume: false });
        const cnt = state.data?.report?.counts;
        if (logEl) {
          logEl.textContent = `Ready (1x engine run · ${cnt?.files_sanitized ?? 0}/${cnt?.files_total ?? 0} files sanitized · ${cnt?.records_processed ?? 0} records). Audit & Arena available on demand.`;
        }
        renderRunDone();
        toast("Sanitized release ready.", "ok");
        return;
      }

      if (st.status === "failed" || st.status === "cancelled") {
        saveActiveJobId(null);
        hideProgress();
        setRunControlsBusy(false);
        setStatus(st.status === "cancelled" ? "Cancelled" : "Run Failed", "fail");
        if (logEl) logEl.textContent = st.status === "cancelled"
          ? "Job cancelled. Nothing from it was exported."
          : `Run failed (${st.error_code || st.status}): ${st.error || "execution stopped"}.`;
        if (state.data?.ready) renderAll(state.data, { keepStatus: true });
        return;
      }

      await sleep(delayMs);
      delayMs = Math.min(1000, Math.round(delayMs * 1.25));
    }
  }

  function currentPolicy() {
    return document.querySelector('input[name="policy"]:checked')?.value || "adaptive";
  }

  async function dispatchUploadRun(logEl) {
    if (state.isSubmitting || !state.stagedFiles.length) return;
    const secretVal = $("secret-input").value.trim(); // blank: the server generates a random one-time key
    clearValidationError();
    setRunControlsBusy(true);
    setStatus("Uploading Dataset...", "busy");
    setStages("uploading");
    showProgress(3, `Uploading ${state.stagedFiles.length} file(s)`, false);
    if (logEl) logEl.textContent = `Uploading ${state.stagedFiles.length} files (${fmtBytes(stagedTotalBytes())})…`;

    try {
      const fd = new FormData();
      fd.append("mode", "upload");
      fd.append("policy", currentPolicy());
      if (secretVal) fd.append("secret", secretVal);
      fd.append("label", `Uploaded Synthetic Dataset (${state.stagedFiles.length} files)`);
      fd.append("relpaths", JSON.stringify(state.stagedFiles.map((f) => f.path)));
      for (const item of state.stagedFiles) {
        fd.append("files", item.file, item.path); // binary multipart, no re-encoding
      }
      const start = await apiFetchJson("/api/run", { method: "POST", body: fd });
      await pollJob(start.job_id, logEl);
    } catch (err) {
      hideProgress();
      setRunControlsBusy(false);
      setStages("failed");
      setStatus("Upload Error", "fail");
      const msg = err.code === "size_limit_exceeded"
        ? "The upload is larger than the server's 16 MB limit. Remove files and try again."
        : `${err.message} (${err.code || "upload_error"})`;
      showValidationError(msg);
      if (logEl) logEl.textContent = `Upload failed: ${msg}`;
    }
  }

  async function dispatchDemoRun(logEl) {
    if (state.isSubmitting) return;
    const secretVal = $("secret-input").value.trim(); // blank: the server uses the public demo key for the synthetic bundle
    clearValidationError();
    setRunControlsBusy(true);
    setStatus("Running demo…", "busy");
    setStages("queued");
    showProgress(8, "Starting VEIL on the bundled synthetic hospitals", false);
    if (logEl) logEl.textContent = "Starting one VEIL engine run on the bundled synthetic dataset…";
    try {
      const start = await apiFetchJson("/api/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: "demo", policy: currentPolicy(), ...(secretVal ? { secret: secretVal } : {}), run_optional: true }),
      });
      await pollJob(start.job_id, logEl);
    } catch (err) {
      hideProgress();
      setRunControlsBusy(false);
      setStages("failed");
      setStatus("Error", "fail");
      if (logEl) logEl.textContent = `Could not start the demo (${err.code || "error"}): ${err.message}`;
      toast(`Could not start the demo: ${err.message}`, "fail");
    }
  }

  $("btn-quick-demo").addEventListener("click", () => dispatchDemoRun($("runner-log")));
  $("btn-run-demo").addEventListener("click", () => dispatchDemoRun($("runner-log")));
  $("btn-empty-demo").addEventListener("click", () => dispatchDemoRun($("runner-log")));
  $("btn-run-uploaded").addEventListener("click", () => dispatchUploadRun($("runner-log")));

  $("btn-cancel-job").addEventListener("click", async () => {
    const jid = state.activeJobId;
    if (!jid) return;
    $("btn-cancel-job").disabled = true;
    try {
      await apiFetchJson(`/api/cancel/${encodeURIComponent(jid)}`, { method: "POST" });
    } catch {
      // pollJob reports the terminal status
    } finally {
      $("btn-cancel-job").disabled = false;
    }
  });

  $("btn-reconnect-job").addEventListener("click", () => {
    const jid = state.activeJobId || getSavedJobId();
    if (jid) pollJob(jid, $("runner-log"));
  });

  $("btn-secret-reveal").addEventListener("click", () => {
    const inp = $("secret-input");
    const show = inp.type === "password";
    inp.type = show ? "text" : "password";
    $("btn-secret-reveal").setAttribute("aria-pressed", String(show));
    $("btn-secret-reveal").setAttribute("aria-label", show ? "Hide secret" : "Show secret");
  });

  function renderRunDone() {
    const d = state.data;
    const el = $("runner-done");
    if (!d?.ready) return el.classList.add("hidden");
    const c = d.report?.counts || {};
    el.innerHTML = `
      <p><b>${fmtInt(c.files_sanitized)}</b> of ${fmtInt(c.files_total)} files exported, <b>${fmtInt(c.records_processed)}</b> records processed.</p>
      <div class="btn-row">
        <a href="/api/download/zip" class="btn btn-primary btn-sm" download>${use("i-download")}<span>Download release</span></a>
        <button class="btn btn-secondary btn-sm" data-goto="inspector">Inspect</button>
        <button class="btn btn-quiet btn-sm" data-goto="passport">Audit</button>
      </div>`;
    el.classList.remove("hidden");
  }

  // ---------- Multiple-file staging (append + dedupe + remove + clear + limit checks) ----------
  const dz = $("dropzone");
  const fi = $("file-input");

  function showValidationError(msg) {
    const el = $("upload-validation-msg");
    if (!el) return;
    el.textContent = msg;
    el.classList.remove("hidden");
  }

  function clearValidationError() {
    const el = $("upload-validation-msg");
    if (!el) return;
    el.textContent = "";
    el.classList.add("hidden");
  }

  function stagedTotalBytes() {
    return state.stagedFiles.reduce((acc, f) => acc + f.size, 0);
  }

  function normalizeSafeRel(raw) {
    const clean = String(raw || "").replace(/\\/g, "/").replace(/^\/+/, "");
    const parts = clean.split("/").filter((p) => p && p !== ".");
    if (!parts.length || parts.some((p) => p === "..")) return null;
    return parts.join("/");
  }

  function dedupePath(rel, usedLower) {
    if (!usedLower.has(rel.toLowerCase())) {
      usedLower.add(rel.toLowerCase());
      return { path: rel, renamed: false };
    }
    const slash = rel.lastIndexOf("/");
    const dir = slash >= 0 ? rel.slice(0, slash) : "";
    const base = slash >= 0 ? rel.slice(slash + 1) : rel;
    const dot = base.lastIndexOf(".");
    const stem = dot > 0 ? base.slice(0, dot) : base;
    const ext = dot > 0 ? base.slice(dot) : "";
    let n = 2;
    for (;;) {
      const cand = dir ? `${dir}/${stem} (${n})${ext}` : `${stem} (${n})${ext}`;
      if (!usedLower.has(cand.toLowerCase())) {
        usedLower.add(cand.toLowerCase());
        return { path: cand, renamed: true };
      }
      n += 1;
    }
  }

  function renderStagedList() {
    const items = state.stagedFiles;
    const totalB = stagedTotalBytes();
    const summaryBar = $("staged-summary-bar");
    const listEl = $("staged-files-list");
    if (!items.length) {
      summaryBar.classList.add("hidden");
      listEl.innerHTML = "";
      $("btn-run-uploaded").disabled = true;
      return;
    }
    summaryBar.classList.remove("hidden");
    $("staged-stats-text").textContent = `${items.length} / ${MAX_UPLOAD_FILES} files · ${fmtBytes(totalB)} of 16 MB`;
    const frac = Math.min(1, Math.max(items.length / MAX_UPLOAD_FILES, totalB / MAX_UPLOAD_BYTES));
    $("staged-meter-fill").style.transform = `scaleX(${frac})`;
    $("staged-meter-fill").parentElement.classList.toggle("near", frac > 0.85);
    listEl.innerHTML = items.map((f, idx) => {
      const slash = f.path.lastIndexOf("/");
      const name = slash >= 0 ? f.path.slice(slash + 1) : f.path;
      const dir = slash >= 0 ? f.path.slice(0, slash) : "";
      return `<li class="queue-item">
        ${use("i-file")}
        <span class="q-name"><span class="q-file" title="${esc(f.path)}">${esc(name)}</span>${dir || f.renamed ? `<span class="q-path">${esc(dir)}${dir && f.renamed ? " · " : ""}${f.renamed ? `renamed from ${esc(f.origPath.split("/").pop())}` : ""}</span>` : ""}</span>
        <span class="q-size">${fmtBytes(f.size)}</span>
        <button type="button" class="staged-rm" data-remove="${idx}" aria-label="Remove ${esc(f.path)}">${use("i-x")}</button>
      </li>`;
    }).join("");
    $("btn-run-uploaded").disabled = state.isSubmitting || items.length === 0;
  }

  // Event delegation: one listener for every remove button.
  $("staged-files-list").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-remove]");
    if (!btn || state.isSubmitting) return;
    e.stopPropagation();
    state.stagedFiles.splice(Number(btn.dataset.remove), 1);
    clearValidationError();
    renderStagedList();
    if (state.stagedFiles.length) $("staged-files-list").querySelector("[data-remove]")?.focus();
    else dz.focus();
  });

  function stageFiles(fileList) {
    if (state.isSubmitting) return;
    const incoming = Array.from(fileList || []);
    if (!incoming.length) return;
    clearValidationError();

    if (state.stagedFiles.length + incoming.length > MAX_UPLOAD_FILES) {
      showValidationError(`That would make ${state.stagedFiles.length + incoming.length} files; the limit is ${MAX_UPLOAD_FILES}. Remove some files or run them in separate batches.`);
      return;
    }

    let runningBytes = stagedTotalBytes();
    const usedLower = new Set(state.stagedFiles.map((f) => f.path.toLowerCase()));
    const toAppend = [];

    for (const f of incoming) {
      const orig = normalizeSafeRel(f.webkitRelativePath || f.name);
      if (!orig) {
        showValidationError(`Skipped an unsafe file name: ${f.name}`);
        return;
      }
      if (runningBytes + f.size > MAX_UPLOAD_BYTES) {
        showValidationError(`Adding ${f.name} would bring the upload to ${fmtBytes(runningBytes + f.size)}, over the 16 MB limit. Nothing from this batch was added.`);
        return;
      }
      runningBytes += f.size;
      const { path, renamed } = dedupePath(orig, usedLower);
      toAppend.push({ id: `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`, path, origPath: orig, renamed, size: f.size, file: f });
    }

    state.stagedFiles.push(...toAppend);
    renderStagedList();
  }

  $("btn-clear-staged").addEventListener("click", () => {
    if (state.isSubmitting) return;
    state.stagedFiles = [];
    clearValidationError();
    renderStagedList();
  });

  let dragDepth = 0;
  dz.addEventListener("click", () => { if (!state.isSubmitting) fi.click(); });
  dz.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      if (!state.isSubmitting) fi.click();
    }
  });
  dz.addEventListener("dragenter", (e) => { e.preventDefault(); dragDepth += 1; dz.classList.add("drag"); });
  dz.addEventListener("dragover", (e) => { e.preventDefault(); });
  dz.addEventListener("dragleave", () => { dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) dz.classList.remove("drag"); });
  dz.addEventListener("drop", (e) => {
    e.preventDefault();
    dragDepth = 0;
    dz.classList.remove("drag");
    if (!state.isSubmitting && e.dataTransfer?.files?.length) stageFiles(e.dataTransfer.files);
  });
  fi.addEventListener("change", () => {
    if (fi.files?.length) stageFiles(fi.files);
    fi.value = ""; // allow selecting the exact same file again
  });

  // ---------- Rendering ----------
  function renderView(viewName, d) {
    state.renderedViews.add(viewName);
    if (viewName === "overview") renderOverview(d);
    else if (viewName === "inspector") renderInspector(d);
    else if (viewName === "graph") { renderGraph(d); renderDecisionsPage(); }
    else if (viewName === "arena") renderArena(d);
    else if (viewName === "clinical") renderClinical(d);
    else if (viewName === "passport") renderPassport(d);
    else if (viewName === "runner") renderRunDone();
  }

  function residueOf(pass) {
    return Object.values(pass?.privacy?.residual_pattern_hits || {}).reduce((a, b) => a + b, 0);
  }

  // One place that decides what the release's assurance state is.
  function assurance(d) {
    const pass = d.passport || {};
    const verified = d.passport_status === "verified";
    const corr = d.corrupted_passport;
    const risks = pass.residual_risks || [];
    const verdict = pass.verdict || (verified ? "PASS" : null);
    if (corr) return { key: "defect", tone: "fail", label: "Defect Caught!" };
    if (!verified) return { key: "pending", tone: "warn", label: "Sanitized Ready · Audit Pending" };
    if (verdict === "FAIL") return { key: "fail", tone: "fail", label: "Review Risks" };
    if (residueOf(pass) > 0 || risks.length || verdict === "WARNING") return { key: "warn", tone: "warn", label: "Verified · Review Warnings" };
    if (verdict === "SKIPPED") return { key: "skipped", tone: "warn", label: "Audit Inconclusive" };
    return { key: "pass", tone: "ok", label: "Verified PASS" };
  }

  function needsData(show) {
    document.querySelectorAll("[data-needs-data]").forEach((el) => {
      el.classList.toggle("hidden", !show);
      if (show && !el.dataset.filled) {
        el.innerHTML = `<h2>No release yet</h2><p>Import synthetic files or run the bundled demo. This view fills in from the run's actual output.</p>
          <div class="btn-row"><button class="btn btn-primary" data-goto="runner">${use("i-import")}<span>Import dataset</span></button></div>`;
        el.dataset.filled = "1";
      }
    });
    document.querySelectorAll("[data-has-data]").forEach((el) => el.classList.toggle("hidden", show));
  }

  function setDownloadEnabled(on) {
    for (const id of ["btn-download-zip", "btn-export-zip", "btn-export-passport-html", "btn-export-passport-json"]) {
      const a = $(id);
      if (!a) continue;
      a.setAttribute("aria-disabled", on ? "false" : "true");
      if (on) a.removeAttribute("tabindex");
      else a.setAttribute("tabindex", "-1");
    }
  }

  function renderAll(d, { keepStatus = false } = {}) {
    state.data = d;
    state.renderedViews.clear();
    renderBenchmarks(d.historical_benchmarks);

    if (!d.ready) {
      $("active-dataset-title").textContent = "No dataset loaded. Import files or run the synthetic demo.";
      $("overview-empty").classList.remove("hidden");
      $("overview-ready").classList.add("hidden");
      needsData(true);
      setDownloadEnabled(false);
      $("nav-file-count").classList.add("hidden");
      if (!keepStatus) setStatus("Awaiting Dataset", "idle");
      if (getSavedJobId()) $("btn-reconnect-job").classList.remove("hidden");
      return;
    }

    $("active-dataset-title").textContent = `${d.dataset_label || "Active dataset"} · ${d.policy_mode} policy · run ${d.run_at || ""}`;
    if ($("runner-log").textContent === "Engine idle.") {
      const c0 = d.report?.counts || {};
      $("runner-log").textContent = `Current release: ${c0.files_sanitized ?? 0}/${c0.files_total ?? 0} files sanitized, ${c0.records_processed ?? 0} records. Import files or run the demo to replace it.`;
      setStages("ready");
    }
    $("overview-empty").classList.add("hidden");
    $("overview-ready").classList.remove("hidden");
    needsData(false);
    setDownloadEnabled(true);
    const nf = (d.file_pairs || []).length;
    $("nav-file-count").textContent = String(nf);
    $("nav-file-count").classList.toggle("hidden", !nf);
    const a = assurance(d);
    if (!keepStatus) setStatus(a.label, a.tone);
    renderTimingsLine(d.timings);
    renderView("overview", d);
    if (state.activeView !== "overview") renderView(state.activeView, d);
  }

  function renderBenchmarks(hb) {
    if (!hb) return;
    $("hist-checkpoint").textContent = hb.checkpoint ? `Checkpoint: ${hb.checkpoint}` : "";
    $("hist-disclaimer").textContent = hb.disclaimer || "";
    $("hist-table").innerHTML = `
      <thead><tr><th>Dataset</th><th>Classification</th><th>Est. total (local)</th><th>Leak</th><th>False merges</th><th>Canaries</th></tr></thead>
      <tbody>${(hb.runs || []).map((r) => `
        <tr><td class="mono">${esc(r.dataset)}</td><td>${esc(r.type)}</td><td>${esc(r.score)}</td><td>${esc(r.leak_pct)}</td><td>${esc(r.false_merges)}</td><td>${esc(r.canaries)}</td></tr>`).join("")}</tbody>`;
    if (hb.scalability) {
      $("scale-table").innerHTML = `
        <thead><tr><th>Workload</th><th class="num">Records</th><th class="num">Wall time</th><th class="num">Peak RSS</th><th class="num">Throughput</th></tr></thead>
        <tbody>${hb.scalability.map((s) => `
          <tr><td>${esc(s.workload)}</td><td class="num">${esc(s.records)}</td><td class="num">${esc(s.wall_s)}s</td><td class="num">${esc(s.peak_rss_mb)} MB</td><td class="num">${esc(s.throughput)}</td></tr>`).join("")}</tbody>`;
    }
  }

  function checkSummary(pass) {
    const checks = Object.values(pass?.checks || {});
    const passed = checks.filter((c) => c.status === "PASS").length;
    const skipped = checks.filter((c) => c.status === "SKIPPED").length;
    return { passed, skipped, total: checks.length };
  }

  function renderOverview(d) {
    const rep = d.report || {};
    const c = rep.counts || {};
    const pass = d.passport || {};
    const a = assurance(d);
    const verified = d.passport_status === "verified";

    const titles = {
      pass: ["Sanitized and verified", (() => {
        const cs0 = checkSummary(pass);
        const skipped = Object.values(pass.checks || {}).filter((c) => c.status === "SKIPPED").length;
        return cs0.passed === cs0.total
          ? `The independent audit passed all ${cs0.total} pillars. The release is ready to download.`
          : `The independent audit passed ${cs0.passed} of ${cs0.total} pillars${skipped ? `; ${skipped} had nothing to check in this dataset` : ""}. The release is ready to download.`;
      })()],
      pending: ["Sanitized, audit pending", "The release passed the engine's output contract and can be downloaded. Run the full audit to verify privacy, clinical values, dates and identity."],
      warn: ["Sanitized, warnings to review", `The audit finished with findings: ${(pass.residual_risks || []).join("; ") || "one or more checks were inconclusive"}.`],
      fail: ["Sanitized, audit failed", `The audit found problems: ${(pass.residual_risks || []).join("; ") || "see the Passport"}.`],
      skipped: ["Sanitized, nothing to audit", "The audit had no applicable checks for this dataset."],
      defect: ["Test defect detected", "A corrupted demonstration copy was audited and the defect was caught. The real release is untouched; re-run VEIL to reverify."],
    };
    const [title, text] = titles[a.key];
    $("ov-state-title").textContent = title;
    $("ov-state-text").textContent = text;
    const mark = $("ov-state-mark");
    mark.dataset.tone = a.tone === "ok" ? "ok" : a.tone;
    mark.innerHTML = a.key === "pass" ? ICON.check : a.key === "pending" ? ICON.clock : ICON.alert;

    let next = "";
    if (a.key === "pending") next = `<button class="btn btn-primary" id="ov-run-audit">Run full audit</button><a class="btn btn-quiet" href="/api/download/zip" download>${use("i-download")}<span>Download anyway</span></a>`;
    else if (a.key === "defect") next = `<button class="btn btn-primary" data-goto="passport">Open Passport to repair</button>`;
    else next = `<a class="btn btn-primary" href="/api/download/zip" download>${use("i-download")}<span>Download release</span></a><button class="btn btn-secondary" data-goto="passport">Open Passport</button>`;
    $("ov-next").innerHTML = `<div class="btn-row">${next}</div>`;
    $("ov-run-audit")?.addEventListener("click", () => { setView("passport"); $("btn-run-passport").click(); });

    const pseudo = verified && typeof pass.identity?.distinct_pseudonyms === "number"
      ? pass.identity.distinct_pseudonyms
      : (d.identity_status === "ready" ? d.identity_graph?.meta?.total_clusters : null);
    const cs = checkSummary(pass);
    const verifyLabel = !verified ? "Pending" : (pass.verdict || "PASS");
    const vTone = !verified ? "pending" : a.tone === "ok" ? "" : a.tone;
    $("ov-pipeline").innerHTML = [
      { n: "Ingest", v: fmtInt(c.files_total), u: "files", s: `${fmtInt(c.files_sanitized)} exported, ${fmtInt(c.files_quarantined)} quarantined`, t: c.files_quarantined ? "" : "" },
      { n: "Detect", v: fmtInt(c.identifiers_detected), u: "", s: "identifiers found and replaced" },
      { n: "Link", v: `${fmtInt(c.records_linked)}`, u: `/ ${fmtInt(c.records_processed)}`, s: pseudo != null ? `records linked into ${fmtInt(pseudo)} pseudonyms` : "records linked to a pseudonym" },
      { n: "Generalise", v: fmtInt(c.records_generalized), u: "", s: `records generalised${c.records_suppressed ? `, ${fmtInt(c.records_suppressed)} suppressed` : ""}` },
      { n: "Verify", v: esc(verifyLabel), u: "", s: verified ? `${cs.passed} of ${cs.total} pillars passed${cs.skipped ? `, ${cs.skipped} skipped` : ""}` : "run the Passport audit", t: vTone },
    ].map((p) => `<li><span class="pipe-name"><i class="${p.t || ""}"></i>${p.n}</span><span class="pipe-num">${p.v}${p.u ? ` <small>${p.u}</small>` : ""}</span><span class="pipe-sub">${p.s}</span></li>`).join("");

    const t = d.timings || {};
    const facts = [
      ["Dataset", esc(d.dataset_label)],
      ["Policy", esc(d.policy_mode)],
      ["Engine runtime", `${fmtSec(d.runtime_s)} <span class="muted">(${d.engine_executions || 1} run)</span>`],
      ["Total time in the workspace", fmtSec(t.total_ui_s ?? d.runtime_s)],
      ["Peak memory (engine)", rep.resources?.peak_rss_mb != null ? `${rep.resources.peak_rss_mb} MB` : "—"],
      ["Audit time", t.passport_s != null && verified ? fmtSec(t.passport_s) : "Not run"],
      ["Run at", esc(d.run_at)],
    ];
    $("ov-facts").innerHTML = facts.map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`).join("");

    const tr = d.transformations || [];
    const maxT = Math.max(1, ...tr.map((x) => x.count));
    $("ov-id-total").textContent = tr.length ? `${tr.reduce((s, x) => s + x.count, 0)} in total` : "";
    $("ov-transform-bars").innerHTML = tr.map((x) => `
      <div class="hbar"><span class="hbar-label mono">${esc(x.token)}</span><div class="hbar-track"><div class="hbar-fill" style="width:${Math.round((100 * x.count) / maxT)}%"></div></div><span class="hbar-val">${x.count}</span></div>`).join("")
      || `<p class="fine">No replacement tags appear in the previewed files.</p>`;
  }

  // ---------- Record inspector ----------
  $("file-tabs").addEventListener("click", (e) => {
    const b = e.target.closest(".file-pill");
    if (!b) return;
    state.selectedFileIdx = Number(b.dataset.idx);
    renderInspector(state.data);
  });
  $("file-tabs").addEventListener("keydown", (e) => {
    if (!["ArrowDown", "ArrowUp"].includes(e.key)) return;
    const pills = [...$("file-tabs").querySelectorAll(".file-pill")];
    const i = pills.indexOf(document.activeElement);
    if (i < 0) return;
    const n = pills[Math.max(0, Math.min(pills.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))];
    n.focus();
    e.preventDefault();
  });

  // Proportional synchronized scrolling between the two panes.
  let syncLock = false;
  function syncFrom(src, dst) {
    if (!$("sync-scroll").checked || syncLock) return;
    syncLock = true;
    const max = src.scrollHeight - src.clientHeight;
    dst.scrollTop = max > 0 ? (src.scrollTop / max) * (dst.scrollHeight - dst.clientHeight) : 0;
    requestAnimationFrame(() => { syncLock = false; });
  }
  $("diff-input-pre").addEventListener("scroll", () => syncFrom($("diff-input-pre"), $("diff-output-pre")), { passive: true });
  $("diff-output-pre").addEventListener("scroll", () => syncFrom($("diff-output-pre"), $("diff-input-pre")), { passive: true });

  async function renderInspector(d) {
    const files = d.file_pairs || [];
    if (state.selectedFileIdx >= files.length) state.selectedFileIdx = 0;
    if (state.inspectorJob !== d.job_id) {
      state.inspectorJob = d.job_id;
      const firstChanged = files.findIndex((f) => Object.keys(f.tag_counts || {}).length || (f.psns || []).length);
      state.selectedFileIdx = firstChanged >= 0 ? firstChanged : 0;
    }
    $("file-nav-count").textContent = String(files.length);

    $("file-tabs").innerHTML = files.map((f, idx) => `
      <li><button class="file-pill ${idx === state.selectedFileIdx ? "active" : ""}" data-idx="${idx}" ${idx === state.selectedFileIdx ? 'aria-current="true"' : ""}>
        <span class="fp-name" title="${esc(f.input_rel)}">${esc(f.input_rel)}</span>
        <span class="fp-meta">${esc(f.format)}${f.status === "quarantined" ? ' <span class="q">quarantined</span>' : ""}</span>
      </button></li>`).join("");

    const cur = files[state.selectedFileIdx];
    if (!cur) {
      $("insp-file-title").textContent = "No files in this release";
      return;
    }
    const quarantined = cur.status === "quarantined";
    $("insp-file-title").textContent = cur.input_rel;
    $("inspector-badges").innerHTML = `
      <span class="tag ${quarantined ? "tag-fail" : "tag-ok"}">${quarantined ? "Quarantined" : "Sanitized"}${cur.reason ? ` · ${esc(cur.reason)}` : ""}</span>
      <span class="tag">${esc(cur.format)}</span>
      <span class="tag mono" title="SHA-256 of the input file">sha ${esc(cur.sha256_short)}</span>
      ${(cur.psns || []).slice(0, 8).map((p) => `<span class="tag tag-psn">${esc(p)}</span>`).join("")}
      ${(cur.psns || []).length > 8 ? `<span class="tag">+${cur.psns.length - 8} more</span>` : ""}`;
    $("diff-in-meta").textContent = `${cur.input_rel} · ${fmtInt(cur.bytes_in)} B`;
    $("diff-out-meta").textContent = cur.output_rel ? `${cur.output_rel} · ${fmtInt(cur.bytes_out)} B` : "Not exported";

    const chips = [];
    for (const [tok, cnt] of Object.entries(cur.tag_counts || {})) chips.push(`<span class="chip"><span class="tok-tag">${esc(tok)}</span><b>${cnt}</b></span>`);
    if ((cur.psns || []).length) chips.push(`<span class="chip"><span class="tok-psn">PSN</span><b>${cur.psns.length}</b> pseudonyms</span>`);
    for (const st of cur.staff_preserved || []) chips.push(`<span class="chip"><span class="tok-staff">${esc(st)}</span> kept</span>`);
    $("inspector-tag-detail").innerHTML = chips.join("") || `<p class="fine">${quarantined ? "This file was quarantined: it was not copied into the release." : "No replacement tags were found in this file's preview."}</p>`;

    const ckey = `${d.job_id || "cur"}:${state.selectedFileIdx}`;
    let diff = state.diffCache.get(ckey);
    if (!diff) {
      $("diff-input-pre").textContent = "Loading preview…";
      $("diff-output-pre").textContent = "Loading preview…";
      try {
        diff = await apiFetchJson(`/api/diff?idx=${state.selectedFileIdx}`);
        state.diffCache.set(ckey, diff);
      } catch (err) {
        $("diff-input-pre").textContent = `Preview unavailable: ${err.message}`;
        $("diff-output-pre").textContent = "";
        return;
      }
      if (state.data !== d || state.selectedFileIdx !== Number(ckey.split(":").pop())) return; // stale response
    }
    $("diff-input-pre").textContent = diff.input_text || "";
    $("diff-output-pre").innerHTML = highlightSanitized(diff.output_text || "");
    for (const id of ["diff-input-pre", "diff-output-pre"]) { const el = $(id); el.classList.remove("fresh"); void el.offsetWidth; el.classList.add("fresh"); }
    $("diff-input-pre").scrollTop = 0;
    $("diff-output-pre").scrollTop = 0;
    const trunc = /preview truncated/.test(diff.input_text || "") || /preview truncated/.test(diff.output_text || "");
    $("diff-trunc-note").classList.toggle("hidden", !trunc);
  }

  // ---------- Identity ----------
  function scriptClass(s) {
    const v = String(s || "").toLowerCase();
    if (v.startsWith("latin")) return "g-script-latin";
    if (v.startsWith("deva") || v.includes("hindi")) return "g-script-deva";
    return "g-script-other";
  }

  $("cluster-list").addEventListener("click", (e) => {
    const b = e.target.closest(".cl-btn");
    if (!b) return;
    state.selectedCluster = b.dataset.psn;
    renderGraph(state.data);
  });

  function renderGraph(d) {
    const g = d.identity_graph || { clusters: [], records: [], edges: [], meta: {} };
    const meta = g.meta || {};
    const svg = $("identity-svg");

    if (d.identity_status !== "ready") {
      $("graph-subset-badge").textContent = "Analysis not run";
      $("graph-subset-badge").dataset.tone = "";
      $("cluster-count").textContent = "";
      $("cluster-list").innerHTML = `<li class="empty-note">Identity analysis runs on demand so large uploads stay fast. Choose <b>Analyze identity graph</b>.</li>`;
      svg.innerHTML = "";
      $("graph-detail-bar").textContent = "Nothing to show yet.";
      return;
    }

    const clusters = g.clusters || [];
    const recs = g.records || [];
    const edges = g.edges || [];
    const dc = meta.displayed_clusters ?? clusters.length;
    const tc = meta.total_clusters ?? clusters.length;
    const dr = meta.displayed_records ?? recs.length;
    const trc = meta.total_records ?? recs.length;
    $("graph-subset-badge").textContent = meta.truncated
      ? `Showing ${dc} of ${tc} clusters · ${dr} of ${trc} records`
      : `${dc} of ${tc} clusters · ${dr} of ${trc} records`;
    $("graph-subset-badge").dataset.tone = "ok";
    $("cluster-count").textContent = meta.truncated ? `${clusters.length} shown, bounded sample` : `${clusters.length}`;

    const byPsn = new Map();
    const recById = new Map();
    for (const r of recs) {
      recById.set(r.id, r);
      if (r.psn) {
        if (!byPsn.has(r.psn)) byPsn.set(r.psn, []);
        byPsn.get(r.psn).push(r);
      }
    }
    if (!state.selectedCluster || !clusters.some((c) => c.psn === state.selectedCluster)) {
      // Open on the patient that tells the most: one with a look-alike kept apart, then most scripts, then most records.
      const contested = new Set();
      for (const e of edges) {
        if (e.decision === "matched") continue;
        for (const id of [e.source, e.target]) if (recById.get(id)?.psn) contested.add(recById.get(id).psn);
      }
      const best = [...clusters].sort((x, y) => (contested.has(y.psn) - contested.has(x.psn)) || (y.scripts?.length || 0) - (x.scripts?.length || 0) || (y.record_count || 0) - (x.record_count || 0))[0];
      state.selectedCluster = best ? best.psn : null;
    }

    $("cluster-list").innerHTML = clusters.map((c) => `
      <li><button class="cl-btn ${c.psn === state.selectedCluster ? "active" : ""}" data-psn="${esc(c.psn)}" ${c.psn === state.selectedCluster ? 'aria-current="true"' : ""}>
        <span class="cl-psn">${esc(c.psn)}</span><span class="cl-count">${esc(c.record_count ?? "—")} rec</span>
        <span class="cl-sub">${(c.files || []).length} file${(c.files || []).length === 1 ? "" : "s"} · ${esc((c.scripts || []).join(" + ") || "—")} · age ${esc(c.age_band || "—")}</span>
      </button></li>`).join("") || `<li class="empty-note">No linked patients in this release.</li>`;

    const cl = clusters.find((c) => c.psn === state.selectedCluster);
    if (!cl) {
      svg.innerHTML = "";
      $("graph-detail-bar").textContent = "No patient selected.";
      return;
    }

    // Focus graph: records (left column) -> pseudonym hub (centre) -> look-alikes kept apart (right column).
    const W = 720;
    const all = byPsn.get(cl.psn) || [];
    const list = all.slice(0, MAX_FOCUS_RECORDS);
    const extra = all.length - list.length;
    const mine = new Set(all.map((r) => r.id));
    const apart = edges.filter((e) => e.decision !== "matched" && (mine.has(e.source) || mine.has(e.target) || e.psn === cl.psn));
    const ghosts = [];
    const seenG = new Set();
    for (const e of apart) {
      const other = mine.has(e.source) ? recById.get(e.target) : recById.get(e.source);
      const key = other?.psn || other?.id || `${e.source}-${e.target}`;
      if (!seenG.has(key) && ghosts.length < 6) {
        seenG.add(key);
        ghosts.push({ psn: other?.psn || "Unlinked record", edge: e });
      }
    }
    const ROW = 46;
    const top = 56;
    const H = Math.max(300, top + Math.max(list.length, ghosts.length, 1) * ROW + 44);
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    const hub = { x: 352, y: top + (Math.max(list.length, 1) * ROW) / 2 - ROW / 2 + 8 };
    const recY = (i) => top + i * ROW + 8;
    const ghY = (i) => (ghosts.length === 1 ? hub.y : top + 8 + (i * Math.max(list.length - 1, ghosts.length - 1, 1) * ROW) / Math.max(1, ghosts.length - 1));

    const parts = [`<text class="g-col-t" x="96" y="28" text-anchor="middle">Source records</text>`,
      `<text class="g-col-t" x="${hub.x}" y="28" text-anchor="middle">Pseudonym</text>`,
      `<text class="g-col-t" x="606" y="28" text-anchor="middle">Look-alikes kept apart</text>`];
    list.forEach((r, i) => {
      const y = recY(i);
      parts.push(`<path class="g-link" style="animation-delay:${i * 45}ms" d="M 172 ${y} C 250 ${y}, 250 ${hub.y}, ${hub.x - 78} ${hub.y}"/>`);
    });
    ghosts.forEach((gh, i) => {
      const y = ghY(i);
      const cls = gh.edge.decision === "rejected" ? "g-veto" : "g-hold";
      parts.push(`<path class="${cls}" d="M ${hub.x + 78} ${hub.y} C 470 ${hub.y}, 470 ${y}, 540 ${y}"/>`);
    });
    list.forEach((r, i) => {
      const y = recY(i);
      const sc = (r.scripts || [])[0];
      parts.push(`<g class="g-rec" style="animation-delay:${120 + i * 45}ms" data-id="${esc(r.id)}" tabindex="0" role="button" aria-label="Record ${esc(r.file)} ${esc(r.loc)}, ${esc(r.format)}">
        <rect class="g-rec-c" x="20" y="${y - 18}" width="152" height="36" rx="7"/>
        <circle class="${scriptClass(sc)}" cx="34" cy="${y - 5}" r="3.2"/>
        <text class="g-rec-t" x="43" y="${y - 1.5}">${esc(String(r.format).slice(0, 15))}</text>
        <text class="g-rec-s" x="34" y="${y + 12}">${esc(`${String(r.file).split("/").pop()} ${r.loc}`.slice(0, 21))}</text>
      </g>`);
    });
    ghosts.forEach((gh, i) => {
      const y = ghY(i);
      parts.push(`<g class="g-rec g-ghost" style="animation-delay:${300 + i * 60}ms" data-ghost="${i}" tabindex="0" role="button" aria-label="${gh.edge.decision === "rejected" ? "Kept apart from" : "Ambiguous with"} ${esc(gh.psn)}">
        <rect class="g-ghost-c" x="540" y="${y - 16}" width="140" height="32" rx="16"/>
        <text class="g-ghost-t" x="610" y="${y + 4}" text-anchor="middle">${esc(String(gh.psn).slice(0, 17))}</text>
        <text class="${gh.edge.decision === "rejected" ? "g-veto-t" : "g-hold-t"}" x="610" y="${y + 30}" text-anchor="middle">${gh.edge.decision === "rejected" ? "kept apart" : "ambiguous"}</text>
      </g>`);
    });
    parts.push(`<rect class="g-hub-ring" x="${hub.x - 78}" y="${hub.y - 30}" width="156" height="60" rx="12"/>`);
    parts.push(`<rect class="g-hub-c" x="${hub.x - 78}" y="${hub.y - 30}" width="156" height="60" rx="12"/>
      <text class="g-hub-t" x="${hub.x}" y="${hub.y - 3}" text-anchor="middle">${esc(cl.psn)}</text>
      <text class="g-hub-s" x="${hub.x}" y="${hub.y + 15}" text-anchor="middle">${esc(cl.record_count ?? all.length)} records · ${(cl.files || []).length} files</text>`);
    if (extra > 0) parts.push(`<text class="g-lbl" x="96" y="${H - 34}" text-anchor="middle">+${extra} more not drawn</text>`);
    if (!ghosts.length) parts.push(`<text class="g-lbl" x="606" y="${hub.y - 4}" text-anchor="middle">No look-alike pairs</text><text class="g-lbl" x="606" y="${hub.y + 12}" text-anchor="middle">recorded for this patient</text>`);
    parts.push(`<g transform="translate(26 ${H - 12})"><circle class="g-script-latin" r="3.2" cx="4" cy="-4"/><text class="g-lbl" x="12" y="0">Latin</text><circle class="g-script-deva" r="3.2" cx="62" cy="-4"/><text class="g-lbl" x="70" y="0">Devanagari</text><circle class="g-script-other" r="3.2" cx="146" cy="-4"/><text class="g-lbl" x="154" y="0">Other script</text></g>`);
    svg.innerHTML = parts.join("");
    svg.setAttribute("aria-label", `${cl.psn}: ${cl.record_count} linked records across ${(cl.files || []).length} files; ${ghosts.length} look-alike pairs kept apart`);

    const clusterText = () => `<b>${esc(cl.psn)}</b> links ${cl.record_count} records from ${esc((cl.files || []).join(", "))}. Scripts: ${esc((cl.scripts || []).join(", ") || "—")}. Age band ${esc(cl.age_band || "—")}; privacy rule <b>${esc(cl.qi_reason || "—")}</b> (${esc(cl.qi_band_years ?? "—")}-year band, PIN ${esc(cl.qi_pin ?? "—")}, district ${esc(cl.qi_district ?? "—")}).`;
    $("graph-detail-bar").innerHTML = clusterText();

    const showRec = (el) => {
      svg.querySelectorAll(".g-rec.sel").forEach((x) => x.classList.remove("sel"));
      el.classList.add("sel");
      if (el.dataset.ghost != null) {
        const gh = ghosts[Number(el.dataset.ghost)];
        $("graph-detail-bar").innerHTML = `<b>${gh.edge.decision === "rejected" ? "Kept apart" : "Ambiguous"}:</b> ${esc(gh.edge.summary || "")}. ${esc(gh.edge.veto || "")}`;
        return;
      }
      const r = recById.get(el.dataset.id);
      if (!r) return;
      const ev = edges.filter((e) => e.decision === "matched" && (e.source === r.id || e.target === r.id)).flatMap((e) => e.evidence || []);
      $("graph-detail-bar").innerHTML = `Record <b>${esc(r.file)}</b> at <code>${esc(r.loc)}</code> (${esc(r.format)}), exported as <code>${esc(r.sanitized_file || "—")}</code>. Scripts: ${esc((r.scripts || []).join(", ") || "—")}. Signals: ${esc((r.signals || []).join(", ") || "none")}.${ev.length ? ` Link evidence (reconstructed): ${esc([...new Set(ev)].join("; "))}.` : ""}`;
    };
    svg.onclick = (e) => { const el = e.target.closest(".g-rec"); if (el) showRec(el); else $("graph-detail-bar").innerHTML = clusterText(); };
    svg.onkeydown = (e) => { const el = e.target.closest(".g-rec"); if (el && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); showRec(el); } };
  }

  document.querySelectorAll(".filter-pill").forEach((b) => {
    b.addEventListener("click", () => {
      document.querySelectorAll(".filter-pill").forEach((x) => { x.classList.remove("active"); x.setAttribute("aria-pressed", "false"); });
      b.classList.add("active");
      b.setAttribute("aria-pressed", "true");
      state.decisionFilter = b.dataset.filter;
      state.decisionPage = 0;
      renderDecisionsPage();
    });
  });
  $("dec-prev").addEventListener("click", () => {
    if (state.decisionPage > 0) { state.decisionPage -= 1; renderDecisionsPage(); }
  });
  $("dec-next").addEventListener("click", () => { state.decisionPage += 1; renderDecisionsPage(); });

  async function renderDecisionsPage() {
    const reqId = ++state.decisionsReq;
    let res;
    try {
      res = await apiFetchJson(`/api/decisions?filter=${encodeURIComponent(state.decisionFilter)}&page=${state.decisionPage}&limit=${DECISIONS_PAGE_LIMIT}`);
    } catch (err) {
      if (reqId !== state.decisionsReq) return;
      $("decisions-table").innerHTML = `<tbody><tr><td class="table-empty">Decisions unavailable: ${esc(err.message)}</td></tr></tbody>`;
      return;
    }
    if (reqId !== state.decisionsReq) return; // a newer page/filter request superseded this one
    const list = res.items || [];
    const total = res.total_filtered || 0;
    const tone = { matched: "tag-ok", rejected: "tag-fail", ambiguous: "tag-warn" };
    const label = { matched: "Linked", rejected: "Kept apart", ambiguous: "Ambiguous" };
    $("decisions-table").innerHTML = `
      <thead><tr><th>Decision</th><th>Record A</th><th>Record B</th><th>Scripts</th><th>Reason</th></tr></thead>
      <tbody>${list.map((row) => `
        <tr><td><span class="tag ${tone[row.decision] || ""}">${esc(label[row.decision] || row.decision)}</span></td>
          <td class="mono">${esc(row.left)}</td><td class="mono">${esc(row.right)}</td>
          <td>${esc((row.scripts || []).join(" ↔ "))}</td><td>${esc(row.rule)}</td></tr>`).join("")
        || `<tr><td colspan="5" class="table-empty">${state.data?.identity_status === "ready" ? "No decisions match this filter." : "Run the identity analysis to load decisions."}</td></tr>`}</tbody>`;
    const startIdx = total ? state.decisionPage * DECISIONS_PAGE_LIMIT + 1 : 0;
    const endIdx = Math.min(total, (state.decisionPage + 1) * DECISIONS_PAGE_LIMIT);
    $("dec-page-info").textContent = `${startIdx}–${endIdx} of ${total}${res.decision_counts?.truncated ? " · bounded candidate sample" : ""}`;
    $("dec-prev").disabled = state.decisionPage === 0;
    $("dec-next").disabled = endIdx >= total;
  }

  $("btn-run-identity").addEventListener("click", async () => {
    const btn = $("btn-run-identity");
    setBusy(btn, true, "Analyzing…");
    const jobAtStart = state.data?.job_id;
    try {
      const res = await apiFetchJson("/api/identity/run", { method: "POST" });
      if (state.data?.job_id !== jobAtStart) return; // dataset changed meanwhile
      state.data.identity_status = "ready";
      state.data.identity_graph = res.identity_graph;
      state.data.identity_decisions = res.identity_decisions;
      state.data.qi_stats = res.qi_stats;
      state.selectedCluster = null;
      state.decisionPage = 0;
      renderGraph(state.data);
      await renderDecisionsPage();
      renderOverview(state.data);
      toast(`Identity analysis finished${res.identity_s != null ? ` in ${res.identity_s}s` : ""}.`, "ok");
    } catch (err) {
      toast(`Identity analysis failed: ${err.message}`, "fail");
    } finally {
      setBusy(btn, false);
    }
  });

  // ---------- Privacy arena ----------
  function arenaMetrics(a) {
    const q = a.qi || {};
    const pts = q.patients || 0;
    return [
      { k: "Patients unique on age, place and gender", v: q.singleton_k1_patients, den: pts, fmt: (v) => `${v} / ${pts}`, better: "low" },
      { k: "Patients with an exact age visible", v: q.exact_age_patients, den: pts, fmt: (v) => `${v} / ${pts}`, better: "low" },
      { k: "6-digit PIN codes still visible", v: a.exact_pins_visible, den: null, fmt: (v) => `${v}`, better: "low" },
      { k: "Highest re-identification risk", v: q.prosecutor_max_risk_pct, den: 100, fmt: (v) => `${v}%`, better: "low" },
      { k: "Clinical values kept", v: a.clinical_kept_pct, den: 100, fmt: (v) => `${v}%`, better: "high", na: "N/A (no probes)" },
    ];
  }

  function renderArena(d) {
    const arena = d.privacy_arena || [];
    const ready = d.arena_status === "ready" && arena.length > 0;
    $("arena-status-badge").textContent = ready ? "Measured Live" : "On-Demand";
    $("arena-status-badge").dataset.tone = ready ? "ok" : "";
    if (!ready) {
      $("arena-cards").innerHTML = `<p class="arena-empty">Not run for this dataset yet. <b>Run comparison</b> re-processes the same input under masking, fixed and adaptive policies (reusing this run's result where it matches) and measures each output.</p>`;
      $("arena-table").innerHTML = "";
      return;
    }
    const pinMax = Math.max(1, ...arena.map((a) => a.exact_pins_visible || 0));
    $("arena-cards").innerHTML = arena.map((a) => {
      const isMine = a.mode === d.policy_mode;
      const rows = arenaMetrics(a).map((m) => {
        const den = m.den ?? pinMax;
        const frac = den ? Math.max(0, Math.min(1, (Number(m.v) || 0) / den)) : 0;
        const goodness = m.better === "low" ? 1 - frac : frac;
        const cls = goodness >= 0.8 ? "good" : goodness >= 0.4 ? "mid" : "bad";
        return `<div class="arena-metric"><div class="am-top"><span>${m.k}</span><span class="am-val">${esc(m.v == null ? (m.na || "—") : m.fmt(m.v))}</span></div>
          <div class="am-track" aria-hidden="true"><div class="am-fill ${cls}" style="width:${Math.round(frac * 100)}%"></div></div></div>`;
      }).join("");
      return `<section class="arena-col ${isMine ? "is-active" : ""}" aria-label="${esc(a.label)}">
        <h3>${esc(a.label)}${isMine ? ' <span class="tag tag-ok">This run</span>' : ""}${a.reused_from_active_run ? ' <span class="tag">Reused</span>' : ""}</h3>
        <p class="summary">${esc(a.summary)}</p>${rows}</section>`;
    }).join("");

    $("arena-table").innerHTML = `
      <thead><tr><th>Policy</th><th class="num">Unique (k=1)</th><th class="num">Exact ages</th><th class="num">PINs visible</th><th class="num">10-year bands</th><th class="num">Districts dropped</th><th class="num">Max risk</th><th class="num">Residual hits</th><th class="num">Clinical kept</th><th class="num">Runtime</th></tr></thead>
      <tbody>${arena.map((a) => `
        <tr><td><b>${esc(a.label)}</b></td>
          <td class="num">${esc(a.qi?.singleton_k1_patients)} / ${esc(a.qi?.patients)}</td>
          <td class="num">${esc(a.qi?.exact_age_patients)}</td>
          <td class="num">${esc(a.exact_pins_visible)}</td>
          <td class="num">${esc(a.qi?.band_10y_patients)}</td>
          <td class="num">${esc(a.qi?.district_dropped_patients)}</td>
          <td class="num">${esc(a.qi?.prosecutor_max_risk_pct)}%</td>
          <td class="num">${esc(a.residual_hits)}</td>
          <td class="num">${a.clinical_kept_pct == null ? "N/A" : `${esc(a.clinical_kept_pct)}%`}</td>
          <td class="num">${esc(a.runtime_s)}s${a.reused_from_active_run ? " (reused)" : ""}</td></tr>`).join("")}</tbody>`;
  }

  $("btn-run-arena").addEventListener("click", async () => {
    const btn = $("btn-run-arena");
    setBusy(btn, true, "Comparing policies…");
    const jobAtStart = state.data?.job_id;
    try {
      const res = await apiFetchJson("/api/arena/run", { method: "POST" });
      if (state.data?.job_id !== jobAtStart) return;
      state.data.arena_status = "ready";
      state.data.privacy_arena = res.privacy_arena;
      if (state.data.timings) state.data.timings.arena_s = res.arena_s;
      renderArena(state.data);
      renderTimingsLine(state.data.timings);
      toast(`Policy comparison finished${res.arena_s != null ? ` in ${res.arena_s}s` : ""}.`, "ok");
    } catch (err) {
      toast(`Comparison failed: ${err.message}`, "fail");
    } finally {
      setBusy(btn, false);
    }
  });

  // ---------- Clinical integrity ----------
  function renderClinical(d) {
    const pass = d.passport || {};
    const det = d.clinical_detail || {};
    const verified = d.passport_status === "verified";
    const clinPct = pass.clinical?.protected_values_kept_pct;
    $("clin-pct-badge").textContent = !verified ? "Pending" : (clinPct == null ? "N/A" : `${clinPct}%`);
    $("los-badge").textContent = verified ? (pass.clinical?.notes_with_intervals_preserved ?? "—") : "Pending";

    const tp = pass.temporal || {};
    $("temporal-facts").innerHTML = verified && Object.keys(tp).length
      ? [
          ["Intervals passed", tp.intervals_passed],
          ["Intervals failed", tp.intervals_failed],
          ["Cross-record chronology", tp.cross_record_patient_chronology],
          ["Skipped (fewer than 2 dates)", tp.skipped_under_2_dates],
          ["Inconclusive", tp.inconclusive_unparseable_or_count_mismatch],
          ["FHIR dates valid", tp.fhir_dates_valid],
        ].map(([k, v]) => `<div><dt>${k}</dt><dd>${esc(v ?? "—")}</dd></div>`).join("")
      : `<div><dt>Temporal checks</dt><dd>Run the Passport audit</dd></div>`;

    const tl = det.timeline_intervals || [];
    const maxLos = Math.max(1, ...tl.map((t) => Math.max(t.input_los_days || 0, t.output_los_days || 0)));
    $("timeline-cards").innerHTML = tl.map((t) => {
      const wIn = Math.max(8, Math.round((70 * (t.input_los_days || 0)) / maxLos));
      const wOut = Math.max(8, Math.round((70 * (t.output_los_days || 0)) / maxLos));
      const shift = t.patient_shift_days;
      return `<div class="tl">
        <div class="tl-head"><span class="tl-file">${esc(t.file)}</span><span class="tag ${t.preserved ? "tag-ok" : "tag-fail"}">${t.preserved ? `Stay unchanged: ${esc(t.input_los_days ?? "—")} days` : `Stay changed by ${esc(t.los_delta_days ?? "—")} days`}</span></div>
        <div class="tl-rows">
          <span>Original</span><div class="tl-track"><div class="tl-bar orig" style="left:0;width:${wIn}%"><span>${esc(t.input_dates?.[0])}</span><span>${esc(t.input_dates?.[(t.input_dates?.length || 1) - 1])}</span></div></div>
          <span>Sanitized</span><div class="tl-track"><div class="tl-bar shift" style="left:${shift < 0 ? 0 : 30 - Math.min(30, wOut / 3)}%;width:${wOut}%"><span>${esc(t.output_dates?.[0])}</span><span>${esc(t.output_dates?.[(t.output_dates?.length || 1) - 1])}</span></div></div>
        </div>
        <p class="tl-foot">Shifted ${shift > 0 ? "+" : ""}${esc(shift ?? "—")} days for this patient. ${esc(t.input_los_days ?? "—")} days before, ${esc(t.output_los_days ?? "—")} days after. Exported as <span class="mono">${esc(t.output_file)}</span>.</p>
      </div>`;
    }).join("") || `<p class="fine">None of the previewed notes contains two or more dates, so there is no interval to show.</p>`;

    const pv = pass.clinical?.protected_values || {};
    $("clinical-categories").innerHTML = Object.entries(pv).map(([cat, ratio]) => {
      const rp = ratioParts(ratio);
      const pct = rp && rp[1] ? Math.round((100 * rp[0]) / rp[1]) : 0;
      return `<div class="hbar"><span class="hbar-label">${esc(cat)}</span><div class="hbar-track"><div class="hbar-fill ${pct < 100 ? "tone-warn" : ""}" style="width:${pct}%"></div></div><span class="hbar-val">${esc(ratio)}</span></div>`;
    }).join("") || `<p class="fine">${verified ? "No protected clinical expressions were found." : "Run the Passport audit to count every medication, dose, vital, lab value and code."}</p>`;

    $("staff-chips").innerHTML = (det.staff_preserved || []).map((s) => `<span class="chip"><span class="tok-staff">${esc(s)}</span></span>`).join("") || `<p class="fine">No clinician names in the previewed files.</p>`;

    const samples = det.samples || [];
    $("clinical-samples-table").innerHTML = samples.length ? `
      <thead><tr><th>Category</th><th>File</th><th>Value</th><th>In sanitized output</th></tr></thead>
      <tbody>${samples.map((s) => `
        <tr><td>${esc(s.category)}</td><td class="mono">${esc(s.file)}</td><td class="mono">${esc(s.value)}</td>
          <td><span class="tag ${s.preserved ? "tag-ok" : "tag-fail"}">${s.preserved ? "Verbatim" : "Missing"}</span></td></tr>`).join("")}</tbody>`
      : `<tbody><tr><td class="table-empty">No clinical values sampled from the previews.</td></tr></tbody>`;
  }

  // ---------- Privacy Passport ----------
  const PILLARS = [
    ["privacy", "Privacy", "privacy"],
    ["clinical", "Clinical integrity", "clinical"],
    ["temporal", "Temporal integrity", "temporal"],
    ["identity", "Identity consistency", "identity"],
    ["structural", "Structural validity", "structural"],
  ];
  const STATUS = {
    PASS: ["ok", "Passed", ICON.check],
    FAIL: ["fail", "Failed", ICON.x],
    WARNING: ["warn", "Warning", ICON.alert],
    INCONCLUSIVE: ["warn", "Inconclusive", ICON.alert],
    SKIPPED: ["pending", "Skipped", ICON.dash],
    PENDING: ["pending", "Pending", ICON.clock],
  };

  function sealSvg() {
    return `<svg viewBox="0 0 120 120" aria-hidden="true">
      <circle class="seal-ring" cx="60" cy="60" r="56"/><circle class="seal-ring2" cx="60" cy="60" r="48"/>
      <g transform="translate(36 34) scale(1.5)"><path class="mk-raw" d="M6 5.5l4.6 9.2M26 5.5l-4.6 9.2"/><path class="mk-safe" d="M11.9 17.4L16 25.7l4.1-8.3"/><rect class="mk-layer" x="4" y="14.6" width="24" height="2.6" rx="1.3"/></g>
    </svg>`;
  }

  function renderPassport(d) {
    const corr = d.corrupted_passport;
    const verified = d.passport_status === "verified";
    const audit = corr ? corr.audit || {} : d.passport || {};
    const risks = audit.residual_risks || [];
    const a = assurance(d);

    $("btn-repair-demo").classList.toggle("hidden", !corr);
    $("btn-corrupt-demo").disabled = false;
    $("sheet-defect").classList.toggle("hidden", !corr);
    $("btn-export-passport-html").href = corr ? "/api/passport/html?variant=corrupt" : "/api/passport/html";
    $("btn-export-passport-json").href = corr ? "/api/passport/json?variant=corrupt" : "/api/passport/json";
    $("btn-export-passport-html").textContent = corr ? "Export defect report (HTML)" : "Export HTML";
    $("btn-export-passport-json").textContent = corr ? "Export defect report (JSON)" : "Export JSON";
    $("btn-export-zip").innerHTML = `${use("i-download")}<span>${corr ? "Clean release ZIP" : "Release ZIP"}</span>`;

    const sheet = $("passport-sheet");
    const banner = $("passport-banner");
    let stamp;
    let sub;
    let tone;
    if (!verified && !corr) {
      tone = "pending"; stamp = "VERIFICATION PENDING"; sub = "The release passed the output contract. The deep audit has not run.";
    } else if (corr) {
      tone = "fail"; stamp = "SYNTHETIC DEFECT CAUGHT"; sub = `In ${corr.target_file || "a release file"}`;
    } else if (a.key === "pass") {
      tone = "ok"; stamp = "RELEASE AUDIT PASSED"; sub = `Verdict ${audit.verdict || "PASS"} · Assurance ${audit.assurance_version || ""}`;
    } else if (a.key === "fail") {
      tone = "fail"; stamp = "REVIEW REQUIRED"; sub = `Verdict ${audit.verdict}`;
    } else {
      tone = "warn"; stamp = a.key === "skipped" ? "INCONCLUSIVE" : "VERIFIED WITH WARNINGS"; sub = `Verdict ${audit.verdict || "WARNING"}`;
    }
    sheet.dataset.tone = tone === "pending" ? "" : tone;
    banner.dataset.tone = tone;
    banner.innerHTML = `${sealSvg()}<span class="seal-stamp">${esc(stamp)}</span><span class="seal-sub">${esc(sub)}</span>`;

    $("pp-title").textContent = corr ? "Defect detection test" : "Release audit";
    const t = d.timings || {};
    $("pp-meta").innerHTML = [
      ["Release", esc(d.dataset_label)],
      ["Sanitized", esc(d.run_at)],
      ["Policy", esc(d.policy_mode)],
      ["Engine runtime", fmtSec(d.runtime_s)],
      ["Audit", verified || corr ? `Assurance ${esc(audit.assurance_version || "—")}${audit.audit_seconds != null ? `, ${audit.audit_seconds}s` : ""}` : "Not run"],
    ].map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`).join("");

    let lede;
    if (!verified && !corr) lede = "Choose Run full audit to check the release for leftover identifiers, altered clinical values, broken intervals, misplaced pseudonyms and structural errors.";
    else if (corr) lede = `${corr.mutation || "A defect was injected into a copy of the release."} The audit flagged: ${risks.join("; ") || "see the pillars below"}. Re-run VEIL to rebuild and reverify the release.`;
    else if (a.key === "pass") {
      const s = audit.structural || {};
      const cp = audit.clinical?.protected_values_kept_pct;
      lede = `No identifier patterns were found across ${audit.privacy?.channels_scanned ?? "—"} channels, ${cp == null ? "no protected clinical expressions were present to check" : `${cp}% of protected clinical expressions were kept verbatim`}, and ${s.exported ?? "—"} of ${s.input_files ?? "—"} files were exported (${s.quarantined ?? 0} quarantined).`;
    } else lede = `Findings: ${risks.join("; ") || "one or more checks did not pass"}.`;
    $("pp-lede").textContent = lede;

    const checks = audit.checks || {};
    $("passport-checks").innerHTML = PILLARS.map(([key, name]) => {
      const c = checks[key] || { status: "PENDING", coverage: "Pending", detail: "Not yet audited" };
      const [stTone, stLabel, glyph] = STATUS[c.status] || ["pending", c.status, ICON.dash];
      const hasDen = typeof c.passed === "number" && typeof c.total === "number" && c.total > 0;
      const pct = hasDen ? Math.round((100 * c.passed) / c.total) : 0;
      const barCls = stTone === "fail" ? "fail" : stTone === "warn" ? "warn" : "";
      return `<li class="ledger-row">
        <span class="lr-glyph" data-tone="${stTone}">${glyph}</span>
        <div><div class="lr-name">${name}</div><div class="lr-status" data-tone="${stTone}">${esc(stLabel)}</div></div>
        <div class="lr-cov">${hasDen ? `${c.passed} / ${c.total}<small>checks passed</small><div class="lr-bar" aria-hidden="true"><span class="${barCls}" style="width:${pct}%"></span></div>` : `${esc(c.coverage || "—")}`}</div>
        <p class="lr-detail">${esc(c.detail || "")}</p>
      </li>`;
    }).join("");

    // Evidence: every field the audit returned, label and value adjacent (no whitespace between them).
    const fmtVal = (v) => {
      if (v == null) return "—";
      if (typeof v === "boolean") return v ? "yes" : "no";
      if (typeof v === "object") {
        const ents = Object.entries(v);
        return ents.length ? ents.map(([k, x]) => `${k} ${x}`).join(", ") : "none";
      }
      return String(v);
    };
    const isBad = (k, v) => (/fail|error|violation|missing|unexpected|unsafe|residue/.test(k) && typeof v === "number" && v > 0);
    $("passport-pillars").innerHTML = PILLARS.map(([key, name], i) => {
      const obj = audit[key] || {};
      const ents = Object.entries(obj);
      const c = checks[key];
      return `<details class="ev"${i === 0 && (verified || corr) ? " open" : ""}><summary>${name}<span class="meta">${ents.length} fields${c?.coverage ? ` · ${esc(c.coverage)}` : ""}</span></summary><dl class="ev-grid">${ents.map(([k, v]) => `<div><dt>${esc(k.replace(/_/g, " "))}</dt><dd class="${isBad(k, v) ? "bad" : ""}">${esc(fmtVal(v))}</dd></div>`).join("") || "<div><dt>No data</dt><dd>—</dd></div>"}</dl></details>`;
    }).join("");

    const hist = d.verification_history || [];
    $("passport-history-table").innerHTML = hist.length ? `
      <thead><tr><th>Time</th><th>Event</th><th>Result</th><th>Details</th></tr></thead>
      <tbody>${hist.map((h) => {
        const [ht] = STATUS[h.status] || ["pending"];
        return `<tr><td class="mono">${esc(h.timestamp)}</td><td>${esc(h.event)}</td><td><span class="tag tag-${ht === "pending" ? "info" : ht}">${esc(h.status)}</span></td><td>${esc(h.summary)}</td></tr>`;
      }).join("")}</tbody>`
      : `<tbody><tr><td class="table-empty">No verification events yet.</td></tr></tbody>`;
  }

  $("btn-run-passport").addEventListener("click", async () => {
    const btn = $("btn-run-passport");
    setBusy(btn, true, "Auditing…");
    $("btn-corrupt-demo").disabled = true;
    const jobAtStart = state.data?.job_id;
    try {
      const res = await apiFetchJson("/api/passport/run", { method: "POST" });
      if (state.data?.job_id !== jobAtStart) return;
      state.data.passport_status = "verified";
      state.data.passport = res.passport;
      state.data.corrupted_passport = null;
      if (res.timings) state.data.timings = res.timings;
      if (res.verification_history) state.data.verification_history = res.verification_history;
      renderAll(state.data);
      renderPassport(state.data);
      const a = assurance(state.data);
      toast(a.key === "pass" ? "Audit passed." : `Audit finished: ${a.label}.`, a.tone === "ok" ? "ok" : "warn");
    } catch (err) {
      toast(`Audit failed to run: ${err.message}`, "fail");
    } finally {
      setBusy(btn, false);
      $("btn-corrupt-demo").disabled = false;
    }
  });

  $("btn-corrupt-demo").addEventListener("click", async () => {
    const btn = $("btn-corrupt-demo");
    setBusy(btn, true, "Injecting…");
    try {
      setStatus("Testing Defect Detection...", "busy");
      const res = await apiFetchJson("/api/passport/corrupt", { method: "POST" });
      state.data.corrupted_passport = res.corrupted_passport;
      if (res.verification_history) state.data.verification_history = res.verification_history;
      renderPassport(state.data);
      state.renderedViews.delete("overview");
      if (state.activeView === "overview") renderOverview(state.data);
      setStatus("Defect Caught!", "fail");
      toast("Defect injected into a copy and caught by the audit. The real release is unchanged.", "warn");
    } catch (err) {
      const a = state.data?.ready ? assurance(state.data) : null;
      if (a) setStatus(a.label, a.tone);
      toast(`Defect test failed: ${err.message}`, "fail");
    } finally {
      setBusy(btn, false);
    }
  });

  $("btn-repair-demo").addEventListener("click", async () => {
    const btn = $("btn-repair-demo");
    setBusy(btn, true, "Re-running VEIL…");
    try {
      setStatus("Repairing Release...", "busy");
      const res = await apiFetchJson("/api/passport/repair", { method: "POST" });
      state.data.corrupted_passport = null;
      state.data.passport = res.passport;
      state.data.passport_status = "verified";
      if (res.runtime_s != null) state.data.runtime_s = res.runtime_s;
      if (res.verification_history) state.data.verification_history = res.verification_history;
      setBusy(btn, false);
      renderAll(state.data);
      renderPassport(state.data);
      toast("Release rebuilt from the original input and reverified.", "ok");
    } catch (err) {
      setBusy(btn, false);
      setStatus("Defect Caught!", "fail");
      toast(`Repair failed: ${err.message}`, "fail");
    }
  });

  // ---------- Boot ----------
  async function loadState({ resume = true } = {}) {
    const data = await apiFetchJson("/api/state");
    renderAll(data);
    if (!resume) return;
    // Resume an in-flight job after a reload: the server's last completed job, or the one this tab started.
    const candidates = [getSavedJobId(), data.active_job_id].filter(Boolean);
    for (const jid of [...new Set(candidates)]) {
      try {
        const st = await apiFetchJson(`/api/status/${encodeURIComponent(jid)}`);
        if (IN_FLIGHT.includes(st.status)) {
          setView("runner");
          pollJob(jid, $("runner-log"));
          return;
        }
        if (jid === getSavedJobId()) saveActiveJobId(null);
      } catch (err) {
        if (err.code === "job_not_found" && jid === getSavedJobId()) saveActiveJobId(null);
      }
    }
    $("btn-reconnect-job").classList.toggle("hidden", !getSavedJobId());
  }

  setView((location.hash.match(/^#\/(\w+)/) || [])[1] || "overview", { updateHash: false });
  loadState().catch((e) => {
    $("active-dataset-title").textContent = `Cannot reach the local VEIL server: ${e.message}`;
    setStatus("Server Unavailable", "fail");
  });
})();
