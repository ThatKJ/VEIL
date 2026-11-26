(() => {
  const MAX_UPLOAD_FILES = 64;
  const MAX_UPLOAD_BYTES = 16 * 1024 * 1024;
  const DECISIONS_PAGE_LIMIT = 50;

  const state = {
    data: null,
    activeView: "overview",
    selectedFileIdx: 0,
    decisionFilter: "all",
    decisionPage: 0,
    stagedFiles: [], // [{ id, path, origPath, renamed, size, file }]
    activeJobId: null,
    isSubmitting: false,
    inspectorReqId: 0,
    decisionsReqId: 0,
    diffCache: new Map(),
    renderedViews: new Set(),
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

  // Navigation — lazy-render tabs on activation instead of eagerly locking the UI thread
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.view;
      state.activeView = target;
      document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
      $(`view-${target}`).classList.add("active");
      if (state.data && state.data.ready && !state.renderedViews.has(target)) {
        renderView(target, state.data);
      }
    });
  });

  async function apiFetchJson(url, opts = {}) {
    let res;
    try {
      res = await fetch(url, opts);
    } catch (netErr) {
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

  function setStatus(label, cls = "status-ok") {
    const el = $("status-pill");
    el.textContent = label;
    el.className = `status-pill ${cls}`;
  }

  function setRunControlsBusy(busy) {
    state.isSubmitting = busy;
    $("btn-quick-demo").disabled = busy;
    $("btn-run-demo").disabled = busy;
    $("btn-run-uploaded").disabled = busy || state.stagedFiles.length === 0;
    if ($("btn-clear-staged")) $("btn-clear-staged").disabled = busy;
    if ($("file-input")) $("file-input").disabled = busy;
    if ($("dropzone")) {
      $("dropzone").setAttribute("aria-disabled", busy ? "true" : "false");
      $("dropzone").style.pointerEvents = busy ? "none" : "";
      $("dropzone").style.opacity = busy ? "0.6" : "";
    }
    document.querySelectorAll(".staged-rm").forEach((b) => { b.disabled = busy; });
  }

  function setExportControlsReady(ready, corrupted) {
    const suffix = corrupted ? "?variant=corrupt" : "";
    const links = [
      ["btn-download-zip", "/api/download/zip"],
      ["btn-export-zip", "/api/download/zip"],
      ["btn-export-passport-html", `/api/passport/html${suffix}`],
      ["btn-export-passport-json", `/api/passport/json${suffix}`],
    ];
    for (const [id, href] of links) {
      const el = $(id);
      if (!el) continue;
      el.setAttribute("href", href);
      el.setAttribute("aria-disabled", ready ? "false" : "true");
      el.dataset.disabled = ready ? "0" : "1";
      el.style.opacity = ready ? "" : "0.45";
      el.style.pointerEvents = ready ? "" : "none";
    }
  }

  for (const id of ["btn-download-zip", "btn-export-zip", "btn-export-passport-html", "btn-export-passport-json"]) {
    const el = $(id);
    if (el) {
      el.addEventListener("click", (e) => {
        if (el.dataset.disabled === "1") e.preventDefault();
      });
    }
  }

  function showProgress(pct, stage, showCancel = false) {
    $("progress-panel").classList.remove("hidden");
    $("progress-pct").textContent = `${pct}%`;
    $("progress-stage").textContent = stage;
    $("progress-fill").style.width = `${pct}%`;
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
      timings.upload_staging_s != null ? `Staging: ${timings.upload_staging_s}s` : null,
      timings.engine_runtime_s != null ? `Engine (1x): ${timings.engine_runtime_s}s` : null,
      timings.validation_s != null ? `Validation: ${timings.validation_s}s` : null,
      timings.total_ui_s != null ? `Total UI: ${timings.total_ui_s}s` : null,
      timings.passport_s != null ? `Passport Audit: ${timings.passport_s}s` : null,
      timings.arena_s != null ? `Arena: ${timings.arena_s}s` : null,
    ].filter(Boolean);
    el.textContent = parts.join(" · ");
  }

  async function pollJob(jobId, logEl) {
    saveActiveJobId(jobId);
    $("btn-reconnect-job").classList.add("hidden");
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
          setStatus(`Reconnecting (${consecutiveNetFails}/8)...`, "status-warn");
          if (logEl) logEl.textContent = `Transient network hiccup while polling job ${jobId}; retrying in ${(wait / 1000).toFixed(1)}s...`;
          await new Promise((r) => setTimeout(r, wait));
          continue;
        }
        hideProgress();
        setRunControlsBusy(false);
        setStatus(err.code === "server_unavailable" ? "Server Unavailable" : "Polling Error", "status-fail");
        if (logEl) logEl.textContent = `ERROR [${err.code || "network"}]: ${err.message}. Click 'Reconnect Active Job' if server returns.`;
        $("btn-reconnect-job").classList.remove("hidden");
        return;
      }

      const stageTxt = st.stage || st.status || "Running";
      showProgress(st.progress ?? 0, stageTxt, ["queued", "running", "validating"].includes(st.status));
      if (logEl) logEl.textContent = `[${st.status.toUpperCase()} · ${st.progress ?? 0}%] ${stageTxt}`;

      if (st.status === "ready") {
        saveActiveJobId(null);
        hideProgress();
        setRunControlsBusy(false);
        state.diffCache.clear();
        state.selectedFileIdx = 0;
        state.decisionPage = 0;
        await loadState();
        const cnt = state.data?.report?.counts;
        if (logEl) {
          logEl.textContent = `Ready (1x engine run · ${cnt?.files_sanitized ?? 0}/${cnt?.files_total ?? 0} files sanitized · ${cnt?.records_processed ?? 0} records). Audit & Arena available on demand.`;
        }
        return;
      }

      if (st.status === "failed" || st.status === "cancelled") {
        saveActiveJobId(null);
        hideProgress();
        setRunControlsBusy(false);
        setStatus(st.status === "cancelled" ? "Cancelled" : "Run Failed", "status-fail");
        if (logEl) logEl.textContent = `ERROR [${st.error_code || st.status}]: ${st.error || "Execution stopped"}`;
        return;
      }

      await new Promise((r) => setTimeout(r, delayMs));
      delayMs = Math.min(1000, Math.round(delayMs * 1.25));
    }
  }

  async function dispatchUploadRun(logEl) {
    if (state.isSubmitting || !state.stagedFiles.length) return;
    const secretVal = $("secret-input").value.trim();
    if (!secretVal) {
      showValidationError("RAKSHA_SECRET is required before running sanitization.");
      return;
    }
    clearValidationError();
    setRunControlsBusy(true);
    setStatus("Uploading Dataset...", "status-warn");
    showProgress(3, `Uploading ${state.stagedFiles.length} file(s)`, false);
    if (logEl) logEl.textContent = `Uploading ${state.stagedFiles.length} files (${fmtBytes(stagedTotalBytes())})...`;

    try {
      const fd = new FormData();
      fd.append("mode", "upload");
      fd.append("policy", $("policy-select").value);
      fd.append("secret", secretVal);
      fd.append("label", `Uploaded Synthetic Dataset (${state.stagedFiles.length} files)`);
      fd.append("relpaths", JSON.stringify(state.stagedFiles.map((f) => f.path)));
      for (const item of state.stagedFiles) {
        fd.append("files", item.file, item.path);
      }
      const start = await apiFetchJson("/api/run", { method: "POST", body: fd });
      await pollJob(start.job_id, logEl);
    } catch (err) {
      hideProgress();
      setRunControlsBusy(false);
      setStatus("Upload Error", "status-fail");
      const msg = `[${err.code || "upload_error"}] ${err.message}`;
      showValidationError(msg);
      if (logEl) logEl.textContent = `ERROR: ${msg}`;
    }
  }

  async function dispatchDemoRun(logEl) {
    if (state.isSubmitting) return;
    const secretVal = $("secret-input").value.trim() || "veil-command-center-demo-key";
    clearValidationError();
    setRunControlsBusy(true);
    setStatus("Executing Demo...", "status-warn");
    showProgress(8, "Starting VEIL demo job", false);
    if (logEl) logEl.textContent = "Dispatching single VEIL engine execution on bundled demo...";
    try {
      const start = await apiFetchJson("/api/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          mode: "demo",
          policy: $("policy-select").value,
          secret: secretVal,
          run_optional: true,
        }),
      });
      await pollJob(start.job_id, logEl);
    } catch (err) {
      hideProgress();
      setRunControlsBusy(false);
      setStatus("Error", "status-fail");
      if (logEl) logEl.textContent = `ERROR [${err.code || "error"}]: ${err.message}`;
    }
  }

  $("btn-quick-demo").addEventListener("click", () => dispatchDemoRun($("runner-log")));
  $("btn-run-demo").addEventListener("click", () => dispatchDemoRun($("runner-log")));
  $("btn-run-uploaded").addEventListener("click", () => dispatchUploadRun($("runner-log")));

  $("btn-cancel-job").addEventListener("click", async () => {
    const jid = state.activeJobId;
    if (!jid) return;
    try {
      await apiFetchJson(`/api/cancel/${encodeURIComponent(jid)}`, { method: "POST" });
    } catch {
      // pollJob handles terminal status
    }
  });

  $("btn-reconnect-job").addEventListener("click", () => {
    const jid = state.activeJobId || getSavedJobId();
    if (jid) pollJob(jid, $("runner-log"));
  });

  // Multiple-file Upload Dropzone (append + dedupe + remove + clear + limit checks)
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
    while (true) {
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
    $("staged-stats-text").textContent = `${items.length} / ${MAX_UPLOAD_FILES} files · ${fmtBytes(totalB)} / 16.00 MB`;
    listEl.innerHTML = items.map((f, idx) => `
      <div class="staged-item" data-idx="${idx}">
        <span class="mono">${esc(f.path)}${f.renamed ? ' <span class="badge badge-slate">renamed</span>' : ""}</span>
        <span class="staged-meta">
          <span class="muted">${fmtBytes(f.size)}</span>
          <button type="button" class="staged-rm" data-remove="${idx}" aria-label="Remove ${esc(f.path)}">×</button>
        </span>
      </div>`).join("");
    listEl.querySelectorAll("[data-remove]").forEach((btn) => {
      btn.disabled = state.isSubmitting;
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        if (state.isSubmitting) return;
        const ridx = Number(btn.dataset.remove);
        state.stagedFiles.splice(ridx, 1);
        clearValidationError();
        renderStagedList();
      });
    });
    $("btn-run-uploaded").disabled = state.isSubmitting || items.length === 0;
  }

  function stageFiles(fileList) {
    if (state.isSubmitting) return;
    const incoming = Array.from(fileList || []);
    if (!incoming.length) return;
    clearValidationError();

    if (state.stagedFiles.length + incoming.length > MAX_UPLOAD_FILES) {
      showValidationError(`File count limit exceeded (${state.stagedFiles.length + incoming.length} selected; max ${MAX_UPLOAD_FILES} files). Remove some files or split into batches.`);
      return;
    }

    let runningBytes = stagedTotalBytes();
    const usedLower = new Set(state.stagedFiles.map((f) => f.path.toLowerCase()));
    const toAppend = [];

    for (const f of incoming) {
      const orig = normalizeSafeRel(f.webkitRelativePath || f.name);
      if (!orig) {
        showValidationError(`Invalid or unsafe filename skipped: ${f.name}`);
        return;
      }
      if (runningBytes + f.size > MAX_UPLOAD_BYTES) {
        showValidationError(`Total upload size exceeds 16 MB limit (${fmtBytes(runningBytes + f.size)}). Remove files before adding more.`);
        return;
      }
      runningBytes += f.size;
      const { path, renamed } = dedupePath(orig, usedLower);
      toAppend.push({
        id: `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
        path,
        origPath: orig,
        renamed,
        size: f.size,
        file: f,
      });
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

  dz.addEventListener("click", () => { if (!state.isSubmitting) fi.click(); });
  dz.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      if (!state.isSubmitting) fi.click();
    }
  });
  dz.addEventListener("dragover", (e) => { e.preventDefault(); if (!state.isSubmitting) dz.classList.add("drag"); });
  dz.addEventListener("dragleave", () => dz.classList.remove("drag"));
  dz.addEventListener("drop", (e) => {
    e.preventDefault();
    dz.classList.remove("drag");
    if (!state.isSubmitting && e.dataTransfer?.files?.length) stageFiles(e.dataTransfer.files);
  });
  fi.addEventListener("change", () => {
    if (fi.files?.length) stageFiles(fi.files);
    fi.value = ""; // allow selecting the exact same file again cleanly
  });

  // Renderers
  function renderView(viewName, d) {
    state.renderedViews.add(viewName);
    if (viewName === "overview") {
      const rep = d.report;
      const pass = d.passport;
      const residue = Object.values(pass.privacy?.residual_pattern_hits || {}).reduce((a, b) => a + b, 0);
      renderOverview(d, rep, pass, residue);
    } else if (viewName === "inspector") {
      renderInspector(d);
    } else if (viewName === "graph") {
      renderGraph(d);
      renderDecisionsPage();
    } else if (viewName === "arena") {
      renderArena(d);
    } else if (viewName === "clinical") {
      renderClinical(d);
    } else if (viewName === "passport") {
      renderPassport(d);
    }
  }

  function renderAll(d) {
    state.data = d;
    state.renderedViews.clear();
    $("active-dataset-title").textContent = d.dataset_label || "Active Dataset";

    if (!d.ready) {
      setExportControlsReady(false, false);
      renderBenchmarks(d.historical_benchmarks);
      setStatus("Awaiting Dataset", "status-warn");
      const saved = getSavedJobId();
      if (saved) $("btn-reconnect-job").classList.remove("hidden");
      return;
    }

    setExportControlsReady(true, Boolean(d.corrupted_passport));
    const pass = d.passport || {};
    const isVerified = d.passport_status === "verified";
    const residue = Object.values(pass.privacy?.residual_pattern_hits || {}).reduce((a, b) => a + b, 0);
    const verdict = pass.verdict || (residue === 0 && !(pass.residual_risks || []).length ? "PASS" : "FAIL");
    if (d.corrupted_passport) {
      setStatus("Review Risks", "status-fail");
    } else if (!isVerified) {
      setStatus("Sanitized Ready · Audit Pending", "status-warn");
    } else if (verdict === "PASS" && residue === 0 && !(pass.residual_risks || []).length) {
      setStatus("Verified PASS", "status-ok");
    } else if (verdict === "WARNING" || verdict === "INCONCLUSIVE" || verdict === "SKIPPED") {
      setStatus(`Verified ${verdict}`, "status-warn");
    } else {
      setStatus("Review Risks", "status-fail");
    }

    renderTimingsLine(d.timings);
    renderView("overview", d);
    if (state.activeView !== "overview" && state.activeView !== "runner") {
      renderView(state.activeView, d);
    }
  }

  function renderBenchmarks(hb) {
    if (!hb) return;
    $("hist-checkpoint").textContent = hb.checkpoint;
    $("hist-disclaimer").textContent = hb.disclaimer;
    $("hist-table").innerHTML = `
      <thead><tr><th>Dataset</th><th>Classification</th><th>Est. Total (Local)</th><th>Truth Leak</th><th>False Merges</th><th>Canaries</th></tr></thead>
      <tbody>${hb.runs.map((r) => `
        <tr>
          <td class="mono">${esc(r.dataset)}</td>
          <td>${esc(r.type)}</td>
          <td class="mono"><strong>${esc(r.score)}</strong></td>
          <td class="mono">${esc(r.leak_pct)}</td>
          <td class="mono">${esc(r.false_merges)}</td>
          <td class="mono">${esc(r.canaries)}</td>
        </tr>`).join("")}</tbody>`;
    if (hb.scalability && $("scale-table")) {
      $("scale-table").innerHTML = `
        <thead><tr><th>Topology Workload</th><th>Records</th><th>Wall Time</th><th>Peak RSS</th><th>Throughput</th></tr></thead>
        <tbody>${hb.scalability.map((s) => `
          <tr>
            <td class="mono">${esc(s.workload)}</td>
            <td class="mono">${esc(s.records)}</td>
            <td class="mono">${esc(s.wall_s)}s</td>
            <td class="mono">${esc(s.peak_rss_mb)} MB</td>
            <td class="mono">${esc(s.throughput)}</td>
          </tr>`).join("")}</tbody>`;
    }
  }

  function renderOverview(d, rep, pass, residue) {
    const c = rep.counts;
    const isVerified = d.passport_status === "verified";
    const idReady = d.identity_status === "ready";
    const decCounts = d.identity_graph?.decision_counts || {};
    const vetoesText = idReady ? `${decCounts.rejected ?? 0} sampled vetoes` : "identity pending";
    const distinctPsns = isVerified ? pass.identity.distinct_pseudonyms : (d.identity_graph?.meta?.total_clusters || "--");
    const clinPct = pass.clinical?.protected_values_kept_pct;
    const clinVal = !isVerified ? "Pending" : (clinPct == null ? "N/A" : `${clinPct}%`);
    const clinSub = isVerified ? `Intervals ${pass.clinical.notes_with_intervals_preserved}` : "Run Passport Audit to measure";
    const verdictLabel = d.corrupted_passport ? "DEFECT INJECTED (FAIL)" : (isVerified ? `VERIFIED ${pass.verdict || "PASS"}` : "PENDING ON-DEMAND AUDIT");

    $("overview-kpis").innerHTML = [
      { label: "Files Processed", val: `${c.files_sanitized}/${c.files_total}`, sub: `${c.files_quarantined} fail-closed quarantined` },
      { label: "Residual Identifier Hits", val: isVerified ? `${residue}` : "Pending", sub: isVerified ? `Across ${pass.privacy.channels_scanned} channels` : "Run Privacy Passport to audit", warn: !isVerified || residue > 0 },
      { label: "Linked Records", val: `${c.records_linked}/${c.records_processed}`, sub: `Clusters: ${distinctPsns} · ${vetoesText}` },
      { label: "Clinical Probes Kept", val: clinVal, sub: clinSub, warn: !isVerified },
      { label: "Engine Runtime (1x)", val: `${d.runtime_s}s`, sub: `Total UI ${d.timings?.total_ui_s ?? d.runtime_s}s · RSS ${rep.resources?.peak_rss_mb ?? "--"} MB` },
    ].map((k) => `
      <div class="kpi-card">
        <div class="kpi-label">${esc(k.label)}</div>
        <div class="kpi-val">${esc(k.val)}</div>
        <div class="kpi-sub ${k.warn ? "warn" : ""}">${esc(k.sub)}</div>
      </div>`).join("");

    $("ov-runtime-badge").textContent = `Policy: ${d.policy_mode} (${d.engine_executions || 1}x run)`;
    $("ov-telemetry-table").innerHTML = `
      <table class="data-table">
        <tr><th>Run Timestamp</th><td class="mono">${esc(d.run_at)}</td></tr>
        <tr><th>Identifiers Detected</th><td class="mono">${c.identifiers_detected}</td></tr>
        <tr><th>Passport Verification Status</th><td class="mono">${esc(verdictLabel)}</td></tr>
        <tr><th>Engine vs Total UI Time</th><td class="mono">${d.runtime_s}s engine / ${d.timings?.total_ui_s ?? d.runtime_s}s total</td></tr>
        <tr><th>Table Row Counts Preserved</th><td class="mono">${esc(pass.structural?.tables_row_count_preserved ?? "Validated")}</td></tr>
        <tr><th>Historical Scale Benchmark</th><td class="mono">${esc(d.historical_benchmarks.scale.records)} in ${d.historical_benchmarks.scale.seconds}s (${d.historical_benchmarks.scale.peak_rss_mb} MB)</td></tr>
      </table>`;

    const tr = d.transformations || [];
    const maxT = Math.max(1, ...tr.map((x) => x.count));
    $("ov-id-total").textContent = `${tr.reduce((a, x) => a + x.count, 0)} sampled tags`;
    $("ov-transform-bars").innerHTML = tr.map((t) => `
      <div class="bar-row">
        <span class="mono">${esc(t.token)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${Math.round((100 * t.count) / maxT)}%"></div></div>
        <span class="mono">${t.count}</span>
      </div>`).join("") || `<div class="muted">No redaction tags found in previewed files.</div>`;

    renderBenchmarks(d.historical_benchmarks);
  }

  async function renderInspector(d) {
    const files = d.file_pairs || [];
    if (state.selectedFileIdx >= files.length) state.selectedFileIdx = 0;

    $("file-tabs").innerHTML = files.map((f, idx) => `
      <button class="file-pill ${idx === state.selectedFileIdx ? "active" : ""}" data-idx="${idx}">
        <span class="badge ${f.status === "quarantined" ? "badge-fail" : "badge-slate"}">${esc(f.format)}</span>
        <span class="mono">${esc(f.input_rel)}</span>
      </button>`).join("");

    document.querySelectorAll(".file-pill").forEach((el) => {
      el.addEventListener("click", () => {
        state.selectedFileIdx = Number(el.dataset.idx);
        renderInspector(state.data);
      });
    });

    const cur = files[state.selectedFileIdx];
    if (!cur) return;
    $("inspector-badges").innerHTML = `
      <span class="badge ${cur.status === "quarantined" ? "badge-fail" : "badge-ok"}">${esc(cur.status.toUpperCase())}${cur.reason ? " (" + esc(cur.reason) + ")" : ""}</span>
      <span class="badge badge-slate">SHA ${esc(cur.sha256_short)}</span>
      ${(cur.psns || []).map((p) => `<span class="badge badge-emerald mono">${esc(p)}</span>`).join("")}
    `;
    $("diff-in-meta").textContent = `${cur.input_rel} (${cur.bytes_in} B)`;
    $("diff-out-meta").textContent = cur.output_rel ? `${cur.output_rel} (${cur.bytes_out} B)` : "Not exported";

    const chips = [];
    for (const [tok, cnt] of Object.entries(cur.tag_counts || {})) {
      chips.push(`<div class="chip"><span class="tok-tag">${esc(tok)}</span> × <strong>${cnt}</strong></div>`);
    }
    for (const st of cur.staff_preserved || []) {
      chips.push(`<div class="chip"><span class="tok-staff">${esc(st)}</span> · Preserved Staff</div>`);
    }
    $("inspector-tag-detail").innerHTML = chips.join("") || `<div class="muted">No identifier tokens sampled in this file.</div>`;

    const reqIdx = state.selectedFileIdx;
    const reqJobId = d.job_id || "cur";
    const ckey = `${reqJobId}:${reqIdx}`;
    let diff = state.diffCache.get(ckey);
    if (!diff) {
      const reqToken = ++state.inspectorReqId;
      $("diff-input-pre").textContent = "Loading bounded file preview...";
      $("diff-output-pre").textContent = "Loading bounded sanitized preview...";
      try {
        diff = await apiFetchJson(`/api/diff?idx=${reqIdx}`);
        if (state.inspectorReqId !== reqToken || (state.data?.job_id || "cur") !== reqJobId || state.selectedFileIdx !== reqIdx) {
          return;
        }
        state.diffCache.set(ckey, diff);
      } catch (err) {
        if (state.inspectorReqId !== reqToken) return;
        $("diff-input-pre").textContent = `Preview unavailable: ${err.message}`;
        $("diff-output-pre").textContent = "";
        return;
      }
    }
    $("diff-input-pre").textContent = diff.input_text || "";
    $("diff-output-pre").innerHTML = highlightSanitized(diff.output_text || "");
  }

  function renderGraph(d) {
    const g = d.identity_graph || { clusters: [], records: [], edges: [], meta: {} };
    const meta = g.meta || {};
    const svg = $("identity-svg");

    if (d.identity_status !== "ready") {
      svg.setAttribute("viewBox", "0 0 980 430");
      $("graph-subset-badge").textContent = "Analysis pending (on-demand)";
      svg.innerHTML = `<text x="490" y="210" fill="#94a3b8" font-size="14" text-anchor="middle">Identity graph &amp; veto inspection runs on demand for fast uploads. Click "Analyze Identity Graph".</text>`;
      return;
    }

    const clusters = g.clusters || [];
    const recs = g.records || [];
    const edges = g.edges || [];
    const subsetLabel = meta.truncated
      ? `Showing ${meta.displayed_clusters} of ${meta.total_clusters} clusters · ${meta.displayed_records} of ${meta.total_records} records`
      : `${clusters.length} clusters · ${recs.length} records (100%)`;
    $("graph-subset-badge").textContent = subsetLabel;

    const W = Math.max(980, clusters.length * 140);
    const cCount = Math.max(1, clusters.length);
    const pos = {};
    const hubs = [];
    clusters.forEach((cl, i) => {
      const x = ((i + 0.5) * W) / cCount;
      const y = 92;
      pos[cl.id] = { x, y };
      hubs.push({ ...cl, x, y });
    });

    const byPsn = {};
    const unlinked = [];
    recs.forEach((r) => {
      if (r.psn && pos[r.psn]) {
        (byPsn[r.psn] = byPsn[r.psn] || []).push(r);
      } else {
        unlinked.push(r);
      }
    });

    const recNodes = [];
    clusters.forEach((cl) => {
      const list = byPsn[cl.id] || [];
      const cx = pos[cl.id].x;
      const span = Math.min(165, Math.max(70, list.length * 36));
      list.forEach((r, k) => {
        const dx = list.length === 1 ? 0 : -span / 2 + (k * span) / (list.length - 1);
        const y = 245 + (k % 2) * 58;
        pos[r.id] = { x: Math.max(54, Math.min(W - 54, cx + dx)), y };
        recNodes.push({ ...r, x: pos[r.id].x, y });
      });
    });

    const unlinkedCols = Math.max(1, Math.floor((W - 108) / 96));
    const unlinkedRows = Math.ceil(unlinked.length / unlinkedCols);
    const H = Math.max(430, 365 + unlinkedRows * 46);
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);

    unlinked.forEach((r, idx) => {
      const col = idx % unlinkedCols;
      const row = Math.floor(idx / unlinkedCols);
      const x = 60 + col * 96;
      const y = 365 + row * 44;
      pos[r.id] = { x, y };
      recNodes.push({ ...r, x, y });
    });

    const parts = [];
    recNodes.forEach((rn) => {
      if (rn.psn && pos[rn.psn]) {
        const hp = pos[rn.psn];
        parts.push(`<line x1="${hp.x}" y1="${hp.y + 22}" x2="${rn.x}" y2="${rn.y - 16}" stroke="#10b981" stroke-opacity="0.45" stroke-width="1.8"/>`);
      }
    });

    const recToPsn = {};
    recs.forEach((r) => { recToPsn[r.id] = r.psn; });
    const nonMatched = edges.filter((e) => e.decision !== "matched");
    nonMatched.forEach((e, idx) => {
      const ha = pos[recToPsn[e.source]] || pos[e.source];
      const hb = pos[recToPsn[e.target]] || pos[e.target];
      if (!ha || !hb) return;
      const midX = (ha.x + hb.x) / 2;
      const arcY = 26 + (idx % 2) * 16;
      const stroke = e.decision === "rejected" ? "#ef4444" : "#f59e0b";
      parts.push(`<path class="g-edge" data-idx="${idx}" d="M ${ha.x} ${ha.y - 22} Q ${midX} ${arcY} ${hb.x} ${hb.y - 22}" fill="none" stroke="${stroke}" stroke-width="2.2" stroke-dasharray="6 4" style="cursor:pointer"/>`);
      parts.push(`<text x="${midX}" y="${arcY + 8}" fill="${stroke}" font-size="10.5" font-weight="700" text-anchor="middle">${e.decision === "rejected" ? "VETO" : "HOLD"}</text>`);
    });

    recNodes.forEach((rn) => {
      const col = rn.psn ? "#38bdf8" : "#f59e0b";
      parts.push(`
        <g class="g-rec" data-id="${esc(rn.id)}" style="cursor:pointer">
          <rect x="${rn.x - 42}" y="${rn.y - 16}" width="84" height="32" rx="7" fill="#121c2e" stroke="${col}" stroke-width="1.3"/>
          <text x="${rn.x}" y="${rn.y - 1}" fill="#e2e8f0" font-size="10.5" font-weight="600" text-anchor="middle">${esc(rn.format)}</text>
          <text x="${rn.x}" y="${rn.y + 11}" fill="#94a3b8" font-size="9.2" font-family="monospace" text-anchor="middle">${esc(rn.loc)}</text>
        </g>`);
    });

    hubs.forEach((h) => {
      parts.push(`
        <g class="g-hub" data-psn="${esc(h.psn)}" style="cursor:pointer">
          <rect x="${h.x - 62}" y="${h.y - 24}" width="124" height="48" rx="10" fill="#0d2622" stroke="#10b981" stroke-width="2"/>
          <text x="${h.x}" y="${h.y - 3}" fill="#6ee7b7" font-size="11.5" font-family="monospace" font-weight="700" text-anchor="middle">${esc(h.psn)}</text>
          <text x="${h.x}" y="${h.y + 13}" fill="#cbd5e1" font-size="10" text-anchor="middle">${h.record_count} recs · Band ${esc(h.age_band)}</text>
        </g>`);
    });

    svg.innerHTML = parts.join("");
    svg.querySelectorAll(".g-hub").forEach((el) => {
      el.addEventListener("click", () => {
        const cl = clusters.find((c) => c.psn === el.dataset.psn);
        if (!cl) return;
        $("graph-detail-bar").innerHTML = `<strong>${esc(cl.psn)}</strong> · ${cl.record_count} linked fragments across <code>${esc(cl.files.join(", "))}</code> · Scripts: ${esc(cl.scripts.join("+"))} · QI Policy Rule: <span class="badge badge-emerald">${esc(cl.qi_reason)} (${cl.qi_band_years}y band, PIN ${esc(cl.qi_pin)}, District ${esc(cl.qi_district)})</span>`;
      });
    });
    svg.querySelectorAll(".g-rec").forEach((el) => {
      el.addEventListener("click", () => {
        const r = recs.find((x) => x.id === el.dataset.id);
        if (!r) return;
        $("graph-detail-bar").innerHTML = `Record <code>${esc(r.file)} (${esc(r.loc)})</code> · Assigned: <strong>${esc(r.psn || "Unlinked Reference")}</strong> · Format: ${esc(r.format)} · Scripts: ${esc(r.scripts.join(", "))} · Signals detected: ${esc(r.signals.join(", ") || "None")}`;
      });
    });
    svg.querySelectorAll(".g-edge").forEach((el) => {
      el.addEventListener("click", () => {
        const ed = nonMatched[Number(el.dataset.idx)];
        if (ed) $("graph-detail-bar").innerHTML = `<strong>${esc(ed.psn)}</strong> · ${esc(ed.veto)}`;
      });
    });
  }

  async function renderDecisionsPage() {
    document.querySelectorAll(".filter-pill").forEach((b) => {
      b.onclick = () => {
        document.querySelectorAll(".filter-pill").forEach((x) => x.classList.remove("active"));
        b.classList.add("active");
        state.decisionFilter = b.dataset.filter;
        state.decisionPage = 0;
        renderDecisionsPage();
      };
    });
    $("dec-prev").onclick = () => {
      if (state.decisionPage > 0) {
        state.decisionPage -= 1;
        renderDecisionsPage();
      }
    };
    $("dec-next").onclick = () => {
      state.decisionPage += 1;
      renderDecisionsPage();
    };

    const decReqToken = ++state.decisionsReqId;
    const targetJobId = state.data?.job_id;
    let res;
    try {
      res = await apiFetchJson(`/api/decisions?filter=${encodeURIComponent(state.decisionFilter)}&page=${state.decisionPage}&limit=${DECISIONS_PAGE_LIMIT}`);
    } catch (err) {
      if (state.decisionsReqId !== decReqToken) return;
      $("decisions-table").innerHTML = `<thead><tr><th>Decision</th><th>Channel A</th><th>Channel B</th><th>Scripts</th><th>Link / Cannot-Link Rationale (No Raw PII)</th></tr></thead><tbody><tr><td colspan="5" class="muted">Failed to load decisions: ${esc(err.message)}</td></tr></tbody>`;
      return;
    }
    if (state.decisionsReqId !== decReqToken || state.data?.job_id !== targetJobId) return;
    const list = res.items || [];
    const total = res.total_filtered || 0;
    const badgeCls = { matched: "badge-ok", rejected: "badge-fail", ambiguous: "badge-warn" };
    $("decisions-table").innerHTML = `
      <thead><tr><th>Decision</th><th>Channel A</th><th>Channel B</th><th>Scripts</th><th>Link / Cannot-Link Rationale (No Raw PII)</th></tr></thead>
      <tbody>${list.map((row) => `
        <tr>
          <td><span class="badge ${badgeCls[row.decision] || "badge-slate"}">${esc(row.decision.toUpperCase())}</span></td>
          <td class="mono">${esc(row.left)}</td>
          <td class="mono">${esc(row.right)}</td>
          <td>${esc((row.scripts || []).join(" ↔ "))}</td>
          <td>${esc(row.rule)}</td>
        </tr>`).join("") || `<tr><td colspan="5" class="muted">No decisions loaded (run Identity Analysis if pending).</td></tr>`}</tbody>`;
    const startIdx = total ? state.decisionPage * DECISIONS_PAGE_LIMIT + 1 : 0;
    const endIdx = Math.min(total, (state.decisionPage + 1) * DECISIONS_PAGE_LIMIT);
    $("dec-page-info").textContent = `Showing ${startIdx}–${endIdx} of ${total} (${res.decision_counts?.truncated ? "bounded sample" : "exact"})`;
    $("dec-prev").disabled = state.decisionPage === 0;
    $("dec-next").disabled = endIdx >= total;
  }

  $("btn-run-identity").addEventListener("click", async () => {
    if (!state.data?.ready) return;
    const targetJobId = state.data.job_id;
    const btn = $("btn-run-identity");
    btn.disabled = true;
    btn.textContent = "Analyzing...";
    try {
      const res = await apiFetchJson("/api/identity/run", { method: "POST" });
      if (state.data?.job_id !== targetJobId) return;
      state.data.identity_status = "ready";
      state.data.identity_graph = res.identity_graph;
      state.data.identity_decisions = res.identity_decisions;
      state.data.qi_stats = res.qi_stats;
      renderGraph(state.data);
      await renderDecisionsPage();
      renderView("overview", state.data);
    } catch (err) {
      alert(err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "Analyze Identity Graph";
    }
  });

  function renderArena(d) {
    const arena = d.privacy_arena || [];
    $("arena-status-badge").textContent = d.arena_status === "ready" ? "Measured Live" : "On-Demand (Not Auto-Run)";
    if (!arena.length) {
      $("arena-cards").innerHTML = `<div class="muted">Privacy Arena was not executed during single-pass sanitization. Click <strong>Run Privacy Arena (On-Demand)</strong> to compare Masking vs Fixed QI vs Adaptive (reusing your completed policy run when cached).</div>`;
      $("arena-table").innerHTML = "";
      return;
    }
    const fmtPct = (v) => (v == null ? "N/A" : `${v}%`);
    $("arena-cards").innerHTML = arena.map((a) => `
      <div class="arena-card ${a.mode === "adaptive" ? "winner" : ""}">
        <div class="card-head" style="margin-bottom:8px">
          <h3>${esc(a.label)}</h3>
          <span class="badge ${a.mode === "adaptive" ? "badge-emerald" : "badge-slate"}">${a.reused_from_active_run ? "Cached/Reused" : esc(a.mode)}</span>
        </div>
        <p class="card-sub" style="margin-bottom:10px">${esc(a.summary)}</p>
        <div class="meta-row"><span>Exact Ages Exposed</span><strong class="mono">${a.qi.exact_age_patients}</strong></div>
        <div class="meta-row"><span>6-Digit PINs Visible</span><strong class="mono">${a.exact_pins_visible}</strong></div>
        <div class="meta-row"><span>10-Yr Adaptive Escalations</span><strong class="mono">${a.qi.band_10y_patients}</strong></div>
        <div class="meta-row"><span>Districts Suppressed</span><strong class="mono">${a.qi.district_dropped_patients}</strong></div>
        <div class="meta-row"><span>Clinical Values Kept</span><strong class="mono">${fmtPct(a.clinical_kept_pct)}</strong></div>
      </div>`).join("");

    $("arena-table").innerHTML = `
      <thead><tr><th>Policy</th><th>Exact Ages Left</th><th>PINs Visible</th><th>10y Wide Bands</th><th>Districts Dropped</th><th>Residual Hits</th><th>Clinical Kept</th><th>Runtime</th></tr></thead>
      <tbody>${arena.map((a) => `
        <tr>
          <td><strong>${esc(a.label)}</strong></td>
          <td class="mono">${a.qi.exact_age_patients}</td>
          <td class="mono">${a.exact_pins_visible}</td>
          <td class="mono">${a.qi.band_10y_patients}</td>
          <td class="mono">${a.qi.district_dropped_patients}</td>
          <td class="mono">${a.residual_hits}</td>
          <td class="mono">${fmtPct(a.clinical_kept_pct)}</td>
          <td class="mono">${a.runtime_s}s${a.reused_from_active_run ? " (reused)" : ""}</td>
        </tr>`).join("")}</tbody>`;
  }

  $("btn-run-arena").addEventListener("click", async () => {
    if (!state.data?.ready) return;
    const targetJobId = state.data.job_id;
    const btn = $("btn-run-arena");
    btn.disabled = true;
    btn.textContent = "Benchmarking...";
    try {
      const res = await apiFetchJson("/api/arena/run", { method: "POST" });
      if (state.data?.job_id !== targetJobId) return;
      state.data.arena_status = "ready";
      state.data.privacy_arena = res.privacy_arena;
      renderArena(state.data);
    } catch (err) {
      alert(err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "Run Privacy Arena (On-Demand)";
    }
  });

  function renderClinical(d) {
    const pass = d.passport || {};
    const det = d.clinical_detail || {};
    const isVerified = d.passport_status === "verified";
    const clinPct = pass.clinical?.protected_values_kept_pct;
    $("los-badge").textContent = `Intervals Kept: ${pass.clinical?.notes_with_intervals_preserved ?? "Pending"}`;
    $("clin-pct-badge").textContent = !isVerified ? "Audit Pending" : (clinPct == null ? "N/A (0 probes)" : `${clinPct}% Kept`);

    const tl = det.timeline_intervals || [];
    $("timeline-cards").innerHTML = tl.map((t) => `
      <div class="timeline-card">
        <div class="meta-row">
          <span class="mono"><strong>${esc(t.file)}</strong> -> ${esc(t.output_file)}</span>
          <span class="badge ${t.preserved ? "badge-ok" : "badge-fail"}">LOS Delta: ${t.los_delta_days} days</span>
        </div>
        <div class="card-sub">
          Input window: <code>${esc(t.input_dates[0])} -> ${esc(t.input_dates[t.input_dates.length - 1])}</code> (${t.input_los_days}d)
          &nbsp;|&nbsp; Shifted (+${t.patient_shift_days}d): <code>${esc(t.output_dates[0])} -> ${esc(t.output_dates[t.output_dates.length - 1])}</code> (${t.output_los_days}d)
        </div>
      </div>`).join("") || `<div class="muted">No multi-date clinical notes sampled in preview.</div>`;

    const pv = pass.clinical?.protected_values || {};
    $("clinical-categories").innerHTML = Object.entries(pv).map(([cat, ratio]) => {
      const [num, den] = ratio.split("/").map(Number);
      const pct = den ? Math.round((100 * num) / den) : 100;
      return `
        <div class="bar-row">
          <span>${esc(cat)}</span>
          <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
          <span class="mono">${esc(ratio)}</span>
        </div>`;
    }).join("") || `<div class="muted">Run Privacy Passport to compute full clinical occurrence preservation.</div>`;

    $("staff-chips").innerHTML = (det.staff_preserved || []).map((s) => `<div class="chip tok-staff">${esc(s)}</div>`).join("") || `<div class="muted">None detected in preview</div>`;

    $("clinical-samples-table").innerHTML = `
      <thead><tr><th>Category</th><th>Channel</th><th>Extracted Clinical Expression</th><th>Status</th></tr></thead>
      <tbody>${(det.samples || []).map((s) => `
        <tr>
          <td>${esc(s.category)}</td>
          <td class="mono">${esc(s.file)}</td>
          <td class="mono">${esc(s.value)}</td>
          <td><span class="badge ${s.preserved ? "badge-ok" : "badge-fail"}">${s.preserved ? "Preserved Verbatim" : "Missing"}</span></td>
        </tr>`).join("")}</tbody>`;
  }

  function renderPassport(d) {
    const corr = d.corrupted_passport;
    const isVerified = d.passport_status === "verified";
    const activeAudit = corr ? corr.audit : (d.passport || {});
    const risks = activeAudit.residual_risks || [];
    const verdict = activeAudit.verdict || (risks.length === 0 ? "PASS" : "FAIL");
    const clinPct = activeAudit.clinical?.protected_values_kept_pct;
    const clinSummary = clinPct == null ? "no clinical probes matched" : `${clinPct}% protected clinical expressions preserved`;

    $("btn-repair-demo").classList.toggle("hidden", !corr);
    setExportControlsReady(Boolean(d.ready), Boolean(corr));
    const banner = $("passport-banner");
    if (!isVerified && !corr) {
      banner.className = "passport-banner pending";
      banner.textContent = "VERIFICATION PENDING: Mandatory engine output contract is validated and downloadable, while deep Privacy Passport audit runs on demand. Click 'Verify Privacy Passport' to execute full residue & clinical occurrence checks.";
    } else if (corr) {
      banner.className = "passport-banner fail";
      banner.innerHTML = `SYNTHETIC DEFECT CAUGHT IN <code>${esc(corr.target_file)}</code>: ${esc(corr.mutation)} Alerts: ${esc(risks.join(" | "))}`;
    } else if (verdict === "PASS" && risks.length === 0) {
      banner.className = "passport-banner ok";
      banner.textContent = `RELEASE AUDIT PASSED: 0 residual identifier hits across ${activeAudit.privacy.channels_scanned} channels · ${clinSummary} · ${activeAudit.structural.exported}/${activeAudit.structural.input_files} sanitized (${activeAudit.structural.quarantined} quarantined).`;
    } else if (verdict === "WARNING" || verdict === "INCONCLUSIVE" || verdict === "SKIPPED") {
      banner.className = "passport-banner pending";
      banner.textContent = `AUDIT ${verdict}: ${activeAudit.privacy.channels_scanned} channels scanned · ${clinSummary}${risks.length ? " · Notes: " + risks.join(" | ") : ""}`;
    } else {
      banner.className = "passport-banner fail";
      banner.textContent = `REVIEW REQUIRED (${verdict}): ${risks.join(" | ")}`;
    }

    const checks = activeAudit.checks || {};
    const statusBadge = (s) => s === "PASS" ? "badge-ok" : (s === "FAIL" ? "badge-fail" : (s === "WARNING" || s === "PENDING" ? "badge-warn" : "badge-slate"));
    $("passport-checks").innerHTML = Object.entries(checks).map(([name, c]) => `
      <div class="kpi-card">
        <div class="meta-row"><span class="kpi-label">${esc(name)}</span><span class="badge ${statusBadge(c.status)}">${esc(c.status)}</span></div>
        <div class="kpi-val" style="font-size:19px">${esc(c.coverage)}</div>
        <div class="kpi-sub">${esc(c.detail)}</div>
      </div>`).join("");

    const pillars = [
      ["A · Privacy Residue", activeAudit.privacy || {}],
      ["B · Clinical Occurrences", activeAudit.clinical || {}],
      ["C · Temporal & FHIR", activeAudit.temporal || {}],
      ["D · Record-Level Identity", activeAudit.identity || {}],
      ["E · Structural Integrity", activeAudit.structural || {}],
    ];
    $("passport-pillars").innerHTML = pillars.map(([title, obj]) => `
      <div class="pillar-card">
        <h3>${esc(title)}</h3>
        <table class="data-table">
          ${Object.entries(obj).map(([k, v]) => `<tr><th>${esc(k.replace(/_/g, " "))}</th><td class="mono">${esc(typeof v === "object" ? JSON.stringify(v) : v)}</td></tr>`).join("")}
        </table>
      </div>`).join("");

    const hist = d.verification_history || [];
    $("passport-history-table").innerHTML = `
      <thead><tr><th>Time</th><th>Event</th><th>State</th><th>Details</th></tr></thead>
      <tbody>${hist.map((h) => `
        <tr>
          <td class="mono">${esc(h.timestamp)}</td>
          <td><strong>${esc(h.event)}</strong></td>
          <td><span class="badge ${statusBadge(h.status)}">${esc(h.status)}</span></td>
          <td>${esc(h.summary)}</td>
        </tr>`).join("")}</tbody>`;
  }

  $("btn-run-passport").addEventListener("click", async () => {
    if (!state.data?.ready) return;
    const targetJobId = state.data.job_id;
    const btn = $("btn-run-passport");
    btn.disabled = true;
    btn.textContent = "Verifying...";
    try {
      const res = await apiFetchJson("/api/passport/run", { method: "POST" });
      if (state.data?.job_id !== targetJobId) return;
      state.data.passport_status = "verified";
      state.data.passport = res.passport;
      state.data.corrupted_passport = null;
      if (res.timings) state.data.timings = res.timings;
      if (res.verification_history) state.data.verification_history = res.verification_history;
      renderAll(state.data);
      renderPassport(state.data);
    } catch (err) {
      alert(err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "Verify Privacy Passport";
    }
  });

  $("btn-corrupt-demo").addEventListener("click", async () => {
    if (!state.data?.ready) return;
    const targetJobId = state.data.job_id;
    const btn = $("btn-corrupt-demo");
    btn.disabled = true;
    try {
      setStatus("Testing Defect Detection...", "status-warn");
      const res = await apiFetchJson("/api/passport/corrupt", { method: "POST" });
      if (state.data?.job_id !== targetJobId) return;
      state.data.corrupted_passport = res.corrupted_passport;
      if (res.verification_history) state.data.verification_history = res.verification_history;
      renderPassport(state.data);
      setStatus("Defect Caught!", "status-fail");
    } catch (err) {
      alert(err.message);
    } finally {
      btn.disabled = false;
    }
  });

  $("btn-repair-demo").addEventListener("click", async () => {
    if (!state.data?.ready) return;
    const targetJobId = state.data.job_id;
    const btn = $("btn-repair-demo");
    btn.disabled = true;
    try {
      setStatus("Repairing Release...", "status-warn");
      const res = await apiFetchJson("/api/passport/repair", { method: "POST" });
      if (state.data?.job_id !== targetJobId) return;
      state.diffCache.clear();
      await loadState();
      if (state.activeView === "passport" && state.data) {
        renderPassport(state.data);
      }
    } catch (err) {
      alert(err.message);
    } finally {
      btn.disabled = false;
    }
  });

  async function loadState() {
    const data = await apiFetchJson("/api/state");
    renderAll(data);
    // Automatically resume an in-flight job if page reloaded during execution
    const runJid = data.running_job_id || data.active_job_id;
    if (runJid) {
      try {
        const st = await apiFetchJson(`/api/status/${encodeURIComponent(runJid)}`);
        if (["uploading", "queued", "running", "validating"].includes(st.status)) {
          pollJob(runJid, $("runner-log"));
        }
      } catch {
        // ignore
      }
    }
  }

  loadState().catch((e) => {
    $("active-dataset-title").textContent = `Server connection error: ${e.message}`;
  });
})();
