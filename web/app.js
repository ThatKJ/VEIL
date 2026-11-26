(() => {
  const state = {
    data: null,
    selectedFileIdx: 0,
    decisionFilter: "all",
    stagedFiles: [],
    activePoll: null,
  };

  const $ = (id) => document.getElementById(id);

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function highlightSanitized(text) {
    let out = esc(text);
    out = out.replace(/\[(NAME|RELATIVE|PHONE|AADHAAR|ABHA|PAN|EMAIL|ID|INSURANCE|PIN|VILLAGE|DISTRICT|DATE|AGE|REDACTED)\]/g, '<span class="tok-tag">[$1]</span>');
    out = out.replace(/\bPSN-[0-9A-Z]{6}\b/g, '<span class="tok-psn">$&</span>');
    out = out.replace(/\b(?:Dr\.|N\/O|DEO)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}/g, '<span class="tok-staff">$&</span>');
    return out;
  }

  // Navigation
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.view;
      document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
      $(`view-${target}`).classList.add("active");
    });
  });

  async function apiJson(url, opts = {}) {
    const res = await fetch(url, opts);
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  function setStatus(label, cls = "status-ok") {
    const el = $("status-pill");
    el.textContent = label;
    el.className = `status-pill ${cls}`;
  }

  function showProgress(pct, stage) {
    $("progress-panel").classList.remove("hidden");
    $("progress-pct").textContent = `${pct}%`;
    $("progress-stage").textContent = stage;
    $("progress-fill").style.width = `${pct}%`;
  }

  function hideProgress() {
    $("progress-panel").classList.add("hidden");
  }

  async function launchRun(body, logEl) {
    try {
      setStatus("Executing VEIL...", "status-warn");
      showProgress(5, "Starting VEIL job");
      if (logEl) logEl.textContent = "Dispatching VEIL subprocess...";
      const start = await apiJson("/api/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const jobId = start.job_id;
      while (true) {
        const st = await apiJson(`/api/status/${jobId}`);
        showProgress(st.progress || 0, st.stage || "Running");
        if (logEl) logEl.textContent = `[${st.progress}%] ${st.stage}`;
        if (st.status === "completed") {
          hideProgress();
          await loadState();
          setStatus("Verified PASS", "status-ok");
          if (logEl) logEl.textContent = "Completed pipeline + Privacy Passport + 3-policy Arena.";
          break;
        }
        if (st.status === "failed") {
          hideProgress();
          setStatus("Run Failed", "status-fail");
          if (logEl) logEl.textContent = `ERROR: ${st.error || "Unknown error"}`;
          break;
        }
        await new Promise((r) => setTimeout(r, 150));
      }
    } catch (err) {
      hideProgress();
      setStatus("Error", "status-fail");
      if (logEl) logEl.textContent = `ERROR: ${err.message}`;
    }
  }

  $("btn-quick-demo").addEventListener("click", () => {
    launchRun({ mode: "demo", policy: $("policy-select").value, secret: $("secret-input").value }, $("runner-log"));
  });
  $("btn-run-demo").addEventListener("click", () => {
    launchRun({ mode: "demo", policy: $("policy-select").value, secret: $("secret-input").value }, $("runner-log"));
  });

  // Upload Dropzone
  const dz = $("dropzone");
  const fi = $("file-input");

  function readFileAsBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const dataUrl = String(reader.result || "");
        resolve(dataUrl.includes(",") ? dataUrl.split(",", 2)[1] : "");
      };
      reader.onerror = () => reject(new Error(`Failed reading ${file.name}`));
      reader.readAsDataURL(file);
    });
  }

  async function stageFiles(fileList) {
    const items = [];
    for (const f of Array.from(fileList)) {
      const b64 = await readFileAsBase64(f);
      items.push({ path: f.webkitRelativePath || f.name, size: f.size, content_b64: b64 });
    }
    state.stagedFiles = items;
    $("staged-files-list").innerHTML = items.map((f) =>
      `<div class="staged-item"><span class="mono">${esc(f.path)}</span><span class="muted">${(f.size / 1024).toFixed(1)} KB</span></div>`
    ).join("");
    $("btn-run-uploaded").disabled = items.length === 0;
  }

  dz.addEventListener("click", () => fi.click());
  dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("drag"); });
  dz.addEventListener("dragleave", () => dz.classList.remove("drag"));
  dz.addEventListener("drop", (e) => {
    e.preventDefault();
    dz.classList.remove("drag");
    if (e.dataTransfer?.files?.length) stageFiles(e.dataTransfer.files);
  });
  fi.addEventListener("change", () => { if (fi.files?.length) stageFiles(fi.files); });

  $("btn-run-uploaded").addEventListener("click", () => {
    if (!state.stagedFiles.length) return;
    launchRun(
      {
        mode: "upload",
        label: `Uploaded Synthetic Dataset (${state.stagedFiles.length} files)`,
        policy: $("policy-select").value,
        secret: $("secret-input").value,
        files: state.stagedFiles.map(({ path, content_b64 }) => ({ path, content_b64 })),
      },
      $("runner-log")
    );
  });

  // Renderers
  function renderAll(d) {
    state.data = d;
    $("active-dataset-title").textContent = d.dataset_label || "Active Dataset";

    if (!d.ready) {
      renderBenchmarks(d.historical_benchmarks);
      setStatus("Awaiting Dataset", "status-warn");
      return;
    }

    const rep = d.report;
    const pass = d.passport;
    const residue = Object.values(pass.privacy.residual_pattern_hits || {}).reduce((a, b) => a + b, 0);
    setStatus(residue === 0 && !d.corrupted_passport ? "Passport PASS" : "Review Risks", residue === 0 ? "status-ok" : "status-warn");

    renderOverview(d, rep, pass, residue);
    renderInspector(d);
    renderGraph(d);
    renderDecisions(d);
    renderArena(d);
    renderClinical(d);
    renderPassport(d);
  }

  function renderBenchmarks(hb) {
    if (!hb) return;
    $("hist-checkpoint").textContent = hb.checkpoint;
    $("hist-disclaimer").textContent = hb.disclaimer;
    const rows = hb.runs.map((r) => `
      <tr>
        <td class="mono">${esc(r.dataset)}</td>
        <td>${esc(r.type)}</td>
        <td class="mono"><strong>${esc(r.score)}</strong></td>
        <td class="mono">${esc(r.leak_pct)}</td>
        <td class="mono">${esc(r.false_merges)}</td>
        <td class="mono">${esc(r.canaries)}</td>
      </tr>`).join("");
    $("hist-table").innerHTML = `
      <thead><tr><th>Dataset</th><th>Classification</th><th>Est. Total (Local)</th><th>Truth Leak</th><th>False Merges</th><th>Canaries</th></tr></thead>
      <tbody>${rows}</tbody>`;
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
    const vetoes = (d.identity_decisions || []).filter((x) => x.decision === "rejected").length;
    $("overview-kpis").innerHTML = [
      { label: "Files Processed", val: `${c.files_sanitized}/${c.files_total}`, sub: `${c.files_quarantined} fail-closed quarantined` },
      { label: "Residual Identifier Hits", val: `${residue}`, sub: `Across ${pass.privacy.channels_scanned} channels`, warn: residue > 0 },
      { label: "Patient Clusters (PSN)", val: `${pass.identity.distinct_pseudonyms}`, sub: `${c.records_linked}/${c.records_processed} linked · ${vetoes} veto splits` },
      { label: "Clinical Probes Kept", val: `${pass.clinical.protected_values_kept_pct}%`, sub: `Temporal intervals ${pass.clinical.notes_with_intervals_preserved}` },
      { label: "Execution Latency", val: `${d.runtime_s}s`, sub: `Peak RSS ${rep.resources?.peak_rss_mb ?? "--"} MB` },
    ].map((k) => `
      <div class="kpi-card">
        <div class="kpi-label">${esc(k.label)}</div>
        <div class="kpi-val">${esc(k.val)}</div>
        <div class="kpi-sub ${k.warn ? "warn" : ""}">${esc(k.sub)}</div>
      </div>`).join("");

    $("ov-runtime-badge").textContent = `Policy: ${d.policy_mode}`;
    $("ov-telemetry-table").innerHTML = `
      <table class="data-table">
        <tr><th>Run Timestamp</th><td class="mono">${esc(d.run_at)}</td></tr>
        <tr><th>Identifiers Detected</th><td class="mono">${c.identifiers_detected}</td></tr>
        <tr><th>Pseudonyms Placed in Output</th><td class="mono">${esc(pass.identity.pseudonym_present_in_exported_file)}</td></tr>
        <tr><th>Table Row Counts Preserved</th><td class="mono">${esc(pass.structural.tables_row_count_preserved)}</td></tr>
        <tr><th>Format Parse Verification</th><td class="mono">${pass.structural.outputs_parse_ok} OK / ${pass.structural.outputs_parse_fail} fail</td></tr>
        <tr><th>Scale Proven Benchmark</th><td class="mono">${esc(d.historical_benchmarks.scale.records)} in ${d.historical_benchmarks.scale.seconds}s (${d.historical_benchmarks.scale.peak_rss_mb} MB)</td></tr>
      </table>`;

    const tr = d.transformations || [];
    const maxT = Math.max(1, ...tr.map((x) => x.count));
    $("ov-id-total").textContent = `${tr.reduce((a, x) => a + x.count, 0)} masked placeholders`;
    $("ov-transform-bars").innerHTML = tr.map((t) => `
      <div class="bar-row">
        <span class="mono">${esc(t.token)}</span>
        <div class="bar-track"><div class="bar-fill" style="width:${Math.round((100 * t.count) / maxT)}%"></div></div>
        <span class="mono">${t.count}</span>
      </div>`).join("") || `<div class="muted">No redaction tags found.</div>`;

    renderBenchmarks(d.historical_benchmarks);
  }

  function renderInspector(d) {
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
      ${cur.psns.map((p) => `<span class="badge badge-emerald mono">${esc(p)}</span>`).join("")}
    `;
    $("diff-in-meta").textContent = `${cur.input_rel} (${cur.bytes_in} B)`;
    $("diff-out-meta").textContent = cur.output_rel ? `${cur.output_rel} (${cur.bytes_out} B)` : "Not exported";
    $("diff-input-pre").textContent = cur.input_text;
    $("diff-output-pre").innerHTML = highlightSanitized(cur.output_text);

    const chips = [];
    for (const [tok, cnt] of Object.entries(cur.tag_counts || {})) {
      chips.push(`<div class="chip"><span class="tok-tag">${esc(tok)}</span> × <strong>${cnt}</strong></div>`);
    }
    for (const st of cur.staff_preserved || []) {
      chips.push(`<div class="chip"><span class="tok-staff">${esc(st)}</span> · Preserved Staff</div>`);
    }
    $("inspector-tag-detail").innerHTML = chips.join("") || `<div class="muted">No identifier tokens in this file (clean reference or quarantined payload).</div>`;
  }

  function renderGraph(d) {
    const g = d.identity_graph || { clusters: [], records: [], edges: [] };
    const svg = $("identity-svg");
    const clusters = g.clusters || [];
    const recs = g.records || [];
    const edges = g.edges || [];

    const W = 980, H = 420;
    const cCount = Math.max(1, clusters.length);
    const pos = {};
    const hubs = [];
    clusters.forEach((cl, i) => {
      const x = ((i + 0.5) * W) / cCount;
      const y = 92;
      pos[cl.id] = { x, y };
      hubs.push({ ...cl, x, y });
    });

    // Layout child records fanned underneath their PSN hub
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

    unlinked.forEach((r, idx) => {
      pos[r.id] = { x: W - 95 - idx * 80, y: 365 };
      recNodes.push({ ...r, x: pos[r.id].x, y: pos[r.id].y });
    });

    const parts = [];
    // Draw hub-to-record containment links
    recNodes.forEach((rn) => {
      if (rn.psn && pos[rn.psn]) {
        const hp = pos[rn.psn];
        parts.push(`<line x1="${hp.x}" y1="${hp.y + 22}" x2="${rn.x}" y2="${rn.y - 16}" stroke="#10b981" stroke-opacity="0.45" stroke-width="1.8"/>`);
      }
    });

    // Draw veto/ambiguous edges between hubs (using rep record -> resolve to hub coordinates!)
    const recToPsn = {};
    recs.forEach((r) => { recToPsn[r.id] = r.psn; });
    edges.filter((e) => e.decision !== "matched").forEach((e, idx) => {
      const ha = pos[recToPsn[e.source]] || pos[e.source];
      const hb = pos[recToPsn[e.target]] || pos[e.target];
      if (!ha || !hb) return;
      const midX = (ha.x + hb.x) / 2;
      const arcY = 26 + (idx % 2) * 16;
      const stroke = e.decision === "rejected" ? "#ef4444" : "#f59e0b";
      parts.push(
        `<path class="g-edge" data-idx="${idx}" d="M ${ha.x} ${ha.y - 22} Q ${midX} ${arcY} ${hb.x} ${hb.y - 22}" fill="none" stroke="${stroke}" stroke-width="2.2" stroke-dasharray="6 4" style="cursor:pointer"/>`
      );
      parts.push(`<text x="${midX}" y="${arcY + 8}" fill="${stroke}" font-size="10.5" font-weight="700" text-anchor="middle">${e.decision === "rejected" ? "VETO" : "HOLD"}</text>`);
    });

    // Record nodes
    recNodes.forEach((rn) => {
      const col = rn.psn ? "#38bdf8" : "#f59e0b";
      parts.push(`
        <g class="g-rec" data-id="${esc(rn.id)}" style="cursor:pointer">
          <rect x="${rn.x - 42}" y="${rn.y - 16}" width="84" height="32" rx="7" fill="#121c2e" stroke="${col}" stroke-width="1.3"/>
          <text x="${rn.x}" y="${rn.y - 1}" fill="#e2e8f0" font-size="10.5" font-weight="600" text-anchor="middle">${esc(rn.format)}</text>
          <text x="${rn.x}" y="${rn.y + 11}" fill="#94a3b8" font-size="9.2" font-family="monospace" text-anchor="middle">${esc(rn.loc)}</text>
        </g>`);
    });

    // Cluster Hubs
    hubs.forEach((h) => {
      parts.push(`
        <g class="g-hub" data-psn="${esc(h.psn)}" style="cursor:pointer">
          <rect x="${h.x - 62}" y="${h.y - 24}" width="124" height="48" rx="10" fill="#0d2622" stroke="#10b981" stroke-width="2"/>
          <text x="${h.x}" y="${h.y - 3}" fill="#6ee7b7" font-size="12" font-family="monospace" font-weight="700" text-anchor="middle">${esc(h.psn)}</text>
          <text x="${h.x}" y="${h.y + 13}" fill="#cbd5e1" font-size="10" text-anchor="middle">${h.record_count} recs · Band ${esc(h.age_band)}</text>
        </g>`);
    });

    svg.innerHTML = parts.join("");

    const nonMatched = edges.filter((e) => e.decision !== "matched");
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

  function renderDecisions(d) {
    document.querySelectorAll(".filter-pill").forEach((b) => {
      b.onclick = () => {
        document.querySelectorAll(".filter-pill").forEach((x) => x.classList.remove("active"));
        b.classList.add("active");
        state.decisionFilter = b.dataset.filter;
        renderDecisions(state.data);
      };
    });

    const list = (d.identity_decisions || []).filter(
      (x) => state.decisionFilter === "all" || x.decision === state.decisionFilter
    );
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
        </tr>`).join("")}</tbody>`;
  }

  function renderArena(d) {
    const arena = d.privacy_arena || [];
    $("arena-cards").innerHTML = arena.map((a) => `
      <div class="arena-card ${a.mode === "adaptive" ? "winner" : ""}">
        <div class="card-head" style="margin-bottom:8px">
          <h3>${esc(a.label)}</h3>
          <span class="badge ${a.mode === "adaptive" ? "badge-emerald" : "badge-slate"}">${a.mode === "adaptive" ? "Recommended" : esc(a.mode)}</span>
        </div>
        <p class="card-sub" style="margin-bottom:10px">${esc(a.summary)}</p>
        <div class="meta-row"><span>Exact Ages Exposed</span><strong class="mono">${a.qi.exact_age_patients}</strong></div>
        <div class="meta-row"><span>6-Digit PINs Visible</span><strong class="mono">${a.exact_pins_visible}</strong></div>
        <div class="meta-row"><span>10-Yr Adaptive Escalations</span><strong class="mono">${a.qi.band_10y_patients}</strong></div>
        <div class="meta-row"><span>Districts Suppressed</span><strong class="mono">${a.qi.district_dropped_patients}</strong></div>
        <div class="meta-row"><span>Clinical Values Kept</span><strong class="mono">${a.clinical_kept_pct}%</strong></div>
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
          <td class="mono">${a.clinical_kept_pct}%</td>
          <td class="mono">${a.runtime_s}s</td>
        </tr>`).join("")}</tbody>`;
  }

  function renderClinical(d) {
    const pass = d.passport;
    const det = d.clinical_detail || {};
    $("los-badge").textContent = `Intervals Kept: ${pass.clinical.notes_with_intervals_preserved}`;
    $("clin-pct-badge").textContent = `${pass.clinical.protected_values_kept_pct}% Kept`;

    const tl = det.timeline_intervals || [];
    $("timeline-cards").innerHTML = tl.map((t) => `
      <div class="timeline-card">
        <div class="meta-row">
          <span class="mono"><strong>${esc(t.file)}</strong> -> ${esc(t.output_file)}</span>
          <span class="badge ${t.preserved ? "badge-ok" : "badge-fail"}">LOS Delta: ${t.los_delta_days} days</span>
        </div>
        <div class="card-sub">
          Input window: <code>${esc(t.input_dates[0])} -> ${esc(t.input_dates[1])}</code> (${t.input_los_days}d)
          &nbsp;|&nbsp; Shifted (+${t.patient_shift_days}d): <code>${esc(t.output_dates[0])} -> ${esc(t.output_dates[1])}</code> (${t.output_los_days}d)
        </div>
      </div>`).join("") || `<div class="muted">No multi-date clinical notes detected in current dataset.</div>`;

    const pv = pass.clinical.protected_values || {};
    $("clinical-categories").innerHTML = Object.entries(pv).map(([cat, ratio]) => {
      const [num, den] = ratio.split("/").map(Number);
      const pct = den ? Math.round((100 * num) / den) : 100;
      return `
        <div class="bar-row">
          <span>${esc(cat)}</span>
          <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
          <span class="mono">${esc(ratio)}</span>
        </div>`;
    }).join("");

    $("staff-chips").innerHTML = (det.staff_preserved || []).map((s) => `<div class="chip tok-staff">${esc(s)}</div>`).join("") || `<div class="muted">None detected</div>`;

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
    const activeAudit = corr ? corr.audit : d.passport;
    const risks = activeAudit.residual_risks || [];
    const isClean = risks.length === 0;

    $("btn-repair-demo").classList.toggle("hidden", !corr);
    const banner = $("passport-banner");
    banner.className = `passport-banner ${isClean && !corr ? "ok" : "fail"}`;
    banner.innerHTML = corr
      ? `SYNTHETIC DEFECT CAUGHT IN <code>${esc(corr.target_file)}</code>: ${esc(corr.mutation)} Alerts: ${esc(risks.join(" | "))}`
      : isClean
        ? `RELEASE AUDIT PASSED: 0 residual identifier hits across ${activeAudit.privacy.channels_scanned} channels · ${activeAudit.clinical.protected_values_kept_pct}% protected clinical expressions preserved · ${activeAudit.structural.exported}/${activeAudit.structural.input_files} sanitized (${activeAudit.structural.quarantined} quarantined).`
        : `REVIEW REQUIRED: ${esc(risks.join(" | "))}`;

    const checks = activeAudit.checks || {};
    const statusBadge = (s) => s === "PASS" ? "badge-ok" : (s === "FAIL" ? "badge-fail" : (s === "WARNING" ? "badge-warn" : "badge-slate"));
    $("passport-checks").innerHTML = Object.entries(checks).map(([name, c]) => `
      <div class="kpi-card">
        <div class="meta-row"><span class="kpi-label">${esc(name)}</span><span class="badge ${statusBadge(c.status)}">${esc(c.status)}</span></div>
        <div class="kpi-val" style="font-size:19px">${esc(c.coverage)}</div>
        <div class="kpi-sub">${esc(c.detail)}</div>
      </div>`).join("");

    const pillars = [
      ["A · Privacy Residue", activeAudit.privacy],
      ["B · Clinical Occurrences", activeAudit.clinical],
      ["C · Temporal & FHIR", activeAudit.temporal || {}],
      ["D · Record-Level Identity", activeAudit.identity],
      ["E · Structural Integrity", activeAudit.structural],
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

  $("btn-corrupt-demo").addEventListener("click", async () => {
    try {
      setStatus("Testing Defect Detection...", "status-warn");
      const res = await apiJson("/api/passport/corrupt", { method: "POST" });
      state.data.corrupted_passport = res.corrupted_passport;
      if (res.verification_history) state.data.verification_history = res.verification_history;
      renderPassport(state.data);
      setStatus("Defect Caught!", "status-fail");
    } catch (err) {
      alert(err.message);
    }
  });

  $("btn-repair-demo").addEventListener("click", async () => {
    try {
      setStatus("Repairing Release...", "status-warn");
      const res = await apiJson("/api/passport/repair", { method: "POST" });
      state.data.corrupted_passport = null;
      state.data.passport = res.passport;
      if (res.verification_history) state.data.verification_history = res.verification_history;
      renderPassport(state.data);
      setStatus("Repaired & Verified", "status-ok");
    } catch (err) {
      alert(err.message);
    }
  });

  async function loadState() {
    const data = await apiJson("/api/state");
    renderAll(data);
  }

  loadState().catch((e) => {
    $("active-dataset-title").textContent = `Server connection error: ${e.message}`;
  });
})();
