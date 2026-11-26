# VEIL Atelier — frontend integration note

| | |
|---|---|
| Protected baseline | `87aba54` (main when Atelier started, 2026-11-27 02:46 IST) |
| Frontend branch / worktree | `design/veil-atelier` (separate local git worktree) |
| Latest OMEGA main checked | `0697872` (includes `5f35fc7` UI/passport fixes) |
| Files changed | `web/index.html`, `web/styles.css`, `web/app.js`, new `web/tests/journeys.py`, `docs/frontend/**` |
| Backend files changed | **None** (`git diff 87aba54 -- . ':!web' ':!docs/frontend'` is empty) |

Nothing on this branch is merged or pushed. Integration is the user's call once OMEGA is done.

## Integration steps (verified in a scratch worktree on `0697872`)

OMEGA's own edits to `web/app.js` / `web/index.html` in `5f35fc7` are functional fixes; every one is
already in, or was ported into, this branch (see "Overlap with OMEGA" below). So integration replaces the
three web files rather than hand-merging them:

```bash
git checkout main            # once OMEGA has finished and committed
git checkout design/veil-atelier -- web/index.html web/styles.css web/app.js web/tests/journeys.py docs/frontend
python3 -m unittest tests.test_ui_hotfix_and_scale tests.test_ui_and_demo -v
python3 web/tests/journeys.py --rows 50000
```

If OMEGA changes `web/` again after `0697872`, diff `main:web/app.js` against `87aba54:web/app.js` first and
port any new behaviour into this branch before replacing the files.

Results of exactly that procedure on `0697872` (scratch worktree, my three files overlaid):
`tests.test_ui_hotfix_and_scale` + `tests.test_ui_and_demo` **OK** (including OMEGA's new
"Drive real Chromium across all 7 UI tabs" test, 0 console errors) and `journeys.py` **34/34**.

## UI contract kept (asserted by backend tests that this branch must not edit)

- Nav: `button[data-view="overview|runner|inspector|graph|arena|clinical|passport"]`, visible at 1280 px.
- Upload: `#file-input`, `#staged-stats-text` (“N / 64 files”), `#staged-files-list` (shows `name (2).csv` on duplicates),
  `[data-remove="i"]`, `#btn-clear-staged`, `#staged-summary-bar` hidden when empty, `#btn-run-uploaded` disabled when empty.
- `#runner-log`: “Ready (1x engine run · X/Y files sanitized · N records)…” (raw integers, no separators).
- `#status-pill`: exactly `Verified PASS`, exactly `Defect Caught!`, or containing `Sanitized Ready`.
- `#diff-output-pre` (highlighted output), `#graph-subset-badge` (“… of N clusters …”).
- `#passport-banner`: contains `VERIFICATION PENDING`, `SYNTHETIC DEFECT CAUGHT` or `RELEASE AUDIT PASSED` (rendered as the seal’s stamp).
- `#passport-pillars`: every audit field, label and value adjacent (e.g. “pseudonym placement errors0”, “5000/5000”).
- `#arena-status-badge`: `On-Demand` before, exactly `Measured Live` after; `#arena-table` contains backend labels.
- `#btn-download-zip` `aria-disabled` = `"true"` before a release, `"false"` after; `#btn-export-passport-html/json`, `#btn-export-zip`;
  export links gain `?variant=corrupt` while a defect copy is shown.
- `/` contains “VEIL — Clinical Privacy Command Center”; `/styles.css` contains `--emerald`; `/app.js` contains `highlightSanitized`.
- No `NaN` / `undefined` in rendered text.

## API contracts relied on (read-only inventory of `tools/veil_ui.py`)

| Method · path | Request | Response used | Errors handled |
|---|---|---|---|
| GET `/api/state` | — | `ready`, `active_job_id`, `historical_benchmarks`; when ready: `job_id`, `dataset_label`, `policy_mode`, `run_at`, `runtime_s`, `engine_executions`, `timings{}`, `report.counts{}`, `report.resources`, `passport_status`, `passport{verdict, checks{}, privacy, clinical, temporal, identity, structural, residual_risks, assurance_version, audit_seconds}`, `corrupted_passport`, `verification_history[]`, `identity_status`, `identity_graph{clusters, records, edges, meta, decision_counts}`, `arena_status`, `privacy_arena[]`, `file_pairs[]`, `transformations[]`, `clinical_detail{timeline_intervals, staff_preserved, samples}` | network → message + retry |
| POST `/api/run` (multipart) | `mode=upload`, `policy`, `secret`, `label`, `relpaths`, `files` (binary, one part per file) | 202 `{job_id}` | 400/413 `error_code` shown inline |
| POST `/api/run` (JSON) | `{mode:"demo", policy, secret, run_optional:true}` | 202 `{job_id}` | same |
| GET `/api/status/{job}` | — | `status` ∈ queued/running/validating/ready/failed/cancelled, `progress`, `stage`, `error`, `error_code` | 404 `job_not_found` → clears saved job; network → 8 bounded retries |
| POST `/api/cancel/{job}` | — | `{status:"cancelled"}` | ignored; poll reports outcome |
| GET `/api/diff?idx=` | — | `input_text`, `output_text` (64 KB preview, truncation marker), file meta | inline “Preview unavailable” |
| GET `/api/decisions?filter&page&limit=50` | — | `items[]{decision,left,right,scripts,rule}`, `total_filtered`, `decision_counts.truncated` | inline row |
| POST `/api/identity/run` | — | `identity_graph`, `identity_decisions`, `qi_stats`, `identity_s` | toast |
| POST `/api/arena/run` | — | `privacy_arena[]{mode,label,summary,qi{…},exact_pins_visible,residual_hits,clinical_kept_pct|null,runtime_s,reused_from_active_run}`, `arena_s` | toast |
| POST `/api/passport/run` | — | `passport`, `timings`, `verification_history` | toast |
| POST `/api/passport/corrupt` | — | `corrupted_passport{target_file, mutation, audit}`, `verification_history` | toast |
| POST `/api/passport/repair` | — | `passport`, `runtime_s`, `verification_history` | toast |
| GET `/api/passport/html|json[?variant=corrupt]`, `/api/download/zip` | — | attachments | browser download |

Assumptions to re-check at integration: response field names above (all defensive, missing values render “—”/“N/A”);
the server only serves `/`, `/index.html`, `/styles.css`, `/app.js`, so all icons and the logo are inline SVG
(a separate asset file would need a backend route — documented, not added).

## Existing features preserved

Multi-file staging (64 files / 16 MB, append across selections, drag-and-drop, duplicate renaming, remove, clear),
binary multipart upload, one engine run per upload, adaptive polling, bounded transient retry, job reconnection
(now also auto-resumes a job this tab started after a reload), cancellation, lazy per-view rendering, bounded
identity graph and paginated decisions, on-demand Arena and Passport, defect inject → detect → repair → reverify,
HTML/JSON Passport export, complete ZIP download.

## New frontend behaviour

- Design system: monochrome soft-panel tokens (light, dark, system; stored only in `localStorage`), Avenir Next / system font stack, no remote assets.
- Shell: floating source-list sidebar with a spring-animated active pill, collapsible Analysis group with tree line,
  icon rail mode (persisted), mobile drawer with scrim and Esc, hash deep links (`#/passport`), skip link.
- Overview: release state + next action, five-stage pipeline built from real report counts, run facts, historical benchmarks collapsed and labelled as not this run.
- Import & run: policy explained as radio cards, secret masked with reveal (never stored), real stage track from job status, completion actions.
- Record inspector: file navigator, synchronized scroll, highlight legend, truncation notice, opens on the first changed file, stale-response guard.
- Identity: patient list + focus graph (records → pseudonym → look-alikes kept apart), keyboard-operable nodes, reconstructed-evidence disclaimer.
- Privacy arena: three policy columns with denominators, “This run” marker, UI-heuristic disclaimer.
- Clinical: kept-verbatim and interval stats, temporal check counts, equal-duration timeline bars, category bars, samples.
- Passport: document sheet with drawn seal and stamp, five-pillar ledger (status, passed/total, detail), expandable evidence, history, defect-copy banner.
- Errors: toasts instead of `alert()`, actionable upload messages; motion respects `prefers-reduced-motion`.

## Overlap with OMEGA (`5f35fc7`) and how it is handled

| OMEGA change in `web/app.js` | Atelier status |
|---|---|
| Escape `'` in `esc()` | already present |
| Sr./Sis. as clinician titles in highlighter | ported |
| Lock staging/remove/clear/dropzone while submitting | ported |
| Export link enable/disable + `?variant=corrupt` | already present, IDs aligned to OMEGA's |
| Honest verdict states (PASS/WARNING/SKIPPED/FAIL) | already present (`assurance()`); stricter: Verified PASS requires verdict PASS |
| `clinical_kept_pct` may be `null` → N/A | ported (arena, clinical, Passport lede) |
| Stale identity/arena/passport/diff/decision responses ignored | already present |
| Multi-date intervals use last date | ported |
| Status after corrupt: “Review Risks” on reload | kept as `Defect Caught!` (consistent with the test that expects it right after injection) |

## Browser tests run

- `tests/test_ui_hotfix_and_scale.py`, `tests/test_ui_and_demo.py` on this branch: OK (Playwright E2E 5k ready 0.41 s, 10k ready ~1.7 s, bounded graph 0.2 s, 0 console/page errors).
- Same suites on OMEGA `0697872` + these web files: OK.
- `web/tests/journeys.py`: 34/34 at 5k, 10k and 50k rows — empty state, demo, ZIP contents, 65-file and >16 MB rejection,
  empty-secret block, reload mid-job resume, stale arena reset, bounded preview, bounded graph (40 of 50000 clusters, 22 SVG nodes),
  Passport pending → verdict, full denominators, 50000-record ZIP, defect → repair, skip link, keyboard nav, rail and dark persistence,
  1280/1024/768/390 px with reduced motion and no horizontal overflow, server-down error toast, zero console errors.

Screenshots: `docs/frontend/screenshots/before/` (old UI) and `docs/frontend/screenshots/after/` (every view, light and dark, 1440 px; 768/390 px; rail; empty; error; post-repair Passport).

## Known limitations

- Full-page screenshots show the sticky sidebar at viewport height; in the live app it stays pinned.
- Very long dataset labels wrap in the facts list on phones.
- The identity focus graph draws up to 24 records per pseudonym and up to 6 look-alikes; the rest are counted, not drawn.
- Contrast was checked by eye in both appearances, not with an automated WCAG tool.
