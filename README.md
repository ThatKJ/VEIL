# Rakshak: a multilingual, longitudinal privacy firewall for hospital records

Rakshak sanitises messy multi-hospital exports in English, Hindi (Devanagari) and Hinglish
(CSV/TSV, nested JSON, JSON Lines, FHIR R4, free-text notes, broken files). It works **offline,
on CPU only, with no LLMs or ML models**, using only the Python standard library. In one release it:

* removes personal data everywhere: content, JSON keys, CSV headers, file names, metadata, base64 attachments;
* keeps medicines, doses, vitals, lab values, diagnoses, doctors and exact hospital-stay lengths intact;
* links the same patient across scripts, files and hospitals (Mohammad / Mohd. / Md. / मोहम्मद), never merging homonyms;
* **measures and reduces patient-level re-identification risk**, the part that makes the attacker fail.

## Run

```bash
pip install -r requirements.txt          # nothing to install: standard library only
RAKSHA_SECRET=<secret> python3 main.py --input <input dir> --output <empty output dir>
```

Output: `sanitized/` (same tree and formats, UTF-8), `report.json`, `records.jsonl` (contract v1).
`RAKSHA_SECRET` keys every pseudonym, date shift and renamed file/key (HMAC-SHA256). It is never written anywhere.
Same input + same secret gives byte-identical output. A different secret gives different pseudonyms and shifts.

## How it works (two passes)

```
input ─► 1. Ingest: BOM/UTF-16/cp1252 sniffing, content-type sniffing (JSON behind .csv, pipe tables in .txt,
            JSON Lines), depth guard; unreadable or unsupported files are QUARANTINED, never copied
       ─► 2. Structure: per-field kind from header/key lexicon (EN/HI/Marathi/Hinglish) + value shape;
            patient records found at any depth (nested arrays, arrays-of-arrays, header+rows tables)
       ─► 3. Harvest: names, IDs, phones and villages from structured fields + labelled free text
       ─► 4. Identity graph: strong IDs, then name skeleton (script-independent) + second clue
            (DOB / relative / village+age), only when unambiguous; whole-cluster cannot-link checks
            (gender, DOB, age, Aadhaar/ABHA/PAN conflicts) stop transitive over-merging
       ─► 5. Pooled-profile privacy engine (USP, below) -> per-patient rule
       ─► 6. Rewrite: structured rules + free-text scrubber (doctor/clinical spans protected first; dates
            shifted per patient; IDs; labelled/kinship/honorific/contextual names; harvested-name sweep;
            address fragments; truthful age bands)
       ─► 7. Independent verification: exact-substring scan of harvested critical values on the output
       ─► report.json (SHA-256 per input file, honest counts), records.jsonl (pseudonym present IN each record)
```

## USP: pooled-profile, patient-level privacy

A patient who is anonymous in one record is often identifiable once all of their records are
pooled, and pooling is exactly what the attacker does. Rakshak resolves each patient's records first, then
evaluates the **pooled** quasi-identifiers (district, gender, age, birth year, conditions) of that patient
across every file, script and hospital. Generalisation is escalated **only for patients whose pooled profile is rare**:
a small equivalence class (`k10 < 2` or `k5 < 5`), a rare condition (shared by at most 3 patients), or age 80 and over. For those
patients a wider truthful age band (`10`-year) is used, and village/district/PIN fine geography are suppressed. Bands are **consistent per patient**,
so intersecting records cannot recover an exact age. Dates (encounters, FHIR `lastUpdated`, and escalated DOBs) move by a secret per-patient HMAC shift, so stays, clinical intervals, and temporal ordering stay exact.

Prior art: risk-driven anonymisation with attacker models exists for structured tables (ARX). Our contribution is applying
it to pooled multilingual free text plus structured records in one offline pipeline. This is a combination, not a "first".

## Measured results (local harness, commit `c7300d4`, NOT the official evaluator)

Local re-implementation of the published scorer and attacker (`docs/SCORING.md`, `docs/ATTACKS.md`). The official
evaluator is sealed, so totals below are **estimates**. Dev = organizer practice data. Chaos sets are independently
generated synthetic data with unseen regional formats, scripts, and traps.

| Dataset | Personal data leaked (`check_dev`) | Canaries | Medical kept | Link F0.5 / false merges | Utility / Privacy | Est. total |
|---|---:|---:|---:|---:|---:|---:|
| official `dev` | 0.0% | 0 / 4 | 99.3% (probes) | 0.989 / **0** | 0.941 / 0.870 | **91.95** |
| `chaos_dev` | 0.0% | 0 / 3 | 99.4% (probes) | 0.978 / **0** | 0.928 / 0.902 | **92.51** |
| 5 validation holdouts (`H1..H5`) | 0.1–0.7% | **0 / 20** | 99.7–100% | 0.971–0.991 / **0** | 0.895–0.913 / 0.834–0.979 | **89.47–94.79** |
| 3 unseen blind regional sets (`H9..H11`) | 0.8–1.8% | **0 / 12** | 100.0% | 0.978–0.994 / **0** | 0.904–0.918 / 0.880–0.921 | **87.09–91.95** (mean **89.94**) |

High-cardinality stress (`scale_cardinality.py`, 2 CPUs): 100,000 rows x 100,000 unique patients completes in **10.87s** (`659.2 MB` peak RSS, `0` quarantined); 2,000 small files in **1.15s**. Full logs: see `docs/brief.pdf` and `research/`.

## Models

None. No LLMs, no transformers, no pretrained models. Only rules, lexicons written for this project, transliteration
tables, and probabilistic-style record linkage.

## Known limitations

* The attacker model is the published one, so resistance to *other* attackers is not guaranteed. No finite test proves anonymity.
* Unseen layouts are handled generically (value shape, nested-record discovery), but entirely novel formats may still leak.
  Files we cannot parse safely (or symlinks outside `--input`) are quarantined cleanly, never exported raw.
* Rare-condition + exact stay length (LOS) remains partially matchable under targeted A5 (`0.20–0.64` rel. to raw) unless clinical diagnoses or stay lengths were degraded; clinical truth is preserved by design.
* Names with no structural or contextual cue at all can survive. An independent `O(N)` verification pass sweeps harvested critical tokens while guarding `Dr.` spans.
